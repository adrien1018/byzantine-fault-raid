#include "filesys_server_impl.h"

#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>

#include "async_query.h"
#include "filesys_common.h"

using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerWriter;
using grpc::Status;

FilesysImpl::FilesysImpl(
    const Config& config, const fs::path& local_storage, uint32_t server_idx)
        : _config(config),
          _data_storage(local_storage, config.servers.size(), config.block_size,
                        GetStripeSize(config.block_size, config.servers.size(), config.num_faulty)),
          _server_idx(server_idx) {
    for (const auto& file : _data_storage.GetFileList("")) {
        _seen_public_keys.insert(file->PublicKey());
    }

    for (uint32_t i = 0; i < config.servers.size(); i++) {
        if (i == server_idx) {
            _peers.emplace_back(nullptr);
            continue;
        }
        const auto address = config.servers[i];
        std::shared_ptr<Channel> channel = grpc::CreateChannel(
            address, grpc::InsecureChannelCredentials());
        _peers.emplace_back(Filesys::NewStub(channel).release());
    }

    std::thread(&FilesysImpl::HeartBeatThread, this).detach();
}

Status FilesysImpl::CreateFile(
    ServerContext* context, const CreateFileArgs* args, google::protobuf::Empty* _) {
    spdlog::info("Server {}: Create {} version={}", _server_idx, args->file_name(), args->version());
    if (_data_storage.CreateFile(
            args->file_name(), args->version(), StrToBytes(args->version_signature()))) {
        std::lock_guard<std::mutex> lock(_mu);
        Bytes public_key = GetPublicKeyFromPath(args->file_name());
        _seen_public_keys.insert(public_key);
        _heartbeat_new_files.erase(public_key);
        return Status::OK;
    } else {
        return grpc::Status(grpc::StatusCode::ALREADY_EXISTS,
                            "File already exists");
    }
}

Status FilesysImpl::ReadBlocks(ServerContext* context, const ReadBlocksArgs* args,
                    ReadBlocksReply* reply) {
    std::string file_name = args->file_name();
    
    auto file = _data_storage[file_name];
    if (file == nullptr) {
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "File not found.");
    }
    std::lock_guard<std::mutex> lock(file->Mutex());

    uint32_t version = args->has_version() ? args->version() : file->LastUpdate().version;
    spdlog::info("Server {}: Read {}, version={}", _server_idx, args->file_name(), version);

    reply->set_version(version);
    for (auto& range : args->stripe_ranges()) {
        Bytes block_data = file->ReadVersion(version, range.offset(), range.count());
        if (block_data.empty()) {
            return grpc::Status(grpc::StatusCode::NOT_FOUND,
                                "Version does not exist or has expired.");
        }
        std::string block_data_str =
            std::string(block_data.begin(), block_data.end());
        *reply->add_block_data() = block_data_str;
    }
    for (const auto& metadata : file->GetUpdateLog(0)) {
        filesys::UpdateMetadata* update_metadata = reply->add_update_log();
        ToGRPCUpdateMetadata(*update_metadata, metadata);
    }
    return Status::OK;
}

Status FilesysImpl::WriteBlocks(ServerContext* context, const WriteBlocksArgs* args,
                    google::protobuf::Empty* _) {
    spdlog::info("Server {}: Write {}, version={}, offset={}, stripes={}, file_size={}",
                  _server_idx, args->file_name(), args->metadata().version(),
                  args->metadata().stripe_range().offset(),
                  args->metadata().stripe_range().count(),
                  args->metadata().file_size());
    Bytes block_data = StrToBytes(args->block_data());
    UpdateMetadata file_metadata = ToUpdateMetadata(args->metadata());
    file_metadata.is_delete = false;

    if (!_data_storage.WriteFile(args->file_name(), file_metadata, _server_idx, block_data)) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "Invalid version.");
    }
    spdlog::info("Server {}: Write success", _server_idx);
    return Status::OK;
}

Status FilesysImpl::GetFileList(ServerContext* context, const GetFileListArgs* args,
                    GetFileListReply* reply) {
    spdlog::info("Server {}: GetFileList {}", _server_idx, args->file_name());
    const auto file_list = _data_storage.GetFileList(args->file_name());
    for (const auto& file : file_list) {
        std::lock_guard<std::mutex> lock(file->Mutex());
        UpdateMetadata file_last_update = file->LastUpdate();
        if (file_last_update.is_delete && !args->include_deleted()) {
            continue;
        }
        FileInfo* file_info = reply->add_files();
        file_info->set_file_name(file->FileName());
        file_info->set_public_key(BytesToStr(file->PublicKey()));
        ToGRPCUpdateMetadata(*file_info->mutable_last_update(), file_last_update);
        file_info->set_start_version(file->StartVersion());
        spdlog::debug("Server {}: file {} version={}", _server_idx, file->FileName(),
                      file_last_update.version);
    }
    return Status::OK;
}

Status FilesysImpl::GetUpdateLog(ServerContext* context, const GetUpdateLogArgs* args,
                    GetUpdateLogReply* reply) {
    spdlog::info("Server {}: GetUpdateLog {} after={}",
                 _server_idx, args->file_name(), args->after_version());
    auto file = _data_storage[args->file_name()];
    if (file == nullptr) {
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "File not found.");
    }

    std::lock_guard<std::mutex> lock(file->Mutex());
    for (const auto& metadata : file->GetUpdateLog(args->after_version())) {
        filesys::UpdateMetadata* update_metadata = reply->add_log();
        ToGRPCUpdateMetadata(*update_metadata, metadata);
    }
    return Status::OK;
}

Status FilesysImpl::DeleteFile(ServerContext* context, const DeleteFileArgs* args,
                    google::protobuf::Empty* _) {
    spdlog::info("Server {}: Delete {} version={}", _server_idx, args->file_name(), args->version());
    if (!_data_storage.DeleteFile(args->file_name(), args->version(),
                                    StrToBytes(args->version_signature()))) {
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "File not found.");
    }
    return Status::OK;
}

void FilesysImpl::HeartBeatThread() {
    std::vector<uint8_t> tried(_peers.size());
    tried[_server_idx] = 1;

    size_t tried_count = 1;
    // anything larger than num_faulty + 1 will work; get some redundancy for better performance
    size_t num_peers = std::min(_peers.size() - 1, (size_t)_config.num_faulty + 5);
    while (true) {
        std::vector<int> servers;
        servers.reserve(num_peers);
        if (tried_count + num_peers >= _peers.size()) {
            for (size_t i = 0; i < _peers.size(); i++) {
                if (!tried[i]) servers.emplace_back(i);
            }
            tried.assign(_peers.size(), 0);
            tried[_server_idx] = 1;
            tried_count = 1;
        }
        if (servers.size() < num_peers) {
            std::vector<uint8_t> in_list(_peers.size());
            for (auto& i : servers) in_list[i] = 1;
            in_list[_server_idx] = 1;
            std::vector<int> options;
            for (size_t i = 0; i < _peers.size(); i++) {
                if (!in_list[i] && !tried[i]) options.emplace_back(i);
            }
            std::shuffle(options.begin(), options.end(), _rng);
            options.resize(num_peers - servers.size());
            tried_count += options.size();
            for (auto& i : options) tried[i] = 1;
            servers.insert(servers.end(), options.begin(), options.end());
        }
        
        HeartBeat(servers);
        std::this_thread::sleep_for(10s);
    }
}

void FilesysImpl::HeartBeat(const std::vector<int>& peer_idx) {
    GetFileListArgs args;
    args.set_include_deleted(true);

    std::vector<Filesys::Stub*> peers;
    for (auto& i : peer_idx) peers.emplace_back(_peers[i]);

    QueryServers<GetFileListReply>(
        peers, args, &Filesys::Stub::AsyncGetFileList,
        0, 1s, 1s,
        [&](const std::vector<AsyncResponse<GetFileListReply>>& responses,
            const std::vector<uint8_t>& replied,
            size_t& minimum_success) -> bool {
            std::unordered_map<std::string, uint32_t> file_versions;
            for (uint32_t i = 0; i < replied.size(); i++) {
                if (!replied[i] || !responses[i].status.ok()) continue;
                const auto& files = responses[i].reply.files();
                for (auto& file : files) {
                    Bytes public_key = StrToBytes(file.public_key());
                    if (!VerifyUpdateSignature(file.last_update(), file.file_name(), public_key)) {
                        continue;
                    }
                    std::string file_name = file.file_name();
                    bool ok = false;
                    
                    std::lock_guard<std::mutex> lock(_mu);
                    if (_seen_public_keys.count(public_key)) {
                        ok = true;
                    } else {
                        auto& entry = _heartbeat_new_files[public_key][file_name];
                        entry.insert(peer_idx[i]);
                        if (entry.size() >= _config.num_malicious + 1) {
                            _seen_public_keys.insert(public_key);
                            _heartbeat_new_files.erase(public_key);
                            ok = true;
                        }
                    }
                    if (ok) {
                        auto& file_version = file_versions[file_name];
                        file_version = std::max(file_version, file.last_update().version());
                    }
                }
            }

            for (auto& [file_name, target_version] : file_versions) {
                auto latest_update = _data_storage.GetLatestVersion(file_name);
                if (!latest_update.has_value() || latest_update.value().version < target_version) {
                    _thread_pool.detach_task([this, file_name = file_name, target_version]() {
                        // Wait for possible write to come.
                        std::this_thread::sleep_for(5s);
                        auto latest_update = _data_storage.GetLatestVersion(file_name);
                        uint32_t current_version = latest_update.has_value() ?
                            latest_update.value().version : 0;
                        if (!latest_update.has_value() || current_version < target_version) {
                            Recovery(file_name, current_version);
                        }
                    });
                }
            }
            return true;
        }, "HeartBeat");
}

void FilesysImpl::Recovery(
    const std::string& file_name, uint32_t current_version) {
    std::unique_lock<std::mutex> lock(_recovery_lock[file_name], std::try_to_lock);
    if (!lock.owns_lock()) return;

    spdlog::info("Server {}: Recovery for {} version={}", _server_idx, file_name, current_version);
    const size_t stripe_size = GetStripeSize(_config.block_size, _config.servers.size(), _config.num_faulty);
    Bytes public_key = GetPublicKeyFromPath(file_name);

    auto peers = _peers;
    peers.erase(peers.begin() + _server_idx);

    GetUpdateLogArgs args;
    args.set_file_name(file_name);
    args.set_after_version(current_version);
    std::map<uint32_t, UpdateMetadata> update_log;
    std::set<std::pair<uint64_t, uint64_t>> segments;
    std::vector<Bytes> reconstructed_blocks;
    uint32_t create_version = 0;
    while (true) {
        reconstructed_blocks.clear();
        segments.clear();

        bool success = QueryServers<GetUpdateLogReply>(
            peers, args, &Filesys::Stub::AsyncGetUpdateLog,
            _config.num_malicious + 1, 1s, 10s,
            [&](const std::vector<AsyncResponse<GetUpdateLogReply>>& responses,
                const std::vector<uint8_t>& replied,
                size_t& minimum_success) -> bool {

                for (uint32_t i = 0; i < replied.size(); i++) {
                    if (!replied[i] || !responses[i].status.ok()) continue;
                    const auto& log = responses[i].reply.log();
                    for (const auto& metadata : log) {
                        if (!VerifyUpdateSignature(metadata, file_name, public_key)) break;
                        update_log[metadata.version()] = ToUpdateMetadata(metadata);
                    }
                }
                return true;
            },
            "GetUpdateLog");
        if (!success) {
            std::this_thread::sleep_for(5s);
            continue;
        }
        uint32_t target_version = update_log.rbegin()->first;
        uint64_t latest_size = update_log.rbegin()->second.file_size;
        uint64_t latest_stripes = (latest_size + stripe_size - 1) / stripe_size;
        if (update_log.rbegin()->second.is_delete) {
            // file deleted
            break;
        }
        // merge segments
        create_version = 0;
        for (uint32_t version = target_version; version > current_version; version--) {
            auto update_it = update_log.find(version);
            if (update_it == update_log.end()) {
                // update log incomplete; assume all blocks are lost
                segments.insert({0, latest_stripes});
                break;
            }
            auto& metadata = update_log[version];
            if (metadata.is_delete) break;
            if (metadata.num_stripes == 0) {
                create_version = version;
                break;
            }
            // insert (metadata.stripe_offset, metadata.stripe_offset + metadata.num_stripes) into segments
            // and merge overlapping segments
            auto [it, inserted] = segments.insert({
                metadata.stripe_offset, metadata.stripe_offset + metadata.num_stripes});
            if (!inserted) continue;
            while (it != segments.begin()) {
                auto prev = std::prev(it);
                if (prev->second < it->first) break;
                std::pair<uint64_t, uint64_t> new_segment = {
                    prev->first, std::max(it->second, prev->second)};
                segments.erase(prev);
                segments.erase(it);
                it = segments.insert(new_segment).first;
            }
            while (true) {
                auto next = std::next(it);
                if (next == segments.end() || next->first > it->second) break;
                std::pair<uint64_t, uint64_t> new_segment = {
                    it->first, std::max(next->second, it->second)};
                segments.erase(it);
                segments.erase(next);
                it = segments.insert(new_segment).first;
            }
        }
        // this should not happen, but just in case
        while (segments.rbegin()->first >= latest_stripes) {
            spdlog::warn("Server {}: file {} version={} has invalid segment ({},{})",
                         _server_idx, file_name, target_version,
                         segments.rbegin()->first, segments.rbegin()->second);
            segments.erase(std::prev(segments.end()));
        }
        if (segments.rbegin()->second > latest_stripes) {
            spdlog::warn("Server {}: file {} version={} has invalid segment ({},{})",
                         _server_idx, file_name, target_version,
                         segments.rbegin()->first, segments.rbegin()->second);
            std::pair<uint64_t, uint64_t> new_segment = {
                segments.rbegin()->first, latest_stripes};
            segments.erase(std::prev(segments.end()));
            segments.insert(new_segment);
        }

        std::vector<ReadRange> ranges;
        ranges.reserve(segments.size());
        reconstructed_blocks.reserve(segments.size());
        for (const auto& [start, end] : segments) {
            reconstructed_blocks.emplace_back((end - start) * _config.block_size);
            ranges.push_back({start * stripe_size, (end - start) * stripe_size,
                             (char*)reconstructed_blocks.back().data()});
        }
        auto read_ret = MultiReadOrReconstruct(
            _peers, file_name, latest_size, std::move(ranges), target_version,
            _config.num_faulty, _config.block_size, 10s, _config.num_malicious, _server_idx);
        if (read_ret.size() != segments.size()) throw std::runtime_error("Unexpected read result");
        bool read_failed = false;
        for (size_t i = 0; i < segments.size(); i++) {
            if (read_ret[i] != (int64_t)reconstructed_blocks[i].size()) {
                spdlog::warn("Server {}: file {} version={} segment {} read failed {} (expected {})",
                             _server_idx, file_name, target_version, i, read_ret[i], reconstructed_blocks[i].size());
                read_failed = true;
                break;
            }
        }
        if (read_failed) {
            std::this_thread::sleep_for(5s);
            continue;
        }
        break;
    }
    std::shared_ptr<File> file = _data_storage[file_name];
    if (file == nullptr) {
        auto it = update_log.find(create_version);
        if (it == update_log.end()) {
            spdlog::warn("Server {}: file {} version={} recovery failed",
                         _server_idx, file_name, create_version);
            return;
        }
        _data_storage.CreateFile(file_name, create_version, it->second.signature);
        file = _data_storage[file_name];
    }
    if (!file->UpdateUndoLogAndFile(update_log, segments, reconstructed_blocks)) {
        spdlog::warn("Server {}: file {} version={} recovery failed",
                     _server_idx, file_name, update_log.rbegin()->first);
    }
}
