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

namespace {

void ToGRPCUpdateMetadata(filesys::UpdateMetadata& out, const UpdateMetadata& metadata) {
    out.set_version(metadata.version);
    out.mutable_stripe_range()->set_offset(metadata.stripe_offset);
    out.mutable_stripe_range()->set_count(metadata.num_stripes);
    out.set_file_size(metadata.file_size);
    out.set_is_delete(metadata.is_delete);
    out.set_version_signature(BytesToStr(metadata.signature));
}

UpdateMetadata ToUpdateMetadata(const filesys::UpdateMetadata& metadata) {
    return UpdateMetadata{
        .version = metadata.version(),
        .stripe_offset = metadata.stripe_range().offset(),
        .num_stripes = metadata.stripe_range().count(),
        .file_size = metadata.file_size(),
        .is_delete = metadata.is_delete(),
        .signature = StrToBytes(metadata.version_signature()),
    };
}

} // namespace

FilesysImpl::FilesysImpl(
    const Config& config, const fs::path& local_storage, uint32_t server_idx)
        : _config(config),
          _data_storage(local_storage, config.servers.size(), config.block_size),
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

    // std::thread(&FilesysImpl::HeartBeat, this).detach();
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
    uint32_t version = 0;
    if (args->has_version()) {
        version = args->version();
    } else {
        auto latest_version = _data_storage.GetLatestVersion(file_name);
        if (!latest_version.has_value()) {
            return grpc::Status(grpc::StatusCode::NOT_FOUND, "File not found.");
        }
        version = latest_version.value().version;
    }
    spdlog::info("Server {}: Read {}, version={}", _server_idx, args->file_name(), version);

    for (auto& range : args->stripe_ranges()) {
        Bytes block_data = _data_storage.ReadFile(file_name, range.offset(),
                                                    range.count(), version);
        if (block_data.empty()) {
            return grpc::Status(grpc::StatusCode::NOT_FOUND,
                                "Version does not exist or has expired.");
        }
        std::string block_data_str =
            std::string(block_data.begin(), block_data.end());
        *reply->add_block_data() = block_data_str;
    }
    reply->set_version(version);
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

    auto update_log = file->GetUpdateLog(args->after_version());
    for (const auto& metadata : update_log) {
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
    size_t num_peers = _config.num_malicious + 1;
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
        peers, args, &Filesys::Stub::PrepareAsyncGetFileList,
        0, 10s, 10s,
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
                if (_data_storage.GetLatestVersion(file_name).value().version < target_version) {
                    _thread_pool.detach_task([this, file_name = file_name, target_version]() {
                        // Wait for possible write to come.
                        std::this_thread::sleep_for(15s);
                        uint32_t current_version =
                            _data_storage.GetLatestVersion(file_name).value().version;
                        if (current_version < target_version) {
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

    const size_t stripe_size = GetStripeSize(_config.block_size, _config.servers.size(), _config.num_malicious);

    GetUpdateLogArgs args;
    args.set_file_name(file_name);
    args.set_after_version(current_version);
    std::map<uint32_t, UpdateMetadata> update_log;
    std::set<std::pair<uint64_t, uint64_t>> segments;
    std::vector<Bytes> reconstructed_blocks;
    bool is_deleted = false;
    while (true) {
        bool success = QueryServers<GetUpdateLogReply>(
            _peers, args, &Filesys::Stub::PrepareAsyncGetUpdateLog,
            _config.num_malicious + 1, 1s, 10s,
            [&](const std::vector<AsyncResponse<GetUpdateLogReply>>& responses,
                const std::vector<uint8_t>& replied,
                size_t& minimum_success) -> bool {

                for (uint32_t i = 0; i < replied.size(); i++) {
                    if (!replied[i] || !responses[i].status.ok()) continue;
                    const auto& log = responses[i].reply.log();
                    for (const auto& metadata : log) {
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
        if (update_log.rbegin()->second.is_delete) {
            // file deleted
            is_deleted = true;
            break;
        }
        // merge segments
        segments.clear();
        for (uint32_t version = target_version; version > current_version; version--) {
            auto update_it = update_log.find(version);
            if (update_it == update_log.end()) {
                // update log incomplete; assume all blocks are lost
                segments.insert({0, (update_log.rbegin()->second.file_size + stripe_size - 1) / stripe_size});
                break;
            }
            auto& metadata = update_log[version];
            if (metadata.is_delete) break;
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
        // TODO: read file for each segment; retry if fail
        break;
    }
    std::shared_ptr<File> file = _data_storage[file_name];
    if (file == nullptr) throw std::runtime_error("File not found");
    // file->UpdateUndoLogAndFile(update_log, segments, reconstructed_blocks, is_delete);
}
