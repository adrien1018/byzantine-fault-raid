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

void ToUpdateMetadata(filesys::UpdateMetadata& out, const UpdateMetadata& metadata) {
    out.set_version(metadata.version);
    out.mutable_stripe_range()->set_offset(metadata.stripe_offset);
    out.mutable_stripe_range()->set_count(metadata.num_stripes);
    out.set_file_size(metadata.file_size);
    out.set_is_delete(metadata.is_delete);
    out.set_version_signature(BytesToStr(metadata.signature));
}

} // namespace

FilesysImpl::FilesysImpl(
    const Config& config, const fs::path& local_storage, uint32_t server_idx)
        : _config(config),
          _data_storage(local_storage, config.servers.size(), config.block_size),
          _server_idx(server_idx) {
    for (uint32_t i = 0; i < config.servers.size(); i++) {
        if (i == server_idx) {
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
    const filesys::UpdateMetadata& metadata = args->metadata();
    Bytes block_data = StrToBytes(args->block_data());

    UpdateMetadata file_metadata{
        .version = metadata.version(),
        .stripe_offset = metadata.stripe_range().offset(),
        .num_stripes = metadata.stripe_range().count(),
        .file_size = metadata.file_size(),
        .is_delete = false,
        .signature = StrToBytes(metadata.version_signature()),
    };
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
        ToUpdateMetadata(*file_info->mutable_last_update(), file_last_update);
        file_info->set_start_version(file->StartVersion());
        spdlog::debug("Server {}: file {} version={}", _server_idx, file->FileName(),
                      file_last_update.version);
    }
    return Status::OK;
}

Status FilesysImpl::GetUpdateLog(ServerContext* context, const GetUpdateLogArgs* args,
                    GetUpdateLogReply* reply) {
    // Only OK if target version is reached
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
            tried_count = 1;
        }
        if (servers.size() < num_peers) {
            std::vector<int> options;
            for (size_t i = 0; i < _peers.size(); i++) {
                if (!tried[i]) options.emplace_back(i);
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
                    if (!VerifyUpdateSignature(file.last_update(), file.file_name(),
                                               file.public_key())) {
                        continue;
                    }
                    std::string file_name = file.file_name();
                    auto& file_version = file_versions[file_name];
                    file_version = std::max(file_version, file.last_update().version());
                }
            }

            for (auto& [file_name, target_version] : file_versions) {
                if (_data_storage.GetLatestVersion(file_name).value().version < target_version) {
                    // TODO: use thread pool?
                    std::thread([this, file_name = file_name, target_version]() {
                        // Wait for possible write to come.
                        std::this_thread::sleep_for(15s);
                        uint32_t current_version =
                            _data_storage.GetLatestVersion(file_name).value().version;
                        if (current_version < target_version) {
                            Recovery(file_name, current_version, target_version);
                        }
                    }).detach();
                }
            }
            return true;
        }, "HeartBeat");
}

void FilesysImpl::Recovery(
    const std::string& file_name, uint32_t current_version, uint32_t target_version) {
    GetUpdateLogArgs args;
    args.set_file_name(file_name);
    args.set_after_version(current_version);
    args.set_target_version(target_version);
    std::map<uint32_t, UndoRecord> update_log;
    while (true) {
        QueryServers<GetUpdateLogReply>(
            _peers, args, &Filesys::Stub::PrepareAsyncGetUpdateLog,
            _config.num_malicious + 1, 1s, 5s,
            [&](const std::vector<AsyncResponse<GetUpdateLogReply>>& responses,
                const std::vector<uint8_t>& replied,
                size_t& minimum_success) -> bool {
                // TODO: Finish after finalizing update log format
                // update target_version if needed
                return true;
            },
            "GetUpdateLog");
        // TODO: merge segments
        // TODO: read file for each segment; continue if fail
        break;
    }
    std::shared_ptr<File> file = _data_storage[file_name];
    if (file == nullptr) throw std::runtime_error("File not found");
    // file->UpdateUndoLogAndFile(update_log, segments);
}
