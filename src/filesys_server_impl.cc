#include "filesys_server_impl.h"

#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>

#include "async_query.h"

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
          _data_storage(local_storage, config.block_size),
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
    std::string file_name = args->file_name();
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
    uint32_t version = args->has_version()
                            ? args->version()
                            : _data_storage.GetLatestVersion(file_name).value().version;

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
    const filesys::UpdateMetadata& metadata = args->metadata();
    Bytes block_data = StrToBytes(args->block_data());

    // spdlog::info("Server {} write {}", _server_idx, block_data);

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
    }
    return Status::OK;
}

Status FilesysImpl::GetUpdateLog(ServerContext* context, const GetUpdateLogArgs* args,
                    GetUpdateLogReply* reply) {
    return Status::OK;
}

Status FilesysImpl::DeleteFile(ServerContext* context, const DeleteFileArgs* args,
                    google::protobuf::Empty* _) {
    if (!_data_storage.DeleteFile(args->file_name(), args->version(),
                                    StrToBytes(args->version_signature()))) {
        return grpc::Status(grpc::StatusCode::NOT_FOUND, "File not found.");
    }
    return Status::OK;
}

void FilesysImpl::HeartBeat() {
    while (true) {
        GetFileListArgs args;
        args.set_include_deleted(true);

        QueryServers<GetFileListReply>(
            _peers, args, &Filesys::Stub::PrepareAsyncGetFileList,
            2 * _config.num_malicious + 1, 1s, 10s,
            [&](const std::vector<AsyncResponse<GetFileListReply>>&
                    responses,
                const std::vector<uint8_t>& replied,
                size_t& minimum_success) -> bool {
                std::unordered_map<std::string, std::vector<uint32_t>>
                    file_versions;
                for (uint32_t i = 0; i < replied.size(); i++) {
                    if (replied[i] && responses[i].status.ok()) {
                        const auto& files = responses[i].reply.files();
                        for (auto& file : files) {
                            std::string file_name = file.file_name();
                            uint32_t version = file.last_update().version();
                            file_versions[file_name].emplace_back(version);
                        }
                    }
                }

                for (auto& [file_name, versions] : file_versions) {
                    if (versions.size() <= _config.num_malicious) continue;
                    std::sort(versions.begin(), versions.end());
                    uint32_t offset =
                        versions.size() - _config.num_malicious - 1;
                    uint32_t target_version = versions[offset];
                    if (versions.size() > _config.num_malicious &&
                        _data_storage.GetLatestVersion(file_name).value().version < target_version) {
                        std::thread([this, file_name = file_name,
                                        target_version]() {
                            // Wait for possible write to come.
                            std::this_thread::sleep_for(15s);
                            uint32_t current_version =
                                _data_storage.GetLatestVersion(file_name).value().version;
                            if (current_version < target_version) {
                                Recovery(file_name, current_version,
                                            target_version);
                            }
                        }).detach();
                    }
                }
                return true;
            },
            "GetFileList");
        std::this_thread::sleep_for(10s);
    }
}

void FilesysImpl::Recovery(const std::string& file_name, uint32_t current_version,
                uint32_t target_version) {
    GetUpdateLogArgs args;
    args.set_file_name(file_name);
    args.set_after_version(current_version);
    std::map<uint32_t, UndoRecord> update_log;
    while (true) {
        QueryServers<GetUpdateLogReply>(
            _peers, args, &Filesys::Stub::PrepareAsyncGetUpdateLog,
            2 * _config.num_malicious + 1, 1s, 5s,
            [&](const std::vector<AsyncResponse<GetUpdateLogReply>>&
                    responses,
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
