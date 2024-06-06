#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <spdlog/fmt/ranges.h>

#include <CLI/CLI.hpp>
#include <algorithm>
#include <filesystem>
#include <string>
#include <unordered_map>

#include "async_query.h"
#include "config.h"
#include "data_storage.h"
#include "file.h"
#include "filesys.grpc.pb.h"

using filesys::CreateFileArgs;
using filesys::DeleteFileArgs;
using filesys::FileInfo;
using filesys::Filesys;
using filesys::GetFileListArgs;
using filesys::GetFileListReply;
using filesys::GetUpdateLogArgs;
using filesys::GetUpdateLogReply;
using filesys::ReadBlocksArgs;
using filesys::ReadBlocksReply;
using filesys::WriteBlocksArgs;
using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerWriter;
using grpc::Status;

#include <iostream>

namespace fs = std::filesystem;

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

class FilesysImpl final : public Filesys::Service {
    Config _config;
    DataStorage _data_storage;
    uint32_t _server_idx;
    std::vector<Filesys::Stub*> _peers;

   public:
    explicit FilesysImpl(const Config& config, const fs::path& local_storage,
                         uint32_t server_idx)
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

    Status CreateFile(ServerContext* context, const CreateFileArgs* args,
                      google::protobuf::Empty* _) override {
        std::string file_name = args->file_name();
        std::string public_key = args->public_key();
        if (_data_storage.CreateFile(
                file_name, Bytes(public_key.begin(), public_key.end()))) {
            return Status::OK;
        } else {
            return grpc::Status(grpc::StatusCode::ALREADY_EXISTS,
                                "File already exists");
        }
    }

    Status ReadBlocks(ServerContext* context, const ReadBlocksArgs* args,
                      ReadBlocksReply* reply) override {
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

    Status WriteBlocks(ServerContext* context, const WriteBlocksArgs* args,
                       google::protobuf::Empty* _) override {
        const filesys::UpdateMetadata& metadata = args->metadata();
        Bytes block_data = StrToBytes(args->block_data());

        // spdlog::info("Server {} write {}", _server_idx, block_data);

        UpdateMetadata file_metadata{
            .version = (int32_t)metadata.version(),
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

    Status GetFileList(ServerContext* context, const GetFileListArgs* args,
                       GetFileListReply* reply) override {
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

    Status GetUpdateLog(ServerContext* context, const GetUpdateLogArgs* args,
                        GetUpdateLogReply* reply) override {
        return Status::OK;
    }

    Status DeleteFile(ServerContext* context, const DeleteFileArgs* args,
                      google::protobuf::Empty* _) override {
        if (!_data_storage.DeleteFile(args->file_name(), args->version(),
                                      StrToBytes(args->version_signature()))) {
            return grpc::Status(grpc::StatusCode::NOT_FOUND, "File not found.");
        }
        return Status::OK;
    }

    void HeartBeat() {
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
                            _data_storage.GetLatestVersion(file_name).value().version <
                                (int32_t)target_version) {
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

    void Recovery(const std::string& file_name, uint32_t current_version,
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
};

/* Entry point of the service. Start the service. */
static void RunServer(const std::string& ip_address, uint32_t server_idx,
                      uint16_t port, const Config& config,
                      const fs::path& local_storage) {
    FilesysImpl service(config, local_storage, server_idx);

    std::string server_address{ip_address + ":" + std::to_string(port)};
    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;
    server->Wait();
}

int main(int argc, char* argv[]) {
    spdlog::set_pattern("[%t] %+");
    spdlog::set_level(spdlog::level::debug);

    /* Parse command line arguments. */
    CLI::App filesys;

    std::string ip_address{"0.0.0.0"};
    filesys.add_option("-a,--address", ip_address);

    uint32_t server_idx;
    filesys.add_option("-i,--index", server_idx)->required(); /* todo. */

    uint16_t port{8080}; /* Default value for the port to serve on. */
    filesys.add_option("-p,--port", port);

    fs::path local_storage{"./storage"};
    filesys.add_option("-s,--storage", local_storage);

    /* Set config file path for settings such as list of servers. */
    filesys.set_config("--config", "../config.toml")->required();

    CLI11_PARSE(filesys, argc, argv);

    /* Process configuration file. */
    const std::string config_file = filesys.get_config_ptr()->as<std::string>();
    Config config = ParseConfig(config_file);
    RunServer(ip_address, server_idx, port, config, local_storage);

    return 0;
}
