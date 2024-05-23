#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include <filesystem>
#include <iostream>
#include <string>

#include "CLI11.hh"
#include "config.h"
#include "data_storage.h"
#include "file.h"
#include "filesys.grpc.pb.h"

using filesys::CreateFileArgs;
using filesys::Filesys;
using filesys::GetFileListReply;
using filesys::GetUpdateLogArgs;
using filesys::GetUpdateLogReply;
using filesys::HeartBeatReply;
using filesys::ReadBlocksArgs;
using filesys::ReadBlocksReply;
using filesys::WriteBlocksArgs;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerWriter;
using grpc::Status;

namespace fs = std::filesystem;

class FilesysImpl final : public Filesys::Service {
    Config _config;
    DataStorage _data_storage;
    uint32_t _server_idx;

   public:
    explicit FilesysImpl(const Config& config, const fs::path& local_storage,
                         uint32_t server_idx)
        : _config(config),
          _data_storage(local_storage, config.block_size),
          _server_idx(server_idx) {}

    Status CreateFile(ServerContext* context, const CreateFileArgs* args,
                      google::protobuf::Empty* _) override {
        std::string file_name = args->file_name();
        std::string public_key = args->public_key();
        _data_storage.CreateFile(file_name,
                                 Bytes(public_key.begin(), public_key.end()));
        return Status::OK;
    }

    Status ReadBlocks(ServerContext* context, const ReadBlocksArgs* args,
                      ReadBlocksReply* reply) override {
        std::string file_name = args->file_name();
        uint32_t version = args->has_version()
                               ? args->version()
                               : _data_storage.GetLatestVersion(file_name);

        Bytes block_data = _data_storage.ReadFile(
            file_name, args->stripe_offset(), args->num_stripes(), version);
        if (block_data.empty()) {
            return grpc::Status(grpc::StatusCode::NOT_FOUND,
                                "Version does not exist or has expired.");
        }
        std::string block_data_str =
            std::string(block_data.begin(), block_data.end());
        reply->set_block_data(block_data_str);
        reply->set_version(version);
        return Status::OK;
    }

    Status WriteBlocks(ServerContext* context, const WriteBlocksArgs* args,
                       google::protobuf::Empty* _) override {
        /* TODO: Verify signature */
        uint32_t version = args->version();
        std::string file_name = args->file_name();
        std::string block_data_str = args->block_data();
        Bytes block_data = Bytes(block_data_str.begin(), block_data_str.end());

        if (!_data_storage.WriteFile(file_name, args->stripe_offset(),
                                     args->num_stripes(), _server_idx, version,
                                     block_data)) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                "Invalid version.");
        }

        return Status::OK;
    }

    Status GetFileList(ServerContext* context, const google::protobuf::Empty* _,
                       ServerWriter<GetFileListReply>* writer) override {
        const auto file_list = _data_storage.GetFileList();
        for (const auto& file : file_list) {
            GetFileListReply reply;
            reply.set_file_name(file->FileName());
            Bytes public_key_bytes = file->PublicKey();
            std::string public_key_str =
                std::string(public_key_bytes.begin(), public_key_bytes.end());
            reply.set_public_key(public_key_str);
            reply.set_version(file->Version());
            writer->Write(reply);
        }
        return Status::OK;
    }

    Status GetUpdateLog(ServerContext* context, const GetUpdateLogArgs* args,
                        ServerWriter<GetUpdateLogReply>* writer) override {
        return Status::OK;
    }

    Status HeartBeat(ServerContext* context, const google::protobuf::Empty* _,
                     ServerWriter<HeartBeatReply>* writer) override {
        return Status::OK;
    }
};

/* Entry point of the service. Start the service. */
static void RunServer(const std::string& ip_address, uint16_t port,
                      const Config& config, const fs::path& local_storage) {
    std::string server_address{ip_address + std::to_string(port)};

    uint32_t server_idx = config.servers.size();
    for (uint32_t i = 0; i < config.servers.size(); i++) {
        const std::string& address_port = config.servers[i];
        const std::string address =
            address_port.substr(0, address_port.find(":"));
        if (address == ip_address) {
            server_idx = i;
        }
    }

    if (server_idx == config.servers.size()) {
        throw std::runtime_error("Invalid server IP address");
    }

    FilesysImpl service(config, local_storage, server_idx);

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<Server> server(builder.BuildAndStart());
    std::cout << "Server listening on " << server_address << std::endl;
    server->Wait();
}

int main(int argc, char* argv[]) {
    /* Parse command line arguments. */
    CLI::App filesys;

    std::string ip_address;
    filesys.add_option("-a,--address", ip_address)->required();

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
    RunServer(ip_address, port, config, local_storage);

    return 0;
}
