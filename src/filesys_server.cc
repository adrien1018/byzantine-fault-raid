#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include <filesystem>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "CLI11.hh"
#include "config.hh"
#include "file.hh"
#include "filesys.grpc.pb.h"

using filesys::Filesys;
using filesys::GetFileListReply;
using filesys::GetUpdateLogArgs;
using filesys::GetUpdateLogReply;
using filesys::HeartBeatReply;
using filesys::MetaData;
using filesys::ReadBlocksArgs;
using filesys::ReadBlocksReply;
using filesys::WriteBlocksArgs;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerWriter;
using grpc::Status;

class FilesysImpl final : public Filesys::Service {
    Config _config;
    std::filesystem::path _local_storage;
    std::map<std::string, File> _file_list;

   public:
    explicit FilesysImpl(const Config& config,
                         const std::filesystem::path& local_storage)
        : _config(config), _local_storage(local_storage) {}
    Status ReadBlocks(ServerContext* context, const ReadBlocksArgs* args,
                      ReadBlocksReply* reply) override {
        std::string file_name = args->file_name();
        uint32_t version = args->has_version() ? args->version()
                                               : _file_list[file_name].version;
        std::cout << version << '\n';
        return Status::OK;
    }

    Status WriteBlocks(ServerContext* context, const WriteBlocksArgs* args,
                       google::protobuf::Empty* _) override {
        /* TODO: Verify signature */
        /* TODO: Store file */
        uint32_t version = args->version();
        /* TODO: Check if the version already exists. Return if so. */
        std::string block_data = args->block_data();

        return Status::OK;
    }

    Status GetFileList(ServerContext* context, const google::protobuf::Empty* _,
                       ServerWriter<GetFileListReply>* writer) override {
        for (const auto& [file_name, meta_data] : _file_list) {
            GetFileListReply reply;
            reply.set_file_name(file_name);
            reply.set_version(meta_data.version);
            /* TODO: meta data */
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

/* Initialize the local storage by creating the storage directory if not already
 * existed. */
static void InitStorage(std::filesystem::path path) {
    std::filesystem::create_directory(path);
}

/* Entry point of the service. Start the service. */
static void RunServer(uint16_t port, const Config& config,
                      const std::filesystem::path& local_storage) {
    std::string server_address{"0.0.0.0:" + std::to_string(port)};
    FilesysImpl service(config, local_storage);

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

    uint16_t port{8080}; /* Default value for the port to serve on. */
    filesys.add_option("-p,--port", port);

    std::filesystem::path local_storage{"./storage"};
    filesys.add_option("-s,--storage", local_storage);

    /* Set config file path for settings such as list of servers. */
    filesys.set_config("--config", "../../config.toml")->required();

    CLI11_PARSE(filesys, argc, argv);

    /* Setup file storage. */
    InitStorage(local_storage);

    /* Process configuration file. */
    const std::string config_file = filesys.get_config_ptr()->as<std::string>();
    Config config = ParseConfig(config_file);
    RunServer(port, config, local_storage);

    return 0;
}
