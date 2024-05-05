#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include <iostream>
#include <string>
#include <vector>

#include "CLI11.hh"
#include "config.hh"
#include "filesys.grpc.pb.h"

using filesys::GetFileListReply;
using filesys::GetUpdateLogArgs;
using filesys::GetUpdateLogReply;
using filesys::HeartBeatReply;
using filesys::MetaData;
using filesys::ReadBlocksArgs;
using filesys::ReadBlocksReply;
using filesys::WriteBlocksArgs;
using grpc::CallbackServerContext;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::Status;

void RunServer(uint16_t port) {}

int main(int argc, char* argv[]) {
    /* Parse command line arguments. */
    CLI::App filesys;

    uint16_t port{8080}; /* Default value for the port to serve on. */
    filesys.add_option("-p,--port", port);

    /* Set config file path for settings such as list of servers. */
    filesys.set_config("--config", "../../config.toml")->required();

    CLI11_PARSE(filesys, argc, argv);

    const std::string config_file = filesys.get_config_ptr()->as<std::string>();

    Config config = ParseConfig(config_file);

    std::cout << config.num_malicious << '\n';

    return 0;
}
