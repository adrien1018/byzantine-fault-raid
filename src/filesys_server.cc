#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <spdlog/spdlog.h>
#include <CLI/CLI.hpp>

#include "filesys_server_impl.h"

using grpc::ServerBuilder;
using grpc::Server;

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
    spdlog::info("Server listening on {}", server_address);
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
