#include <grpcpp/grpcpp.h>

#include <iostream>

#include "CLI11.hh"
#include "config.h"
#include "filesys.grpc.pb.h"
#include "signature.h"
#include "async_query.h"

using filesys::CreateFileArgs;
using filesys::Filesys;
using filesys::GetFileListArgs;
using filesys::GetFileListReply;
using filesys::GetUpdateLogArgs;
using filesys::GetUpdateLogReply;
using filesys::HeartBeatReply;
using filesys::ReadBlocksArgs;
using filesys::ReadBlocksReply;
using filesys::WriteBlocksArgs;
using google::protobuf::Empty;
using grpc::Channel;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::Status;

class FilesysClient {
    std::vector<std::unique_ptr<Filesys::Stub>> _servers;
    Config _config;

   public:
    explicit FilesysClient(const Config& config) : _config(config) {
        for (const auto& address : _config.servers) {
            std::shared_ptr<Channel> channel = grpc::CreateChannel(
                address, grpc::InsecureChannelCredentials());
            _servers.emplace_back(Filesys::NewStub(channel));
        }
    }

    void GetFileList() {
        ClientContext context;
        GetFileListArgs args;

        for (auto& server : _servers) {
            std::unique_ptr<ClientReader<GetFileListReply>> reader(
                server->GetFileList(&context, args));

            GetFileListReply reply;
            while (reader->Read(&reply)) {
                std::cout << reply.file_name() << ' ' << reply.version()
                          << '\n';
            }

            Status status = reader->Finish();
            if (status.ok()) {
                std::cout << "GetFileList successful\n";
            } else {
                std::cout << "GetFileList failed\n";
            }
        }
    }

    void ReadBlocks(const std::string& file_name, uint32_t stripe_offset,
                    uint32_t num_stripes, uint32_t version) {
        std::vector<Filesys::Stub*> query_servers(_servers.size());
        for (size_t i = 0; i < _servers.size(); i++) query_servers[i] = _servers[i].get();

        ReadBlocksArgs args;
        args.set_file_name(file_name);
        args.set_stripe_offset(stripe_offset);
        args.set_num_stripes(num_stripes);
        args.set_version(version);

        QueryServers<ReadBlocksReply>(
            query_servers, args, &Filesys::Stub::PrepareAsyncReadBlocks, 0,
            [&](
                const std::vector<AsyncResponse<ReadBlocksReply>>& responses,
                const std::vector<uint8_t>& replied,
                size_t recent_idx,
                size_t& minimum_success
            ) {
                // return true if done
                return false;
            });
    }
};

int main(int argc, char* argv[]) {
    CLI::App filesys;
    filesys.set_config("--config", "../config.toml")->required();

    CLI11_PARSE(filesys, argc, argv);

    const std::string config_file = filesys.get_config_ptr()->as<std::string>();
    Config config = ParseConfig(config_file);

    FilesysClient client(config);
    client.GetFileList();
    client.ReadBlocks("temp", 0, 1, 1);
}
