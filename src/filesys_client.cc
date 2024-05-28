#include <grpcpp/grpcpp.h>

#include <iostream>

#include "CLI11.hh"
#include "config.h"
#include "filesys.grpc.pb.h"
#include "signature.h"

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
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::ClientReader;
using grpc::CompletionQueue;
using grpc::Status;

template <class T>
struct AsyncResponse {
    Status status;
    T reply;
};

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
        ClientContext context;
        ReadBlocksArgs args;
        args.set_file_name(file_name);
        args.set_stripe_offset(stripe_offset);
        args.set_num_stripes(num_stripes);
        args.set_version(version);
        CompletionQueue cq;

        std::vector<AsyncResponse<ReadBlocksReply>> response_buffer(
            _servers.size());
        for (uint32_t i = 0; i < _servers.size(); i++) {
            std::unique_ptr<ClientAsyncResponseReader<ReadBlocksReply>>
                response_header =
                    _servers[i]->PrepareAsyncReadBlocks(&context, args, &cq);

            response_header->StartCall();
            response_header->Finish(&response_buffer[i].reply,
                                    &response_buffer[i].status,
                                    (void*)&response_buffer[i]);
        }

        void* got_tag;
        bool ok = false;
        uint32_t wait_count = _servers.size();
        while (cq.Next(&got_tag, &ok)) {
            AsyncResponse<ReadBlocksReply>* reply =
                static_cast<AsyncResponse<ReadBlocksReply>*>(got_tag);
            if (reply->status.ok()) {
                std::cerr << reply->reply.version() << '\n';
            } else {
                std::cerr << "ReadBlocks failed\n";
            }
            wait_count--;
            if (!wait_count) {
                break;
            }
        }
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
