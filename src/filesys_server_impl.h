#pragma once

#include <random>
#include <filesystem>

#include "config.h"
#include "data_storage.h"
#include "thread_pool.hpp"
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
using grpc::ServerContext;
using grpc::Status;

namespace fs = std::filesystem;

class FilesysImpl final : public Filesys::Service {
    Config _config;
    DataStorage _data_storage;
    uint32_t _server_idx;
    std::vector<Filesys::Stub*> _peers;
    std::mt19937_64 _rng;
    BS::thread_pool _thread_pool;

    std::mutex _mu;
    std::unordered_set<Bytes> _seen_public_keys;
    std::unordered_map<Bytes, std::unordered_map<std::string, std::unordered_set<uint32_t>>> _heartbeat_new_files;
    std::unordered_map<std::string, std::mutex> _recovery_lock;

   public:
    explicit FilesysImpl(const Config& config, const fs::path& local_storage,
                         uint32_t server_idx);

    Status CreateFile(ServerContext* context, const CreateFileArgs* args,
                      google::protobuf::Empty* _) override;

    Status ReadBlocks(ServerContext* context, const ReadBlocksArgs* args,
                      ReadBlocksReply* reply) override;

    Status WriteBlocks(ServerContext* context, const WriteBlocksArgs* args,
                       google::protobuf::Empty* _) override;

    Status GetFileList(ServerContext* context, const GetFileListArgs* args,
                       GetFileListReply* reply) override;

    Status GetUpdateLog(ServerContext* context, const GetUpdateLogArgs* args,
                        GetUpdateLogReply* reply) override;

    Status DeleteFile(ServerContext* context, const DeleteFileArgs* args,
                      google::protobuf::Empty* _) override;

  private:
    void HeartBeatThread();
    void HeartBeat(const std::vector<int>& peer_idx);
    void Recovery(const std::string& file_name, uint32_t current_version);
};
