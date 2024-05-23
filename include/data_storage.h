#ifndef _FILESYS_DATA_STORAGE_H
#define _FILESYS_DATA_STORAGE_H

#include <filesystem>
#include <fstream>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

#include "file.h"

class DataStorage {
    std::mutex _mu;
    fs::path _storage_directory;
    std::fstream _recent_data_log;
    std::unordered_map<std::string, std::shared_ptr<File>> _file_list;
    const uint32_t _block_size;

    void PersistLog();
    void LoadStorageFromLog(); /* In case of recovery from crash, read the */

   public:
    explicit DataStorage(const fs::path& storage_directory,
                         uint32_t block_size);
    bool CreateFile(const std::string& file_name, const Bytes& public_key);
    bool WriteFile(const std::string& file_name, uint32_t stripe_offset,
                   uint32_t num_stripe, uint32_t block_idx, uint32_t version,
                   const Bytes& block_data);
    Bytes ReadFile(const std::string& file_name, uint32_t stripe_offset,
                   uint32_t num_stripe, uint32_t version);
    uint32_t GetLatestVersion(const std::string& file_name);
    std::vector<std::shared_ptr<File>> GetFileList();
};

#endif