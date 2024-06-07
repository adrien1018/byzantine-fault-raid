#ifndef _FILESYS_DATA_STORAGE_H
#define _FILESYS_DATA_STORAGE_H

#include <optional>
#include <queue>
#include <unordered_map>

#include "file.h"

class DataStorage {
    std::mutex _mu;
    fs::path _storage_directory;
    std::unordered_map<std::string, std::shared_ptr<File>> _file_list;
    const uint32_t _block_size;

   public:
    explicit DataStorage(const fs::path& storage_directory,
                         uint32_t block_size);
    bool CreateFile(const std::string& file_name, const Bytes& public_key);
    bool WriteFile(const std::string& file_name, const UpdateMetadata& metadata,
                   uint32_t block_idx, const Bytes& block_data);
    Bytes ReadFile(const std::string& file_name, uint64_t stripe_offset,
                   uint64_t num_stripe, int32_t version);
    std::optional<UpdateMetadata> GetLatestVersion(
        const std::string& file_name);
    std::vector<std::shared_ptr<File>> GetFileList(
        const std::string& file_name);
    bool DeleteFile(const std::string& file_name, uint32_t version,
                    const Bytes& signature);
    std::shared_ptr<File> operator[](const std::string& file_name);
};

#endif