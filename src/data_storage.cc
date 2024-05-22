#include "data_storage.h"

#include <algorithm>

DataStorage::DataStorage(const fs::path& storage_directory)
    : _storage_directory(storage_directory) {
    /* If directory already existed then nothing happens. */
    fs::create_directory(_storage_directory);
}

bool DataStorage::CreateFile(const std::string& file_name,
                             const Bytes& public_key) {
    std::lock_guard<std::mutex> lock(_mu);
    if (_file_list.find(file_name) != _file_list.end()) {
        /* File already exists. */
        return false;
    }

    _file_list.emplace(file_name,
                       new File(_storage_directory, file_name, public_key));
    return true;
}

bool DataStorage::WriteFile(const std::string& file_name,
                            uint32_t stripe_offset, uint32_t num_stripes,
                            uint32_t block_idx, uint32_t version,
                            const Bytes& block_data) {
    std::unique_lock<std::mutex> lock(_mu);
    if (_file_list.find(file_name) == _file_list.end()) {
        return false;
    }

    auto file = _file_list[file_name];
    lock.unlock();
    return file->WriteStripes(stripe_offset, num_stripes, block_idx, version,
                              block_data);
}

Bytes DataStorage::ReadFile(const std::string& file_name,
                            uint32_t stripe_offset, uint32_t num_stripes,
                            uint32_t version) {
    std::unique_lock<std::mutex> lock(_mu);
    if (_file_list.find(file_name) == _file_list.end()) {
        return Bytes{};
    }

    auto file = _file_list[file_name];
    lock.unlock();

    return file->ReadVersion(version, stripe_offset, num_stripes);
}

uint32_t DataStorage::GetLatestVersion(const std::string& file_name) {
    std::lock_guard<std::mutex> lock(_mu);
    if (_file_list.find(file_name) == _file_list.end()) {
        return 0; /* TODO: define an error code for not found. */
    }

    return _file_list[file_name]->Version();
}

std::vector<std::shared_ptr<File>> DataStorage::GetFileList() {
    std::lock_guard<std::mutex> lock(_mu);

    std::vector<std::shared_ptr<File>> file_list(_file_list.size());
    std::transform(_file_list.begin(), _file_list.end(), file_list.begin(),
                   [](const auto& pair) { return pair.second; });
    return file_list;
}