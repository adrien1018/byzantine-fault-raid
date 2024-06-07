#include "data_storage.h"

#include <algorithm>
#include <iostream>

DataStorage::DataStorage(const fs::path& storage_directory, int n_servers,
                         uint32_t block_size, uint32_t raw_stripe_size) :
    _storage_directory(storage_directory),
    _n_servers(n_servers),
    _block_size(block_size),
    _raw_stripe_size(raw_stripe_size) {
    std::error_code ec;
    /* If directory already existed then nothing happens. */
    fs::create_directory(_storage_directory, ec);

    /* Load the files already in the directory. */
    for (const auto& entry : fs::directory_iterator(_storage_directory / "files", ec)) {
        if (entry.is_regular_file()) {
            std::string file_name = PathDecode(entry.path().filename());
            _file_list.emplace(
                file_name,
                new File(_storage_directory, file_name, _n_servers, _block_size, _raw_stripe_size));
        }
    }
}

bool DataStorage::CreateFile(const std::string& file_name,
                             uint32_t version, const Bytes& signature) {
    std::lock_guard<std::mutex> lock(_mu);
    if (auto handle = _file_list.find(file_name); handle != _file_list.end()) {
        std::lock_guard<std::mutex> file_lock(handle->second->Mutex());
        return handle->second->Recreate(version, signature);
    }
    try {
        _file_list.emplace(file_name, new File(
            _storage_directory, file_name, version, signature, _n_servers, _block_size, _raw_stripe_size));
    } catch (const std::runtime_error& e) {
        return false;
    }
    return true;
}

bool DataStorage::WriteFile(const std::string& file_name, const UpdateMetadata& metadata,
                            uint32_t block_idx, const Bytes& block_data) {
    std::unique_lock<std::mutex> lock(_mu);
    if (_file_list.find(file_name) == _file_list.end()) {
        return false;
    }
    auto& file = _file_list[file_name];
    lock.unlock();
    std::lock_guard<std::mutex> file_lock(file->Mutex());
    return file->WriteStripes(metadata, block_idx, block_data);
}

Bytes DataStorage::ReadFile(const std::string& file_name,
                            uint64_t stripe_offset, uint64_t num_stripes,
                            uint32_t version) {
    std::unique_lock<std::mutex> lock(_mu);
    if (_file_list.find(file_name) == _file_list.end()) {
        return {};
    }
    auto& file = _file_list[file_name];
    lock.unlock();
    std::lock_guard<std::mutex> file_lock(file->Mutex());
    return file->ReadVersion(version, stripe_offset, num_stripes);
}

std::optional<UpdateMetadata> DataStorage::GetLatestVersion(const std::string& file_name) {
    std::lock_guard<std::mutex> lock(_mu);
    if (_file_list.find(file_name) == _file_list.end()) {
        return std::nullopt;
    }
    std::lock_guard<std::mutex> file_lock(_file_list[file_name]->Mutex());
    return _file_list[file_name]->LastUpdate();
}

std::vector<std::shared_ptr<File>> DataStorage::GetFileList(
    const std::string& file_name) {
    std::lock_guard<std::mutex> lock(_mu);
    std::vector<std::shared_ptr<File>> file_list;
    if (file_name.empty()) {
        file_list.resize(_file_list.size());
        std::transform(_file_list.begin(), _file_list.end(), file_list.begin(),
                       [](const auto& pair) { return pair.second; });
    } else if (auto entry = _file_list.find(file_name); entry != _file_list.end()) {
        file_list.emplace_back(entry->second);
    }
    return file_list;
}

bool DataStorage::DeleteFile(const std::string& file_name, uint32_t version, const Bytes& signature) {
    std::unique_lock<std::mutex> lock(_mu);
    if (auto handle = _file_list.find(file_name); handle == _file_list.end()) {
        return false;
    } else {
        lock.unlock();
        std::lock_guard<std::mutex> file_lock(handle->second->Mutex());
        return handle->second->Delete(version, signature);
    }
}

std::shared_ptr<File> DataStorage::operator[](const std::string& file_name) {
    std::lock_guard<std::mutex> lock(_mu);
    auto it = _file_list.find(file_name);
    if (it == _file_list.end()) {
        return nullptr;
    }
    return it->second;
}
