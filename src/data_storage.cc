#include "data_storage.h"

#include <algorithm>
#include <iostream>

DataStorage::DataStorage(const fs::path& storage_directory, uint32_t block_size)
    : _storage_directory(storage_directory), _block_size(block_size) {
    /* If directory already existed then nothing happens. */
    fs::create_directory(_storage_directory);

    /* Load the files already in the directory. */
    for (const auto& entry : fs::directory_iterator(_storage_directory)) {
        if (entry.is_regular_file()) {
            std::string file_name = entry.path().filename();
            _file_list.emplace(file_name, new File(_storage_directory,
                                                   file_name, _block_size));
        }
    }
}

bool DataStorage::CreateFile(const std::string& file_name,
                             const Bytes& public_key) {
    std::lock_guard<std::mutex> lock(_mu);
    if (auto handle = _file_list.find(file_name);
        handle != _file_list.end() && !handle->second->Deleted()) {
        /* File already exists. */
        return false;
    } else {
        if (handle != _file_list.end()) {
            handle->second->UpdateSignKey(public_key);
        } else {
            _file_list.emplace(
                file_name, new File(_storage_directory, file_name, public_key,
                                    _block_size));
        }
    }
    return true;
}

bool DataStorage::WriteFile(const std::string& file_name,
                            uint64_t stripe_offset, uint64_t num_stripes,
                            uint32_t block_idx, uint32_t version,
                            const Bytes& block_data, const Metadata& metadata) {
    std::unique_lock<std::mutex> lock(_mu);
    if (_file_list.find(file_name) == _file_list.end()) {
        std::cerr << "File not found: " << file_name << std::endl;
        return false;
    }

    auto file = _file_list[file_name];
    lock.unlock();
    return file->WriteStripes(stripe_offset, num_stripes, block_idx, version,
                              block_data, metadata);
}

Bytes DataStorage::ReadFile(const std::string& file_name,
                            uint64_t stripe_offset, uint64_t num_stripes,
                            uint32_t version) {
    std::unique_lock<std::mutex> lock(_mu);
    if (_file_list.find(file_name) == _file_list.end()) {
        std::cerr << "File not found\n";
        return {};
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

std::vector<std::shared_ptr<File>> DataStorage::GetFileList(
    const std::string& file_name) {
    std::lock_guard<std::mutex> lock(_mu);
    std::vector<std::shared_ptr<File>> file_list;
    if (file_name.empty()) {
        file_list.resize(_file_list.size());
        std::transform(_file_list.begin(), _file_list.end(), file_list.begin(),
                       [](const auto& pair) { return pair.second; });
    } else if (auto entry = _file_list.find(file_name);
               entry != _file_list.end()) {
        file_list.emplace_back(entry->second);
    }
    return file_list;
}

bool DataStorage::DeleteFile(const std::string& file_name) {
    std::unique_lock<std::mutex> lock(_mu);
    if (auto handle = _file_list.find(file_name); handle == _file_list.end()) {
        return false;
    } else {
        lock.unlock();
        handle->second->Delete();
    }
    return true;
}

std::shared_ptr<File> DataStorage::operator[](const std::string& file_name) {
    std::lock_guard<std::mutex> lock(_mu);
    auto it = _file_list.find(file_name);
    if (it == _file_list.end()) {
        return nullptr;
    }
    return it->second;
}