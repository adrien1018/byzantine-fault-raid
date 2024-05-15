#include "data_storage.h"

DataStorage::DataStorage(const fs::path& storage_directory)
    : _storage_directory(storage_directory) {
    /* If directory already existed then nothing happens. */
    fs::create_directory(_storage_directory);

    _recent_data_log.open(_storage_directory / "recent_data.log");
    if (_recent_data_log.fail()) {
        throw std::runtime_error("Failed to open recent data file.");
    }
}

bool DataStorage::WriteFile(const std::string& file_name,
                            uint32_t stripe_offset, uint32_t num_stripes,
                            uint32_t version, const std::string& block_data) {
    std::unique_lock<std::mutex> lock(_mu);
    if (_file_list.find(file_name) == _file_list.end()) {
        _file_list.emplace(file_name, new File(_storage_directory, file_name));
    }

    auto file = _file_list[file_name];
    lock.unlock();
    Bytes block_data_bytes(block_data.begin(), block_data.end());
    file->WriteStripes(stripe_offset, num_stripes, block_data_bytes);

    return true;
}

Bytes DataStorage::ReadFile(const std::string& file_name, uint32_t version) {
    std::unique_lock<std::mutex> lock(_mu);
    if (_file_list.find(file_name) == _file_list.end()) {
        return Bytes{};
    }

    auto file = _file_list[file_name];
    lock.unlock();

    Bytes block_data = file->ReadVersion(version);
    return block_data;
}

uint32_t DataStorage::GetLatestVersion(const std::string& file_name) {
    std::lock_guard<std::mutex> lock(_mu);
    if (_file_list.find(file_name) == _file_list.end()) {
        return 0; /* TODO: define an error code for not found. */
    }

    return _file_list[file_name]->Version();
}