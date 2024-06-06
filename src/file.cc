#include "file.h"

#include <iostream>
#include <iterator>
#include <optional>
#include <spdlog/spdlog.h>

#include "encode_decode.h"

using namespace std::chrono_literals;

//#define NO_VERIFY

/* Persisting the record on disk. The format is:
    |version (4 bytes)|stripe_offset (8 bytes)|num_stripes (8 bytes)
    |is_delete (1 byte)|signature (64 bytes)
    |stripe_size (8 bytes)|metadata_file_size (8 bytes)|has_image (1 byte)
    |buffer_size(8 bytes)|block_data (variable size)| */

UndoRecord UndoRecord::ReadFromFile(std::ifstream& ifs) {
    UndoRecord record;
    ifs.read((char*)&record.metadata.version, sizeof(int32_t));
    ifs.read((char*)&record.metadata.stripe_offset, sizeof(uint64_t));
    ifs.read((char*)&record.metadata.num_stripes, sizeof(uint64_t));
    ifs.read((char*)&record.metadata.is_delete, sizeof(bool));
    record.metadata.signature.resize(SigningKey::kSignatureSize);
    ifs.read((char*)record.metadata.signature.data(), SigningKey::kSignatureSize);
    ifs.read((char*)&record.stripe_size, sizeof(uint64_t));
    ifs.read((char*)&record.metadata.file_size, sizeof(uint64_t));
    ifs.read((char*)&record.has_image, sizeof(bool));
    uint64_t read_size;
    ifs.read((char*)&read_size, sizeof(uint64_t));
    record.old_image.resize(read_size);
    ifs.read((char*)record.old_image.data(), read_size);
    record.time_to_live = Clock::now() + 30s;
    return record;
}

void UndoRecord::WriteToFile(std::ofstream& ofs) const {
    ofs.write((char*)&metadata.version, sizeof(int32_t));
    ofs.write((char*)&metadata.stripe_offset, sizeof(uint64_t));
    ofs.write((char*)&metadata.num_stripes, sizeof(uint64_t));
    ofs.write((char*)&metadata.is_delete, sizeof(bool));
    if (metadata.signature.size() != SigningKey::kSignatureSize) {
        throw std::runtime_error("Invalid signature size");
    }
    ofs.write((char*)metadata.signature.data(), SigningKey::kSignatureSize);
    ofs.write((char*)&stripe_size, sizeof(uint64_t));
    ofs.write((char*)&metadata.file_size, sizeof(uint64_t));
    ofs.write((char*)&has_image, sizeof(bool));
    uint64_t read_size = old_image.size();
    ofs.write((char*)&read_size, sizeof(uint64_t));
    ofs.write((char*)old_image.data(), read_size);
    ofs.close();
}

/* A file is stored as
    | start_version (4 bytes) | public key (32 bytes)
    | block data (variable size)
*/
const uint64_t File::kBasePosition = 4 + 32;

File::File(const std::string& directory, const std::string& file_name,
           const Bytes& public_key, uint32_t _block_size)
    : _directory(directory),
      _file_name(file_name),
      _public_key(public_key, false),
      _start_version(0),
      _first_image_version(0),
      _file_closed(false),
      _garbage_collection(&File::GarbageCollectRecord, this),
      _block_size(_block_size) {
    fs::path file_path = _directory / _file_name;
    std::fstream::openmode open_mode = std::fstream::binary | std::fstream::in |
                                       std::fstream::out | std::fstream::trunc;

    _file_stream.open(file_path, open_mode);
    if (_file_stream.fail()) {
        throw std::runtime_error("Failed to open fail");
    }

    fs::path log_directory = _directory / fs::path(file_name + "_log");
    fs::create_directory(log_directory);

    UpdateMetadata meta = {
        .version = 0,
        .stripe_offset = 0,
        .num_stripes = 0,
        .file_size = 0,
        .is_delete = false,
        .signature = Bytes(SigningKey::kSignatureSize), // TODO: Add signature
    };
    _update_record[-1] = CreateUndoRecord(meta);

    WriteMetadata();
}

File::File(const std::string& directory, const std::string& file_name,
           uint32_t block_size)
    : _directory(directory),
      _file_name(file_name),
      _start_version(0),
      _first_image_version(0),
      _file_closed(false),
      _garbage_collection(&File::GarbageCollectRecord, this),
      _block_size(block_size) {
    fs::path file_path = _directory / _file_name;
    std::fstream::openmode open_mode =
        std::fstream::binary | std::fstream::in | std::fstream::out;
    _file_stream.open(file_path, open_mode);

    _file_stream.read((char*)&_start_version, sizeof(int32_t));
    Bytes public_key(SigningKey::kKeySize);
    _file_stream.read((char*)public_key.data(), SigningKey::kKeySize);
    _public_key = SigningKey(public_key, false);

    if (_file_stream.tellg() != kBasePosition) {
        throw std::runtime_error("Incorrect base position");
    }

    fs::path log_directory = _directory / fs::path(file_name + "_log");
    LoadUndoRecords(log_directory);
}

File::~File() {
    _file_closed.store(true);
    _file_stream.close();
    _garbage_collection.join();
}

int32_t File::_version() const {
    return _update_record.rbegin()->first + 1;
}

bool File::_deleted() const {
    return _update_record.rbegin()->second.metadata.is_delete;
}

UndoRecord File::LoadUndoRecord(const std::string& record_path) {
    std::ifstream ifs;
    ifs.open(record_path, std::fstream::binary);
    UndoRecord record = UndoRecord::ReadFromFile(ifs);
    ifs.close();
    return record;
}

void File::LoadUndoRecords(const std::string& log_directory) {
    for (const auto& entry : fs::directory_iterator(log_directory)) {
        if (entry.is_regular_file()) {
            std::string file_name = entry.path().filename();
            int32_t version = std::stol(file_name);
            UndoRecord record = LoadUndoRecord(entry.path());
            if (!record.has_image && version >= 0) {
                _first_image_version =
                    std::max(version + 1, _first_image_version);
            }
            _update_record[version] = std::move(record);
        }
    }
}

void File::WriteMetadata() {
    _file_stream.write((char*)&_start_version, sizeof(int32_t));
    Bytes public_key = _public_key.PublicKey();
    if (public_key.size() != SigningKey::kKeySize) {
        throw std::runtime_error("Invalid public key size");
    }
    _file_stream.write((char*)public_key.data(), SigningKey::kKeySize);
    _file_stream.flush();

    if (_file_stream.tellp() != kBasePosition) {
        throw std::runtime_error("Incorrect base position");
    }
}

bool File::WriteStripes(const UpdateMetadata& metadata, uint32_t block_idx,
                        const Bytes& block_data) {
#ifndef NO_VERIFY
    for (uint64_t i = 0; i < metadata.num_stripes; i++) {
        const Bytes block = Bytes(block_data.begin() + i * _block_size,
                                  block_data.begin() + (i + 1) * _block_size);
        if (!VerifyBlock(block, block_idx, _public_key, _file_name,
                         metadata.stripe_offset + i, metadata.version)) {
            spdlog::warn("Block verification failed");
            return false;
        }
    }
    if (!VerifyUpdate(metadata.signature, _public_key, _file_name,
                      metadata.version, metadata.stripe_offset, metadata.num_stripes, false)) {
        spdlog::warn("Version signature verification failed");
        return false;
    }
#endif
    int32_t new_version = _version() + 1;
    if (metadata.version < new_version) {
        /* Stale write. */
        return true;
    } else if (metadata.version != new_version) {
        /* Version gap. */
        return false;
    }

    UndoRecord record = CreateUndoRecord(metadata);
    _update_record[metadata.version - 1] = record;

    _file_stream.seekp(kBasePosition + metadata.stripe_offset * _block_size);
    _file_stream.write((char*)block_data.data(), block_data.size());
    _file_stream.flush();

    return true;
}

Bytes File::ReadVersion(int32_t version, uint64_t stripe_offset,
                        uint64_t num_stripes) {
    if (_deleted()) {
        return {};
    }
    std::set<Segment> segments = ReconstructVersion(version);
    if (segments.empty()) {
        return {};
    }

    Bytes block_data(num_stripes * _block_size);
    int32_t current_version = _version();

    for (const auto& [start, end, version] : segments) {
        if (stripe_offset >= end || stripe_offset + num_stripes <= start) {
            continue;
        }
        uint64_t effective_start = std::max(start, stripe_offset);
        uint64_t effective_end = std::min(end, stripe_offset + num_stripes);
        if (version == current_version) {
            _file_stream.seekg(kBasePosition + effective_start * _block_size);
            _file_stream.read(
                (char*)block_data.data() +
                    (effective_start - stripe_offset) * _block_size,
                (effective_end - effective_start) * _block_size);
        } else {
            auto& record = _update_record[version];
            const Bytes& version_block = record.old_image;
            uint64_t image_offset =
                (effective_start - record.metadata.stripe_offset) * _block_size;
            uint64_t size = (effective_end - effective_start) * _block_size;
            std::copy(version_block.begin() + image_offset,
                      version_block.begin() + image_offset + size,
                      block_data.begin() +
                          (effective_start - stripe_offset) * _block_size);
        }
    }
    return block_data;
}

bool File::Delete(int32_t version, const Bytes& signature) {
#ifndef NO_VERIFY
    if (!VerifyUpdate(signature, _public_key, _file_name, 0, 0, version, true)) {
        spdlog::warn("Version signature verification failed");
        return false;
    }
#endif
    int32_t new_version = _version() + 1;
    if (version < new_version) {
        /* Stale write. */
        return true;
    } else if (version != new_version) {
        /* Version gap. */
        return false;
    }

    for (const auto& [version, record] : _update_record) {
        fs::remove(UndoLogPath(version));
    }
    _update_record.clear();
    _update_record[new_version - 1] = CreateUndoRecord(UpdateMetadata{
        .version = new_version,
        .stripe_offset = 0,
        .num_stripes = 0,
        .file_size = 0,
        .is_delete = true,
        .signature = signature,
    });
    _file_stream.close();
    fs::path file_path = _directory / _file_name;
    fs::remove(file_path);
    return true;
}

bool File::Recreate(const Bytes& public_key) {
    if (!_deleted()) {
        return false;
    }

    std::fstream::openmode open_mode = std::fstream::binary | std::fstream::in |
                                       std::fstream::out | std::fstream::trunc;
    fs::path file_path = _directory / _file_name;
    _file_stream.open(file_path, open_mode);
    if (_file_stream.is_open()) {
        throw std::runtime_error("Failed to open");
    }

    int32_t new_version = _version() + 1;
    _update_record.clear();
    _update_record[new_version - 1] = CreateUndoRecord(UpdateMetadata{
        .version = new_version,
        .stripe_offset = 0,
        .num_stripes = 0,
        .file_size = 0,
        .is_delete = true,
        .signature = Bytes(SigningKey::kSignatureSize),
    });
    _public_key = SigningKey(public_key, false);
    WriteMetadata();
    return true;
}

std::string File::FileName() const { return _file_name; }

Bytes File::PublicKey() const { return _public_key.PublicKey(); }

fs::path File::UndoLogPath(int32_t version) const {
    return _directory / fs::path(_file_name + "_log") / std::to_string(version);
}

UndoRecord File::CreateUndoRecord(const UpdateMetadata& metadata) {
    std::ofstream ofs;
    ofs.open(UndoLogPath(metadata.version - 1), std::fstream::binary);
    if (!ofs.is_open()) {
        throw std::runtime_error("Failed to create undo log.");
    }

    Bytes buffer;
    uint64_t read_size;
    uint64_t file_size = GetCurrentStripeSize();
    if (metadata.stripe_offset * _block_size < file_size && metadata.num_stripes > 0) {
        uint64_t end =
            std::min(file_size, (metadata.stripe_offset + metadata.num_stripes) * _block_size);
        read_size = end - (metadata.stripe_offset * _block_size);
        if (read_size) {
            _file_stream.seekg(kBasePosition + metadata.stripe_offset * _block_size);
            buffer.resize(read_size);
            _file_stream.read((char*)buffer.data(), read_size);
        }
    }

    UndoRecord record{
        .metadata = metadata,
        .stripe_size = GetCurrentStripeSize(),
        .has_image = true,
        .old_image = buffer,
        .time_to_live = Clock::now() + 30s,
    };

    record.WriteToFile(ofs);
    ofs.close();

    return record;
}

void File::GarbageCollectRecord() {
    std::unique_lock<std::mutex> lock(_mu, std::defer_lock);
    while (!_file_closed.load()) {
        lock.lock();
        if (_update_record.empty()) {
            lock.unlock();
            std::this_thread::sleep_for(500ms);
            continue;
        }
        auto current_version = _version();
        for (int32_t version = _first_image_version; version <= current_version;
             version++) {
            auto it = _update_record.find(version);
            if (it == _update_record.end()) continue;
            UndoRecord& record = it->second;
            if (record.time_to_live > Clock::now() ||
                record.metadata.version + 1 <= current_version) {
                continue;
            }
            // clear the old image and update undo log file
            record.old_image.clear();
            record.has_image = false;
            std::ofstream ofs;
            ofs.open(UndoLogPath(version), std::fstream::binary);
            if (ofs.fail()) {
                throw std::runtime_error("Failed to create undo log.");
            }
            record.WriteToFile(ofs);
            _first_image_version = std::max(version + 1, _first_image_version);
        }
        lock.unlock();
        std::this_thread::sleep_for(500ms);
    }
}

uint64_t File::GetCurrentStripeSize() {
    _file_stream.seekg(0, std::ios::end);
    return std::max(kBasePosition, static_cast<uint64_t>(_file_stream.tellg())) - kBasePosition;
}

std::set<Segment> File::ReconstructVersion(int32_t version) {
    auto current_version = _version();
    if (version > current_version) {
        /* The version is higher than the current version. */
        return {};
    }
    if (version != current_version &&
        (_update_record.empty() || _first_image_version > version)) {
        /* Not enough information to recover the old version. */
        return {};
    }
    uint64_t file_size = GetCurrentStripeSize();
    if (file_size % _block_size) {
        throw std::runtime_error("File size not on block boundary");
    }
    std::set<Segment> segments{{0, file_size / _block_size, current_version}};
    uint64_t version_block_size = file_size / _block_size;
    for (auto latest_update = _update_record.rbegin();
         latest_update != _update_record.rend() && latest_update->first >= version;
         ++latest_update) {
        /* This operation assumes that each update only keeps the file size
         * the same or extends it, but never shrinks. */
        std::optional<std::set<Segment>::iterator> start_remover = std::nullopt;
        if (latest_update->first == version) {
            version_block_size = latest_update->second.stripe_size / _block_size;
        }
        uint64_t segment_start = latest_update->second.metadata.stripe_offset;
        auto start_overlap = segments.lower_bound({segment_start, 0, 0});
        if (start_overlap != segments.begin()) {
            auto to_edit = std::prev(start_overlap);
            const auto [prev_start, prev_end, prev_version] = *to_edit;
            if (prev_end > segment_start) {
                segments.emplace(prev_start, segment_start, prev_version);
                start_remover = to_edit;
            }
        }

        uint64_t segment_end = latest_update->second.metadata.stripe_offset +
                               latest_update->second.metadata.num_stripes;
        auto end_overlap = segments.lower_bound({segment_end, 0, 0});
        if (end_overlap != segments.begin()) {
            auto to_edit = std::prev(end_overlap);
            const auto [prev_start, prev_end, prev_version] = *to_edit;
            if (prev_end > segment_end) {
                segments.emplace(segment_end, prev_end, prev_version);
            }
        }

        if (start_remover.has_value()) {
            segments.erase(start_remover.value());
        }

        while (start_overlap != end_overlap) {
            start_overlap = segments.erase(start_overlap);
        }
        segments.emplace(segment_start, segment_end, latest_update->first);
    }

    auto unused_segment = segments.lower_bound({version_block_size, 0, 0});
    if (unused_segment != segments.begin()) {
        auto to_edit = std::prev(unused_segment);
        auto [prev_start, prev_end, prev_version] = *to_edit;
        if (prev_end > version_block_size) {
            if (prev_start != version_block_size) {
                segments.emplace(prev_start, version_block_size, prev_version);
            }
            segments.erase(to_edit);
        }
    }
    segments.erase(unused_segment, segments.end());
    return segments;
}

UpdateMetadata File::LastUpdate() const {
    if (_update_record.empty()) throw std::runtime_error("No update record");
    return _update_record.rbegin()->second.metadata;
}

int32_t File::StartVersion() const { return _start_version; }
