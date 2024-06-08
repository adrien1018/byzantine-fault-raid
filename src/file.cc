#include "file.h"

#include <iostream>
#include <iterator>
#include <optional>
#include <spdlog/spdlog.h>

using namespace std::chrono_literals;

//#define NO_VERIFY

/* Persisting the record on disk. The format is:
    |version (4 bytes)|stripe_offset (8 bytes)|num_stripes (8 bytes)
    |is_delete (1 byte)|signature (64 bytes)|file_size (8 bytes)
    |metadata (variable size)| */

UndoRecord UndoRecord::ReadFromFile(std::ifstream& ifs) {
    UndoRecord record;
    ifs.read((char*)&record.metadata.version, sizeof(uint32_t));
    ifs.read((char*)&record.metadata.stripe_offset, sizeof(uint64_t));
    ifs.read((char*)&record.metadata.num_stripes, sizeof(uint64_t));
    ifs.read((char*)&record.metadata.is_delete, sizeof(bool));
    record.metadata.signature.resize(SigningKey::kSignatureSize);
    ifs.read((char*)record.metadata.signature.data(), SigningKey::kSignatureSize);
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
    ofs.write((char*)&metadata.version, sizeof(uint32_t));
    ofs.write((char*)&metadata.stripe_offset, sizeof(uint64_t));
    ofs.write((char*)&metadata.num_stripes, sizeof(uint64_t));
    ofs.write((char*)&metadata.is_delete, sizeof(bool));
    if (metadata.signature.size() != SigningKey::kSignatureSize) {
        throw std::runtime_error("Invalid signature size");
    }
    ofs.write((char*)metadata.signature.data(), SigningKey::kSignatureSize);
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
           uint32_t version, const Bytes& version_signature, int n_servers,
           uint32_t block_size, uint32_t raw_stripe_size)
    : _directory(directory),
      _file_name(file_name),
      _encoded_file_name(PathEncode(file_name)),
      _public_key(GetPublicKeyFromPath(file_name), false),
      _n_servers(n_servers),
      _start_version(version),
      _first_image_version(version),
      _file_closed(false),
      _garbage_collection(&File::_GarbageCollectRecord, this),
      _block_size(block_size),
      _raw_stripe_size(raw_stripe_size) {

    UpdateMetadata meta = {
        .version = version,
        .stripe_offset = 0,
        .num_stripes = 0,
        .file_size = 0,
        .is_delete = false,
        .signature = version_signature,
    };
#ifndef NO_VERIFY
    if (!VerifyUpdate(version_signature, _public_key, _file_name, meta)) {
        spdlog::error("Version signature verification failed");
        throw std::runtime_error("Version signature verification failed");
    }
#endif
    {
        std::error_code ec;
        fs::create_directory(_directory / "files", ec);
        fs::create_directories(_UndoLogDirectory());
    }
    std::fstream::openmode open_mode = std::fstream::binary | std::fstream::in |
                                       std::fstream::out | std::fstream::trunc;

    _file_stream.open(_FilePath(), open_mode);
    if (!_file_stream.is_open()) {
        spdlog::error("Failed to open file");
        throw std::runtime_error("Failed to open file");
    }

    _update_record[version] = _CreateUndoRecord(meta);

    _WriteMetadata();
}

File::File(const std::string& directory, const std::string& file_name,
           int n_servers, uint32_t block_size, uint32_t raw_stripe_size)
    : _directory(directory),
      _file_name(file_name),
      _encoded_file_name(PathEncode(file_name)),
      _n_servers(n_servers),
      _start_version(0),
      _first_image_version(0),
      _file_closed(false),
      _garbage_collection(&File::_GarbageCollectRecord, this),
      _block_size(block_size),
      _raw_stripe_size(raw_stripe_size) {
    fs::path file_path = _directory / "files" / _encoded_file_name;
    std::fstream::openmode open_mode =
        std::fstream::binary | std::fstream::in | std::fstream::out;
    _file_stream.open(file_path, open_mode);

    _file_stream.read((char*)&_start_version, sizeof(uint32_t));
    Bytes public_key(SigningKey::kKeySize);
    _file_stream.read((char*)public_key.data(), SigningKey::kKeySize);
    _public_key = SigningKey(public_key, false);

    if (_file_stream.tellg() != kBasePosition) {
        throw std::runtime_error("Incorrect base position");
    }

    fs::path log_directory = _directory / "logs" / _encoded_file_name;
    _LoadUndoRecords(log_directory);
}

File::~File() {
    _file_closed.store(true);
    _file_stream.close();
    _garbage_collection.join();
}

uint32_t File::_version() const {
    return _update_record.rbegin()->first;
}

bool File::_deleted() const {
    return _update_record.rbegin()->second.metadata.is_delete;
}

UndoRecord File::_LoadUndoRecord(const std::string& record_path) {
    std::ifstream ifs;
    ifs.open(record_path, std::fstream::binary);
    UndoRecord record = UndoRecord::ReadFromFile(ifs);
    ifs.close();
    return record;
}

void File::_LoadUndoRecords(const std::string& log_directory) {
    for (const auto& entry : fs::directory_iterator(log_directory)) {
        if (entry.is_regular_file()) {
            std::string file_name = entry.path().filename();
            uint32_t version = std::stoul(file_name);
            UndoRecord record = _LoadUndoRecord(entry.path());
            if (!record.has_image) {
                _first_image_version =
                    std::max(version + 1, _first_image_version);
            }
            _update_record[version] = std::move(record);
        }
    }
}

void File::_WriteMetadata() {
    _file_stream.write((char*)&_start_version, sizeof(uint32_t));
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

fs::path File::_UndoLogDirectory() const {
    return _directory / "logs" / _encoded_file_name;
}
fs::path File::_UndoLogPath(uint32_t version) const {
    return _UndoLogDirectory() / std::to_string(version);
}
fs::path File::_FilePath() const {
    return _directory / "files" / _encoded_file_name;
}

UndoRecord File::_CreateUndoRecord(const UpdateMetadata& metadata, bool current) {
    std::ofstream ofs;
    ofs.open(_UndoLogPath(metadata.version), std::fstream::binary);
    if (!ofs.is_open()) {
        throw std::runtime_error("Failed to create undo log.");
    }

    UndoRecord record{
        .metadata = metadata,
        .has_image = false,
        .old_image = Bytes(),
        .time_to_live = Clock::now() + 30s,
    };

    if (current) {
        Bytes buffer;
        uint64_t read_size;
        uint64_t file_size = _GetCurrentStripeSize();
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
        record.has_image = true;
        record.old_image = std::move(buffer);
    } else {
        _first_image_version = std::max(metadata.version + 1, _first_image_version);
    }

    record.WriteToFile(ofs);
    ofs.close();

    return record;
}

void File::_ClearUndoRecordImage(UndoRecord& record) {
    record.old_image.clear();
    record.has_image = false;
    std::ofstream ofs(_UndoLogPath(record.metadata.version), std::fstream::binary | std::fstream::trunc);
    if (ofs.fail()) {
        throw std::runtime_error("Failed to create undo log.");
    }
    record.WriteToFile(ofs);
    _first_image_version = std::max(record.metadata.version + 1, _first_image_version);
}

void File::_GarbageCollectRecord() {
    std::unique_lock<std::mutex> lock(_mu, std::defer_lock);
    while (!_file_closed.load()) {
        lock.lock();
        if (_update_record.empty()) {
            lock.unlock();
            std::this_thread::sleep_for(2s);
            continue;
        }
        auto current_version = _version();
        for (uint32_t version = _first_image_version; version <= current_version;
             version++) {
            auto it = _update_record.find(version);
            if (it == _update_record.end()) continue;
            UndoRecord& record = it->second;
            if (record.time_to_live > Clock::now() ||
                record.metadata.version + 1 <= current_version) {
                continue;
            }
            if (version != record.metadata.version) throw std::runtime_error("Version mismatch?");
            _ClearUndoRecordImage(record);
        }
        lock.unlock();
        std::this_thread::sleep_for(2s);
    }
}

uint64_t File::_GetCurrentStripeSize() {
    _file_stream.seekg(0, std::ios::end);
    return std::max(kBasePosition, static_cast<uint64_t>(_file_stream.tellg())) - kBasePosition;
}

std::set<Segment> File::_ReconstructVersion(uint32_t version) {
    auto current_version = _version();
    if (version > current_version) {
        spdlog::warn("The version is higher than the current version.");
        /* The version is higher than the current version. */
        return {};
    }
    if (version != current_version &&
        (_update_record.empty() || _first_image_version > version + 1)) {
        spdlog::warn("Not enough information to recover the old version.");
        /* Not enough information to recover the old version. */
        return {};
    }
    uint64_t target_version_blocks = 0;
    if (auto it = _update_record.find(version); it == _update_record.end()) {
        spdlog::warn("Version not exist.");
        return {};
    } else {
        target_version_blocks = (it->second.metadata.file_size + _raw_stripe_size - 1) / _raw_stripe_size;
    }
    uint64_t file_size = _GetCurrentStripeSize();
    if (file_size % _block_size) {
        throw std::runtime_error("File size not on block boundary");
    }

    std::set<Segment> segments{{0, target_version_blocks, current_version}};
    for (auto latest_update = _update_record.rbegin();
         latest_update != _update_record.rend() && latest_update->first > version;
         ++latest_update) {
        /* This operation assumes that each update only keeps the file size
         * the same or extends it, but never shrinks. */
        
        uint64_t segment_start = std::min(
            latest_update->second.metadata.stripe_offset,
            target_version_blocks);
        uint64_t segment_end = std::min(
            latest_update->second.metadata.stripe_offset +
            latest_update->second.metadata.num_stripes,
            target_version_blocks);
        if (segment_start >= segment_end) {
            continue;
        }
        UpdateSegments(segments, {segment_start, segment_end, latest_update->first - 1});
    }
    return segments;
}

bool File::WriteStripes(const UpdateMetadata& metadata, uint32_t block_idx,
                        const Bytes& block_data) {
#ifndef NO_VERIFY
    for (uint64_t i = 0; i < metadata.num_stripes; i++) {
        const Bytes block = Bytes(block_data.begin() + i * _block_size,
                                  block_data.begin() + (i + 1) * _block_size);
        if (!VerifyBlock(block, _n_servers, block_idx, _public_key, _file_name,
                         metadata.stripe_offset + i, metadata.version)) {
            spdlog::warn("Block verification failed");
            return false;
        }
    }
    
    if (!VerifyUpdate(metadata.signature, _public_key, _file_name, metadata)) {
        spdlog::warn("Version signature verification failed");
        return false;
    }
#endif
    uint32_t new_version = _version() + 1;
    if (metadata.version < new_version) {
        /* Stale write. */
        return true;
    } else if (metadata.version != new_version) {
        /* Version gap. */
        return false;
    }

    UndoRecord record = _CreateUndoRecord(metadata);
    _update_record[metadata.version] = record;

    _file_stream.seekp(kBasePosition + metadata.stripe_offset * _block_size);
    _file_stream.write((char*)block_data.data(), block_data.size());
    _file_stream.flush();

    return true;
}

Bytes File::ReadVersion(uint32_t version, uint64_t stripe_offset,
                        uint64_t num_stripes) {
    if (_deleted()) {
        spdlog::warn("Deleted");
        return {};
    }
    std::set<Segment> segments = _ReconstructVersion(version);
    if (segments.empty()) {
        spdlog::warn("Empty segment");
        return {};
    }

    Bytes block_data(num_stripes * _block_size);
    uint32_t current_version = _version();

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
            auto& record = _update_record[version + 1];
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

bool File::Delete(uint32_t version, const Bytes& signature) {
    UpdateMetadata meta{
        .version = version,
        .stripe_offset = 0,
        .num_stripes = 0,
        .file_size = 0,
        .is_delete = true,
        .signature = signature,
    };
#ifndef NO_VERIFY
    if (!VerifyUpdate(signature, _public_key, _file_name, meta)) {
        spdlog::warn("Version signature verification failed");
        return false;
    }
#endif
    uint32_t new_version = _version() + 1;
    if (version < new_version) {
        /* Stale write. */
        return true;
    } else if (version != new_version) {
        /* Version gap. */
        return false;
    }

    for (const auto& [version, record] : _update_record) {
        fs::remove(_UndoLogPath(version));
    }
    _update_record.clear();
    _update_record[new_version] = _CreateUndoRecord(meta);
    _file_stream.close();
    fs::remove(_FilePath());
    return true;
}

bool File::Recreate(uint32_t version, const Bytes& signature) {
    if (!_deleted()) {
        return false;
    }
    UpdateMetadata meta = {
        .version = version,
        .stripe_offset = 0,
        .num_stripes = 0,
        .file_size = 0,
        .is_delete = false,
        .signature = signature,
    };
#ifndef NO_VERIFY
    if (!VerifyUpdate(signature, _public_key, _file_name, meta)) {
        spdlog::error("Version signature verification failed");
        throw std::runtime_error("Version signature verification failed");
    }
#endif
    uint32_t new_version = _version() + 1;
    if (version < new_version) {
        /* Stale write. */
        return true;
    } else if (version != new_version) {
        /* Version gap. */
        return false;
    }

    std::fstream::openmode open_mode = std::fstream::binary | std::fstream::in |
                                       std::fstream::out | std::fstream::trunc;
    _file_stream.open(_FilePath(), open_mode);
    if (!_file_stream.is_open()) {
        spdlog::error("Failed to open");
        throw std::runtime_error("Failed to open");
    }

    _update_record.clear();
    _update_record[new_version] = _CreateUndoRecord(meta);
    _WriteMetadata();
    return true;
}

bool File::UpdateUndoLogAndFile(
    const std::map<uint32_t, UpdateMetadata>& update_log,
    const std::set<std::pair<uint64_t, uint64_t>>& segments,
    const std::vector<Bytes>& reconstructed_blocks) {
    if (segments.size() != reconstructed_blocks.size()) {
        throw std::invalid_argument("Segment and block size mismatch");
    }
    uint32_t current_version = _version();
    uint32_t first_version = 0;
    for (auto& i : update_log) {
        if (i.first <= current_version) continue;
        if (i.second.num_stripes == 0) {
            first_version = i.first;
        }
    }
    if (first_version != 0) {
        // first_version is either a create or a delete
        // remove all prior versions
        for (const auto& [version, record] : _update_record) {
            fs::remove(_UndoLogPath(version));
        }
        _update_record.clear();
    }
    for (auto& i : _update_record) {
        // remove all images
        if (i.second.has_image) _ClearUndoRecordImage(i.second);
    }
    for (auto& i : update_log) {
        if (i.first <= current_version) continue;
        if (i.first < first_version || _update_record.find(i.first) != _update_record.end()) {
            continue;
        }
        _update_record[i.first] = _CreateUndoRecord(i.second, false);
    }
    if (_update_record.rbegin()->second.metadata.is_delete) {
        _file_stream.close();
        fs::remove(_FilePath());
        return true;
    }
    if (first_version != 0) {
        _file_stream.close();
        _file_stream.open(
            _FilePath(),
            std::fstream::binary | std::fstream::in | std::fstream::out | std::fstream::trunc);
        _start_version = first_version;
    }
    auto it = segments.begin();
    for (size_t i = 0; i < segments.size(); i++, ++it) {
        const auto& [start, end] = *it;
        const Bytes& data = reconstructed_blocks[i];
        if (data.size() != (end - start) * _block_size) {
            throw std::invalid_argument("Block size mismatch");
        }
        _file_stream.seekp(kBasePosition + start * _block_size);
        _file_stream.write((char*)data.data(), data.size());
        _file_stream.flush();
    }
    return true;
}

std::string File::FileName() const { return _file_name; }

Bytes File::PublicKey() const { return _public_key.PublicKey(); }

UpdateMetadata File::LastUpdate() const {
    if (_update_record.empty()) {
        spdlog::error("No update record");
        throw std::runtime_error("No update record");
    }
    return _update_record.rbegin()->second.metadata;
}

uint32_t File::StartVersion() const { return _start_version; }

std::vector<UpdateMetadata> File::GetUpdateLog(uint32_t start_version) {
    std::vector<UpdateMetadata> log;
    for (auto it = _update_record.lower_bound(start_version);
         it != _update_record.end(); ++it) {
        log.push_back(it->second.metadata);
    }
    return log;
}


