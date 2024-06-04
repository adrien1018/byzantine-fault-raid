#include "file.h"

#include <iostream>
#include <iterator>
#include <optional>
#include <utility>

#include "encode_decode.h"

using namespace std::chrono_literals;

/* Persisting the record on disk. The format is:
    |version (4 bytes)|stripe_offset (8 bytes)|num_stripes (8 bytes)
    |stripe_size (8 bytes)|public_key_size(4 bytes)|metadata_public_key
    (variable bytes)|metadata_file_size (8 bytes)
    |buffer_size(8 bytes)|block_data (variable size)| */

UndoRecord UndoRecord::ReadFromFile(std::ifstream& ifs) {
    UndoRecord record;
    ifs.read((char*)&record.version, sizeof(uint32_t));
    ifs.read((char*)&record.stripe_offset, sizeof(uint64_t));
    ifs.read((char*)&record.num_stripes, sizeof(uint64_t));
    ifs.read((char*)&record.stripe_size, sizeof(uint64_t));
    uint32_t public_key_size;
    ifs.read((char*)&public_key_size, sizeof(uint32_t));
    record.metadata.public_key.resize(public_key_size);
    ifs.read((char*)record.metadata.public_key.data(), public_key_size);
    ifs.read((char*)&record.metadata.file_size, sizeof(uint64_t));
    uint64_t read_size;
    ifs.read((char*)&read_size, sizeof(uint64_t));
    record.old_image.resize(read_size);
    ifs.read((char*)record.old_image.data(), read_size);
    record.time_to_live = Clock::now() + 30s;
    return record;
}

void UndoRecord::WriteToFile(std::ofstream& ofs) const {
    ofs.write((char*)&version, sizeof(uint32_t));
    ofs.write((char*)&stripe_offset, sizeof(uint64_t));
    ofs.write((char*)&num_stripes, sizeof(uint64_t));
    ofs.write((char*)&stripe_size, sizeof(uint64_t));
    uint32_t public_key_size = metadata.public_key.size();
    ofs.write((char*)&public_key_size, sizeof(uint32_t));
    ofs.write((char*)metadata.public_key.data(), public_key_size);
    ofs.write((char*)&metadata.file_size, sizeof(uint64_t));
    uint64_t read_size = old_image.size();
    ofs.write((char*)&read_size, sizeof(uint64_t));
    ofs.write((char*)old_image.data(), read_size);
    ofs.close();
}

/* A file is stored as
    | version (4 bytes) | deleted (1 byte) | file_size (8 bytes)
    | key size (4 bytes) | public key (variable size)
    | block data (variable size)
*/

File::File(const std::string& directory, const std::string& file_name,
           const Bytes& public_key, uint32_t _block_size)
    : _directory(directory),
      _file_name(file_name),
      _public_key(public_key, false),
      _version(0),
      _first_image_version(0),
      _garbage_collection(&File::GarbageCollectRecord, this),
      _file_closed(false),
      _file_size(0),
      _deleted(false),
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
}

File::File(const std::string& directory, const std::string& file_name,
           uint32_t block_size)
    : _directory(directory),
      _file_name(file_name),
      _first_image_version(0),
      _garbage_collection(&File::GarbageCollectRecord, this),
      _file_closed(false),
      _file_size(0),
      _deleted(false),
      _block_size(block_size) {
    fs::path file_path = _directory / _file_name;
    std::fstream::openmode open_mode =
        std::fstream::binary | std::fstream::in | std::fstream::out;
    _file_stream.open(file_path, open_mode);

    _file_stream.read((char*)&_version, sizeof(uint32_t));
    _file_stream.read((char*)&_deleted, sizeof(bool));
    _file_stream.read((char*)&_file_size, sizeof(uint64_t));
    uint32_t public_key_size;
    _file_stream.read((char*)&public_key_size, sizeof(uint32_t));
    Bytes public_key(public_key_size);
    _file_stream.read((char*)public_key.data(), public_key_size);
    _public_key = SigningKey(public_key, false);
    _base_position = _file_stream.tellg();

    fs::path log_directory = _directory / fs::path(file_name + "_log");
    LoadUndoRecords(log_directory);
}

File::~File() {
    _file_closed.store(true);
    _file_stream.close();
    _garbage_collection.join();
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
            uint32_t version = std::stoul(file_name);
            UndoRecord record = LoadUndoRecord(entry.path());
            if (record.old_image.empty()) {
                _first_image_version =
                    std::max(version + 1, _first_image_version);
            }
            _update_record[version] = std::move(record);
        }
    }
}

void File::WriteMetadata() {
    _file_stream.write((char*)&_version, sizeof(uint32_t));
    _file_stream.write((char*)&_deleted, sizeof(bool));
    _file_stream.write((char*)&_file_size, sizeof(uint64_t));
    Bytes public_key = _public_key.PublicKey();
    uint32_t public_key_size = public_key.size();
    _file_stream.write((char*)&public_key_size, sizeof(uint32_t));
    _file_stream.write((char*)public_key.data(), public_key_size);
    _file_stream.flush();
    _base_position = _file_stream.tellp();
}

bool File::WriteStripes(uint64_t stripe_offset, uint64_t num_stripes,
                        uint32_t block_idx, uint32_t version,
                        const Bytes& block_data, const Metadata& metadata) {
    std::cerr << stripe_offset << ' ' << num_stripes << ' ' << block_idx << ' '
              << version << ' ' << block_data.size() << '\n';
    for (uint64_t i = 0; i < num_stripes; i++) {
        const Bytes block = Bytes(block_data.begin() + i * _block_size,
                                  block_data.begin() + (i + 1) * _block_size);
        if (!VerifyBlock(block, block_idx, _public_key, _file_name,
                         stripe_offset + i, version)) {
            std::cerr << "Failed to verify block" << std::endl;
            return false;
        }
    }
    std::lock_guard<std::mutex> lock(_mu);

    if (version <= _version) {
        /* Stale write. */
        return true;
    } else if (version != _version + 1) {
        std::cerr << "Version gap" << std::endl;
        /* Version gap. */
        return false;
    }

    UndoRecord record = CreateUndoRecord(stripe_offset, num_stripes);
    _update_record[_version] = record;

    _file_stream.seekp(_base_position + stripe_offset * _block_size);
    _file_stream.write((char*)block_data.data(), block_data.size());
    _file_stream.flush();
    _version++;
    _file_size = metadata.file_size;

    return true;
}

Bytes File::ReadVersion(uint32_t version, uint64_t stripe_offset,
                        uint64_t num_stripes) {
    std::lock_guard<std::mutex> lock(_mu);

    std::cerr << "Read version " << version << ' ' << stripe_offset << ' '
              << num_stripes << std::endl;

    if (_deleted) {
        return {};
    }
    std::set<Segment> segments = ReconstructVersion(version);
    std::cerr << "Segments done " << segments.size() << std::endl;
    std::cerr << segments.size() << std::endl;
    if (segments.empty()) {
        return {};
    }

    Bytes block_data(num_stripes * _block_size);

    for (const auto& [start, end, version] : segments) {
        if (stripe_offset >= end || stripe_offset + num_stripes <= start) {
            continue;
        }
        uint64_t effective_start = std::max(start, stripe_offset);
        uint64_t effective_end = std::min(end, stripe_offset + num_stripes);
        if (version == _version) {
            _file_stream.seekg(_base_position + effective_start * _block_size);
            _file_stream.read(
                (char*)block_data.data() +
                    (effective_start - stripe_offset) * _block_size,
                (effective_end - effective_start) * _block_size);
        } else {
            auto& record = _update_record[version];
            const Bytes& version_block = record.old_image;
            uint64_t image_offset =
                (effective_start - record.stripe_offset) * _block_size;
            uint64_t size = (effective_end - effective_start) * _block_size;
            std::copy(version_block.begin() + image_offset,
                      version_block.begin() + image_offset + size,
                      block_data.begin() +
                          (effective_start - stripe_offset) * _block_size);
        }
    }
    return block_data;
}

void File::Delete() {
    std::lock_guard<std::mutex> lock(_mu);
    for (const auto& [version, record] : _update_record) {
        fs::remove(UndoLogPath(version));
    }
    _update_record.clear();
    _file_stream.close();
    fs::path file_path = _directory / _file_name;
    fs::remove(file_path);

    _deleted = true;
    _file_size = 0;
    _version++;
}

bool File::Deleted() {
    std::lock_guard<std::mutex> lock(_mu);
    return _deleted;
}

bool File::UpdateSignKey(const Bytes& public_key) {
    std::lock_guard<std::mutex> lock(_mu);
    if (!_deleted) {
        return false;
    }

    std::fstream::openmode open_mode = std::fstream::binary | std::fstream::in |
                                       std::fstream::out | std::fstream::trunc;
    fs::path file_path = _directory / _file_name;
    _file_stream.open(file_path, open_mode);

    if (_file_stream.fail()) {
        throw std::runtime_error("Failed to open fail");
    }

    _deleted = false;
    _public_key = SigningKey(public_key, false);
    WriteMetadata();
    std::cerr << "Stripe size after: " << GetCurrentStripeSize() << '\n';
    return true;
}

uint32_t File::Version() {
    std::lock_guard<std::mutex> lock(_mu);
    return _version;
}

std::string File::FileName() const { return _file_name; }

Bytes File::PublicKey() const { return _public_key.PublicKey(); }

fs::path File::UndoLogPath(uint32_t version) const {
    return _directory / fs::path(_file_name + "_log") / std::to_string(version);
}

UndoRecord File::CreateUndoRecord(uint64_t stripe_offset,
                                  uint64_t num_stripes) {
    std::ofstream ofs;
    ofs.open(UndoLogPath(_version), std::fstream::binary);

    if (ofs.fail()) {
        throw std::runtime_error("Failed to create undo log.");
    }

    Bytes buffer;
    uint64_t read_size;
    uint64_t file_size = GetCurrentStripeSize();
    if (stripe_offset * _block_size < file_size) {
        uint64_t end =
            std::min(file_size, (stripe_offset + num_stripes) * _block_size);
        read_size = end - (stripe_offset * _block_size);
        if (read_size) {
            _file_stream.seekg(_base_position + stripe_offset * _block_size);
            buffer.resize(read_size);
            _file_stream.read((char*)buffer.data(), read_size);
        }
    }

    UndoRecord record{
        .version = _version,
        .stripe_offset = stripe_offset,
        .num_stripes = num_stripes,
        .stripe_size = GetCurrentStripeSize(),
        .old_image = buffer,
        .time_to_live = Clock::now() + 30s,
        .metadata =
            Metadata{
                .public_key = PublicKey(),
                .file_size = _file_size,
            },
    };

    return record;
}

void File::GarbageCollectRecord() {
    std::unique_lock<std::mutex> lock(_mu, std::defer_lock);
    while (!_file_closed.load()) {
        lock.lock();
        for (uint32_t version = _first_image_version; version <= _version;
             version++) {
            auto it = _update_record.find(version);
            if (it == _update_record.end()) continue;
            UndoRecord& record = it->second;
            if (record.time_to_live > Clock::now() ||
                record.version + 2 <= _version) {
                continue;
            }
            // clear the old image and update undo log file
            record.old_image.clear();
            std::ofstream ofs;
            ofs.open(UndoLogPath(version), std::fstream::binary);
            if (ofs.fail()) {
                throw std::runtime_error("Failed to create undo log.");
            }
            record.WriteToFile(ofs);
            _first_image_version = std::max(version + 1, _first_image_version);
        }
        lock.unlock();
        std::this_thread::sleep_for(200ms);
    }
}

uint64_t File::GetCurrentStripeSize() {
    _file_stream.seekg(0, std::ios::end);
    std::cerr << _file_stream.tellg() << ' ' << _base_position << '\n';
    return static_cast<uint64_t>(_file_stream.tellg()) - _base_position;
}

std::set<Segment> File::ReconstructVersion(uint32_t version) {
    if (version > _version) {
        /* The version is higher than the current version. */
        std::cerr << "Return due to version\n";
        return {};
    }
    if (version != _version &&
        (_update_record.empty() || _first_image_version > version)) {
        /* Not enough information to recover the old version. */
        std::cerr << "No info\n";
        return {};
    }
    auto latest_update = _update_record.rbegin();
    std::cerr << "Getting stripe size\n";
    uint64_t file_size = GetCurrentStripeSize();
    std::cerr << "Stripe size: " << file_size << '\n';
    if (file_size % _block_size) {
        throw std::runtime_error("File size not on block boundary");
    }
    std::set<Segment> segments{{0, file_size / _block_size, _version}};
    std::cerr << "Segment now contains " << file_size / _block_size << '\n';
    std::cerr << "Update record size: " << _update_record.size() << '\n';
    uint64_t version_block_size = file_size / _block_size;
    while (latest_update != _update_record.rend() &&
           latest_update->second.version >= version) {
        /* This operation assumes that each update only keeps the file size
         * the same or extends it, but never shrinks. */
        std::optional<std::set<Segment>::iterator> start_remover = std::nullopt;
        if (latest_update->second.version == version) {
            version_block_size =
                latest_update->second.stripe_size / _block_size;
        }
        uint64_t segment_start = latest_update->second.stripe_offset;
        auto start_overlap = segments.lower_bound({segment_start, 0, 0});
        if (start_overlap != segments.begin()) {
            auto to_edit = std::prev(start_overlap);
            const auto [prev_start, prev_end, prev_version] = *to_edit;
            if (prev_end > segment_start) {
                segments.emplace(prev_start, segment_start, prev_version);
                start_remover = to_edit;
            }
        }

        uint64_t segment_end = latest_update->second.stripe_offset +
                               latest_update->second.num_stripes;
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
        segments.emplace(segment_start, segment_end,
                         latest_update->second.version);
        latest_update = std::next(latest_update);
    }
    std::cerr << "Out of while loop\n";

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

    std::cerr << "Erasing unused\n";
    while (unused_segment != segments.end()) {
        unused_segment = segments.erase(unused_segment);
    }
    std::cerr << "Done\n";

    return segments;
}

uint64_t File::FileSize() {
    std::lock_guard<std::mutex> lock(_mu);
    return _file_size;
}