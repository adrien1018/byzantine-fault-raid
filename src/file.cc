#include "file.h"

#include <iterator>
#include <optional>
#include <utility>

#include "encode_decode.h"

File::File(const std::string& directory, const std::string& file_name,
           const Bytes& public_key, uint32_t _block_size)
    : _directory(directory),
      _file_name(file_name),
      _public_key(public_key, false),
      _version(0),
      _garbage_collection(&File::GarbageCollectRecord, this),
      _file_removed(false),
      _block_size(_block_size) {
    fs::path file_path = _directory / _file_name;
    std::fstream::openmode open_mode =
        std::fstream::binary | std::fstream::in | std::fstream::out;
    if (!fs::exists(file_path)) {
        open_mode |= std::fstream::trunc;
    }
    _file_stream.open(file_path, open_mode);
    if (_file_stream.fail()) {
        throw std::runtime_error("Failed to open fail");
    }
}

File::~File() {
    _file_removed.store(true);
    _file_stream.close();
    _garbage_collection.join();
}

bool File::WriteStripes(uint32_t stripe_offset, uint32_t num_stripes,
                        uint32_t block_idx, uint32_t version,
                        const Bytes& block_data) {
    for (uint32_t i = 0; i < num_stripes; i++) {
        const Bytes block = Bytes(block_data.begin() + i * _block_size,
                                  block_data.begin() + (i + 1) * _block_size);
        if (!VerifyBlock(block, block_idx, _public_key, _file_name,
                         stripe_offset + i, version)) {
            return false;
        }
    }
    std::lock_guard<std::mutex> lock(_mu);

    if (version != _version + 1) {
        return false;
    }

    UndoRecord record = CreateUndoRecord(stripe_offset, num_stripes);
    _update_record[_version] = record;

    _file_stream.seekp(stripe_offset * _block_size);
    _file_stream.write((char*)block_data.data(), block_data.size());
    _file_stream.flush();
    _version++;

    return true;
}

Bytes File::ReadVersion(uint32_t version, uint32_t stripe_offset,
                        uint32_t num_stripes) {
    std::lock_guard<std::mutex> lock(_mu);

    std::set<Segment> segments = ReconstructVersion(version);
    if (segments.empty()) {
        return {};
    }

    Bytes block_data(num_stripes * _block_size);

    for (const auto& [start, end, version] : segments) {
        if (stripe_offset >= end || stripe_offset + num_stripes <= start) {
            continue;
        }
        uint32_t effective_start = std::max(start, stripe_offset);
        uint32_t effective_end = std::min(end, stripe_offset + num_stripes);
        if (version == _version) {
            _file_stream.seekg(effective_start * _block_size);
            _file_stream.read(
                (char*)block_data.data() +
                    (effective_start - stripe_offset) * _block_size,
                (effective_end - effective_start) * _block_size);
        } else {
            auto& record = _update_record[version];
            const Bytes& version_block = record.old_image;
            uint32_t image_offset =
                (effective_start - record.stripe_offset) * _block_size;
            uint32_t size = (effective_end - effective_start) * _block_size;
            std::copy(version_block.begin() + image_offset,
                      version_block.begin() + image_offset + size,
                      block_data.begin() +
                          (effective_start - stripe_offset) * _block_size);
        }
    }
    return block_data;
}

uint32_t File::Version() {
    std::lock_guard<std::mutex> lock(_mu);
    return _version;
}

std::string File::FileName() const { return _file_name; }

Bytes File::PublicKey() const { return _public_key.PublicKey(); }

UndoRecord File::CreateUndoRecord(uint32_t stripe_offset,
                                  uint32_t num_stripes) {
    std::ofstream ofs;
    fs::path undo_log =
        _directory / (_file_name + "_version" + std::to_string(_version));
    ofs.open(undo_log, std::fstream::binary);

    if (ofs.fail()) {
        throw std::runtime_error("Failed to create undo log.");
    }

    Bytes buffer;
    _file_stream.seekg(0, std::ios::end);
    std::streampos file_size = _file_stream.tellg();
    if (stripe_offset * _block_size < file_size) {
        uint32_t end = std::min(static_cast<uint32_t>(file_size),
                                (stripe_offset + num_stripes) * _block_size);
        uint32_t read_size = end - (stripe_offset * _block_size);
        if (read_size) {
            _file_stream.seekg(stripe_offset * _block_size);
            buffer.resize(read_size);
            _file_stream.read((char*)buffer.data(), read_size);
            ofs.write((char*)buffer.data(), read_size);
        }
    }
    ofs.close();

    UndoRecord record{
        .version = _version,
        .stripe_offset = stripe_offset,
        .num_stripes = num_stripes,
        .file_size = GetCurrentFileSize(),
        .old_image = buffer,
        .time_to_live = Clock::now() + std::chrono::seconds(30),
    };

    return record;
}

void File::GarbageCollectRecord() {
    std::unique_lock<std::mutex> lock(_mu, std::defer_lock);
    while (!_file_removed.load()) {
        lock.lock();
        while (!_update_record.empty() &&
               _update_record.begin()->second.time_to_live <= Clock::now()) {
            fs::path undo_log =
                _directory /
                (_file_name + "_version" +
                 std::to_string(_update_record.begin()->second.version));
            fs::remove(undo_log);
            _update_record.erase(_update_record.begin());
        }
        auto wake_up_time = Clock::now() + std::chrono::seconds(30);
        if (!_update_record.empty()) {
            wake_up_time = _update_record.begin()->second.time_to_live;
        }
        lock.unlock();
        std::this_thread::sleep_until(Clock::now() +
                                      std::chrono::milliseconds(200));
    }
}

uint32_t File::GetCurrentFileSize() {
    _file_stream.seekg(0, std::ios::end);
    return _file_stream.tellg();
}
std::set<Segment> File::ReconstructVersion(uint32_t version) {
    if (version != _version &&
        (_update_record.empty() ||
         _update_record.begin()->second.version > version)) {
        /* Not enough information to recover the old version. */
        return {};
    }
    auto latest_update = _update_record.rbegin();

    uint32_t file_size = GetCurrentFileSize();
    if (file_size % _block_size) {
        throw std::runtime_error("File size not on block boundary");
    }
    std::set<Segment> segments{{0, file_size / _block_size, _version}};
    uint32_t version__block_size = file_size / _block_size;
    while (latest_update != _update_record.rend() &&
           latest_update->second.version >= version) {
        /* This operation assumes that each update only keeps the file size
         * the same or extends it, but never shrinks.*/
        std::optional<std::set<Segment>::iterator> start_remover = std::nullopt;
        if (latest_update->second.version == version) {
            version__block_size = latest_update->second.file_size / _block_size;
        }
        uint32_t segment_start = latest_update->second.stripe_offset;
        auto start_overlap = segments.lower_bound({segment_start, 0, 0});
        if (start_overlap != segments.begin()) {
            auto to_edit = std::prev(start_overlap);
            const auto [prev_start, prev_end, prev_version] = *to_edit;
            if (prev_end > segment_start) {
                segments.emplace(prev_start, segment_start, prev_version);
                start_remover = to_edit;
            }
        }

        uint32_t segment_end = latest_update->second.stripe_offset +
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

    auto unused_segment = segments.lower_bound({version__block_size, 0, 0});
    if (unused_segment != segments.begin()) {
        auto to_edit = std::prev(unused_segment);
        auto [prev_start, prev_end, prev_version] = *to_edit;
        if (prev_end > version__block_size) {
            if (prev_start != version__block_size) {
                segments.emplace(prev_start, version__block_size, prev_version);
            }
            segments.erase(to_edit);
        }
    }

    while (unused_segment != segments.end()) {
        unused_segment = segments.erase(unused_segment);
    }

    return segments;
}