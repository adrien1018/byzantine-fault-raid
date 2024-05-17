#include "file.h"

File::File(const std::string& directory, const std::string& file_name,
           const Bytes& public_key)
    : _directory(directory),
      _file_name(file_name),
      _public_key(public_key),
      _version(0),
      _garbage_collection(&File::GarbageCollectRecord, this) {
    fs::path file_path = _directory / _file_name;
    std::fstream::openmode open_mode =
        std::fstream::binary | std::fstream::in | std::fstream::out;
    if (!fs::exists(file_path)) {
        open_mode |= std::fstream::trunc;
    }
    _file_stream.open(file_path, open_mode);
    if (_file_stream.fail()) {
        exit(0);
    }
    _garbage_collection.detach();
}

File::~File() { _file_stream.close(); }

bool File::WriteStripes(uint32_t stripe_offset, uint32_t num_stripes,
                        uint32_t version, const Bytes& block_data) {
    std::lock_guard<std::mutex> lock(_mu);

    if (version != _version + 1) {
        return false;
    }

    UndoRecord record = CreateUndoRecord(stripe_offset, num_stripes);
    _update_record.push_back(record);

    _file_stream.seekp(stripe_offset * BLOCK_SIZE);
    _file_stream.write((char*)block_data.data(), block_data.size());
    _file_stream.flush();
    _version++;

    return true;
}

Bytes File::ReadVersion(uint32_t version) {
    std::lock_guard<std::mutex> lock(_mu);

    _file_stream.seekg(0, std::ios::beg);
    Bytes block_data = Bytes(std::istreambuf_iterator<char>(_file_stream),
                             std::istreambuf_iterator<char>());

    if (version < _version) {
        if (!ReconstructVersion(version, block_data)) {
            return Bytes{};
        }
    }

    return block_data;
}

uint32_t File::Version() {
    std::lock_guard<std::mutex> lock(_mu);
    return _version;
}

std::string File::FileName() const { return _file_name; }

Bytes File::PublicKey() const { return _public_key; }

UndoRecord File::CreateUndoRecord(uint32_t stripe_offset,
                                  uint32_t num_stripes) {
    /* TODO: what if the current update is to extend the file? i.e., the undo
     * record is empty.*/
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
    if (stripe_offset * BLOCK_SIZE < file_size) {
        uint32_t end = std::min(static_cast<uint32_t>(file_size),
                                (stripe_offset + num_stripes) * BLOCK_SIZE);
        uint32_t read_size = end - (stripe_offset * BLOCK_SIZE);
        if (read_size) {
            _file_stream.seekg(stripe_offset * BLOCK_SIZE);
            buffer.resize(read_size);
            _file_stream.read((char*)buffer.data(), read_size);
            ofs.write((char*)buffer.data(), read_size);
        }
    }
    ofs.close();

    UndoRecord record{
        .stripe_offset = stripe_offset,
        .num_stripes = num_stripes,
        .version = _version,
        .old_image = buffer,
        .time_to_live = Clock::now() + std::chrono::seconds(30),
    };

    return record;
}

void File::GarbageCollectRecord() {}

bool File::ReconstructVersion(uint32_t version, Bytes& latest_version) {
    if (_update_record.empty() || _update_record.front().version > version) {
        /* Not enough information to recover the old version. */
        return false;
    }
    auto latest_update = _update_record.rbegin();
    while (latest_update->version >= version) {
        uint32_t stripe_offset = latest_update->stripe_offset;
        std::copy(latest_update->old_image.begin(),
                  latest_update->old_image.end(),
                  latest_version.begin() + stripe_offset * BLOCK_SIZE);
        latest_update = std::next(latest_update);
    }

    return true;
}

/* TODO: Garbage collect update record periodically. */