#include "file.h"

#include <fstream>

/* TODO: Pass block size here. */
#define BLOCK_SIZE 128

File::File(const std::string& directory, const std::string& file_name,
           const Bytes& public_key)
    : _directory(directory),
      _file_name(file_name),
      _public_key(public_key),
      _version(0) {}

void File::WriteStripes(uint32_t stripe_offset, uint32_t num_stripes,
                        uint32_t version, const Bytes& data_block) {
    std::lock_guard<std::mutex> lock(_mu);

    /* If version is 0 then the file is empty and no need for undo log. */
    if (_version) {
        UndoRecord record = CreateUndoRecord(stripe_offset, num_stripes);
        _update_record.push_back(record);
    }

    /* Update the file content. */
    fs::path file_path = _directory / _file_name;
    std::ofstream ofs;
    ofs.open(file_path, std::fstream::binary | std::fstream::app);

    if (ofs.fail()) {
        throw std::runtime_error("Failed to open file");
    }

    ofs.seekp(stripe_offset * BLOCK_SIZE);
    ofs.write((char*)&data_block[0], data_block.size());
    ofs.close();
    _version++;
}

Bytes File::ReadVersion(uint32_t version) {
    std::lock_guard<std::mutex> lock(_mu);

    std::ifstream ifs;
    fs::path file_path = _directory / _file_name;
    ifs.open(file_path, std::fstream::binary);

    if (ifs.fail()) {
        throw std::runtime_error("Failed to open file");
    }

    Bytes block_data = Bytes(std::istreambuf_iterator<char>(ifs),
                             std::istreambuf_iterator<char>());
    ifs.close();

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
    std::ifstream ifs;
    fs::path file = _directory / _file_name;
    ifs.open(file, std::fstream::binary);

    if (ifs.fail()) {
        throw std::runtime_error("Failed to open file.");
    }

    std::ofstream ofs;
    fs::path undo_log =
        _directory / (_file_name + "_version" + std::to_string(_version));
    ofs.open(undo_log, std::fstream::binary | std::fstream::app);

    if (ofs.fail()) {
        throw std::runtime_error("Failed to create undo log.");
    }

    ifs.seekg(stripe_offset * BLOCK_SIZE);
    char* buffer = new char[num_stripes * BLOCK_SIZE];
    ifs.read(buffer, num_stripes * BLOCK_SIZE);
    ofs.write(buffer, num_stripes * BLOCK_SIZE);

    ifs.close();
    ofs.close();

    UndoRecord record{
        .stripe_offset = stripe_offset,
        .num_stripes = num_stripes,
        .version = _version,
        .old_image = Bytes(buffer, buffer + num_stripes * BLOCK_SIZE),
    };

    delete[] buffer;

    return record;
}

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