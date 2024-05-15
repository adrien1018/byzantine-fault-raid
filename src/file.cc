#include "file.h"

#include <fstream>

/* TODO: Pass block size here. */
#define BLOCK_SIZE 128

File::File(const std::string& directory, const std::string& file_name)
    : _directory(directory), _file_name(file_name), _version(0) {}

void File::WriteStripes(uint32_t stripe_offset, uint32_t num_stripes,
                        const Bytes& data_block) {
    std::lock_guard<std::mutex> lock(_mu);
    _update_record.push(UpdateRecord{.stripe_offset = stripe_offset,
                                     .num_stripes = num_stripes,
                                     .data_block = data_block});
    /* TODO: Write update record to log file. */

    /* Update the file content. */
    fs::path file_path = _directory / _file_name;
    std::ofstream fs;
    fs.open(file_path, std::fstream::binary | std::fstream::app);

    if (fs.fail()) {
        throw std::runtime_error("Failed to open file");
    }

    fs.seekp(stripe_offset * BLOCK_SIZE);
    fs.write((char*)&data_block[0], data_block.size());
    fs.close();
    _version++;
}

Bytes File::ReadVersion(uint32_t version) {
    std::lock_guard<std::mutex> lock(_mu);

    if (_version == version) {
        std::ifstream fs;
        fs::path file_path = _directory / _file_name;
        fs.open(file_path, std::fstream::binary);

        if (fs.fail()) {
            throw std::runtime_error("Failed to open file");
        }

        Bytes block_data = Bytes(std::istreambuf_iterator<char>(fs),
                                 std::istreambuf_iterator<char>());
        return block_data;
    } else {
        return ReconstructVersion(version);
    }
}

uint32_t File::Version() {
    std::lock_guard<std::mutex> lock(_mu);
    return _version;
}

Bytes File::ReconstructVersion(uint32_t version) {
    return Bytes{};
    /* TODO: use update log to reconstruct a specific version. */
}