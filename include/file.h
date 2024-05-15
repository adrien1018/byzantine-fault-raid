#ifndef _FILESYS_FILE_H
#define _FILESYS_FILE_H

#include <mutex>
#include <queue>
#include <string>

#include "signature.h"

struct UpdateRecord {
    uint32_t stripe_offset;
    uint32_t num_stripes;
    Bytes data_block;
};

class File {
    std::mutex _mu;
    fs::path _directory;
    std::string _file_name;
    uint32_t _version;
    std::queue<UpdateRecord> _update_record;

    Bytes ReconstructVersion(uint32_t version);

   public:
    File(const std::string& directory, const std::string& file_name);
    void WriteStripes(uint32_t stripe_offset, uint32_t num_stripes,
                      const Bytes& data_block);
    Bytes ReadVersion(uint32_t version);
    uint32_t Version();
};

#endif