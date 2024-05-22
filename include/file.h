#ifndef _FILESYS_FILE_H
#define _FILESYS_FILE_H

#include <chrono>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include "signature.h"

/* TODO: Pass block size here. */
#define BLOCK_SIZE 128

using Clock = std::chrono::steady_clock;
using Segment = std::tuple<uint32_t, uint32_t, uint32_t>;

struct UndoRecord {
    uint32_t version;
    uint32_t stripe_offset;
    uint32_t num_stripes;
    uint32_t file_size;
    Bytes old_image; /* TODO: Do we need to store this in memory or can we read
                        it from file. */
    Clock::time_point time_to_live;
};

class File {
    std::mutex _mu;
    fs::path _directory;
    std::string _file_name;
    SigningKey _public_key;
    uint32_t _version;
    std::map<uint32_t, UndoRecord> _update_record;
    std::thread _garbage_collection;
    std::fstream _file_stream;

    std::set<Segment> ReconstructVersion(uint32_t version);
    UndoRecord CreateUndoRecord(uint32_t stripe_offset, uint32_t num_stripes);
    void GarbageCollectRecord();
    uint32_t GetCurrentFileSize();

   public:
    File(const std::string& directory, const std::string& file_name,
         const Bytes& public_key);
    ~File();
    bool WriteStripes(uint32_t stripe_offset, uint32_t num_stripes,
                      uint32_t block_idx, uint32_t version,
                      const Bytes& block_data);
    Bytes ReadVersion(uint32_t version, uint32_t stripe_offset,
                      uint32_t num_stripes);
    uint32_t Version();
    std::string FileName() const;
    Bytes PublicKey() const;
};

#endif