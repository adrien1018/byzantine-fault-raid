#ifndef _FILESYS_FILE_H
#define _FILESYS_FILE_H

#include <chrono>
#include <deque>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>

#include "signature.h"

/* TODO: Pass block size here. */
#define BLOCK_SIZE 128

using Clock = std::chrono::steady_clock;

struct UndoRecord {
    uint32_t stripe_offset;
    uint32_t num_stripes;
    uint32_t version;
    Bytes old_image; /* TODO: Do we need to store this in memory or can we read
                        it from file. */
    Clock::time_point time_to_live;
};

class File {
    std::mutex _mu;
    fs::path _directory;
    std::string _file_name;
    Bytes _public_key;
    uint32_t _version;
    std::deque<UndoRecord> _update_record;
    std::thread _garbage_collection;
    std::fstream _file_stream;

    bool ReconstructVersion(uint32_t version, Bytes& latest_version);
    UndoRecord CreateUndoRecord(uint32_t stripe_offset, uint32_t num_stripes);
    void GarbageCollectRecord();

   public:
    File(const std::string& directory, const std::string& file_name,
         const Bytes& public_key);
    ~File();
    bool WriteStripes(uint32_t stripe_offset, uint32_t num_stripes,
                      uint32_t version, const Bytes& block_data);
    Bytes ReadVersion(uint32_t version);
    uint32_t Version();
    std::string FileName() const;
    Bytes PublicKey() const;
};

#endif