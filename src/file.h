#ifndef _FILESYS_FILE_H
#define _FILESYS_FILE_H

#include <atomic>
#include <chrono>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include "signature.h"

using Clock = std::chrono::steady_clock;
using Segment = std::tuple<uint64_t, uint64_t, uint32_t>; // (start, end, version)

struct Metadata {
    Bytes public_key;
    uint64_t file_size;
};

struct UndoRecord {
    uint32_t version;
    uint64_t stripe_offset;
    uint64_t num_stripes;
    uint64_t stripe_size; /* The number of stripes in this version times
                             block_size. */
    Bytes old_image;
    Clock::time_point time_to_live;
    Metadata metadata;

    static UndoRecord ReadFromFile(std::ifstream& ifs);
    void WriteToFile(std::ofstream& ofs) const;
};

class File {
    std::mutex _mu;
    fs::path _directory;
    std::string _file_name;
    SigningKey _public_key;
    uint32_t _version;
    uint32_t _first_image_version;
    std::map<uint32_t, UndoRecord> _update_record;
    std::thread _garbage_collection;
    std::fstream _file_stream;
    std::atomic<bool> _file_closed;
    uint64_t _file_size;
    bool _deleted;
    uint32_t _base_position;
    const uint32_t _block_size;

    fs::path UndoLogPath(uint32_t version) const;
    std::set<Segment> ReconstructVersion(uint32_t version);
    UndoRecord CreateUndoRecord(uint64_t stripe_offset, uint64_t num_stripes);
    void GarbageCollectRecord();
    uint64_t GetCurrentStripeSize();
    void LoadUndoRecords(const std::string& log_directory);
    UndoRecord LoadUndoRecord(const std::string& record_path);

   public:
    File(const std::string& directory, const std::string& file_name,
         const Bytes& public_key, uint32_t block_size);
    File(const std::string& directory, const std::string& file_name,
         uint32_t block_size);
    ~File();
    bool WriteStripes(uint64_t stripe_offset, uint64_t num_stripes,
                      uint32_t block_idx, uint32_t version,
                      const Bytes& block_data, const Metadata& metadata);
    Bytes ReadVersion(uint32_t version, uint64_t stripe_offset,
                      uint64_t num_stripes);
    void Delete();
    bool Deleted();
    bool UpdateSignKey(const Bytes& public_key);
    uint32_t Version();
    std::string FileName() const;
    Bytes PublicKey() const;
};

#endif