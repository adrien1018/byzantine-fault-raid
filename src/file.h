#ifndef _FILESYS_FILE_H
#define _FILESYS_FILE_H

#include <map>
#include <set>
#include <mutex>
#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <fstream>

#include "signature.h"

using Clock = std::chrono::steady_clock;
using Segment =
    std::tuple<uint64_t, uint64_t, int32_t>;  // (start, end, version)

struct UpdateMetadata {
    int32_t version;
    uint64_t stripe_offset;
    uint64_t num_stripes;
    uint64_t file_size;
    bool is_delete;
    Bytes signature;
};

struct UndoRecord {
    UpdateMetadata metadata;
    uint64_t stripe_size; /* The number of stripes in this version times
                             block_size. */
    bool has_image;
    Bytes old_image;
    Clock::time_point time_to_live;

    static UndoRecord ReadFromFile(std::ifstream& ifs);
    void WriteToFile(std::ofstream& ofs) const;
};

class File {
    static const uint64_t kBasePosition;

    std::mutex _mu;
    fs::path _directory;
    std::string _file_name;
    std::string _encoded_file_name;
    SigningKey _public_key;
    int32_t _start_version; // the version number that the creation happens
    int32_t _first_image_version; // the first version that still has data remaining
    std::map<int32_t, UndoRecord> _update_record;
    std::fstream _file_stream;
    std::atomic<bool> _file_closed;
    std::thread _garbage_collection;
    const uint32_t _block_size;

    fs::path UndoLogDirectory() const;
    fs::path UndoLogPath(int32_t version) const;
    std::set<Segment> ReconstructVersion(int32_t version);
    UndoRecord CreateUndoRecord(const UpdateMetadata& metadata);
    void GarbageCollectRecord();
    uint64_t GetCurrentStripeSize();
    void LoadUndoRecords(const std::string& log_directory);
    UndoRecord LoadUndoRecord(const std::string& record_path);
    void WriteMetadata();

    int32_t _version() const;
    bool _deleted() const;

   public:
    File(const std::string& directory, const std::string& file_name,
         const Bytes& version_signature, uint32_t block_size);
    File(const std::string& directory, const std::string& file_name,
         uint32_t block_size);
    ~File();
    std::mutex& Mutex() { return _mu; }
    // obtain the mutex before doing any the following operations
    bool WriteStripes(const UpdateMetadata& metadata, uint32_t block_idx,
                      const Bytes& block_data);
    Bytes ReadVersion(int32_t version, uint64_t stripe_offset,
                      uint64_t num_stripes);
    bool Delete(int32_t version, const Bytes& signature);
    bool Recreate(int32_t version, const Bytes& signature);
    Bytes PublicKey() const;
    std::string FileName() const;
    UpdateMetadata LastUpdate() const;
    int32_t StartVersion() const;
};

#endif