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
    std::tuple<uint64_t, uint64_t, uint32_t>;  // (start, end, version)

struct UpdateMetadata {
    uint32_t version;
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
    const fs::path _directory;
    const std::string _file_name;
    const std::string _encoded_file_name;
    SigningKey _public_key;
    const int _n_servers;
    uint32_t _start_version; // the version number that the creation happens
    uint32_t _first_image_version; // the first version that still has data remaining
    std::map<uint32_t, UndoRecord> _update_record;
    std::fstream _file_stream;
    std::atomic<bool> _file_closed;
    std::thread _garbage_collection;
    const uint32_t _block_size, _raw_stripe_size;

    fs::path _UndoLogDirectory() const;
    fs::path _UndoLogPath(uint32_t version) const;
    fs::path _FilePath() const;
    std::set<Segment> _ReconstructVersion(uint32_t version);
    UndoRecord _CreateUndoRecord(const UpdateMetadata& metadata, bool current = true);
    void _ClearUndoRecordImage(UndoRecord& record);
    void _GarbageCollectRecord();
    uint64_t _GetCurrentStripeSize();
    void _LoadUndoRecords(const std::string& log_directory);
    UndoRecord _LoadUndoRecord(const std::string& record_path);
    void _WriteMetadata();

    uint32_t _version() const;
    bool _deleted() const;

   public:
    File(const std::string& directory, const std::string& file_name,
         const Bytes& version_signature, int n_servers,
         uint32_t block_size, uint32_t raw_stripe_size);
    File(const std::string& directory, const std::string& file_name,
         int n_servers, uint32_t block_size, uint32_t raw_stripe_size);
    ~File();
    std::mutex& Mutex() { return _mu; }
    // obtain the mutex before doing any the following operations
    bool WriteStripes(const UpdateMetadata& metadata, uint32_t block_idx,
                      const Bytes& block_data);
    Bytes ReadVersion(uint32_t version, uint64_t stripe_offset,
                      uint64_t num_stripes);
    bool Delete(uint32_t version, const Bytes& signature);
    bool Recreate(uint32_t version, const Bytes& signature);
    bool UpdateUndoLogAndFile(
        const std::map<uint32_t, UpdateMetadata>& update_log,
        const std::set<std::pair<uint64_t, uint64_t>>& segments,
        const std::vector<Bytes>& reconstructed_blocks);


    Bytes PublicKey() const;
    std::string FileName() const;
    UpdateMetadata LastUpdate() const;
    uint32_t StartVersion() const;
    std::vector<UpdateMetadata> GetUpdateLog(uint32_t start_version);
};

#endif