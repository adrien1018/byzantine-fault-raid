#ifndef _FILESYS_FILE_H
#define _FILESYS_FILE_H

#include <deque>
#include <mutex>
#include <string>

#include "signature.h"

struct UndoRecord {
    uint32_t stripe_offset;
    uint32_t num_stripes;
    uint32_t version;
    Bytes old_image; /* TODO: Do we need to store this in memory or can we read
                        it from file. */
};

class File {
    std::mutex _mu;
    fs::path _directory;
    std::string _file_name;
    Bytes _public_key;
    uint32_t _version;
    std::deque<UndoRecord> _update_record;

    bool ReconstructVersion(uint32_t version, Bytes& latest_version);
    UndoRecord CreateUndoRecord(uint32_t stripe_offset, uint32_t num_stripes);

   public:
    File(const std::string& directory, const std::string& file_name,
         const Bytes& public_key);
    void WriteStripes(uint32_t stripe_offset, uint32_t num_stripes,
                      uint32_t version, const Bytes& data_block);
    Bytes ReadVersion(uint32_t version);
    uint32_t Version();
    std::string FileName() const;
    Bytes PublicKey() const;
};

#endif