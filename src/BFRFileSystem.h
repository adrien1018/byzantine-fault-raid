/*
 * Byzantine Fault-tolerant RAID-like file system client library
 */

#pragma once

#include <string>
#include <vector>
#include <memory>

#include "signature.h"
#include "filesys.grpc.pb.h"

using filesys::Filesys;

typedef struct FileMetadata {
    uint32_t version;
    uint64_t fileSize;

    /* For unordered_map. */
    bool operator ==(const FileMetadata &other) const
    {
        return (this->version == other.version) &&
               (this->fileSize == other.fileSize);
    }

} FileMetadata;

/* How to hash FileMetadata for unordered_map. */
template<> struct std::hash<FileMetadata>
{
    std::size_t operator()(const FileMetadata &m) const
    {
        return std::hash<uint32_t>()(m.version) ^
               std::hash<uint64_t>()(m.fileSize);
    }
};

class BFRFileSystem final {
public:
    /*
     * Initializes connections to servers; loads signing key.
     */
    BFRFileSystem(const std::vector<std::string> &serverAddresses,
                  const int numMalicious, const int numFaulty,
                  const int blockSize);

    /*
     * Returns the list of files.
     */
    std::unordered_set<std::string> getFileList() const;

    /*
     * Creates a new BFR file.
     * Returns 0 on success; -EIO on failure (e.g. file already exists).
     */
    int create(const char *path) const;

    /*
     * Returns the file's metadata if sufficient servers agree.
     */
    std::optional<FileMetadata> open(const char *path) const;

    /*
     * Reads a BFR file.
     * Returns the number of bytes read; -errno on failure.
     */
    int read(const char *path, char *buf, const size_t size,
             const off_t offset) const;

    /*
     * Writes to a BFR file.
     * Only able to be called by the file's owner.
     * Returns the number of bytes written; or -errno on failure.
     */
    int write(const char *path, const char *buf, const size_t size,
              const off_t offset) const;

    /*
     * Deletes a BFR file.
     * Only able to be called by the file's owner.
     * Returns 0 on success; -EIO on failure.
     */
    int unlink(const char *path) const;

private:
    std::vector<std::unique_ptr<Filesys::Stub>> servers_;
    int numServers_;
    int numMalicious_;
    int numFaulty_;
    int blockSize_;
    int stripeSize_;
    SigningKey signingKey_;
    std::chrono::microseconds timeout_;

    std::vector<Filesys::Stub*> QueryServers_() const;
};

