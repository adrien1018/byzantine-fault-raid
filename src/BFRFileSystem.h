/*
 * Byzantine Fault-tolerant RAID-like file system client library
 */

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "filesys.grpc.pb.h"

#include "config.h"
#include "signature.h"

using filesys::Filesys;

struct FileMetadata {
    uint32_t version;
    uint64_t fileSize;
    bool isDeleted;
};

class BFRFileSystem final {
   public:
    /*
     * Initializes connections to servers; loads signing key.
     */
    BFRFileSystem(const Config& config, const std::string &signing_key_path);


    /*
     * Returns the list of files.
     */
    std::unordered_set<std::string> getFileList() const;

    /*
     * Creates a new BFR file.
     * Returns 0 on success; -EIO on failure (e.g. file already exists).
     */
    int create(const std::string& path) const;

    /*
     * Returns the file's metadata if sufficient servers agree.
     */
    std::optional<FileMetadata> open(const std::string& path) const;

    /*
     * Reads a BFR file.
     * Returns the number of bytes read; -errno on failure.
     */
    int64_t read(const std::string& path, char *buf, const size_t size,
                 const off_t offset) const;

    /*
     * Writes to a BFR file.
     * Only able to be called by the file's owner.
     * Returns the number of bytes written; or -errno on failure.
     */
    int64_t write(const std::string& path, const char *buf, const size_t size,
                  const off_t offset) const;

    /*
     * Deletes a BFR file.
     * Only able to be called by the file's owner.
     * Returns 0 on success; -EIO on failure.
     */
    int unlink(const std::string& path) const;

    // with trailing slash
    const std::string& GetPrefix() const { return prefix_; }
    bool CheckPrefix(const std::string& path) const {
        return path.size() > prefix_.size() && path.substr(0, prefix_.size()) == prefix_;
    }

   private:
    std::vector<std::unique_ptr<Filesys::Stub>> servers_;
    int numServers_;
    int numMalicious_;
    int numFaulty_;
    int blockSize_;
    int stripeSize_;
    SigningKey signingKey_;
    std::string prefix_;
    std::chrono::microseconds timeout_;

    std::vector<Filesys::Stub *> QueryServers_() const;
    std::optional<FileMetadata> QueryMetadata_(const std::string& path, bool with_delete = false) const;
};
