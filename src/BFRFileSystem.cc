#include "BFRFileSystem.h"

#include <grpcpp/grpcpp.h>
#include <spdlog/fmt/ranges.h>
#include <spdlog/spdlog.h>

#include "signature.h"
#include "async_query.h"
#include "filesys_common.h"
#include "filesys.grpc.pb.h"

using filesys::CreateFileArgs;
using filesys::DeleteFileArgs;
using filesys::FileInfo;
using filesys::GetFileListArgs;
using filesys::GetFileListReply;
using filesys::ReadBlocksArgs;
using filesys::ReadBlocksReply;
using filesys::WriteBlocksArgs;
using google::protobuf::Empty;
using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::InsecureChannelCredentials;
using grpc::Status;

#define NUM_RETRIES 10
namespace std {

// custom hash function for std::pair<std::string, uint32_t>
template <>
struct hash<std::pair<std::string, uint32_t>> {
    size_t operator()(const std::pair<std::string, uint32_t> &p) const {
        return std::hash<std::string>()(p.first) ^ std::hash<uint32_t>()(p.second);
    }
};

// C++20 erase
template< class T, class Alloc, class U >
constexpr typename std::vector<T, Alloc>::size_type erase(
    std::vector<T, Alloc>& c, const U& value) {
    auto it = std::remove(c.begin(), c.end(), value);
    auto r = c.end() - it;
    c.erase(it, c.end());
    return r;
}
template< class T, class Alloc, class Pred >
constexpr typename std::vector<T, Alloc>::size_type erase_if(
    std::vector<T, Alloc>& c, Pred pred) {
    auto it = std::remove_if(c.begin(), c.end(), pred);
    auto r = c.end() - it;
    c.erase(it, c.end());
    return r;
}

}  // namespace std


/*
 * Rounds down a number to the closest specified multiple.
 */
static uint64_t roundDown(const uint64_t numToRound, const uint64_t multiple) {
    return (numToRound / multiple) * multiple;
}

/*
 * Rounds up a number to the closest specified multiple.
 * Only works with positive numbers.
 * Source:
 * https://stackoverflow.com/questions/3407012/rounding-up-to-the-nearest-multiple-of-a-number
 */
static uint64_t roundUp(const uint64_t numToRound, const uint64_t multiple) {
    if (multiple == 0) {
        return numToRound;
    }

    const uint64_t remainder = numToRound % multiple;
    if (remainder == 0) {
        return numToRound;
    }

    return numToRound + multiple - remainder;
}

BFRFileSystem::BFRFileSystem(const Config& config, const std::string& signing_key_path) {
    for (const std::string &address : config.servers) {
        std::shared_ptr<Channel> channel =
            CreateChannel(address, InsecureChannelCredentials());
        servers_.emplace_back(Filesys::NewStub(channel));
    }
    numServers_ = config.servers.size();
    numMalicious_ = config.num_malicious;
    numFaulty_ = config.num_faulty;
    blockSize_ = config.block_size;
    stripeSize_ = GetStripeSize(blockSize_, numServers_, numFaulty_);
    signingKey_ = SigningKey(signing_key_path, true);
    prefix_ = Base64Encode(signingKey_.PublicKey()) + "/";
    timeout_ = 10s;
}

std::vector<Filesys::Stub *> BFRFileSystem::QueryServers_() const {
    std::vector<Filesys::Stub *> query_servers;
    for (auto &i : servers_) query_servers.push_back(i.get());
    return query_servers;
}

std::optional<FileMetadata> BFRFileSystem::QueryMetadata_(
    const std::string& path, bool include_deleted) const {
    GetFileListArgs args;
    args.set_file_name(path);
    args.set_include_deleted(include_deleted);

    bool has_result = false;
    FileMetadata metadata{
        .version = 0,
        .fileSize = 0,
    };

    size_t success_threshold = numMalicious_ + 1; // anything more than this is fine
    bool ret = QueryServers<GetFileListReply>(
        QueryServers_(), args, &Filesys::Stub::AsyncGetFileList,
        success_threshold, 100ms, timeout_,
        [&](const std::vector<AsyncResponse<GetFileListReply>> &responses,
            const std::vector<uint8_t> &replied,
            size_t &minimum_success) -> bool {
            for (size_t i = 0; i < responses.size(); ++i) {
                if (!replied[i] || !responses[i].status.ok()) {
                    continue;
                }
                auto &reply = responses[i].reply;
                if (!reply.files().size()) {
                    continue;
                }
                auto& file = reply.files(0);
                if (!VerifyUpdateSignature(file.last_update(), path,
                                           file.public_key())) {
                    spdlog::warn("Invalid signature for file {}", path);
                    continue;
                }
                if (!has_result || file.last_update().version() > metadata.version) {
                    metadata.version = file.last_update().version();
                    metadata.fileSize = file.last_update().file_size();
                    metadata.isDeleted = file.last_update().is_delete();
                    has_result = true;
                }
            }
            return true;
        },
        "Open");

    if (!ret || !has_result) {
        return std::nullopt;
    }
    return metadata;
}

std::unordered_set<std::string> BFRFileSystem::getFileList() const {
    std::unordered_map<std::string, std::map<uint32_t, int>> filenameCounts;
    GetFileListArgs args;
    args.set_include_deleted(false);

    size_t success_threshold = std::min(2 * numMalicious_ + 1, numServers_ - numMalicious_);
    size_t accept_threshold = success_threshold - numMalicious_;
    bool ret = QueryServers<GetFileListReply>(
        QueryServers_(), args, &Filesys::Stub::AsyncGetFileList,
        success_threshold, 100ms, timeout_,
        [&](const std::vector<AsyncResponse<GetFileListReply>> &responses,
            const std::vector<uint8_t> &replied,
            size_t &minimum_success) -> bool {
            for (size_t i = 0; i < responses.size(); ++i) {
                if (!replied[i] || !responses[i].status.ok()) continue;
                auto &reply = responses[i].reply;
                /*
                 * Keep track of the unique filenames returned by a server
                 * because a malicious server could return the same filename
                 * more than once.
                 */
                std::unordered_map<std::string, uint32_t> uniqueFilenames;

                for (const FileInfo &fileInfo : reply.files()) {
                    // verify signature
                    if (!VerifyUpdateSignature(fileInfo.last_update(), fileInfo.file_name(),
                                               fileInfo.public_key())) {
                        spdlog::warn("Invalid signature for file {}", fileInfo.file_name());
                        continue;
                    }
                    if (fileInfo.start_version() > fileInfo.last_update().version()) {
                        spdlog::warn("Invalid version for file {}", fileInfo.file_name());
                        continue;
                    }
                    std::string filename = fileInfo.file_name();
                    uniqueFilenames.emplace(fileInfo.file_name(), fileInfo.start_version());
                }

                for (auto&[filename, version] : uniqueFilenames) {
                    ++filenameCounts[filename][version];
                }
            }
            return true;
        },
        "GetFileList");
    if (!ret) {
        throw std::runtime_error("Failed to get file list");
    }

    /*
     * Only consider version with more than accept_threshold replies.
     */
    std::unordered_set<std::string> fileList;
    for (const auto &[filename, lst] : filenameCounts) {
        for (auto& [_, count] : lst) {
            if ((size_t)count > accept_threshold) {
                fileList.insert(filename);
                break;
            }
        }
    }

    return fileList;
}

int BFRFileSystem::create(const std::string& path) const {
    if (path.size() <= prefix_.size() || path.substr(0, prefix_.size()) != prefix_) {
        return -EINVAL;
    }
    const std::optional<FileMetadata> metadata = QueryMetadata_(path, true);
    uint32_t version = 0;
    if (metadata.has_value()) {
        if (!metadata.value().isDeleted) {
            return -EEXIST;
        }
        version = metadata.value().version + 1;
    }

    CreateFileArgs args;
    args.set_file_name(path);
    args.set_version(version);
    args.set_version_signature(BytesToStr(
        SignUpdate(signingKey_, path, 0, 0, version, false)));

    auto servers = QueryServers_();
    for (int i = 0; i < NUM_RETRIES; i++) {
        size_t success_threshold = servers.size() - numFaulty_ + numMalicious_;
        std::vector<uint8_t> success = std::vector<uint8_t>(servers.size(), 0);
        const bool createSuccess = QueryServers<Empty>(
            QueryServers_(), args, &Filesys::Stub::AsyncCreateFile,
            1, 0s, timeout_,
            [&](const std::vector<AsyncResponse<Empty>> &responses,
                const std::vector<uint8_t> &replied,
                size_t &minimum_success) -> bool {
                size_t num_success = 0;
                for (size_t i = 0; i < responses.size(); ++i) {
                    if (replied[i] && responses[i].status.ok()) {
                        success[i] = 1;
                        num_success++;
                    }
                }
                return num_success >= success_threshold;
            }, "Create");
        if (createSuccess) {
            return 0;
        }
        for (int i = 0; i < numServers_; ++i) {
            if (success[i]) servers[i] = nullptr;
        }
        std::erase(servers, nullptr);
    }

    return -EIO;
}

std::optional<FileMetadata> BFRFileSystem::open(const std::string& path) const {
    return QueryMetadata_(path, false);
}

int64_t BFRFileSystem::read(const std::string& path, char *buf, size_t size,
                            off_t offset) const {
    const std::optional<FileMetadata> metadata = this->open(path);
    if (metadata.has_value()) {
        const uint64_t filesize = metadata.value().fileSize;
        if (offset > (int64_t)filesize) {
            /* Can't read past EOF. */
            return 0;
        }
        if (offset + size > filesize) {
            /* Trim read size if exceeds filesize. */
            size = filesize - offset;
        }
    } else {
        /* File doesn't exist. */
        return -ENOENT;
    }
    if (size == 0) return 0;

    const uint64_t startOffset = roundDown(offset, stripeSize_);
    const uint64_t startStripeId = startOffset / stripeSize_;
    const uint64_t offsetDiff = offset - startOffset;

    const uint64_t endOffset = roundUp(offset + size, stripeSize_);
    const uint64_t endStripeId = endOffset / stripeSize_;
    spdlog::debug("{} {} start{} {}, end {} {}", size, offset, startOffset,
                  startStripeId, endOffset, endStripeId);

    const uint64_t numStripes = endStripeId - startStripeId;
    const uint32_t version = metadata.value().version;

    if (!version) {
        return 0;
    }

    ReadBlocksArgs args;
    filesys::StripeRange *range = args.add_stripe_ranges();
    args.set_file_name(path);
    range->set_offset(startStripeId);
    range->set_count(numStripes);
    args.set_version(version);

    /*
     * Outer vector represents stripes.
     * Inner vector represents the blocks within a stripe.
     * A single block is represented by a Bytes object.
     */
    std::vector<std::vector<Bytes>> encodedBlocks(
        numStripes, std::vector<Bytes>(numServers_));
    /*spdlog::debug("outside {}", (void *)&encodedBlocks);
    spdlog::debug("outside {} {}", numStripes, encodedBlocks.size());*/

    bool ret = QueryServers<ReadBlocksReply>(
        QueryServers_(), args, &Filesys::Stub::AsyncReadBlocks,
        numServers_ - numFaulty_, 100ms, timeout_,
        [&](const std::vector<AsyncResponse<ReadBlocksReply>> &responses,
            const std::vector<uint8_t> &replied,
            size_t &minimum_success) -> bool {
            /*spdlog::debug("inside {}", (void *)&encodedBlocks);
            spdlog::debug("inside {}", encodedBlocks.size());*/
            size_t num_success = 0;
            for (size_t i = 0; i < responses.size(); ++i) {
                if (!encodedBlocks[0][i].empty() || !replied[i] ||
                    !responses[i].status.ok())
                    continue;
                auto &reply = responses[i].reply;
                spdlog::debug("{} version {}", reply.block_data(0).size(),
                              reply.version());
                if (reply.block_data(0).size() != numStripes * blockSize_ ||
                    reply.version() != version)
                    continue;

                const Bytes blocks(reply.block_data(0).begin(),
                                   reply.block_data(0).end());
                for (size_t stripeOffset = 0; stripeOffset < numStripes;
                     ++stripeOffset) {
                    encodedBlocks[stripeOffset][i] = Bytes(
                        blocks.begin() + (stripeOffset * blockSize_),
                        blocks.begin() + ((stripeOffset + 1) * blockSize_));
                }
                num_success++;
            }

            try {
                Bytes bytesRead;
                for (size_t stripeOffset = 0; stripeOffset < numStripes;
                     ++stripeOffset) {
                    const std::vector<Bytes> stripe =
                        encodedBlocks[stripeOffset];
                    /*spdlog::debug("{}, {}, {}", stripeOffset,
                                  encodedBlocks.size(), stripe);*/
                    const uint64_t stripeId = startStripeId + stripeOffset;
                    // spdlog::debug("Decode {}, {}, {}, {}, {}, {}, {}",
                    //               stripeSize_, numServers_, numFaulty_,
                    //               signingKey_.PublicKey(), path, stripeId,
                    //               version);
                    const Bytes decodedStripe =
                        Decode(stripe, stripeSize_, numServers_, numFaulty_,
                               signingKey_, path, stripeId, version);
                    bytesRead.insert(bytesRead.end(), decodedStripe.begin(),
                                     decodedStripe.end());
                }
                memcpy(buf, bytesRead.data() + offsetDiff, size);
            } catch (DecodeError &e) {
                spdlog::info("Decode error: {} {} {}", e.what(),
                             e.remaining_blocks, num_success);
                minimum_success = num_success + e.remaining_blocks;
                return false;
            }
            return true;
        },
        "Read");

    // TODO (optional): retry if failed because version too old?

    if (!ret) return -EIO;
    return size;
}

int64_t BFRFileSystem::write(const std::string& path, const char *buf,
                             const size_t size, const off_t offset) const {
    /* Open file to get metadata. */
    const std::optional<FileMetadata> metadata = this->open(path);
    if (!metadata.has_value()) {
        return -ENOENT;
    }

    /* Fist calculate the stripes to read. */
    const uint64_t startOffset = roundDown(offset, stripeSize_);
    const uint64_t startStripeId = startOffset / stripeSize_;
    const uint64_t offsetDiff = offset - startOffset;

    const uint64_t endOffset = roundUp(offset + size, stripeSize_);
    const uint64_t endStripeId = endOffset / stripeSize_;

    const uint64_t numStripes = endStripeId - startStripeId;
    if (numStripes == 0) return 0;

    const uint64_t stripesBufSize = numStripes * stripeSize_;

    Bytes stripesBuf(stripesBufSize, 0);

    /* Read the stripes. */
    // TODO: only read the first and the last block
    const int64_t bytesRead =
        this->read(path, reinterpret_cast<char*>(stripesBuf.data()), stripesBufSize, startOffset);
    if (bytesRead < 0) {
        return -EIO;
    }

    /* Write the desired bytes onto the read stripes. */
    std::memcpy(stripesBuf.data() + offsetDiff, buf, size);

    /* Generate requests */
    const uint32_t newVersion = metadata.value().version + 1;
    const uint64_t newFilesize = (offset + size > metadata.value().fileSize)
                                     ? offset + size
                                     : metadata.value().fileSize;
    std::vector<WriteBlocksArgs> requests(numServers_);

    std::string update_signature = BytesToStr(
        SignUpdate(signingKey_, path, startStripeId, numStripes, newVersion, false));
    for (auto& i : requests) {
        i.set_file_name(path);
        i.mutable_block_data()->resize(blockSize_ * numStripes);
        filesys::UpdateMetadata* update_metadata = i.mutable_metadata();
        update_metadata->set_file_size(newFilesize);
        update_metadata->set_version(newVersion);
        filesys::StripeRange *range = update_metadata->mutable_stripe_range();
        range->set_offset(startStripeId);
        range->set_count(numStripes);
        update_metadata->set_version_signature(update_signature);
    }

    for (uint64_t stripeOffset = 0; stripeOffset < numStripes; ++stripeOffset) {
        /* Encode each stripe. */
        const size_t stripeId = startStripeId + stripeOffset;
        Bytes rawStripe(stripesBuf.data() + (stripeOffset * stripeSize_),
                        stripesBuf.data() + ((stripeOffset + 1) * stripeSize_));
        // spdlog::debug("Encode {}, {}, {}, {}, {}, {}, {}", rawStripe,
        //               numServers_, numFaulty_, signingKey_.PublicKey(), path,
        //               stripeId, newVersion);
        std::vector<Bytes> encodedStripe =
            Encode(rawStripe, numServers_, numFaulty_, signingKey_, path,
                   stripeId, newVersion);
        for (size_t serverId = 0; serverId < encodedStripe.size(); ++serverId) {
            /* Assign a block from each stripe to its corresponding server. */
            memcpy(requests[serverId].mutable_block_data()->data() + (stripeOffset * blockSize_),
                   encodedStripe[serverId].data(), blockSize_);
        }
    }
    Bytes().swap(stripesBuf);

    auto servers = QueryServers_();
    for (int i = 0; i < NUM_RETRIES; i++) {
        size_t success_threshold = servers.size() - numFaulty_ + numMalicious_;
        std::vector<uint8_t> success = std::vector<uint8_t>(servers.size(), 0);
        const bool writeSuccess = QueryServers<Empty>(
            QueryServers_(), requests, &Filesys::Stub::AsyncWriteBlocks,
            1, 0s, timeout_,
            [&](const std::vector<AsyncResponse<Empty>> &responses,
                const std::vector<uint8_t> &replied,
                size_t &minimum_success) -> bool {
                size_t num_success = 0;
                for (size_t i = 0; i < responses.size(); ++i) {
                    if (replied[i] && responses[i].status.ok()) {
                        success[i] = 1;
                        num_success++;
                    }
                }
                return num_success >= success_threshold;
            }, "Write");
        if (writeSuccess) {
            return 0;
        }
        for (int i = 0; i < numServers_; ++i) {
            if (success[i]) {
                servers[i] = nullptr;
                requests[i].clear_block_data();
            }
        }
        std::erase(servers, nullptr);
        std::erase_if(requests, [](const auto& x) { return x.block_data().empty(); });
    }

    return -EIO;
}

int BFRFileSystem::unlink(const std::string& path) const {
    /* Open file to get metadata. */
    const std::optional<FileMetadata> metadata = this->open(path);
    if (!metadata.has_value()) {
        return -ENOENT;
    }

    const uint32_t newVersion = metadata.value().version + 1;

    DeleteFileArgs args;
    args.set_file_name(path);
    args.set_version(newVersion);
    args.set_version_signature(BytesToStr(
        SignUpdate(signingKey_, path, 0, 0, newVersion, true)));

    const bool deleteSuccess = QueryServers<Empty>(
        QueryServers_(), args, &Filesys::Stub::AsyncDeleteFile,
        numServers_ - numFaulty_ + numMalicious_, 100ms, timeout_,
        [&](const std::vector<AsyncResponse<Empty>> &responses,
            const std::vector<uint8_t> &replied,
            size_t &minimum_success) -> bool { return true; },
        "Delete");

    return deleteSuccess ? 0 : -EIO;
}
