#include "BFRFileSystem.h"

#include <grpcpp/grpcpp.h>

#include "async_query.h"
#include "encode_decode.h"
#include "filesys.grpc.pb.h"
#include "signature.h"
#include "spdlog/spdlog.h"

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

BFRFileSystem::BFRFileSystem(const std::vector<std::string> &serverAddresses,
                             const int numMalicious, const int numFaulty,
                             const int blockSize) {
    for (const std::string &address : serverAddresses) {
        std::shared_ptr<Channel> channel =
            CreateChannel(address, InsecureChannelCredentials());
        servers_.emplace_back(Filesys::NewStub(channel));
    }
    numServers_ = serverAddresses.size();
    numMalicious_ = numMalicious;
    numFaulty_ = numFaulty;
    blockSize_ = blockSize;
    stripeSize_ = (blockSize - sizeof(SigningKey::kSignatureSize)) *
                  (numServers_ - numFaulty_);
    // TODO: Add option to read key from file
    timeout_ = 10s;
}

std::vector<Filesys::Stub *> BFRFileSystem::QueryServers_() const {
    std::vector<Filesys::Stub *> query_servers;
    for (auto &i : servers_) query_servers.push_back(i.get());
    return query_servers;
}

std::unordered_set<std::string> BFRFileSystem::getFileList() const {
    std::unordered_map<std::string, int> filenameCounts;
    GetFileListArgs args;
    args.set_metadata(true);
    args.set_include_deleted(false);

    bool ret = QueryServers<GetFileListReply>(
        QueryServers_(), args, &Filesys::Stub::PrepareAsyncGetFileList,
        numServers_ - numFaulty_, 100ms, timeout_,
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
                std::unordered_set<std::string> uniqueFilenames;

                for (const FileInfo &fileInfo : reply.files()) {
                    std::string filename = fileInfo.file_name();
                    uniqueFilenames.insert(filename);
                }

                for (const std::string &filename : uniqueFilenames) {
                    ++filenameCounts[filename];
                }
            }
            return true;
        },
        "GetFileList");

    /*
     * Only consider filenames most common filenames
     * (those reported by honest servers).
     */
    std::unordered_set<std::string> fileList;
    for (const auto &[filename, count] : filenameCounts) {
        if (count > numMalicious_) {
            fileList.insert(filename);
        }
    }

    return fileList;
}

int BFRFileSystem::create(const char *path) const {
    CreateFileArgs args;
    args.set_file_name(path);
    const Bytes publicKey = signingKey_.PublicKey();
    args.set_public_key(std::string(publicKey.begin(), publicKey.end()));

    CompletionQueue cq;

    std::vector<AsyncResponse<Empty>> responseBuffer(numServers_);

    for (size_t serverId = 0; serverId < numServers_; ++serverId) {
        ClientContext context;
        const std::chrono::system_clock::time_point deadline =
            std::chrono::system_clock::now() + timeout_;
        context.set_deadline(deadline);
        std::unique_ptr<ClientAsyncResponseReader<Empty>> responseHeader =
            servers_[serverId]->PrepareAsyncCreateFile(&context, args, &cq);
        responseHeader->StartCall();
        responseHeader->Finish(&responseBuffer[serverId].reply,
                               &responseBuffer[serverId].status,
                               (void *)serverId);
    }

    void *tag;
    bool ok = false;
    int successCount = 0;

    while (cq.Next(&tag, &ok)) {
        successCount++;
        const size_t serverId = (size_t)tag;
        const AsyncResponse<Empty> *reply = &responseBuffer[serverId];
        if (reply->status.ok()) {
            spdlog::info("Create {} on server {} success", serverId, path);
        } else {
            spdlog::warn(
                "Create {} on server {} FAILED ({}: {})", path, serverId,
                static_cast<int>(
                    reply->status.error_code()),  // fmt doesn't like enums
                reply->status.error_message());
        }

        if (successCount >= numServers_ - numFaulty_ + numMalicious_) {
            /* Sufficient servers successfully acknowledged create. */
            cq.Shutdown();
            return 0;
        }
    }

    return -EEXIST;
}

std::optional<FileMetadata> BFRFileSystem::open(const char *path) const {
    GetFileListArgs args;
    args.set_metadata(true);
    args.set_file_name(path);
    args.set_include_deleted(false);

    CompletionQueue cq;

    std::vector<AsyncResponse<GetFileListReply>> responseBuffer(numServers_);
    for (size_t serverId = 0; serverId < numServers_; ++serverId) {
        ClientContext context;
        const std::chrono::system_clock::time_point deadline =
            std::chrono::system_clock::now() + timeout_;
        context.set_deadline(deadline);
        std::unique_ptr<ClientAsyncResponseReader<GetFileListReply>>
            responseHeader = servers_[serverId]->PrepareAsyncGetFileList(
                &context, args, &cq);
        responseHeader->StartCall();
        responseHeader->Finish(&responseBuffer[serverId].reply,
                               &responseBuffer[serverId].status,
                               (void *)serverId);
    }

    std::unordered_map<FileMetadata, int> metadataCounts;

    void *tag;
    bool ok = false;
    int successCount = 0;

    while (cq.Next(&tag, &ok)) {
        ++successCount;
        const size_t serverId = (size_t)tag;
        AsyncResponse<GetFileListReply> *reply = &responseBuffer[serverId];
        if (reply->status.ok()) {
            const FileMetadata m = {
                .version = reply->reply.files()[0].version(),
                .fileSize = reply->reply.files()[0].metadata().file_size()};
            ++metadataCounts[m];

            spdlog::info("Get {} metadata on server {} success", path,
                         serverId);

        } else {
            spdlog::warn("Get {} metadata on server {} FAILED", path, serverId);
        }

        if (successCount >= numServers_ - numFaulty_) {
            cq.Shutdown();
            break;
        }
    }

    const auto commonMetadata =
        std::max_element(std::begin(metadataCounts), std::end(metadataCounts),
                         [](const std::pair<FileMetadata, int> &p1,
                            const std::pair<FileMetadata, int> &p2) {
                             return p1.second < p2.second;
                         });

    if (commonMetadata->second > numFaulty_) {
        /* Sufficient servers responded with the same metadata. */
        return commonMetadata->first;
    } else {
        return std::nullopt;
    }
}

int64_t BFRFileSystem::read(const char *path, char *buf, size_t size,
                            off_t offset) const {
    const std::optional<FileMetadata> metadata = this->open(path);
    if (metadata.has_value()) {
        const uint64_t filesize = metadata.value().fileSize;
        if (offset > filesize) {
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

    const uint64_t startOffset = roundDown(offset, stripeSize_);
    const uint64_t startStripeId = startOffset / stripeSize_;
    const uint64_t offsetDiff = offset - startOffset;

    const uint64_t endOffset = roundUp(offset + size, stripeSize_);
    const uint64_t endStripeId = endOffset / stripeSize_;

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

    bool ret = QueryServers<ReadBlocksReply>(
        QueryServers_(), args, &Filesys::Stub::PrepareAsyncReadBlocks,
        numServers_ - numFaulty_, 100ms, timeout_,
        [&](const std::vector<AsyncResponse<ReadBlocksReply>> &responses,
            const std::vector<uint8_t> &replied,
            size_t &minimum_success) -> bool {
            size_t num_success = 0;
            for (size_t i = 0; i < responses.size(); ++i) {
                if (!encodedBlocks[i].empty() || !replied[i] ||
                    !responses[i].status.ok())
                    continue;
                auto &reply = responses[i].reply;
                if (reply.block_data_size() != numStripes * blockSize_ ||
                    reply.version() != version)
                    continue;

                const Bytes blocks(reply.block_data(0).begin(),
                                   reply.block_data(0).end());
                for (size_t stripeOffset = 0; stripeOffset < numStripes;
                     ++stripeOffset) {
                    const Bytes::const_iterator first =
                        blocks.begin() + (stripeOffset * blockSize_);
                    const Bytes::const_iterator last =
                        blocks.begin() + ((stripeOffset + 1) + blockSize_);
                    encodedBlocks[stripeOffset][i] = Bytes(first, last);
                }
                num_success++;
            }

            try {
                Bytes bytesRead;
                for (size_t stripeOffset = 0; stripeOffset < numStripes;
                     ++stripeOffset) {
                    const std::vector<Bytes> stripe =
                        encodedBlocks[stripeOffset];
                    const uint64_t stripeId = startStripeId + stripeOffset;
                    const Bytes decodedStripe =
                        Decode(stripe, stripeSize_, numServers_, numFaulty_,
                               signingKey_, path, stripeId, version);
                    bytesRead.insert(bytesRead.end(), decodedStripe.begin(),
                                     decodedStripe.end());
                }
                memcpy(buf, bytesRead.data() + offsetDiff, size);
            } catch (DecodeError &e) {
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

int64_t BFRFileSystem::write(const char *path, const char *buf,
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

    const uint64_t stripesBufSize = numStripes * stripeSize_;
    char *stripesBuf = (char *)std::malloc(stripesBufSize);
    if (stripesBuf == nullptr) {
        return -ENOMEM;
    }

    /* Read the stripes. */
    const int64_t bytesRead =
        this->read(path, stripesBuf, stripesBufSize, startOffset);
    if (bytesRead < 0) {
        return -EIO;
    }

    /* Write the desired bytes onto the read stripes. */
    std::memcpy(stripesBuf + offsetDiff, buf, size);

    /*
     * Outer vector represents each server.
     * Inner vector represents each stripe.
     * Bytes object represents a block.
     */
    std::vector<std::vector<Bytes>> blocksToWrite(
        numServers_,
        std::vector<Bytes>(numStripes, std::vector<uint8_t>(blockSize_, 0)));

    const uint32_t newVersion = metadata.value().version + 1;
    const uint64_t newFilesize = (offset + size > metadata.value().fileSize)
                                     ? offset + size
                                     : metadata.value().fileSize;

    for (uint64_t stripeOffset = 0; stripeOffset < numStripes; ++stripeOffset) {
        /* Encode each stripe. */
        const size_t stripeId = startStripeId + stripeOffset;
        Bytes rawStripe(stripesBuf + (stripeOffset * stripeSize_),
                        stripesBuf + ((stripeOffset + 1) * stripeSize_));
        std::vector<Bytes> encodedStripe =
            Encode(rawStripe, numServers_, numFaulty_, signingKey_, path,
                   stripeId, newVersion);
        for (size_t serverId = 0; serverId < encodedStripe.size(); ++serverId) {
            /* Assign a block from each stripe to its corresponding server. */
            blocksToWrite[serverId][stripeOffset] = encodedStripe[serverId];
        }
    }

    CompletionQueue cq;

    std::vector<AsyncResponse<Empty>> responseBuffer(numServers_);

    for (size_t serverId = 0; serverId < numServers_; ++serverId) {
        std::cerr << "Talking to server " << serverId << std::endl;
        ClientContext context;
        const std::chrono::system_clock::time_point deadline =
            std::chrono::system_clock::now() + timeout_;
        context.set_deadline(deadline);
        WriteBlocksArgs args;
        filesys::Metadata *m = args.mutable_metadata();
        const Bytes publicKey = signingKey_.PublicKey();
        m->set_public_key(std::string(publicKey.begin(), publicKey.end()));
        m->set_file_size(newFilesize);

        filesys::StripeRange *range = args.mutable_stripe_range();
        args.set_file_name(path);
        std::cerr << "Writing " << startStripeId << ' ' << numStripes << ' '
                  << newVersion << '\n';
        range->set_offset(startStripeId);
        range->set_count(numStripes);
        args.set_version(newVersion);
        Bytes concatenatedBlocks;
        for (auto &&block : blocksToWrite[serverId]) {
            concatenatedBlocks.insert(concatenatedBlocks.end(), block.begin(),
                                      block.end());
        }
        std::cerr << "size is " << concatenatedBlocks.size() << '\n';
        args.set_block_data(
            std::string(concatenatedBlocks.begin(), concatenatedBlocks.end()));
        std::cerr << "Preparing call" << std::endl;
        std::unique_ptr<ClientAsyncResponseReader<Empty>> responseHeader =
            servers_[serverId]->PrepareAsyncWriteBlocks(&context, args, &cq);
        std::cerr << "Starting call" << std::endl;
        responseHeader->StartCall();
        std::cerr << "Finishing call" << std::endl;
        responseHeader->Finish(&responseBuffer[serverId].reply,
                               &responseBuffer[serverId].status,
                               (void *)serverId);
        std::cerr << "ending call" << std::endl;
    }

    void *tag;
    bool ok = false;
    int successCount = 0;

    std::cerr << "Waiting for responses" << std::endl;
    while (cq.Next(&tag, &ok)) {
        ++successCount;
        size_t serverId = (size_t)tag;
        std::cerr << "Got response from server " << serverId << ' ' << ok
                  << std::endl;
        if (responseBuffer[serverId].status.ok()) {
            std::cerr << "ok\n";
        } else {
            spdlog::warn("WriteBlocks FAILED");
        }

        spdlog::info("WriteBlocks success");
        if (successCount >= numServers_ - numFaulty_ + numMalicious_) {
            /* Sufficient servers successfully acknowledged. */
            cq.Shutdown();
            return size;
        }
    }

    // TODO: record which servers failed and retry in the background
    // the record should be in permanent storage so that we can recover

    return -1;
}

int BFRFileSystem::unlink(const char *path) const {
    ClientContext context;
    const std::chrono::system_clock::time_point deadline =
        std::chrono::system_clock::now() + timeout_;
    context.set_deadline(deadline);

    DeleteFileArgs args;
    args.set_file_name(path);

    CompletionQueue cq;

    std::vector<AsyncResponse<Empty>> responseBuffer(numServers_);

    for (size_t serverId = 0; serverId < numServers_; ++serverId) {
        std::unique_ptr<ClientAsyncResponseReader<Empty>> responseHeader =
            servers_[serverId]->PrepareAsyncDeleteFile(&context, args, &cq);

        responseHeader->StartCall();
        responseHeader->Finish(&responseBuffer[serverId].reply,
                               &responseBuffer[serverId].status,
                               (void *)serverId);
    }

    void *tag;
    bool ok = false;
    int successCount = 0;

    while (cq.Next(&tag, &ok)) {
        const size_t serverId = (size_t)tag;
        const AsyncResponse<Empty> *reply = &responseBuffer[serverId];
        if (reply->status.ok()) {
            ++successCount;
            spdlog::info("Delete {} success", path);
            if (successCount >= numServers_ - numFaulty_ + numMalicious_) {
                /* Sufficient servers successfully acknowledged. */
                return 0;
            }
        } else {
            spdlog::warn(
                "Delete {} failed ({}: {})", path,
                static_cast<int>(
                    reply->status.error_code()),  // fmt doesn't like enums
                reply->status.error_message());
        }
    }

    return -EIO;
}
