#include <grpcpp/grpcpp.h>

#include "BFRFileSystem.h"
#include "encode_decode.h"
#include "signature.h"
#include "spdlog/spdlog.h"
#include "filesys.grpc.pb.h"

using filesys::CreateFileArgs;
using filesys::DeleteFileArgs;
using filesys::FileInfo;
using filesys::GetFileListArgs;
using filesys::GetFileListReply;
using filesys::ReadBlocksReply;
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

template <class T>
struct AsyncResponse {
    Status status;
    T reply;
};

/*
 * Rounds down a number to the closest specified multiple.
 */
static uint64_t roundDown(const uint64_t numToRound, const uint64_t multiple)
{
    return (numToRound / multiple) * multiple;
}

/*
 * Rounds up a number to the closest specified multiple.
 * Only works with positive numbers.
 * Source: https://stackoverflow.com/questions/3407012/rounding-up-to-the-nearest-multiple-of-a-number
 */
static uint64_t roundUp(const uint64_t numToRound, const uint64_t multiple)
{
    if (multiple == 0)
    {
        return numToRound;
    }

    const uint64_t remainder = numToRound % multiple;
    if (remainder == 0)
    {
        return numToRound;
    }

    return numToRound + multiple - remainder;
}

BFRFileSystem::BFRFileSystem(const std::vector<std::string> &serverAddresses,
                             const int numMalicious, const int numFaulty,
                             const int blockSize)
{
    for (const std::string &address : serverAddresses)
    {
        std::shared_ptr<Channel> channel
            = CreateChannel(address, InsecureChannelCredentials());
        servers_.emplace_back(Filesys::NewStub(channel));
    }
    numServers_ = serverAddresses.size();
    numMalicious_ = numMalicious;
    numFaulty_ = numFaulty;
    blockSize_ = blockSize;
    stripeSize_ = (blockSize - sizeof(SigningKey::kSignatureSize)) * (numServers_ - numFaulty_);
    // TODO: Add option to read key from file
    timeout_ = 10; /* Seconds. */
}

std::unordered_set<std::string> BFRFileSystem::getFileList() const
{
    std::unordered_map<std::string, int> filenameCounts;

    ClientContext context;
    const std::chrono::system_clock::time_point deadline
        = std::chrono::system_clock::now() + std::chrono::seconds(timeout_);
    context.set_deadline(deadline);

    GetFileListArgs args;
    args.set_metadata(true);
    args.set_include_deleted(false);

    CompletionQueue cq;

    std::vector<AsyncResponse<GetFileListReply>> responseBuffer(numServers_);

    for (size_t serverId = 0; serverId < numServers_; ++serverId)
    {
        std::unique_ptr<ClientAsyncResponseReader<GetFileListReply>> responseHeader
            = servers_[serverId]->PrepareAsyncGetFileList(&context, args, &cq);
        responseHeader->StartCall();
        responseHeader->Finish(&responseBuffer[serverId].reply,
                               &responseBuffer[serverId].status,
                               (void *) serverId);
    }

    void *tag;
    bool ok = false;
    int successCount = 0;
    while (cq.Next(&tag, &ok))
    {
        const size_t serverId = (size_t) tag;
        AsyncResponse<GetFileListReply> *reply = &responseBuffer[serverId];
        if (reply->status.ok())
        {
            /*
             * Keep track of the unique filenames returned by a server because
             * a malicious server could return the same filename more than
             * once.
             */
            std::unordered_set<std::string> uniqueFilenames;

            for (const FileInfo &fileInfo : reply->reply.files())
            {
                std::string filename = fileInfo.file_name();
                uniqueFilenames.insert(filename);
            }

            for (const std::string &filename : uniqueFilenames)
            {
                ++filenameCounts[filename];
            }

            spdlog::info("Get file list from server {} success", serverId);

            ++successCount;
            if (successCount >= numServers_ - numFaulty_)
            {
                /* Sufficient servers responded with their file lists. */
                cq.Shutdown();
                break;
            }
        }
        else
        {
            spdlog::warn("Get file list from server {} FAILED", serverId);
        }
    }

    /*
     * Only consider filenames most common filenames
     * (those reported by honest servers).
     */
    std::unordered_set<std::string> fileList;
    for (const auto &[filename, count] : filenameCounts)
    {
        if (count > numMalicious_)
        {
            fileList.insert(filename);
        }
    }

    return fileList;
}

int BFRFileSystem::create(const char *path) const
{
    ClientContext context;
    const std::chrono::system_clock::time_point deadline
        = std::chrono::system_clock::now() + std::chrono::seconds(timeout_);
    context.set_deadline(deadline);

    CreateFileArgs args;
    args.set_file_name(path);
    const Bytes publicKey = signingKey_.PublicKey();
    args.set_public_key(std::string(publicKey.begin(), publicKey.end()));

    CompletionQueue cq;

    std::vector<AsyncResponse<Empty>> responseBuffer(numServers_);

    for (size_t serverId = 0; serverId < numServers_; ++serverId)
    {
        std::unique_ptr<ClientAsyncResponseReader<Empty>> responseHeader
            = servers_[serverId]->PrepareAsyncCreateFile(&context, args, &cq);
        responseHeader->StartCall();
        responseHeader->Finish(&responseBuffer[serverId].reply,
                               &responseBuffer[serverId].status,
                               (void *) serverId);
    }

    void *tag;
    bool ok = false;
    int successCount = 0;
    
    while (cq.Next(&tag, &ok))
    {
        const size_t serverId = (size_t) tag;
        const AsyncResponse<Empty> *reply = &responseBuffer[serverId];
        if (reply->status.ok())
        {
            ++successCount;
            spdlog::info("Create {} on server {} success", serverId, path);

            if (successCount >= numServers_ - numFaulty_ + numMalicious_)
            {
                /* Sufficient servers successfully acknowledged create. */
                cq.Shutdown();
                return 0;
            }
        }
        else
        {
            spdlog::warn("Create {} on server {} FAILED ({}: {})",
                         path,
                         serverId,
                         static_cast<int>(reply->status.error_code()), // fmt doesn't like enums
                         reply->status.error_message());
        }
    }

    return -EEXIST;
}

std::optional<FileMetadata> BFRFileSystem::open(const char *path) const
{
    ClientContext context;
    const std::chrono::system_clock::time_point deadline
        = std::chrono::system_clock::now() + std::chrono::seconds(timeout_);
    context.set_deadline(deadline);

    GetFileListArgs args;
    args.set_metadata(true);
    args.set_file_name(path);
    args.set_include_deleted(false);

    CompletionQueue cq;

    std::vector<AsyncResponse<GetFileListReply>> responseBuffer(numServers_);
    for (size_t serverId = 0; serverId < numServers_; ++serverId)
    {
        std::unique_ptr<ClientAsyncResponseReader<GetFileListReply>>
            responseHeader = servers_[serverId]->PrepareAsyncGetFileList(&context, args, &cq);
        responseHeader->StartCall();
        responseHeader->Finish(&responseBuffer[serverId].reply,
                               &responseBuffer[serverId].status,
                               (void *) serverId);
    }

    std::unordered_map<FileMetadata, int> metadataCounts;

    void *tag;
    bool ok = false;
    int successCount = 0;

    while (cq.Next(&tag, &ok))
    {
        const size_t serverId = (size_t) tag;
        AsyncResponse<GetFileListReply> *reply = &responseBuffer[serverId];
        if (reply->status.ok())
        {
            const FileMetadata m = {
                .version = reply->reply.files(0).version(),
                .fileSize = reply->reply.files(0).metadata().file_size()
            };
            ++metadataCounts[m];

            spdlog::info("Get {} metadata on server {} success", path, serverId);

            ++successCount;
            if (successCount >= numServers_ - numFaulty_)
            {
                cq.Shutdown();
                break;
            }
        }
        else
        {
            spdlog::warn("Get {} metadata on server {} FAILED", path, serverId);
        }
    }

    const auto commonMetadata = std::max_element(
        std::begin(metadataCounts),
        std::end(metadataCounts),
        [] (const std::pair<FileMetadata, int> &p1,
            const std::pair<FileMetadata, int> &p2)
        {
            return p1.second < p2.second;
        }
    );

    if (commonMetadata->second > numFaulty_)
    {
        /* Sufficient servers responded with the same metadata. */
        return commonMetadata->first;
    }
    else
    {
        return std::nullopt;
    }
}

int BFRFileSystem::read(const char *path, char *buf, size_t size,
                        off_t offset) const
{
    const std::optional<FileMetadata> metadata = this->open(path);
    if (metadata.has_value())
    {
        const uint64_t filesize = metadata.value().fileSize;
        if (offset > filesize)
        {
            /* Can't read past EOF. */
            return 0;
        }
        if (offset + size > filesize) {
            /* Trim read size if exceeds filesize. */
            size = filesize - offset;
        }
    }
    else
    {
        /* File doesn't exist. */
        return -ENOENT;
    }

    ClientContext context;
    const std::chrono::system_clock::time_point deadline
        = std::chrono::system_clock::now() + std::chrono::seconds(timeout_);
    context.set_deadline(deadline);

    const uint64_t startOffset = roundDown(offset, stripeSize_);
    const uint64_t startStripeId = startOffset / stripeSize_;
    const uint64_t offsetDiff = offset - startOffset;

    const uint64_t endOffset = roundUp(offset + size, stripeSize_);
    const uint64_t endStripeId = endOffset / stripeSize_;

    const uint64_t numStripes = endStripeId - startStripeId;

    ReadBlocksArgs args;
    args.set_file_name(path);
    args.set_stripe_offset(startStripeId);
    args.set_num_stripes(numStripes);
    args.set_version(metadata.value().version);

    CompletionQueue cq;
    std::vector<AsyncResponse<ReadBlocksReply>> responseBuffer(numServers_);

    for (size_t serverId = 0; serverId < numServers_; ++serverId)
    {
        std::unique_ptr<ClientAsyncResponseReader<ReadBlocksReply>> responseHeader
            = servers_[serverId]->PrepareAsyncReadBlocks(&context, args, &cq);
        responseHeader->StartCall();
        responseHeader->Finish(&responseBuffer[serverId].reply,
                               &responseBuffer[serverId].status,
                               (void *) serverId);
    }

    /*
     * Outer vector represents stripes.
     * Inner vector represents the blocks within a stripe.
     * A single block is represented by a Bytes object.
     */
    std::vector<std::vector<Bytes>> encodedBlocks(
        numStripes,
        std::vector<Bytes>(numServers_, std::vector<uint8_t>(blockSize_, 0))
    );

    void *tag;
    bool ok = false;
    int successCount = 0;

    while (cq.Next(&tag, &ok))
    {
        const size_t serverId = (size_t) tag;
        const AsyncResponse<ReadBlocksReply> *reply = &responseBuffer[serverId];
        if (reply->status.ok())
        {
            // concatenation of blocks
            const Bytes blocks(reply->reply.block_data().begin(),
                               reply->reply.block_data().end());
            if (blocks.size() == numStripes * blockSize_)
            {
                for (size_t stripeOffset = 0; stripeOffset < numStripes; ++stripeOffset)
                {
                    const Bytes::const_iterator first
                        = blocks.begin() + (stripeOffset * blockSize_);
                    const Bytes::const_iterator last
                        = blocks.begin() + ((stripeOffset + 1) + blockSize_);
                    const Bytes block(first, last);
                    encodedBlocks[stripeOffset][serverId] = block;
                }
            }

            spdlog::info("Read blocks success");

            ++successCount;
            if (successCount >= numServers_ - numFaulty_)
            {
                /* Sufficient servers provided blocks. */
                cq.Shutdown();
                break;
            }
        }
        else
        {
            spdlog::warn("Read blocks failed");
        }
    }

    Bytes bytesRead;

    for (size_t stripeOffset = 0; stripeOffset < numStripes; ++stripeOffset)
    {
        const std::vector<Bytes> stripe = encodedBlocks[stripeOffset];
        const int stripeId = startStripeId + stripeOffset;
        const Bytes decodedStripe = Decode(stripe, stripeSize_, numServers_,
                                           numFaulty_, signingKey_, path, stripeId,
                                           metadata.value().version);
        bytesRead.insert(std::end(bytesRead),
                         std::begin(decodedStripe),
                         std::end(decodedStripe)); 
    }

    std::copy(bytesRead.begin() + offsetDiff, bytesRead.end(), buf);

    return size;
}

int BFRFileSystem::write(const char *path, const char *buf, const size_t size,
                         const off_t offset) const
{
    /* Open file to get metadata. */
    const std::optional<FileMetadata> metadata = this->open(path);
    if (!metadata.has_value())
    {
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
    char *stripesBuf = (char *) std::malloc(stripesBufSize);
    if (stripesBuf == nullptr)
    {
        return -ENOMEM;
    }

    /* Read the stripes. */
    const int bytesRead = this->read(path, stripesBuf, stripesBufSize, startOffset);
    if (bytesRead <= 0)
    {
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
        numServers_, std::vector<Bytes>(numStripes, std::vector<uint8_t>(blockSize_, 0))
    );

    const uint32_t newVersion = metadata.value().version + 1;
    const uint64_t newFilesize = (offset + size > metadata.value().fileSize) ?
                                 offset + size :
                                 metadata.value().fileSize;

    for (int stripeOffset = 0; stripeOffset < numStripes; ++stripeOffset)
    {
        /* Encode each stripe. */
        const size_t stripeId = startStripeId + stripeOffset;
        Bytes rawStripe(stripesBuf + (stripeOffset * stripeSize_),
                        stripesBuf + ((stripeOffset + 1) * stripeSize_));
        std::vector<Bytes> encodedStripe = Encode(rawStripe, numServers_,
                                                  numFaulty_, signingKey_,
                                                  path, stripeId, newVersion);
        for (size_t serverId = 0; serverId < encodedStripe.size(); ++serverId)
        {
            /* Assign a block from each stripe to its corresponding server. */
            blocksToWrite[serverId][stripeOffset] = encodedStripe[serverId];
        }
    }

    ClientContext context;
    const std::chrono::system_clock::time_point deadline
        = std::chrono::system_clock::now() + std::chrono::seconds(timeout_);
    context.set_deadline(deadline);

    CompletionQueue cq;

    std::vector<AsyncResponse<Empty>> responseBuffer(numServers_);

    for (size_t serverId = 0; serverId < numServers_; ++serverId)
    {
        filesys::Metadata m;
        const Bytes publicKey = signingKey_.PublicKey();
        m.set_public_key(std::string(publicKey.begin(), publicKey.end()));
        m.set_file_size(newFilesize);

        WriteBlocksArgs args;
        args.set_file_name(path);
        args.set_stripe_offset(startStripeId);
        args.set_num_stripes(numStripes);
        args.set_version(newVersion);
        Bytes concatenatedBlocks;
        for (auto && block : blocksToWrite[serverId])
        {
            concatenatedBlocks.insert(concatenatedBlocks.end(),
                                      block.begin(),
                                      block.end());
        }
        args.set_block_data(std::string(concatenatedBlocks.begin(),
                                        concatenatedBlocks.end()));
        args.set_allocated_metadata(&m);

        std::unique_ptr<ClientAsyncResponseReader<Empty>> responseHeader
            = servers_[serverId]->PrepareAsyncWriteBlocks(&context, args, &cq);
        responseHeader->StartCall();
        responseHeader->Finish(&responseBuffer[serverId].reply,
                               &responseBuffer[serverId].status,
                               (void *) serverId);
    }

    void *tag;
    bool ok = false;
    int successCount = 0;

    while (cq.Next(&tag, &ok))
    {
        size_t serverId = (size_t) tag;
        if (responseBuffer[serverId].status.ok())
        {
            ++successCount;
            spdlog::info("WriteBlocks success");
            if (successCount >= numServers_ - numFaulty_ + numMalicious_)
            {
                /* Sufficient servers successfully acknowledged. */
                cq.Shutdown();
                return size;
            }
        }
        else
        {
            spdlog::warn("WriteBlocks FAILED");
        }
    }

    return -1;
}

int BFRFileSystem::unlink(const char *path) const
{
    ClientContext context;
    const std::chrono::system_clock::time_point deadline
        = std::chrono::system_clock::now() + std::chrono::seconds(timeout_);
    context.set_deadline(deadline);

    DeleteFileArgs args;
    args.set_file_name(path);

    CompletionQueue cq;

    std::vector<AsyncResponse<Empty>> responseBuffer(numServers_);

    for (size_t serverId = 0; serverId < numServers_; ++serverId)
    {
        std::unique_ptr<ClientAsyncResponseReader<Empty>> responseHeader
            = servers_[serverId]->PrepareAsyncDeleteFile(&context, args, &cq);

        responseHeader->StartCall();
        responseHeader->Finish(&responseBuffer[serverId].reply,
                               &responseBuffer[serverId].status,
                               (void *) serverId);
    }

    void *tag;
    bool ok = false;
    int successCount = 0;

    while (cq.Next(&tag, &ok))
    {
        const size_t serverId = (size_t) tag;
        const AsyncResponse<Empty> *reply = &responseBuffer[serverId];
        if (reply->status.ok())
        {
            ++successCount;
            spdlog::info("Delete {} success", path);
            if (successCount >= numServers_ - numFaulty_ + numMalicious_)
            {
                /* Sufficient servers successfully acknowledged. */
                return 0;
            }
        }
        else
        {
            spdlog::warn("Delete {} failed ({}: {})",
                         path,
                         static_cast<int>(reply->status.error_code()), // fmt doesn't like enums
                         reply->status.error_message());
        }
    }

    return -EIO;
}

