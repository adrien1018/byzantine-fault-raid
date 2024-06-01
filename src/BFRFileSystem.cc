#include "BFRFileSystem.h"
#include "encode_decode.h"
#include "signature.h"

using filesys::CreateFileArgs;
using filesys::DeleteFileArgs;
using filesys::GetFileListArgs;
using filesys::ReadBlocksReply;
using filesys::ReadBlocksArgs;
using filesys::ReadBlocksReply;
using filesys::WriteBlocksArgs;
using google::protobuf::Empty;
using grpc::Channel;
using grpc::ClientAsyncResponseReader
using grpc::ClientContext;
using grpc::CompletionQueue;
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
        std::shared_ptr<Channel> channel =
            grpc::CreateChannel(address, grpc::InsecureChannelCredentials());
        servers_.emplace_back(Filesys::NewStub(channel));
    }
    numServers_ = serverAddresses.size();
    numMalicious_ = numMalicious;
    numFaulty_ = numFaulty;
    stripeSize_ = (blockSize - sizeof(signature)) * (numServers_ - numFaulty_);
    // TODO: Add option to read key from file
    signingKey_ = new SigningKey();
    timeout_ = 10; /* Seconds. */
}

std::unordered_set<std::string> BFRFileSystem::getFileList()
{
    std::unordered_map<std::string, int> filenameCounts;

    ClientContext context;
    const std::chrono::system_clock::time_point deadline
        = std::chrono::system_clock::now() + std::chrono::seconds(timeout_);
    context.set_deadline(deadline);

    GetFileListArgs args;
    args.set_metadata(true);
    args.include_deleted(false);

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
        AsyncResponse<GetFileListReply> *reply
            = static_cast<AsyncResponse<GetFileListReply>*>(responseBuffer[serverId]);
        if (reply->status.ok())
        {
            /*
             * Keep track of the unique filenames returned by a server because
             * a malicious server could return the same filename more than
             * once.
             */
            std::unordered_set<std::string> uniqueFilenames;

            for (const FileInfo &fileInfo : reply->reply().files)
            {
                std::string filename = fileInfo.file_name;
                returnedFilenames.insert(filename);
            }

            for (const std::string &filename : uniqueFilenames)
            {
                ++filenameCounts[filename];
            }

            logger->info("Get file list from server {} success", serverId);

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
            logger->warn("Get file list from server {} FAILED", serverId);
        }
    }

    /*
     * Only consider filenames most common filenames
     * (those reported by honest servers).
     */
    std::unordered_set<std::string> fileList;
    for (const auto &[filename, count] : filenameCount)
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
    args.set_public_key(singingKey_.PublicKey());

    CompletionQueue cq;

    std::vector<AsyncResponse<Empty>> responseBuffer(numServers_);

    for (int serverId = 0; serverId < numServers_; ++serverId)
    {
        std::unique_ptr<ClientAsyncResponseReader<Empty>> responseHeader
            = servers_[i]->PrepareAsyncCreateFile(&context, args, &cq);
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
        AsyncResponse<Empty> *reply
            = static_cast<AsyncResponse<Empty>*>(responseBuffer[serverId]);
        if (reply->status.ok())
        {
            ++successCount;
            logger->info("Create {} on server {} success", serverId, path);

            if (successCount >= numServers_ - numFaulty_ + numMalicious_)
            {
                /* Sufficient servers successfully acknowledged create. */
                cq.Shutdown();
                return 0;
            }
        }
        else
        {
            logger->warn("Create {} on server {} FAILED ({}: {})",
                         path,
                         serverId,
                         reply->status.error_code(),
                         reply->status.error_message());
        }
    }

    return -EEXIST;
}

std::optional<Metadata> BFRFileSystem::open(const char *path) const
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
    for (int serverId = 0; serverId < numServers_; ++serverId)
    {
        std::unique_ptr<ClientAsyncResponseReader<GetFileListReply>>
            responseHeader = servers_[serverId]->PrepareAsyncGetFileList(&context, args, &cq);
        responseHeader->StartCall();
        responseHeader->Finish(&responseBuffer[serverId].reply,
                               &responseBuffer[serverId].status,
                               (void *) serverId);
    }

    std::unordered_set<Metadata, int> metadataCounts; // TODO: Metadata has to be hashable

    void *tag;
    bool ok = false;
    // TODO: How many servers must respond to get majority?
    while (cq.Next(&tag, &ok))
    {
        const size_t serverId = (size_t) tag;
        AsyncResponse<GetFileListReply> *reply
            = static_cast<AsyncResponse<GetFileListReply>*>(responseBuffer[serverId]);
        if (reply->status.ok())
        {
            const Metadata m = {
                .version = reply->reply.get_version();
                .filesize = reply->reply.get_filesize();
            };
            metadataCounts[m] += 1;
            logger->info("Get {} metadata on server {} success", path, serverId);
        } else {
            logger->warn("Get {} metadata on server {} FAILED", path, serverId);
        }
    }

    const auto commonMetadata = std::maxElement(
        std::begin(metadataCounts),
        std::end(metadataCounts),
        [] (const pair_type &p1, const pair_type &p2) {
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

int BFRFileSystem::read(const char *path, const char *buf, size_t size,
                        off_t offset, uint32_t &version) const
{
    const std::optional<Metadata> metadata = this.open(path);
    if (metadata.has_value())
    {
        const uint64_t filesize = metadata.value().filesize;
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

    const uint64_t endOffset = roundUp(offset + size, stripeSize_)l
    const uint64_t endStripeId = endOffset / stripeSize_;

    const uint64_t numStripes = endStripeId - startStripeId;

    ReadBlocksArgs args;
    args.set_file_name(path);
    args.set_stripe_offset(startStripeId);
    args.set_num_stripes(numStripes);
    args.set_version(metadata.value().version);

    CompletionQueue cq;
    std::vector<AsyncResponse<ReadBlocksReply>> responseBuffer(numServers_);

    for (int i = 0; i < numServers_; ++i)
    {
        std::unique_ptr<ClientAsyncResopnseReader<ReadBlocksReply>> responseHeader
            = _servers[i]->PrepareAsyncReadBlocks(&context, args, &cq);
        responseHeader->StartCall();
        responseHeader->Finish(&responseBuffer[i].reply,
                               &responseBuffer[i].status,
                               (void *) i);
    }

    /*
     * Outer vector represents stripes.
     * Inner vector represents the blocks within a stripe.
     * A single block is represented by a Bytes object.
     */
    std::vector<std::vector<Bytes>> encodedBlocks(
        numStripes,
        std::vector<Bytes>(numServers_, std::vector<uint8_t>(blockSize_, 0)
    );

    void *tag;
    bool ok = false;
    int successCount = 0;

    while (cq.Next(*tag, &ok))
    {
        const size_t serverId = (size_t) tag;
        const AsyncResponse<ReadBlocksReply> *reply =
            = static_cast<AsyncResponse<ReadBlocksReply>*>(responseBuffer[serverId]);
        if (reply->status.ok())
        {
            const Bytes blocks = reply->reply.block_data(); // concatenation of blocks
            if (blocks.size() == numStripes * blockSize_)
            {
                for (size_t stripeOffset = 0; stripeOffset < numStripes; ++stripeOffset)
                {
                    Bytes::const_iterator first = blocks.begin() + (stripeOffset * blockSize_);
                    Bytes::const_iterator last = blocks.begin() + ((stripeOffset + 1) + blockSize_);
                    Bytes block(first, last);
                    encodedBlocks[stripeOffset][serverId] = block;
                }
            }

            logger->info("Read blocks success");

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
            logger->warn("Read blocks failed");
        }
    }

    const Bytes bytesRead;

    for (size_t stripeOffset = 0; stripeOffset < numStripes; ++stripeOffset)
    {
        std::vector<Bytes> stripe = encodedBlocks[stripeOffset];
        int stripeId = startStripeId + stripeOffset;
        Bytes decodedStripe = Decode(stripe, stripeSize_, numServers_,
                                     numFaulty_, signingKey_, path, stripeId,
                                     metadata.value().version);
        bytesRead.insert(std::end(bytesRead),
                         std::begin(decodedStripe),
                         std::end(decodedStripe)); 
    }

    std::copy(bytesRead.begin() + offsetDiff, bytesRead.end(), buf);
    version = metadata.value().version;

    return size;
}

int BFRFileSystem::write(const char *path, const char *buf, const size_t size,
                         const off_t offset) const
{
    /* Fist calculate the stripes to read. */
    const uint64_t startOffset = roundDown(offset, stripeSize_);
    const uint64_t startStripeId = startOffset / stripeSize_;
    const uint64_t offsetDiff = offset - startOffset;

    const uint64_t endOffset = roundUp(offset + size, stripeSize_);
    const uint64_t endStripeId = endOffset / stripeSize_;

    const uint64_t numStripes = endStripeId - startStripeId;

    uint64_t stripesBufSize = numStripes * stripeSize;
    char *stripesBuf = malloc(stripesBufSize);
    if (stripesBuf == std::nullptr)
    {
        return -ENOMEM;
    }

    /* Read the stripes. */
    uint32_t oldVersion;
    int bytesRead = this.read(path, stripesBuf, stripesBufSize, startOffset, oldVersion);
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
        numServers_, std::vector<Bytes>(numStripes, std::vector<uint8_t, 0>)
    );

    const uint32_t newVersion = oldVersion + 1;

    for (int stripeOffset = 0; stripeOffset < numStripes, ++stripeOffset)
    {
        /* Encode each stripe. */
        const size_t stripeId = startStripeId + stripeOffset;
        Bytes rawStripe = ;
        std::vector<Bytes> encodedStripe = Encode(rawStripe, numServers_,
                                                  numFaulty_, signingKey_,
                                                  path, stripeId, newVersion);
        for (int serverId = 0; serverId < encodedStripe.size(); ++serverId)
        {
            /* Assign a block from each stripe to its corresponding server. */
            blocksToWrite[serverId].insert(std::end(blocksToWrite[serverId]),
                                           std::begin(encodedStripe[serverId]),
                                           std::end(encodedStripe[serverId]));
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
        m.set_public_key(); // TODO
        m.set_file_size(); // TODO

        WriteBlocksArgs args;
        args.set_file_name(path);
        args.set_stripe_offset(startStripeId);
        args.set_num_stripes(numStripes);
        args.set_version(newVersion);
        args.set_block_data(); // TODO
        args.set_metadata(m);

        std::unique_ptr<ClientAsyncResponseReader<Empty>> responseHeader
            = servers_[i]->PrepareAsyncWriteBlocks(&context, args, &cq);
        responseHeader->StartCall();
        responseHeader->Finish(&responseBuffer[i].reply,
                               &responseBuffer[i].status,
                               (void *) serverId);
    }

    void *tag;
    bool ok = false;
    int successCount = 0;

    while (cq.Next(&tag, &ok))
    {
        size_t serverId = (size_t) tag;
        if (responseBuffer[i].status.ok())
        {
            ++successCount;
            logger->info("WriteBlocks success");
            if (successCount >= numServers_ - numFaulty_ + numMalicious_)
            {
                /* Sufficient servers successfully acknowledged. */
                cq.Shutdown();
                return size;
            }
        }
        else
        {
            logger->warn("WriteBlocks FAILED");
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

    std::vector<AsyncResponse<Empty> responseBuffer(numServers_);

    for (int serverId = 0; serverId < numServers_; ++serverId)
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
        AsyncResponse<Empty> *reply
            = static_cast<AsyncResponse<Empty> *>(responseBuffer[serverId]);
        if (reply->status.ok())
        {
            ++successCount;
            logger->info("Delete {} success", path);
            if (successCount >= numServers_ - numFaulty_ + numMalicious_)
            {
                /* Sufficient servers successfully acknowledged. */
                return 0;
            }
        }
        else
        {
            logger->warn("Delete {} failed: {} {}",
                            path,
                            reply->status.error_status(),
                            reply->status.error_message());
        }
    }

    return -EIO;
}

