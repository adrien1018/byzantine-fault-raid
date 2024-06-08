#include "filesys_common.h"

#include "segment.h"
#include "async_query.h"
#include "encode_decode.h"

#include <spdlog/fmt/ranges.h>

struct RangeMeta {
  uint64_t startStripeId, numStripes, offsetDiff;

  RangeMeta(const ReadRange& range, uint64_t stripe_size) {
    startStripeId = range.offset / stripe_size;
    const uint64_t startOffset = startStripeId * stripe_size;
    offsetDiff = range.offset - startOffset;

    const uint64_t endStripeId = (range.offset + range.count + stripe_size - 1) / stripe_size;
    numStripes = endStripeId - startStripeId;
  }
};

void ToGRPCUpdateMetadata(filesys::UpdateMetadata& out, const UpdateMetadata& metadata) {
    out.set_version(metadata.version);
    out.mutable_stripe_range()->set_offset(metadata.stripe_offset);
    out.mutable_stripe_range()->set_count(metadata.num_stripes);
    out.set_file_size(metadata.file_size);
    out.set_is_delete(metadata.is_delete);
    out.set_version_signature(BytesToStr(metadata.signature));
}

UpdateMetadata ToUpdateMetadata(const filesys::UpdateMetadata& metadata) {
    return UpdateMetadata{
        .version = metadata.version(),
        .stripe_offset = metadata.stripe_range().offset(),
        .num_stripes = metadata.stripe_range().count(),
        .file_size = metadata.file_size(),
        .is_delete = metadata.is_delete(),
        .signature = StrToBytes(metadata.version_signature()),
    };
}

std::vector<int64_t> MultiReadOrReconstruct(
    std::vector<filesys::Filesys::Stub*> peers,
    const std::string& filename, size_t file_size,
    std::vector<ReadRange>&& ranges, uint32_t version,
    uint32_t num_faulty, uint64_t block_size,
    const std::chrono::microseconds& timeout,
    int num_malicious, int reconstruct_server) {
  const uint32_t num_servers = peers.size();
  const size_t stripe_size = GetStripeSize(block_size, num_servers, num_faulty);

  std::vector<int64_t> ret(ranges.size(), -EIO);

  filesys::ReadBlocksArgs args;
  args.set_file_name(filename);
  args.set_version(version);

  std::vector<int> idx;
  std::vector<RangeMeta> range_metas;
  std::vector<std::vector<std::vector<Bytes>>> encodedBlocks;
  for (size_t i = 0; i < ranges.size(); ++i) {
    auto& range = ranges[i];
    if (range.offset >= file_size) {
      range.count = 0;
      ret[i] = 0;
      continue;
    }
    idx.push_back(i);
    if (range.offset + range.count > file_size) {
      range.count = file_size - range.offset;
    }
    RangeMeta range_meta(range, stripe_size);

    filesys::StripeRange *stripe_range = args.add_stripe_ranges();
    stripe_range->set_offset(range_meta.startStripeId);
    stripe_range->set_count(range_meta.numStripes);

    /*
     * Outer vector represents stripes.
     * Inner vector represents the blocks within a stripe.
     * A single block is represented by a Bytes object.
     */
    encodedBlocks.emplace_back(
        range_meta.numStripes, std::vector<Bytes>(num_servers));
    range_metas.push_back(range_meta);
  }
  if (idx.empty()) return ret;

  SigningKey public_key(GetPublicKeyFromPath(filename), false);

  if (reconstruct_server != -1) {
    peers.erase(peers.begin() + reconstruct_server);
  }
  std::map<uint32_t, UpdateMetadata> update_log;
  QueryServers<filesys::ReadBlocksReply>(
      peers, args, &filesys::Filesys::Stub::AsyncReadBlocks,
      num_servers - num_faulty, 100ms, timeout,
      [&](const std::vector<AsyncResponse<filesys::ReadBlocksReply>> &responses,
          const std::vector<uint8_t> &replied,
          size_t &minimum_success) -> bool {

        /*spdlog::debug("inside {}", (void *)&encodedBlocks);
        spdlog::debug("inside {}", encodedBlocks.size());*/
        size_t num_success = 0;
        for (int i = 0; i < (int)responses.size(); i++) {
          size_t serverId = (i < reconstruct_server || reconstruct_server == -1) ? i : i + 1;
          if (!encodedBlocks.back()[0][serverId].empty() || !replied[i] || !responses[i].status.ok()) {
            continue;
          }
          auto &reply = responses[i].reply;
          if (reply.version() != version) continue;

          bool fail = false;
          for (size_t range_id = 0; range_id < idx.size(); ++range_id) {
            const uint64_t numStripes = range_metas[range_id].numStripes;
            spdlog::debug("{} version {}, {}", reply.block_data(range_id).size(),
                          reply.version(), numStripes * block_size);
            if (reply.block_data(range_id).size() != numStripes * block_size) {
              fail = true;
              break;
            }
            const auto& blocks = reply.block_data(range_id);
            for (size_t stripeOffset = 0; stripeOffset < numStripes; ++stripeOffset) {
              encodedBlocks[range_id][stripeOffset][serverId] = Bytes(
                  blocks.begin() + (stripeOffset * block_size),
                  blocks.begin() + ((stripeOffset + 1) * block_size));
            }
          }

          for (auto& update : reply.update_log()) {
            if (update_log.count(update.version())) continue;
            if (!VerifyUpdateSignature(update, filename, public_key.PublicKey())) continue;
            update_log[update.version()] = ToUpdateMetadata(update);
          }
          if (fail) continue;
          num_success++;
        }

        if (update_log.empty()) {
          spdlog::error("No valid update log");
          return false;
        }
        uint32_t prev_version = update_log.rbegin()->first;
        for (auto it = --update_log.end();; --it) {
          if (prev_version - it->second.version > 1 || it->second.file_size == 0) {
            update_log.erase(update_log.begin(), it);
            break;
          }
          if (it == update_log.begin()) break;
          prev_version = it->second.version;
        }
        std::set<Segment> segments;
        for (const auto& [version, metadata] : update_log) {
          UpdateSegments(segments, {
              metadata.stripe_offset, metadata.stripe_offset + metadata.num_stripes, version});
        }
        // for (auto& i : segments) spdlog::debug("Segment {}", i);

        std::vector<int64_t> nret = ret;
        try {
          for (size_t range_id = 0; range_id < idx.size(); ++range_id) {
            auto& range = ranges[idx[range_id]];
            const uint64_t startStripeId = range_metas[range_id].startStripeId;
            const uint64_t numStripes = range_metas[range_id].numStripes;
            const uint64_t unit = reconstruct_server == -1 ? stripe_size : block_size;
            Bytes bytesRead(numStripes * unit);
            for (size_t stripeOffset = 0; stripeOffset < numStripes; ++stripeOffset) {
              const std::vector<Bytes>& stripe = encodedBlocks[range_id][stripeOffset];
              //spdlog::debug("{}, {}, {}", stripeOffset,
              //              encodedBlocks.size(), stripe);
              const uint64_t stripeId = startStripeId + stripeOffset;
              auto update_it = segments.lower_bound({stripeId + 1, 0, 0});
              if (update_it == segments.begin() || std::get<1>(*--update_it) <= stripeId) {
                spdlog::error("No valid segment");
                return false;
              }
              uint32_t stripe_version = std::get<2>(*update_it);
              // spdlog::debug("Decode {}, {}, {}, {}, {}, {}, {}, {}",
              //               stripe_size, num_servers, num_faulty,
              //               public_key.PublicKey(), filename, stripeId, version, stripe[0]);
              if (reconstruct_server == -1) {
                const Bytes decodedStripe = Decode(
                    stripe, stripe_size, num_servers, num_faulty,
                    public_key, filename, stripeId, stripe_version);
                memcpy(bytesRead.data() + stripeOffset * stripe_size, decodedStripe.data(), stripe_size);
              } else {
                const Bytes reconstructedBlock = Reconstruct(
                    stripe, stripe_size, num_servers, num_faulty, num_malicious,
                    reconstruct_server, public_key, filename, stripeId, stripe_version);
                memcpy(bytesRead.data() + stripeOffset * block_size, reconstructedBlock.data(), block_size);
              }
            }
            if (reconstruct_server == -1) {
              memcpy(range.out, bytesRead.data() + range_metas[range_id].offsetDiff, range.count);
              nret[idx[range_id]] = range.count;
            } else {
              memcpy(range.out, bytesRead.data(), bytesRead.size());
              nret[idx[range_id]] = bytesRead.size();
            }
          }
        } catch (DecodeError &e) {
          spdlog::info("Decode error: {} {} {}", e.what(), e.remaining_blocks, num_success);
          minimum_success = num_success + e.remaining_blocks;
          return false;
        }
        ret = nret;
        return true;
      }, reconstruct_server == -1 ? "Read" : "Reconstruct");

  return ret;
}
