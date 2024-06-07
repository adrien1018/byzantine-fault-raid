#pragma once

#include "filesys.grpc.pb.h"
#include "encode_decode.h"

inline bool VerifyUpdateSignature(
    const filesys::UpdateMetadata& metadata, const std::string& filename,
    const Bytes& public_key) {
  if (public_key != GetPublicKeyFromPath(filename)) {
    return false;
  }
  return VerifyUpdate(StrToBytes(metadata.version_signature()), 
                      SigningKey(public_key, false), filename,
                      metadata.stripe_range().offset(), metadata.stripe_range().count(),
                      metadata.version(), metadata.is_delete());
}

inline bool VerifyUpdateSignature(
    const filesys::UpdateMetadata& metadata, const std::string& filename,
    const std::string& public_key) {
  return VerifyUpdateSignature(metadata, filename, StrToBytes(public_key));
}

struct ReadRange {
  uint64_t offset;
  uint64_t count;
  char* out;
};

// num_malicious & reconstruct_server only used in reconstruction
std::vector<int64_t> MultiReadOrReconstruct(
    std::vector<filesys::Filesys::Stub*> peers,
    const std::string& filename, size_t file_size,
    std::vector<ReadRange>&& ranges, uint32_t version,
    uint32_t num_faulty, uint64_t block_size,
    const std::chrono::microseconds& timeout,
    int num_malicious = 0, int reconstruct_server = -1);
