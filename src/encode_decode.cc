#include "encode_decode.h"

#include <cstring>
#include "reed_solomon.h"

namespace {

constexpr void IntToBytes(uint64_t x, uint8_t ret[]) {
  ret[0] = x;       ret[1] = x >> 8;  ret[2] = x >> 16; ret[3] = x >> 24;
  ret[4] = x >> 32; ret[5] = x >> 40; ret[6] = x >> 48; ret[7] = x >> 56;
}

Bytes GenerateMetadata(const std::string& filename, size_t stripe_id, int version) {
  Bytes ret(16 + filename.size());
  IntToBytes(stripe_id, ret.data());
  IntToBytes(version, ret.data() + 8);
  memcpy(ret.data() + 16, filename.data(), filename.size());
  return ret;
}

} // namespace

std::vector<Bytes> Encode(
    const Bytes& raw_stripe, int n, int d, const SigningKey& private_key,
    const std::string& filename, size_t stripe_id, int version) {
  if (n > 255) {
    throw std::invalid_argument("n > 255 not implemented");
  }
  size_t stride = n - d;
  if (raw_stripe.size() % stride != 0) {
    throw std::length_error("stripe size must be multiples of n-d");
  }
  size_t block_size = raw_stripe.size() / stride;
  Bytes metadata = GenerateMetadata(filename, stripe_id, version);

  auto blocks = RSEncode(n, d, block_size, raw_stripe.data());
  for (auto& block : blocks) block.resize(block_size + 1 + metadata.size());

  // signing loop
  for (int block_id = 0; block_id < n; block_id++) {
    Bytes& block = blocks[block_id];
    // signed data: concat(block, block_id, metadata)
    block[block_size] = block_id; // block_id \in [0,255)
    memcpy(block.data() + block_size + 1, metadata.data(), metadata.size());
    Bytes signature = private_key.Sign(block);
    // remove metadata and append signature to block
    block.resize(block_size + signature.size());
    memcpy(block.data() + block_size, signature.data(), signature.size());
  }
  return blocks;
}

Bytes Decode(
    const std::vector<Bytes>& blocks, size_t raw_stripe_size, int n, int d, const SigningKey& public_key,
    const std::string& filename, size_t stripe_id, int version) {
  if (n > 255) {
    throw std::invalid_argument("n > 255 not implemented");
  }
  if ((int)blocks.size() != n) {
    throw std::invalid_argument("block count incorrect");
  }
  size_t stride = n - d;
  if (raw_stripe_size % stride != 0) {
    throw std::length_error("stripe size must be multiples of n-d");
  }
  size_t block_size = raw_stripe_size / stride;
  size_t expected_block_size = block_size + SigningKey::kSignatureSize;
  Bytes metadata = GenerateMetadata(filename, stripe_id, version);

  std::vector<uint8_t> is_err(n, true);
  { // signature verification
    // signed data: concat(block, block_id, metadata)
    int num_correct = 0;
    Bytes validate_buffer(block_size + 1 + metadata.size());
    memcpy(validate_buffer.data() + block_size + 1, metadata.data(), metadata.size());
    for (int block_id = 0; block_id < n && block_id - num_correct <= d; block_id++) {
      const Bytes& block = blocks[block_id];
      if (block.size() != expected_block_size) continue;
      memcpy(validate_buffer.data(), block.data(), block_size);
      validate_buffer[block_size] = block_id;
      if (public_key.Verify(validate_buffer.data(), validate_buffer.size(), block.data() + block_size)) {
        is_err[block_id] = false;
        num_correct++;
      }
    }
    if (n - num_correct > d) throw DecodeError("Too many invalid blocks");
  }

  Bytes ret(raw_stripe_size);
  if (!RSDecode(n, d, block_size, blocks, (const bool*)is_err.data(), ret.data())) {
    throw std::runtime_error("unexpected decode error");
  }
  return ret;
}

bool VerifyBlock(
    const Bytes& block, int block_id, const SigningKey& public_key,
    const std::string& filename, size_t stripe_id, int version) {
  size_t block_size = block.size() - SigningKey::kSignatureSize;
  Bytes metadata = GenerateMetadata(filename, stripe_id, version);

  Bytes validate_buffer(block_size + 1 + metadata.size());
  memcpy(validate_buffer.data(), block.data(), block_size);
  validate_buffer[block_size] = block_id;
  memcpy(validate_buffer.data() + block_size + 1, metadata.data(), metadata.size());
  return public_key.Verify(validate_buffer.data(), validate_buffer.size(), block.data() + block_size);
}
