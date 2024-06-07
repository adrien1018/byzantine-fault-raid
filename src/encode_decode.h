#pragma once

#include <stdexcept>

#include "signature.h"

struct DecodeError : public std::runtime_error {
  size_t remaining_blocks;
  DecodeError(size_t remaining_blocks, const std::string& msg = "") :
      std::runtime_error(msg), remaining_blocks(remaining_blocks) {}
};

std::vector<Bytes> Encode(const Bytes& raw_stripe, int n, int d,
                          const SigningKey& private_key,
                          const std::string& filename, size_t stripe_id,
                          int version);

// pass empty vector for missing blocks
// raw_stripe_size is raw_stripe.size() passed to Encode()
Bytes Decode(const std::vector<Bytes>& blocks, size_t raw_stripe_size, int n,
             int d, const SigningKey& public_key, const std::string& filename,
             size_t stripe_id, int version);

Bytes Reconstruct(const std::vector<Bytes>& blocks, size_t raw_stripe_size, int n,
                  int d, int p, int block_id, const SigningKey& public_key,
                  const std::string& filename, size_t stripe_id, int version);

bool VerifyBlock(const Bytes& block, int n, int block_id, const SigningKey& public_key,
                 const std::string& filename, size_t stripe_id, int version);

Bytes SignUpdate(const SigningKey& private_key, const std::string& filename,
                 size_t stripe_offset, size_t stripe_num, int version, bool is_delete);
bool VerifyUpdate(const Bytes& sig, const SigningKey& public_key, const std::string& filename,
                  size_t stripe_offset, size_t stripe_num, int version, bool is_delete);

inline size_t GetStripeSize(size_t block_size, int n, int d) {
  return (block_size - (n * SigningKey::kSignatureSize)) * (n - d);
}
