#pragma once

#include <cstdint>
#include <vector>
#include "bytes.h"

std::vector<Bytes> RSEncode(uint8_t N, uint8_t D, size_t blocks, const uint8_t in[]);
bool RSDecode(uint8_t N, uint8_t D, size_t blocks, const std::vector<Bytes>& in,
              const bool err[], uint8_t out[]);
bool RSReconstruct(uint8_t N, uint8_t D, size_t blocks, const std::vector<Bytes>& in,
                   const bool err[], uint8_t block_id, uint8_t out[]);
