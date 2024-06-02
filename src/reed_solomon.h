#pragma once

#include <cstdint>
#include <vector>
#include "signature.h"

std::vector<Bytes> RSEncode(uint8_t N, uint8_t D, size_t blocks, const uint8_t in[]);
Bytes RSEncodeOneBlock(uint8_t N, uint8_t D, size_t blocks, const uint8_t in[], uint8_t block_id);
bool RSDecode(uint8_t N, uint8_t D, size_t blocks, const std::vector<Bytes>& in, const bool err[], uint8_t out[]);
