#pragma once

#include <cstdint>

void RSEncode(uint8_t N, uint8_t D, size_t blocks, const uint8_t in[], uint8_t out[]);
bool RSDecode(uint8_t N, uint8_t D, size_t blocks, const uint8_t in[], const bool err[], uint8_t out[]);
