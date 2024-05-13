extern "C" {
#include <correct.h>
}
#include "encode_decode.h"

#include <iostream>
#include <random>

int main() {
  std::mt19937_64 gen;
  SigningKey key;
  int n = 20;
  int d = 6;
  Bytes data((n-d) * 5);
  for (auto& i : data) i = gen();

  for (auto& i : data) printf("%u ", (uint32_t)i);
  puts("");
  auto blocks = Encode(data, n, d, key, "name", 0, 0);
  blocks[0][0] = 1;
  blocks[1][0] = 1;
  blocks[2][0] = 1;
  blocks[3][0] = 1;
  blocks[4][0] = 1;
  blocks[5][0] = 1;
  auto ret = Decode(blocks, data.size(), n, d, key, "name", 0, 0);
  std::cout << (data == ret) << std::endl;
  for (auto& i : ret) printf("%u ", (uint32_t)i);
  puts("");
}
