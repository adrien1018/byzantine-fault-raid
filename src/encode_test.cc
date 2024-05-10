extern "C" {
#include <correct.h>
}
#include <vector>
#include <cstdio>

int main() {
  std::vector<uint8_t> msg{1,2,3,4,5,6,7,8,9,10};
  int redundancy = 5;
  auto encoder = correct_reed_solomon_create(
      correct_rs_primitive_polynomial_ccsds, 1, 1, redundancy);

  std::vector<uint8_t> data(msg.size() + redundancy);
  correct_reed_solomon_encode(encoder, msg.data(), msg.size(), data.data());
  for (uint8_t x : data) printf("%u ", (uint32_t)x);
  puts("");

  std::vector<uint8_t> error_pos{3,5,7,9,11};
  for (int x : error_pos) data[x] = 0;

  std::vector<uint8_t> msg_reconstruct(msg.size());
  correct_reed_solomon_decode_with_erasures(
      encoder, data.data(), data.size(), error_pos.data(), error_pos.size(), msg_reconstruct.data());
  for (uint8_t x : msg_reconstruct) printf("%u ", (uint32_t)x);
  puts("");

  correct_reed_solomon_destroy(encoder);
}
