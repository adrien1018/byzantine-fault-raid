#include "encode_decode.h"

#include <iostream>
#include <random>
#include <chrono>

int main() {
  using namespace std::chrono;
  std::mt19937_64 gen;
  /*
  for (int n = 15; n <= 255; n++) {
    SigningKey key;
    int d = 6;
    Bytes data((n-d) * 5);
    for (auto& i : data) i = gen();

    //for (auto& i : data) printf("%u ", (uint32_t)i);
    //puts("");
    auto blocks = Encode(data, n, d, key, "name", 0, 0);
    for (int i = 0; i < n; i++) {
      std::cout << VerifyBlock(blocks[i], i, key, "name", 0, 0);
    }
    blocks[0][0] = 1;
    blocks[1][0] = 1;
    blocks[2][0] = 1;
    blocks[3][0] = 1;
    blocks[4][0] = 1;
    blocks[5][0] = 1;
    auto ret = Decode(blocks, data.size(), n, d, key, "name", 0, 0);
    std::cout << (data == ret) << std::endl;
    //for (auto& i : ret) printf("%u ", (uint32_t)i);
    //puts("");
  }
  */
  //constexpr int SIZE = 4 * 1024 * 1024;
  printf("%7s%4s%4s%6s%12s%12s%12s%12s%12s\n", "Block", "n", "d", "eff%", "Encode", "Recon", "Dec no err", "Dec 1 err", "Dec n-d err");
  for (int block_size : {512, 4096, 16384, 65536}) for (int n : {10}) for (int d : {3}) for (int i = 0; i < 5; i++) {
    //Bytes data(SIZE / (n-d) * (n-d));
    Bytes data(block_size * (n - d));
    for (auto& i : data) i = gen();
    SigningKey key;
    auto start = steady_clock::now();
    auto blocks = Encode(data, n, d, key, "name", 0, 0);
    auto end = steady_clock::now();
    double encode_time = duration<double>(end - start).count();

    for (int i = 0; i < n; i++) {
      if (!VerifyBlock(blocks[i], n, i, key, "name", 0, 0)) throw;
    }

    start = steady_clock::now();
    auto ret = Decode(blocks, data.size(), n, d, key, "name", 0, 0);
    end = steady_clock::now();
    double decode_time = duration<double>(end - start).count();
    if (ret != data) throw;

    auto orig_block = blocks[0];
    blocks[0][0]++;
    start = steady_clock::now();
    ret = Reconstruct(blocks, data.size(), n, d, 2, 0, key, "name", 0, 0);
    end = steady_clock::now();
    double reconstruct_time = duration<double>(end - start).count();
    if (ret != orig_block) throw;

    blocks[0][0]++;
    start = steady_clock::now();
    ret = Decode(blocks, data.size(), n, d, key, "name", 0, 0);
    end = steady_clock::now();
    double decode_correct_1_time = duration<double>(end - start).count();
    if (ret != data) throw;

    for (int i = 0; i < d; i++) blocks[i][0]++;
    start = steady_clock::now();
    ret = Decode(blocks, data.size(), n, d, key, "name", 0, 0);
    end = steady_clock::now();
    double decode_correct_time = duration<double>(end - start).count();
    if (ret != data) throw;

    encode_time = data.size() / (encode_time * 1024 * 1024);
    reconstruct_time = data.size() / (reconstruct_time * 1024 * 1024);
    decode_time = data.size() / (decode_time * 1024 * 1024);
    decode_correct_1_time = data.size() / (decode_correct_1_time * 1024 * 1024);
    decode_correct_time = data.size() / (decode_correct_time * 1024 * 1024);

    printf("%7d%4d%4d%6.1lf%12.3lf%12.3lf%12.3lf%12.3lf%12.3lf MB/s\n",
           (int)blocks.back().size(), n, d, (double)block_size / blocks.back().size() * 100,
           encode_time, reconstruct_time, decode_time, decode_correct_1_time, decode_correct_time);
  }
}
