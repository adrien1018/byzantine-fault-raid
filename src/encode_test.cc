extern "C" {
#include <correct.h>
}
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
  constexpr int SIZE = 1 * 1024 * 1024;
  for (int n : {8, 15, 80, 255}) {
    int d = 4;
    Bytes data(SIZE / (n-d) * (n-d));
    for (auto& i : data) i = gen();
    SigningKey key;
    auto start = steady_clock::now();
    auto blocks = Encode(data, n, d, key, "name", 0, 0);
    auto end = steady_clock::now();
    double encode_time = duration<double>(end - start).count();

    start = steady_clock::now();
    auto ret = Decode(blocks, data.size(), n, d, key, "name", 0, 0);
    end = steady_clock::now();
    double decode_time = duration<double>(end - start).count();

    blocks[0][0]++;
    start = steady_clock::now();
    ret = Decode(blocks, data.size(), n, d, key, "name", 0, 0);
    end = steady_clock::now();
    double decode_correct_1_time = duration<double>(end - start).count();

    for (int i = 0; i < d; i++) blocks[i][0]++;
    start = steady_clock::now();
    ret = Decode(blocks, data.size(), n, d, key, "name", 0, 0);
    end = steady_clock::now();
    double decode_correct_time = duration<double>(end - start).count();
    printf("%.6lf %.6lf %.6lf %.6lf\n", encode_time, decode_time, decode_correct_1_time, decode_correct_time);
  }
}
