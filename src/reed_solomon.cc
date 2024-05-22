#include "reed_solomon.h"

#include <cstring>
#include <algorithm>

#include "signature.h"

namespace {

constexpr uint8_t kExpTable[] = {
  1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19,
  53, 95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34,
  102, 170, 229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112,
  144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104,
  184, 211, 110, 178, 205, 76, 212, 103, 169, 224, 59, 77, 215, 98,
  166, 241, 8, 24, 40, 120, 136, 131, 158, 185, 208, 107, 189, 220,
  127, 129, 152, 179, 206, 73, 219, 118, 154, 181, 196, 87, 249, 16,
  48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163, 254, 25, 43, 125,
  135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160, 251, 22,
  58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 195,
  94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218,
  117, 159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223,
  122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101, 175, 234, 37,
  111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27,
  45, 119, 153, 176, 203, 70, 202, 69, 207, 74, 222, 121, 139, 134,
  145, 168, 227, 62, 66, 198, 81, 243, 14, 18, 54, 90, 238, 41, 123,
  141, 140, 143, 138, 133, 148, 167, 242, 13, 23, 57, 75, 221, 124,
  132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, 1
};

constexpr uint8_t kLogTable[] = {
  0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223,
  3, 100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105,
  28, 193, 125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114,
  154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130,
  69, 53, 147, 218, 142, 150, 143, 219, 189, 54, 208, 206, 148, 19,
  92, 210, 241, 64, 70, 131, 56, 102, 221, 253, 48, 191, 6, 139, 98,
  179, 37, 226, 152, 34, 136, 145, 16, 126, 110, 72, 195, 163, 182,
  30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 43, 121, 10, 21, 155,
  159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87, 175, 88, 168,
  80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 44,
  215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81,
  160, 127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164,
  118, 123, 183, 204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161,
  108, 170, 85, 41, 157, 151, 178, 135, 144, 97, 190, 220, 252, 188,
  149, 207, 205, 55, 63, 91, 209, 83, 57, 132, 60, 65, 162, 109, 71,
  20, 42, 158, 93, 86, 242, 211, 171, 68, 17, 146, 217, 35, 32, 46,
  137, 180, 124, 184, 38, 119, 153, 227, 165, 103, 74, 237, 222, 197,
  49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7
};

struct GFInt {
  uint8_t val;
  GFInt() {}
  GFInt(uint8_t x) : val(x) {}
  operator uint8_t() { return val; }
  GFInt operator+(GFInt x) const { return val ^ x.val; }
  GFInt operator-(GFInt x) const { return val ^ x.val; }
  GFInt operator*(GFInt x) const {
    if (!val || !x.val) return 0;
    int32_t a = (uint32_t)kLogTable[val] + kLogTable[x.val] - 255;
    a += a >> 31 & 255;
    return kExpTable[a];
  }
  GFInt operator/(GFInt x) const {
    if (!val || !x.val) return 0;
    int32_t a = (uint32_t)kLogTable[val] - kLogTable[x.val];
    a += a >> 31 & 255;
    return kExpTable[a];
  }
  GFInt operator+=(GFInt x) { return *this = *this + x; }
  GFInt operator-=(GFInt x) { return *this = *this - x; }
  GFInt operator*=(GFInt x) { return *this = *this * x; }
  GFInt operator/=(GFInt x) { return *this = *this / x; }
  GFInt inv() const { return kExpTable[255 - kLogTable[val]]; }
};

std::vector<GFInt> ComputeEncodeTable(uint8_t N) {
  std::vector<GFInt> x(N, GFInt(1));
  for (uint8_t i = 0; i < N; i++) {
    for (uint8_t j = 0; j < N; j++) {
      if (i == j) continue;
      x[i] /= GFInt(i) - GFInt(j);
    }
  }
  return x;
}

std::vector<GFInt> ComputeDecodeTable(const std::vector<uint8_t>& pos) {
  std::vector<GFInt> x(pos.size(), GFInt(1));
  for (uint8_t i = 0; i < pos.size(); i++) {
    for (uint8_t j = 0; j < pos.size(); j++) {
      if (i == j) continue;
      x[i] /= GFInt(pos[i]) - GFInt(pos[j]);
    }
  }
  return x;
}

} // namespace

std::vector<Bytes> RSEncode(uint8_t N, uint8_t D, size_t blocks, const uint8_t in[]) {
  uint8_t deg = N-D;
  auto table = ComputeEncodeTable(deg);
  std::vector<GFInt> ls(D, 1);
  for (uint8_t x = deg; x < N; x++) {
    for (uint8_t j = 0; j < deg; j++) ls[x-deg] *= GFInt(x) - GFInt(j);
  }
  std::vector<GFInt> ins(deg);
  std::vector<Bytes> out(N, Bytes(blocks));
  for (uint8_t j = 0; j < deg; j++) {
    memcpy(out[j].data(), in + j * blocks, blocks);
  }
  std::vector<GFInt> table_x(deg);
  for (uint8_t x = deg; x < N; x++) {
    for (uint8_t j = 0; j < deg; j++) table_x[j] = table[j] / (GFInt(x) - GFInt(j));
    for (size_t i = 0; i < blocks; i++) {
      GFInt sum = 0;
      for (uint8_t j = 0; j < deg; j++) sum += table_x[j] * GFInt(in[j * blocks + i]);
      out[x][i] = ls[x-deg] * sum;
    }
  }
  return out;
}

bool RSDecode(uint8_t N, uint8_t D, size_t blocks, const std::vector<Bytes>& in, const bool err[], uint8_t out[]) {
  uint8_t deg = N-D;
  size_t errs = std::count_if(err, err + deg, [](bool x){ return x; });
  for (uint8_t j = 0; j < deg; j++) {
    if (!err[j]) memcpy(out + j * blocks, in[j].data(), blocks);
  }
  if (errs == 0) return true;
  std::vector<uint8_t> pos, err_pos;
  pos.reserve(deg);
  err_pos.reserve(errs);
  for (int i = 0; i < deg; i++) {
    if (err[i]) {
      err_pos.push_back(i);
    } else {
      pos.push_back(i);
    }
  }
  for (uint8_t i = deg; i < N && pos.size() < deg; i++) {
    if (!err[i]) pos.push_back(i);
  }
  if (pos.size() < deg) return false;
  auto table = ComputeDecodeTable(pos);
  std::vector<GFInt> ls(err_pos.size(), 1);
  for (uint8_t i = 0; i < err_pos.size(); i++) {
    for (uint8_t k = 0; k < deg; k++) ls[i] *= GFInt(err_pos[i]) - GFInt(pos[k]);
  }
  std::vector<GFInt> table_x(deg);
  for (uint8_t j = 0; j < err_pos.size(); j++) {
    uint8_t x = err_pos[j];
    for (uint8_t k = 0; k < deg; k++) table_x[k] = table[k] / (GFInt(x) - GFInt(pos[k]));
    for (size_t i = 0; i < blocks; i++) {
      GFInt sum = 0;
      for (uint8_t k = 0; k < deg; k++) sum += table_x[k] * GFInt(in[pos[k]][i]);
      out[x * blocks + i] = ls[j] * sum;
    }
  }
  return true;
}

#ifdef DEBUG_ONE_FILE

#include <random>
#include <iostream>
#include <chrono>

int main() {
  using namespace std::chrono;
  for (uint32_t a = 0; a < 256; a++) {
    for (uint32_t b = 1; b < 256; b++) {
      /*std::cout
        << (uint32_t)a << ' '
        << (uint32_t)b << ' '
        << (uint32_t)(GFInt(a) * GFInt(b)) << ' '
        << (uint32_t)(GFInt(a) * GFInt(b) / GFInt(b)) << '\n';*/
      if (GFInt(a) * GFInt(b) / GFInt(b) != GFInt(a)) throw;
      if (GFInt(1) / GFInt(b) != GFInt(b).inv()) throw;
      for (uint32_t c = 0; c < 256; c++) {
        if ((GFInt(a) + GFInt(c)) / GFInt(b) != GFInt(a) / GFInt(b) + GFInt(c) / GFInt(b)) throw;
        if ((GFInt(a) + GFInt(c)) * GFInt(b) != GFInt(a) * GFInt(b) + GFInt(c) * GFInt(b)) throw;
        if (GFInt(a) * GFInt(b) * GFInt(c) != GFInt(a) * (GFInt(b) * GFInt(c))) throw;
      }
    }
  }
  std::mt19937_64 gen;
  for (int N : {8, 15, 80, 255}) {
    int D = 4;

    int C = 1 * 1024 * 1024 / (N-D);
    //int C = 1;
    std::vector<uint8_t> data((N-D)*C), res((N-D)*C);
    bool err_vec[256] = {};
    for (auto& i : data) i = gen();

    auto start = steady_clock::now();
    auto encode = RSEncode(N, D, C, data.data());
    auto end = steady_clock::now();
    double encode_time = duration<double>(end - start).count();

    std::vector<uint8_t> errs;
    start = steady_clock::now();
    bool st = RSDecode(N, D, C, encode, err_vec, res.data());
    end = steady_clock::now();
    double decode_time = duration<double>(end - start).count();
    if (!st || res != data) throw;

    memset(res.data(), 0, res.size());
    errs.push_back(1);
    err_vec[1] = true;
    for (auto& i : errs) encode[i].clear(), err_vec[i] = true;

    start = steady_clock::now();
    st = RSDecode(N, D, C, encode, err_vec, res.data());
    end = steady_clock::now();
    double decode_correct_1_time = duration<double>(end - start).count();
    if (!st || res != data) throw;

    memset(res.data(), 0, res.size());
    for (int i = 0; i < D; i++) {
      errs.push_back(i);
    }
    for (auto& i : errs) encode[i].clear(), err_vec[i] = true;

    start = steady_clock::now();
    st = RSDecode(N, D, C, encode, err_vec, res.data());
    end = steady_clock::now();
    double decode_correct_time = duration<double>(end - start).count();
    if (!st || res != data) throw;

    printf("%.6lf %.6lf %.6lf %.6lf\n", encode_time, decode_time, decode_correct_1_time, decode_correct_time);
    /*
  for (auto& i : data) std::cout << (uint32_t)i << ' ';
  std::cout << '\n';
  for (auto& i : encode) for (auto& j : i) std::cout << (uint32_t)j << ' ';
  std::cout << '\n';
  for (auto& i : res) std::cout << (uint32_t)i << ' ';
  std::cout << '\n';
  */
  }

}

#endif
