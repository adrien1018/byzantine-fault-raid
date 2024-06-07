#pragma GCC optimize("O2")
#include "reed_solomon.h"

#include <cstring>
#include <algorithm>

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
    uint8_t v = (!val || !x.val) - 1;
    int32_t a = (uint32_t)kLogTable[val] + kLogTable[x.val] - 255;
    a += a >> 31 & 255;
    return kExpTable[a] & v;
  }
  GFInt operator/(GFInt x) const {
    uint8_t v = (!val || !x.val) - 1;
    int32_t a = (uint32_t)kLogTable[val] - kLogTable[x.val];
    a += a >> 31 & 255;
    return kExpTable[a] & v;
  }
  GFInt operator+=(GFInt x) { return *this = *this + x; }
  GFInt operator-=(GFInt x) { return *this = *this - x; }
  GFInt operator*=(GFInt x) { return *this = *this * x; }
  GFInt operator/=(GFInt x) { return *this = *this / x; }
  GFInt inv() const { return kExpTable[255 - kLogTable[val]]; }
};

std::vector<GFInt> ComputeEncodeTable(uint8_t N) {
  static std::vector<GFInt> cache[256];
  if (cache[N].size()) return cache[N];
  std::vector<GFInt> x(N, GFInt(1));
  for (uint8_t i = 0; i < N; i++) {
    for (uint8_t j = 0; j < N; j++) {
      if (i == j) continue;
      x[i] /= GFInt(i) - GFInt(j);
    }
  }
  cache[N] = x;
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

#pragma GCC diagnostic ignored "-Wclass-memaccess"

template <class InFunc>
inline void RSLoop(size_t blocks, uint8_t deg, const std::vector<GFInt>& table_x, GFInt ls, InFunc in, uint8_t* out) {
  constexpr size_t kBlock = 64;
  for (size_t bi = 0; bi < blocks; bi += kBlock) {
    alignas(32) GFInt sum[kBlock], ins[kBlock];
    memset(sum, 0, sizeof(sum));
    memset(ins, 0, sizeof(ins));
    size_t p = std::min(kBlock, blocks - bi);
    for (uint8_t j = 0; j < deg; j++) {
      memcpy(ins, in(j) + bi, p);
#pragma GCC unroll 8
      for (size_t i = 0; i < kBlock; i++) sum[i] += table_x[j] * ins[i];
    }
    for (size_t ni = 0, i = bi; ni < p; ni++, i++) {
      out[i] = ls * sum[ni];
    }
  }
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
    RSLoop(blocks, deg, table_x, ls[x-deg], [&](uint8_t j) { return in + j * blocks; }, out[x].data());
  }
  return out;
}

bool RSDecode(uint8_t N, uint8_t D, size_t blocks, const std::vector<Bytes>& in,
              const bool err[], uint8_t out[]) {
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
    RSLoop(blocks, deg, table_x, ls[j], [&](uint8_t k) { return in[pos[k]].data(); }, out + x * blocks);
  }
  return true;
}

bool RSReconstruct(uint8_t N, uint8_t D, size_t blocks, const std::vector<Bytes>& in,
                      const bool err[], uint8_t block_id, uint8_t out[]) {
  if (!err[block_id]) {
    memcpy(out, in[block_id].data(), blocks);
    return true;
  }
  uint8_t deg = N-D;
  std::vector<uint8_t> pos;
  pos.reserve(deg);
  for (uint8_t i = 0; i < N && pos.size() < deg; i++) {
    if (!err[i]) pos.push_back(i);
  }
  if (pos.size() < deg) return false;
  auto table = ComputeDecodeTable(pos);
  GFInt ls(1);
  for (uint8_t k = 0; k < deg; k++) ls *= GFInt(block_id) - GFInt(pos[k]);
  std::vector<GFInt> table_x(deg);
  uint8_t x = block_id;
  for (uint8_t k = 0; k < deg; k++) table_x[k] = table[k] / (GFInt(x) - GFInt(pos[k]));
  RSLoop(blocks, deg, table_x, ls, [&](uint8_t k) { return in[pos[k]].data(); }, out);
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
    int D = N/2;

    int C = 1 * 1024 * 1024 / (N-D);
    //int C = 4;
    std::vector<uint8_t> data((N-D)*C), res((N-D)*C);
    bool err_vec[256] = {};
    for (auto& i : data) i = gen();

    auto start = steady_clock::now();
    auto encode = RSEncode(N, D, C, data.data());
    auto end = steady_clock::now();
    double encode_time = duration<double>(end - start).count();

    for (int i = 0; i < N; i++) {
      // remove i-th block and check if RSReconstruct works
      auto n_encode = encode;
      n_encode[i].clear();
      std::vector<uint8_t> recon(C);
      err_vec[i] = true;
      bool st = RSReconstruct(N, D, C, n_encode, err_vec, i, recon.data());
      if (!st) throw;
      if (recon != encode[i]) throw;
      memset(err_vec, 0, sizeof(err_vec));
    }

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
