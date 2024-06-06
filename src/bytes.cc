#include "bytes.h"

#include <array>

Bytes StrToBytes(const std::string& str) {
  return Bytes(str.begin(), str.end());
}

std::string BytesToStr(const Bytes& bytes) {
  return std::string(bytes.begin(), bytes.end());
}

namespace {

struct Base64Table {
  std::array<uint8_t, 256> decode_table;
  std::array<char, 64> encode_table;

  constexpr Base64Table() : decode_table{}, encode_table{} {
    for (size_t i = 0; i < 64; i++) {
      decode_table["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[i]] = i;
      encode_table[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[i];
    }
  }
};

constexpr Base64Table kBase64Table;

} // namespace

// no trailing '='
std::string Base64Encode(const Bytes& bytes) {
  std::string result;
  size_t i = 0;
  size_t j = 0;
  uint8_t a3[3];
  uint8_t a4[4];
  for (const auto& byte : bytes) {
    a3[i++] = byte;
    if (i == 3) {
      a4[0] = (a3[0] & 0xfc) >> 2;
      a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
      a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
      a4[3] = a3[2] & 0x3f;
      for (i = 0; i < 4; i++) {
        result += kBase64Table.encode_table[a4[i]];
      }
      i = 0;
    }
  }
  if (i) {
    for (j = i; j < 3; j++) {
      a3[j] = '\0';
    }
    a4[0] = (a3[0] & 0xfc) >> 2;
    a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
    a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
    a4[3] = a3[2] & 0x3f;
    for (j = 0; j < i + 1; j++) {
      result += kBase64Table.encode_table[a4[j]];
    }
  }
  return result;
}

Bytes Base64Decode(const std::string& str) {
  Bytes result;
  size_t i = 0;
  size_t j = 0;
  uint8_t a3[3];
  uint8_t a4[4];
  for (const auto& c : str) {
    if (c == '=') break;
    a4[i++] = c;
    if (i == 4) {
      for (i = 0; i < 4; i++) {
        a4[i] = kBase64Table.decode_table[a4[i]];
      }
      a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
      a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
      a3[2] = ((a4[2] & 0x3) << 6) + a4[3];
      for (i = 0; i < 3; i++) {
        result.push_back(a3[i]);
      }
      i = 0;
    }
  }
  if (i) {
    for (j = i; j < 4; j++) {
      a4[j] = 0;
    }
    for (j = 0; j < 4; j++) {
      a4[j] = kBase64Table.decode_table[a4[j]];
    }
    a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
    a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
    a3[2] = ((a4[2] & 0x3) << 6) + a4[3];
    for (j = 0; j < i - 1; j++) {
      result.push_back(a3[j]);
    }
  }
  return result;
}

std::string PathEncode(const std::string& str) {
  // replace all '/' with '@0', '\' as '@1', and '@' as '@2'
  std::string result;
  for (const auto& c : str) {
    if (c == '/') {
      result += "@0";
    } else if (c == '\\') {
      result += "@1";
    } else if (c == '@') {
      result += "@2";
    } else {
      result += c;
    }
  }
  return result;
}

std::string PathDecode(const std::string& str) {
  // replace all '@0' with '/', '@1' as '\', and '@2' as '@'
  std::string result;
  for (size_t i = 0; i < str.size(); i++) {
    if (str[i] == '@') {
      if (i + 1 < str.size()) {
        if (str[i + 1] == '0') {
          result += '/';
          i++;
        } else if (str[i + 1] == '1') {
          result += '\\';
          i++;
        } else if (str[i + 1] == '2') {
          result += '@';
          i++;
        } else {
          result += str[i];
        }
      } else {
        result += str[i];
      }
    } else {
      result += str[i];
    }
  }
  return result;
}

Bytes GetPublicKeyFromPath(const std::string& path) {
    const size_t pos = path.find('/');
    if (pos == std::string::npos) {
        return Bytes{};
    }
    return Base64Decode(path.substr(0, pos));
}
