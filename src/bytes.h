#pragma once

#include <cstdint>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;

Bytes StrToBytes(const std::string& str);
std::string BytesToStr(const Bytes& bytes);

std::string Base64Encode(const Bytes& bytes);
Bytes Base64Decode(const std::string& str);
std::string PathEncode(const std::string& str);
std::string PathDecode(const std::string& str);
Bytes GetPublicKeyFromPath(const std::string& path);
