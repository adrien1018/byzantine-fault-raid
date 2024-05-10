#pragma once

#include <memory>
#include <vector>
#include <filesystem>

#include <openssl/evp.h>

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)>;
using Bytes = std::vector<uint8_t>;
namespace fs = std::filesystem;

class SigningKey {
 private:
  EVP_PKEY_ptr key_pair_;
  bool private_key_;

  static EVP_PKEY* ReadPubkey_(const fs::path& pubkey_path);
 public:
  SigningKey();
  SigningKey(const fs::path& key_path, bool private_key);
  SigningKey(const Bytes& key, bool private_key);

  void ExportPublicKey(const fs::path& path) const;
  void ExportPrivateKey(const fs::path& path) const;

  Bytes PublicKeyStr() const;
  Bytes PrivateKeyStr() const;

  Bytes Sign(const Bytes& msg) const;
  bool Verify(const Bytes& msg, const Bytes& sig) const;
};
