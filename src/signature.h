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
 public:
  static constexpr size_t kSignatureSize = 64;

  // note: private key contains the information of public key
  SigningKey();
  SigningKey(const fs::path& key_path, bool is_private_key);
  SigningKey(const Bytes& key, bool is_private_key);

  // export public / private key to a file using PEM format
  void ExportPublicKey(const fs::path& path) const;
  void ExportPrivateKey(const fs::path& path) const;

  // raw public / private key data
  Bytes PublicKey() const;
  Bytes PrivateKey() const;

  Bytes Sign(const void* msg, size_t msg_len) const;
  Bytes Sign(const Bytes& msg) const;
  bool Verify(const void* msg, size_t msg_len, const uint8_t* sig) const;
  bool Verify(const Bytes& msg, const Bytes& sig) const;
};
