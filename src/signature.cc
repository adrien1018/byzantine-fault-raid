#include "signature.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <memory>
#include <vector>
#include <filesystem>

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)>;
using Bytes = std::vector<uint8_t>;
namespace fs = std::filesystem;

EVP_PKEY* SigningKey::ReadPubkey_(const fs::path& pubkey_path) {
  EVP_PKEY* pkey = nullptr;
  FILE* fp = fopen(pubkey_path.c_str(), "r");
  PEM_read_PUBKEY(fp, &pkey, nullptr, nullptr);
  fclose(fp);
  if (!pkey) throw std::runtime_error("Failed to read public key");
  return pkey;
}

SigningKey::SigningKey() : key_pair_(nullptr, EVP_PKEY_free), private_key_(true) {
  EVP_PKEY* pkey = nullptr;
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  EVP_PKEY_keygen_init(pctx);
  EVP_PKEY_keygen(pctx, &pkey);
  EVP_PKEY_CTX_free(pctx);
  if (!pkey) throw std::runtime_error("Failed to generate key");
  key_pair_.reset(pkey);
}

SigningKey::SigningKey(const fs::path& key_path, bool private_key) :
    key_pair_(nullptr, EVP_PKEY_free), private_key_(private_key) {
  EVP_PKEY* pkey = nullptr;
  FILE* fp = fopen(key_path.c_str(), "r");
  if (private_key) {
    PEM_read_PrivateKey(fp, &pkey, nullptr, nullptr);
  } else {
    PEM_read_PUBKEY(fp, &pkey, nullptr, nullptr);
  }
  fclose(fp);
  if (!pkey) throw std::runtime_error("Failed to read key");
  key_pair_.reset(pkey);
}

SigningKey::SigningKey(const Bytes& key, bool private_key) :
    key_pair_(nullptr, EVP_PKEY_free), private_key_(private_key) {
  EVP_PKEY* pkey = nullptr;
  if (private_key) {
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, key.data(), key.size());
  } else {
    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, key.data(), key.size());
  }
  if (!pkey) throw std::runtime_error("Failed to read key");
  key_pair_.reset(pkey);
}

void SigningKey::ExportPublicKey(const fs::path& path) const {
  FILE* fp = fopen(path.c_str(), "w");
  PEM_write_PUBKEY(fp, key_pair_.get());
  fclose(fp);
}

void SigningKey::ExportPrivateKey(const fs::path& path) const {
  if (!private_key_) throw std::invalid_argument("Not a private key object");
  FILE* fp = fopen(path.c_str(), "w");
  PEM_write_PrivateKey(fp, key_pair_.get(), nullptr, nullptr, 0, nullptr, nullptr);
  fclose(fp);
}

Bytes SigningKey::PublicKeyStr() const {
  size_t len = 0;
  EVP_PKEY_get_raw_public_key(key_pair_.get(), nullptr, &len);
  Bytes str(len);
  EVP_PKEY_get_raw_public_key(key_pair_.get(), (unsigned char*)str.data(), &len);
  return str;
}

Bytes SigningKey::PrivateKeyStr() const {
  if (!private_key_) throw std::invalid_argument("Not a private key object");
  size_t len = 0;
  EVP_PKEY_get_raw_private_key(key_pair_.get(), nullptr, &len);
  Bytes str(len, 0);
  EVP_PKEY_get_raw_private_key(key_pair_.get(), (unsigned char*)str.data(), &len);
  return str;
}

Bytes SigningKey::Sign(const void* msg, size_t msg_len) const {
  if (!private_key_) throw std::invalid_argument("Not a private key object");
  EVP_MD_CTX_ptr mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
  size_t sig_len = 0;
  if (1 != EVP_DigestSignInit(mdctx.get(), nullptr, nullptr, nullptr, key_pair_.get()) ||
      1 != EVP_DigestSign(mdctx.get(), nullptr, &sig_len, nullptr, 0)) {
    throw std::runtime_error("Failed to initialize DigestSign");
  }
  if (sig_len != kSignatureSize) throw std::runtime_error("Unexpected signature size");
  Bytes sig(sig_len);
  if (1 != EVP_DigestSign(mdctx.get(), sig.data(), &sig_len, (const unsigned char*)msg, msg_len)) {
    throw std::runtime_error("Failed to sign message");
  }
  return sig;
}

Bytes SigningKey::Sign(const Bytes& msg) const {
  return Sign(msg.data(), msg.size());
}

bool SigningKey::Verify(const void* msg, size_t msg_len, const uint8_t* sig) const {
  EVP_MD_CTX_ptr mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
  if (1 != EVP_DigestVerifyInit(mdctx.get(), nullptr, nullptr, nullptr, key_pair_.get())) {
    throw std::runtime_error("Failed to initialize DigestVerify");
  }
  return 1 == EVP_DigestVerify(mdctx.get(), sig, kSignatureSize, (const unsigned char*)msg, msg_len);
}

bool SigningKey::Verify(const Bytes& msg, const Bytes& sig) const {
  if (sig.size() != kSignatureSize) return false;
  return Verify(msg.data(), msg.size(), sig.data());
}

#ifdef DEBUG_ONE_FILE

#include <iostream>

int main() {
  SigningKey key;
  key.ExportPublicKey("pubkey");
  key.ExportPrivateKey("privkey");

  Bytes msg;
  for (int i = 0; i < 255; i++) msg.push_back(i);
  Bytes sig = key.Sign(msg);
  std::cout << key.Verify(msg, sig) << ' ' << SigningKey(key.PublicKeyStr(), false).Verify(msg, sig) << '\n';
}

#endif
