#pragma once

#include "filesys.pb.h"
#include "encode_decode.h"

inline bool VerifyUpdateSignature(
    const filesys::UpdateMetadata& metadata, const std::string& filename,
    const Bytes& public_key) {
  if (public_key != GetPublicKeyFromPath(filename)) {
    return false;
  }
  return VerifyUpdate(StrToBytes(metadata.version_signature()), 
                      SigningKey(public_key, false), filename,
                      metadata.stripe_range().offset(), metadata.stripe_range().count(),
                      metadata.version(), metadata.is_delete());
}

inline bool VerifyUpdateSignature(
    const filesys::UpdateMetadata& metadata, const std::string& filename,
    const std::string& public_key) {
  return VerifyUpdateSignature(metadata, filename, StrToBytes(public_key));
}
