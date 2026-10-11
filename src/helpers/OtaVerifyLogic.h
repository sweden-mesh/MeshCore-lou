#pragma once
// A signed firmware image, verified before it is trusted (2026-10-08, ships with ar-11).
//
// The pull-OTA path downloads whatever the manifest host serves and HTTPUpdate
// checks only the transfer, so whoever serves the manifest decides what the
// fleet runs. Two things close that: the manifest carries the image's SHA-256
// and an Ed25519 signature over it by the RELEASE key -- a key held by whoever
// cuts releases, never the command key, so a leaked command key cannot become a
// firmware weapon -- and the node checks the signature before it downloads a
// byte and the hash while it writes, aborting the slot on a mismatch.
//
// Pure functions, host-tested in test_ota_verify: the firmware passes the
// manifest's fields and the baked-in OTA_RELEASE_PUBKEY (64 hex); the hash is
// computed by the caller as it streams (mbedtls on the device, any SHA-256 in a
// test) and compared here.
//
//     signed   "<sha256 hex, lower>|<version>|<file>"      (the manifest's own fields)
//     sig      128 hex Ed25519 by the release key
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ed_25519.h>

#define OTA_SHA256_HEX_LEN 64
#define OTA_SIG_HEX_LEN    128
#define OTA_PUBKEY_HEX_LEN 64

static inline int otaHexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static inline bool otaHexToBytes(const char* hex, size_t hex_len, uint8_t* out, size_t out_len) {
  if (hex == NULL || out == NULL || hex_len != out_len * 2) return false;
  for (size_t i = 0; i < out_len; i++) {
    int hi = otaHexNibble(hex[2 * i]), lo = otaHexNibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

// Is the manifest's claim about this image signed by the release key? Checked
// before any download. Every field is the manifest's own text, so a changed hash,
// version or file name fails; an empty release key (a dev build) fails closed.
static inline bool otaManifestSignatureOk(const char* release_pubkey_hex, const char* sha256_hex,
                                          const char* version, const char* file, const char* sig_hex) {
  if (release_pubkey_hex == NULL || sha256_hex == NULL || version == NULL || file == NULL || sig_hex == NULL) return false;
  if (strlen(release_pubkey_hex) != OTA_PUBKEY_HEX_LEN || strlen(sha256_hex) != OTA_SHA256_HEX_LEN ||
      strlen(sig_hex) != OTA_SIG_HEX_LEN) return false;
  uint8_t pub[32], sig[64];
  if (!otaHexToBytes(release_pubkey_hex, OTA_PUBKEY_HEX_LEN, pub, sizeof(pub))) return false;
  if (!otaHexToBytes(sig_hex, OTA_SIG_HEX_LEN, sig, sizeof(sig))) return false;
  char msg[OTA_SHA256_HEX_LEN + 1 + 64 + 1 + 256 + 1];
  int n = snprintf(msg, sizeof(msg), "%s|%s|%s", sha256_hex, version, file);
  if (n <= 0 || (size_t)n >= sizeof(msg)) return false;
  return ed25519_verify(sig, (const uint8_t*)msg, (size_t)n, pub) == 1;
}

// Does the hash computed over the written bytes match the manifest's? Compared
// as bytes, so case in the manifest does not matter; a short or malformed
// manifest hash never matches.
static inline bool otaImageHashOk(const uint8_t digest[32], const char* sha256_hex) {
  uint8_t expected[32];
  if (digest == NULL || sha256_hex == NULL || strlen(sha256_hex) != OTA_SHA256_HEX_LEN) return false;
  if (!otaHexToBytes(sha256_hex, OTA_SHA256_HEX_LEN, expected, sizeof(expected))) return false;
  int diff = 0;
  for (int i = 0; i < 32; i++) diff |= digest[i] ^ expected[i];
  return diff == 0;
}

// Is the build on offer newer than the one running? (2026-10-08, operator ruling: the
// auto-reply revision `ar-N` decides.) Compared in this order:
//   1. the `-ar-N-` revision in each version string: a higher N is an update, a lower N
//      never is -- a channel cannot roll a node back by accident;
//   2. with the same revision, the build number (4th version component) when both have one;
//   3. else the commit hash: different is an update, which is upstream's rule for images
//      that carry no build number.
// `hash_equal` is the caller's shared-prefix compare of the two hashes.
enum OtaVerdict { OTA_UP_TO_DATE = 0, OTA_NEWER = 1, OTA_OLDER = 2 };

static inline int otaRevisionOf(const char* version) {
  if (version == NULL) return -1;
  const char* p = strstr(version, "-ar-");
  if (p == NULL) return -1;
  p += 4;
  if (*p < '0' || *p > '9') return -1;
  int n = 0;
  while (*p >= '0' && *p <= '9') { n = n * 10 + (*p - '0'); p++; }
  return n;
}

static inline OtaVerdict otaUpdateVerdict(const char* own_version, const char* avail_version,
                                          int own_build, int avail_build, bool hash_equal) {
  int own_ar = otaRevisionOf(own_version), avail_ar = otaRevisionOf(avail_version);
  if (own_ar >= 0 && avail_ar >= 0 && own_ar != avail_ar) {
    return avail_ar > own_ar ? OTA_NEWER : OTA_OLDER;
  }
  if (own_build >= 0 && avail_build >= 0 && own_build != avail_build) {
    return avail_build > own_build ? OTA_NEWER : OTA_OLDER;
  }
  return hash_equal ? OTA_UP_TO_DATE : OTA_NEWER;
}
