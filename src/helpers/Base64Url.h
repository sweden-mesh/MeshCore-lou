#pragma once

#include <stddef.h>
#include <stdint.h>

// base64url without padding, as the command plane writes its MQTT payloads (mcc3). The names
// are the ones the v2 envelope gave them (ar-13); the envelope is gone, its callers are not.

// base64url of n bytes, no padding
#define MQTTV2_B64_LEN(n)      (((n) * 4 + 2) / 3)

static inline size_t mqttV2B64Encode(const uint8_t* in, size_t len, char* out, size_t out_size) {
  static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  size_t need = MQTTV2_B64_LEN(len);
  if (out_size < need + 1) return 0;
  size_t o = 0;
  for (size_t i = 0; i < len; i += 3) {
    uint32_t v = (uint32_t)in[i] << 16;
    if (i + 1 < len) v |= (uint32_t)in[i + 1] << 8;
    if (i + 2 < len) v |= in[i + 2];
    out[o++] = a[(v >> 18) & 63];
    out[o++] = a[(v >> 12) & 63];
    if (i + 1 < len) out[o++] = a[(v >> 6) & 63];
    if (i + 2 < len) out[o++] = a[v & 63];
  }
  out[o] = 0;
  return o;
}

static inline int mqttV2B64Value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

// Decodes exactly `len` characters; 0 for anything that is not unpadded base64url.
static inline size_t mqttV2B64Decode(const char* in, size_t len, uint8_t* out, size_t out_size) {
  if (len % 4 == 1) return 0;
  size_t need = len * 3 / 4;
  if (need > out_size) return 0;
  size_t o = 0;
  uint32_t acc = 0;
  int bits = 0;
  for (size_t i = 0; i < len; i++) {
    int v = mqttV2B64Value(in[i]);
    if (v < 0) return 0;
    acc = (acc << 6) | (uint32_t)v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (uint8_t)(acc >> bits);
    }
  }
  if (acc & ((1u << bits) - 1)) return 0;    // non-canonical trailing bits
  return o;
}
