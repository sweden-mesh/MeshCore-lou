#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ChaChaPoly.h>
#include <HKDF.h>
#include <SHA256.h>

#include "MqttControlLogic.h"

// The v2 command envelope (firmware TODO 17, contract in planning/firmware/TODO.md 17a):
// a command and its result readable only by the operator and the node.
//
//   key      HKDF-SHA256(ikm = X25519 of the operator's command key and the node's identity,
//            salt = empty, info = "mccontrol-v2|" + the node's command topic, L = 32)
//   nonce    dir(1) | 0x00 * 7 | counter(4, big-endian); dir 0x00 command, 0x01 result
//   command  v2|<counter>|<expiry>|<b64url(ct||tag)>|<128-hex Ed25519 by the operator>
//            plaintext the command zero-padded to 64, or 160 if longer; AAD "v2|<c>|<e>"
//   result   r3|<counter>|<b64url(ct||tag)>
//            plaintext "<code>|<command>|<reply>" zero-padded to 256, or 512 if longer
//            (the reply cut to fit); AAD "r3|<counter>"
//
// A result reuses its command's counter under the other direction, and the counter is
// strictly increasing and persisted before the command runs, so no nonce repeats under
// one key, across reboots too. The outer signature is the broker's to check; the node
// opens the AEAD first, which already proves the holder of the operator's key, and drops
// a forgery before any other work.
//
// Kept out of MqttControlLogic.h because it needs the real ChaCha20-Poly1305 and SHA-256:
// its host suite is env:native_v2, which links rweather/Crypto instead of test/mocks.

#define MQTTV2_VERSION_TAG     "v2"
#define MQTTV2_RESULT_TAG      "r3"
#define MQTTV2_KEY_LEN         32
#define MQTTV2_TAG_LEN         16
#define MQTTV2_NONCE_LEN       12
#define MQTTV2_DIR_COMMAND     0x00
#define MQTTV2_DIR_RESULT      0x01
#define MQTTV2_CMD_PAD_SMALL   64
#define MQTTV2_CMD_PAD_LARGE   160
#define MQTTV2_RES_PAD_SMALL   256
#define MQTTV2_RES_PAD_LARGE   512
#define MQTTV2_INFO_PREFIX     "mccontrol-v2|"

// base64url of n bytes, no padding
#define MQTTV2_B64_LEN(n)      (((n) * 4 + 2) / 3)
// "r3|" + 10 digits + "|" + base64url of the largest result, + NUL
#define MQTTV2_MAX_RESULT      (3 + 10 + 1 + MQTTV2_B64_LEN(MQTTV2_RES_PAD_LARGE + MQTTV2_TAG_LEN) + 1)

static inline void mqttV2DeriveKey(const uint8_t shared[32], const char* topic,
                                   uint8_t key[MQTTV2_KEY_LEN]) {
  char info[sizeof(MQTTV2_INFO_PREFIX) + MQTTCTRL_MAX_TOPIC];
  int n = snprintf(info, sizeof(info), MQTTV2_INFO_PREFIX "%s", topic);
  hkdf<SHA256>(key, MQTTV2_KEY_LEN, shared, 32, NULL, 0, info, (size_t)n);
}

static inline void mqttV2Nonce(uint8_t dir, uint32_t counter, uint8_t nonce[MQTTV2_NONCE_LEN]) {
  memset(nonce, 0, MQTTV2_NONCE_LEN);
  nonce[0] = dir;
  nonce[8] = (uint8_t)(counter >> 24);
  nonce[9] = (uint8_t)(counter >> 16);
  nonce[10] = (uint8_t)(counter >> 8);
  nonce[11] = (uint8_t)counter;
}

// The padded size for `len` bytes of plaintext, or 0 when it does not fit the larger one.
static inline size_t mqttV2PadTo(size_t len, size_t small, size_t large) {
  return len <= small ? small : len <= large ? large : 0;
}

// ---- base64url, no padding ------------------------------------------------------------

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

// ---- the AEAD -------------------------------------------------------------------------

static inline void mqttV2Seal(const uint8_t key[MQTTV2_KEY_LEN], uint8_t dir, uint32_t counter,
                              const char* aad, const uint8_t* plain, size_t len, uint8_t* out) {
  uint8_t nonce[MQTTV2_NONCE_LEN];
  mqttV2Nonce(dir, counter, nonce);
  ChaChaPoly c;
  c.setKey(key, MQTTV2_KEY_LEN);
  c.setIV(nonce, sizeof(nonce));
  c.addAuthData(aad, strlen(aad));
  c.encrypt(out, plain, len);
  c.computeTag(out + len, MQTTV2_TAG_LEN);
  c.clear();
}

// `in` is ciphertext || tag, `len` both together. False, and `out` wiped, on a bad tag.
static inline bool mqttV2Open(const uint8_t key[MQTTV2_KEY_LEN], uint8_t dir, uint32_t counter,
                              const char* aad, const uint8_t* in, size_t len, uint8_t* out) {
  if (len < MQTTV2_TAG_LEN) return false;
  size_t n = len - MQTTV2_TAG_LEN;
  uint8_t nonce[MQTTV2_NONCE_LEN];
  mqttV2Nonce(dir, counter, nonce);
  ChaChaPoly c;
  c.setKey(key, MQTTV2_KEY_LEN);
  c.setIV(nonce, sizeof(nonce));
  c.addAuthData(aad, strlen(aad));
  c.decrypt(out, in, n);
  bool ok = c.checkTag(in + n, MQTTV2_TAG_LEN);
  c.clear();
  if (!ok) memset(out, 0, n);
  return ok;
}

// ---- the command ----------------------------------------------------------------------

static inline bool mqttV2IsEnvelope(const char* payload, size_t len) {
  return payload != NULL && len > 3 && memcmp(payload, MQTTV2_VERSION_TAG "|", 3) == 0;
}

// Builds a v2 command payload: what mccontrol sends, and what the host suite writes into
// the shared fixture. `sign` signs "<topic>\n<everything before the last '|'>".
static inline size_t mqttV2BuildCommand(const uint8_t key[MQTTV2_KEY_LEN], const char* topic,
                                        uint32_t counter, uint32_t expiry, const char* command,
                                        MqttCtrlSigner sign, void* ctx, char* out, size_t out_size) {
  size_t cmd_len = strlen(command);
  size_t padded = mqttV2PadTo(cmd_len, MQTTV2_CMD_PAD_SMALL, MQTTV2_CMD_PAD_LARGE);
  if (padded == 0) return 0;
  uint8_t plain[MQTTV2_CMD_PAD_LARGE] = {0};
  memcpy(plain, command, cmd_len);
  char aad[32];
  snprintf(aad, sizeof(aad), MQTTV2_VERSION_TAG "|%u|%u", (unsigned)counter, (unsigned)expiry);
  uint8_t sealed[MQTTV2_CMD_PAD_LARGE + MQTTV2_TAG_LEN];
  mqttV2Seal(key, MQTTV2_DIR_COMMAND, counter, aad, plain, padded, sealed);

  int n = snprintf(out, out_size, "%s|", aad);
  if (n <= 0 || (size_t)n >= out_size) return 0;
  size_t b = mqttV2B64Encode(sealed, padded + MQTTV2_TAG_LEN, out + n, out_size - n);
  if (b == 0) return 0;
  size_t body = (size_t)n + b;
  if (body + 1 + MQTTCTRL_SIG_HEX_LEN + 1 > out_size) return 0;

  size_t topic_len = strlen(topic);
  uint8_t msg[MQTTCTRL_MAX_SIGNED];
  if (topic_len + 1 + body > sizeof(msg)) return 0;
  memcpy(msg, topic, topic_len);
  msg[topic_len] = '\n';
  memcpy(msg + topic_len + 1, out, body);
  uint8_t sig[64];
  sign(ctx, sig, msg, topic_len + 1 + body);
  static const char hex_digits[] = "0123456789ABCDEF";
  char* p = out + body;
  *p++ = '|';
  for (int i = 0; i < 64; i++) { *p++ = hex_digits[sig[i] >> 4]; *p++ = hex_digits[sig[i] & 0x0F]; }
  *p = 0;
  return body + 1 + MQTTCTRL_SIG_HEX_LEN;
}

// Opens a v2 command into `env`, whose command then points into `text` (at least
// MQTTV2_CMD_PAD_LARGE + 1 bytes), the padding stripped. The AEAD is opened before
// anything is believed: a tag that fails is MQTTCTRL_ERR_SIG_INVALID and nothing else
// was done. The signature field is only checked for shape; it is the broker's.
static inline MqttCtrlResult mqttV2OpenCommand(const uint8_t key[MQTTV2_KEY_LEN],
                                               const char* payload, size_t len,
                                               MqttCtrlEnvelope* env, char* text) {
  if (!mqttV2IsEnvelope(payload, len)) return MQTTCTRL_ERR_BAD_VERSION;
  // v2|counter|expiry|b64|sig: split on the four separators
  const char* f[5];
  size_t fl[5];
  size_t start = 0;
  int k = 0;
  for (size_t i = 0; i <= len && k < 5; i++) {
    if (i == len || payload[i] == MQTTCTRL_FIELD_SEP) {
      if (k == 4 && i != len) return MQTTCTRL_ERR_BAD_FIELDS;
      f[k] = payload + start;
      fl[k] = i - start;
      k++;
      start = i + 1;
    }
  }
  if (k != 5) return MQTTCTRL_ERR_BAD_FIELDS;
  if (fl[4] != MQTTCTRL_SIG_HEX_LEN) return MQTTCTRL_ERR_BAD_SIG_LEN;

  uint32_t counter = 0, expiry = 0;
  if (!mqttCtrlParseU32(f[1], fl[1], &counter) || !mqttCtrlParseU32(f[2], fl[2], &expiry)) {
    return MQTTCTRL_ERR_BAD_COUNTER;
  }
  uint8_t sealed[MQTTV2_CMD_PAD_LARGE + MQTTV2_TAG_LEN];
  size_t n = mqttV2B64Decode(f[3], fl[3], sealed, sizeof(sealed));
  if (n != MQTTV2_CMD_PAD_SMALL + MQTTV2_TAG_LEN && n != MQTTV2_CMD_PAD_LARGE + MQTTV2_TAG_LEN) {
    return MQTTCTRL_ERR_BAD_FIELDS;
  }
  char aad[32];
  snprintf(aad, sizeof(aad), MQTTV2_VERSION_TAG "|%u|%u", (unsigned)counter, (unsigned)expiry);
  // The AAD is the received fields, rebuilt: a counter written "007" would rebuild as
  // "7" and fail the tag, which is right -- the bytes signed are the bytes sent.
  if (strlen(aad) != (size_t)(f[3] - 1 - payload) || memcmp(aad, payload, strlen(aad)) != 0) {
    return MQTTCTRL_ERR_BAD_FIELDS;
  }
  if (!mqttV2Open(key, MQTTV2_DIR_COMMAND, counter, aad, sealed, n, (uint8_t *) text)) {
    return MQTTCTRL_ERR_SIG_INVALID;
  }
  size_t plain = n - MQTTV2_TAG_LEN;
  size_t cmd_len = plain;
  while (cmd_len > 0 && text[cmd_len - 1] == 0) cmd_len--;
  text[cmd_len] = 0;

  memset(env, 0, sizeof(*env));
  env->counter = counter;
  env->expiry = expiry;
  env->command = text;
  env->command_len = cmd_len;
  return MQTTCTRL_OK;
}

// ---- the result -----------------------------------------------------------------------

// r3|<counter>|<b64url(ct||tag)>; the reply is cut so the plaintext fits 512.
static inline size_t mqttV2BuildResult(const uint8_t key[MQTTV2_KEY_LEN], uint32_t counter,
                                       int code, const char* command, const char* reply,
                                       char* out, size_t out_size) {
  char line[MQTTV2_RES_PAD_LARGE + 1];
  int n = snprintf(line, sizeof(line), "%d|%s|%s", code, command ? command : "", reply ? reply : "");
  if (n < 0) return 0;
  size_t len = (size_t)n < MQTTV2_RES_PAD_LARGE ? (size_t)n : MQTTV2_RES_PAD_LARGE;
  uint8_t plain[MQTTV2_RES_PAD_LARGE] = {0};
  memcpy(plain, line, len);
  size_t padded = mqttV2PadTo(len, MQTTV2_RES_PAD_SMALL, MQTTV2_RES_PAD_LARGE);

  char aad[16];
  snprintf(aad, sizeof(aad), MQTTV2_RESULT_TAG "|%u", (unsigned)counter);
  uint8_t sealed[MQTTV2_RES_PAD_LARGE + MQTTV2_TAG_LEN];
  mqttV2Seal(key, MQTTV2_DIR_RESULT, counter, aad, plain, padded, sealed);
  int h = snprintf(out, out_size, "%s|", aad);
  if (h <= 0 || (size_t)h >= out_size) return 0;
  size_t b = mqttV2B64Encode(sealed, padded + MQTTV2_TAG_LEN, out + h, out_size - h);
  return b == 0 ? 0 : (size_t)h + b;
}

// What a tool does with an r3: the plaintext, padding stripped, into `text` (at least
// MQTTV2_RES_PAD_LARGE + 1 bytes). False for anything that is not an r3 this key sealed.
static inline bool mqttV2OpenResult(const uint8_t key[MQTTV2_KEY_LEN], const char* line,
                                    uint32_t* counter, char* text) {
  if (line == NULL || strncmp(line, MQTTV2_RESULT_TAG "|", 3) != 0) return false;
  const char* c = line + 3;
  const char* sep = strchr(c, MQTTCTRL_FIELD_SEP);
  if (sep == NULL || !mqttCtrlParseU32(c, (size_t)(sep - c), counter)) return false;
  uint8_t sealed[MQTTV2_RES_PAD_LARGE + MQTTV2_TAG_LEN];
  size_t n = mqttV2B64Decode(sep + 1, strlen(sep + 1), sealed, sizeof(sealed));
  if (n != MQTTV2_RES_PAD_SMALL + MQTTV2_TAG_LEN && n != MQTTV2_RES_PAD_LARGE + MQTTV2_TAG_LEN) {
    return false;
  }
  char aad[16];
  snprintf(aad, sizeof(aad), MQTTV2_RESULT_TAG "|%u", (unsigned)*counter);
  if (!mqttV2Open(key, MQTTV2_DIR_RESULT, *counter, aad, sealed, n, (uint8_t *) text)) return false;
  size_t len = n - MQTTV2_TAG_LEN;
  while (len > 0 && text[len - 1] == 0) len--;
  text[len] = 0;
  return true;
}
