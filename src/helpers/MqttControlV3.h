#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <ChaCha.h>
#include <ChaChaPoly.h>
#include <HKDF.h>
#include <SHA256.h>

#include "MqttControlLogic.h"
#include "MqttControlV2.h"        // base64url

// mcc3 (lou-20, IATA-2): the control plane keyed by the node and sealed to its owner. The
// contract is mccontrol-spec's docs/wire-format-mcc3.md, and its vectors are the host suite's
// (test/test_mqtt_v3, test/data/mcc3-vectors.json). No IATA in a topic, a key, a signature or
// a gate; one command key per node; no broadcast topic.
//
//   S        X25519(node identity, command key)      LocalIdentity::calcSharedSecret
//   K_cmd    HKDF-SHA256(S, salt empty, "mcc3/cmd/"   + KEY)   MQTT commands and results, mesh responses
//   K_mesh   HKDF-SHA256(S, salt empty, "mcc3/mesh/"  + KEY)   mesh requests: ChaCha20, no tag
//   K_alive  HKDF-SHA256(S, salt empty, "mcc3/alive/" + KEY)   alive messages
//   signed   "mcc3/sig|" node key, road, flags, counter, expiry, RID (MQTT only), command
//
// Both the AEAD and the owner's signature inside it are checked on the node: the broker is
// blind. Every integer is little-endian; MQTT payloads are base64url without padding, since
// the bridge hands the plane a C string. Every result and response is sealed under a fresh
// random nonce: a node answers a replay or a rate-limited command without consuming the
// counter, so a counter-derived nonce would repeat.
//
// Nothing here draws randomness or touches the node's state: the caller passes nonces, keys
// and the verifier, so the vectors can be rebuilt byte for byte.

#define MCC3_KEY_LEN           32
#define MCC3_NONCE_LEN         12
#define MCC3_TAG_LEN           16
#define MCC3_RID_LEN           16
#define MCC3_SIG_LEN           64
#define MCC3_SIG_LABEL         "mcc3/sig|"
#define MCC3_ROAD_MQTT         0x00
#define MCC3_ROAD_MESH         0x01
#define MCC3_KIND_COMMAND      0x43
#define MCC3_KIND_RESULT       0x52
#define MCC3_KIND_ALIVE        0x41

// MQTT command: kind, flags, nonce (the AAD) | counter, expiry, RID, signature, command | tag
#define MCC3_CMD_HEAD          (2 + MCC3_NONCE_LEN)
#define MCC3_CMD_FIELDS        (4 + 4 + MCC3_RID_LEN + MCC3_SIG_LEN)
#define MCC3_CMD_PAD_SMALL     64
#define MCC3_CMD_PAD_LARGE     160
#define MCC3_CMD_SIZE(pad)     (MCC3_CMD_HEAD + MCC3_CMD_FIELDS + (pad) + MCC3_TAG_LEN)
// result: kind, nonce (the AAD) | counter, code, clock, command length, command, reply | tag
#define MCC3_RES_HEAD          (1 + MCC3_NONCE_LEN)
#define MCC3_RES_FIELDS        (4 + 1 + 4 + 1)
#define MCC3_RES_PAD_SMALL     256
#define MCC3_RES_PAD_LARGE     512
#define MCC3_RES_SIZE(pad)     (MCC3_RES_HEAD + (pad) + MCC3_TAG_LEN)
#define MCC3_MAX_RESULT        (MQTTV2_B64_LEN(MCC3_RES_SIZE(MCC3_RES_PAD_LARGE)) + 1)
// alive: kind, nonce (the AAD) | 160 bytes | tag
#define MCC3_ALIVE_PLAIN       160
#define MCC3_ALIVE_SIZE        (1 + MCC3_NONCE_LEN + MCC3_ALIVE_PLAIN + MCC3_TAG_LEN)
#define MCC3_ALIVE_B64         MQTTV2_B64_LEN(MCC3_ALIVE_SIZE)
#define MCC3_ALIVE_MAX_VERSION 31
#define MCC3_ALIVE_MAX_REGION  29
#define MCC3_ALIVE_MAX_NAME    32
// The mesh road: an ANON_REQ of exactly the 136 bytes createAnonDatagram takes. The tag,
// sub-type, flags and counter are clear; expiry, signature and a 58-byte command field are
// ChaCha20 under K_mesh, with no tag: the signature inside is the integrity (operator
// decision 2026-11-18). The field always ends in a zero, so a command is 1..57 bytes.
#define MCC3_MESH_SUBTYPE      0xC2
#define MCC3_MESH_REQUEST      136
#define MCC3_MESH_HEAD         (4 + 1 + 1 + 4)
#define MCC3_MESH_FIELD        58
#define MCC3_MESH_MAX_COMMAND  (MCC3_MESH_FIELD - 1)
// response: companion tag, kind, nonce | counter, code, clock, reply | tag. Not padded.
#define MCC3_MESH_RESP_OVERHEAD (4 + 1 + MCC3_NONCE_LEN + 9 + MCC3_TAG_LEN)

// What the owner's key signs; the longest is an MQTT command of 160 bytes.
#define MCC3_MAX_SIGNED        (9 + 32 + 1 + 1 + 4 + 4 + MCC3_RID_LEN + MCC3_CMD_PAD_LARGE)

struct Mcc3Keys {
  uint8_t cmd[MCC3_KEY_LEN];
  uint8_t mesh[MCC3_KEY_LEN];
  uint8_t alive[MCC3_KEY_LEN];
};

// A command that opened and verified, on either road.
struct Mcc3Command {
  uint32_t tag;                              // the mesh road's companion tag, echoed back
  uint32_t counter;
  uint32_t expiry;
  uint8_t rid[MCC3_RID_LEN];                 // MQTT only: where the result goes
  char command[MCC3_CMD_PAD_LARGE + 1];
  size_t command_len;
};

// The owner's signature, checked by the caller's key (mesh::Identity::verify on the node).
typedef bool (*Mcc3Verifier)(void* ctx, const uint8_t sig[MCC3_SIG_LEN], const uint8_t* msg, size_t len);

static inline bool mcc3Topic(const char* kind, const char* node_hex, char* out, size_t out_size) {
  int n = snprintf(out, out_size, "mcc/%s/%s", kind, node_hex);
  return n > 0 && (size_t)n < out_size;
}

// `mcc/cmd/<KEY>`: the node subscribes to its own and nothing else under it.
static inline bool mcc3IsCommandTopic(const char* topic) {
  return topic != NULL && strncmp(topic, "mcc/cmd/", 8) == 0;
}

// `mcc/r/<RID>`, the RID in upper-case hex.
static inline bool mcc3ResultTopic(const uint8_t rid[MCC3_RID_LEN], char* out, size_t out_size) {
  static const char d[] = "0123456789ABCDEF";
  if (out_size < 6 + 2 * MCC3_RID_LEN + 1) return false;
  memcpy(out, "mcc/r/", 6);
  for (int i = 0; i < MCC3_RID_LEN; i++) {
    out[6 + 2 * i] = d[rid[i] >> 4];
    out[7 + 2 * i] = d[rid[i] & 15];
  }
  out[6 + 2 * MCC3_RID_LEN] = 0;
  return true;
}

// Once per command key: at boot and after `set mqtt.cmd.pubkey`, as the v2 key is.
static inline void mcc3DeriveKeys(const uint8_t shared[32], const char* node_hex, Mcc3Keys* keys) {
  static const char* const labels[3] = { "mcc3/cmd/", "mcc3/mesh/", "mcc3/alive/" };
  uint8_t* out[3] = { keys->cmd, keys->mesh, keys->alive };
  char info[12 + 64 + 1];
  for (int i = 0; i < 3; i++) {
    int n = snprintf(info, sizeof(info), "%s%s", labels[i], node_hex);
    hkdf<SHA256>(out[i], MCC3_KEY_LEN, shared, 32, NULL, 0, info, (size_t)n);
  }
}

static inline size_t mcc3SignedBytes(const uint8_t node_key[32], uint8_t road, uint8_t flags,
                                     uint32_t counter, uint32_t expiry, const uint8_t* rid,
                                     const char* command, size_t command_len, uint8_t* out) {
  size_t n = 0;
  memcpy(out, MCC3_SIG_LABEL, 9); n += 9;
  memcpy(out + n, node_key, 32); n += 32;
  out[n++] = road;
  out[n++] = flags;
  mqttCtrlMeshPutU32(out + n, counter); n += 4;
  mqttCtrlMeshPutU32(out + n, expiry); n += 4;
  if (rid != NULL) { memcpy(out + n, rid, MCC3_RID_LEN); n += MCC3_RID_LEN; }
  memcpy(out + n, command, command_len);
  return n + command_len;
}

// The longest prefix of `len` bytes that ends on a UTF-8 character boundary.
static inline size_t mcc3Utf8Cut(const char* s, size_t len, size_t limit) {
  if (len <= limit) return len;
  size_t n = limit;
  while (n > 0 && ((uint8_t)s[n] & 0xC0) == 0x80) n--;
  return n;
}

// The command in a zero-padded field, or 0 when the field holds none: empty, too long, a
// character the CLI must never see, or a non-zero byte after the padding began (which leaves
// a NUL inside what is left).
static inline size_t mcc3CommandIn(const uint8_t* field, size_t size, size_t max) {
  size_t n = size;
  while (n > 0 && field[n - 1] == 0) n--;
  if (n == 0 || n > max || !mqttCtrlCommandCharsOk((const char *)field, n)) return 0;
  return n;
}

// ---- the ciphers ----------------------------------------------------------------------

static inline void mcc3Seal(const uint8_t key[MCC3_KEY_LEN], const uint8_t nonce[MCC3_NONCE_LEN],
                            const uint8_t* aad, size_t aad_len, const uint8_t* plain, size_t len,
                            uint8_t* out) {
  ChaChaPoly c;
  c.setKey(key, MCC3_KEY_LEN);
  c.setIV(nonce, MCC3_NONCE_LEN);
  c.addAuthData(aad, aad_len);
  c.encrypt(out, plain, len);
  c.computeTag(out + len, MCC3_TAG_LEN);
  c.clear();
}

// `in` is the ciphertext and its tag, `len` the ciphertext alone; `out` may be `in`. False,
// and `out` wiped, when the tag fails.
static inline bool mcc3Open(const uint8_t key[MCC3_KEY_LEN], const uint8_t nonce[MCC3_NONCE_LEN],
                            const uint8_t* aad, size_t aad_len, const uint8_t* in, size_t len,
                            uint8_t* out) {
  ChaChaPoly c;
  c.setKey(key, MCC3_KEY_LEN);
  c.setIV(nonce, MCC3_NONCE_LEN);
  c.addAuthData(aad, aad_len);
  c.decrypt(out, in, len);
  bool ok = c.checkTag(in + len, MCC3_TAG_LEN);
  c.clear();
  if (!ok) memset(out, 0, len);
  return ok;
}

// RFC 8439 ChaCha20 under K_mesh from block 1, nonce 00 x 8 || counter: ChaCha20-Poly1305's
// ciphertext without its tag, so any library with the AEAD has it. Its own inverse.
static inline void mcc3MeshStream(const uint8_t key[MCC3_KEY_LEN], uint32_t counter,
                                  const uint8_t* in, size_t len, uint8_t* out) {
  uint8_t nonce[MCC3_NONCE_LEN] = {0};
  mqttCtrlMeshPutU32(&nonce[8], counter);
  static const uint8_t first_block[4] = { 1, 0, 0, 0 };
  ChaCha c;
  c.setKey(key, MCC3_KEY_LEN);
  c.setIV(nonce, sizeof(nonce));
  c.setCounter(first_block, sizeof(first_block));
  c.encrypt(out, in, len);
  c.clear();
}

// ---- the command on MQTT --------------------------------------------------------------

// The node's side, in the spec's order, every refusal silent: base64url of 182 or 278 bytes
// with kind 'C' (bad-fields), flags 0 (bad-version: the delegation bit is reserved), the AEAD
// (sig-invalid), the command field (command-chars), the owner's signature (sig-invalid).
// Replay, expiry, the deny list and the rate limit come after, as for every road.
static inline MqttCtrlResult mcc3OpenCommand(const Mcc3Keys* keys, const uint8_t node_key[32],
                                             const char* payload, size_t len, Mcc3Verifier verify,
                                             void* ctx, Mcc3Command* out) {
  uint8_t raw[MCC3_CMD_SIZE(MCC3_CMD_PAD_LARGE)];
  size_t n = mqttV2B64Decode(payload, len, raw, sizeof(raw));
  if ((n != MCC3_CMD_SIZE(MCC3_CMD_PAD_SMALL) && n != MCC3_CMD_SIZE(MCC3_CMD_PAD_LARGE))
      || raw[0] != MCC3_KIND_COMMAND) {
    return MQTTCTRL_ERR_BAD_FIELDS;
  }
  if (raw[1] != 0) return MQTTCTRL_ERR_BAD_VERSION;
  uint8_t* plain = raw + MCC3_CMD_HEAD;
  const size_t plain_len = n - MCC3_CMD_HEAD - MCC3_TAG_LEN;
  if (!mcc3Open(keys->cmd, raw + 2, raw, MCC3_CMD_HEAD, plain, plain_len, plain)) {
    return MQTTCTRL_ERR_SIG_INVALID;
  }
  const uint8_t* field = plain + MCC3_CMD_FIELDS;
  size_t cmd_len = mcc3CommandIn(field, plain_len - MCC3_CMD_FIELDS, MCC3_CMD_PAD_LARGE);
  if (cmd_len == 0) {
    memset(raw, 0, sizeof(raw));
    return MQTTCTRL_ERR_COMMAND_CHARS;
  }
  out->tag = 0;
  out->counter = mqttCtrlMeshU32(plain);
  out->expiry = mqttCtrlMeshU32(plain + 4);
  memcpy(out->rid, plain + 8, MCC3_RID_LEN);
  memcpy(out->command, field, cmd_len);
  out->command[cmd_len] = 0;
  out->command_len = cmd_len;

  uint8_t msg[MCC3_MAX_SIGNED];
  size_t m = mcc3SignedBytes(node_key, MCC3_ROAD_MQTT, 0, out->counter, out->expiry, out->rid,
                             out->command, cmd_len, msg);
  const bool ok = verify(ctx, plain + 8 + MCC3_RID_LEN, msg, m);
  memset(raw, 0, sizeof(raw));
  if (!ok) {
    memset(out, 0, sizeof(*out));
    return MQTTCTRL_ERR_SIG_INVALID;
  }
  return MQTTCTRL_OK;
}

typedef void (*Mcc3Signer)(void* ctx, uint8_t sig[MCC3_SIG_LEN], const uint8_t* msg, size_t len);

// The owner's side, for the host suite and the vectors: a command the node takes. 0 for a
// command no sender may build (empty, longer than 160, a character the rule refuses).
static inline size_t mcc3BuildCommand(const Mcc3Keys* keys, const uint8_t node_key[32],
                                      const uint8_t nonce[MCC3_NONCE_LEN], uint32_t counter,
                                      uint32_t expiry, const uint8_t rid[MCC3_RID_LEN],
                                      const char* command, Mcc3Signer sign, void* ctx,
                                      char* out, size_t out_size) {
  size_t cmd_len = strlen(command);
  if (!mqttCtrlCommandCharsOk(command, cmd_len)) return 0;
  const size_t pad = cmd_len <= MCC3_CMD_PAD_SMALL ? MCC3_CMD_PAD_SMALL : MCC3_CMD_PAD_LARGE;
  uint8_t raw[MCC3_CMD_SIZE(MCC3_CMD_PAD_LARGE)] = {0};
  raw[0] = MCC3_KIND_COMMAND;
  memcpy(raw + 2, nonce, MCC3_NONCE_LEN);
  uint8_t* plain = raw + MCC3_CMD_HEAD;
  mqttCtrlMeshPutU32(plain, counter);
  mqttCtrlMeshPutU32(plain + 4, expiry);
  memcpy(plain + 8, rid, MCC3_RID_LEN);
  uint8_t msg[MCC3_MAX_SIGNED];
  size_t m = mcc3SignedBytes(node_key, MCC3_ROAD_MQTT, 0, counter, expiry, rid, command, cmd_len, msg);
  sign(ctx, plain + 8 + MCC3_RID_LEN, msg, m);
  memcpy(plain + MCC3_CMD_FIELDS, command, cmd_len);
  const size_t plain_len = MCC3_CMD_FIELDS + pad;
  mcc3Seal(keys->cmd, nonce, raw, MCC3_CMD_HEAD, plain, plain_len, plain);
  return mqttV2B64Encode(raw, MCC3_CMD_SIZE(pad), out, out_size);
}

// ---- the result on MQTT ---------------------------------------------------------------

// What the node publishes on `mcc/r/<RID>` for every outcome after the command proved itself.
// The reply is cut, on a character boundary, so the whole fits 512.
static inline size_t mcc3BuildResult(const uint8_t key[MCC3_KEY_LEN],
                                     const uint8_t nonce[MCC3_NONCE_LEN], uint32_t counter, int code,
                                     uint32_t clock, const char* command, const char* reply,
                                     char* out, size_t out_size) {
  uint8_t raw[MCC3_RES_SIZE(MCC3_RES_PAD_LARGE)] = {0};
  raw[0] = MCC3_KIND_RESULT;
  memcpy(raw + 1, nonce, MCC3_NONCE_LEN);
  uint8_t* plain = raw + MCC3_RES_HEAD;
  size_t cmd_len = command != NULL ? strlen(command) : 0;
  if (cmd_len > MCC3_CMD_PAD_LARGE) cmd_len = MCC3_CMD_PAD_LARGE;
  mqttCtrlMeshPutU32(plain, counter);
  plain[4] = (uint8_t)code;
  mqttCtrlMeshPutU32(plain + 5, clock);
  plain[9] = (uint8_t)cmd_len;
  if (cmd_len > 0) memcpy(plain + MCC3_RES_FIELDS, command, cmd_len);
  size_t used = MCC3_RES_FIELDS + cmd_len;
  size_t reply_len = reply != NULL ? mcc3Utf8Cut(reply, strlen(reply), MCC3_RES_PAD_LARGE - used) : 0;
  if (reply_len > 0) memcpy(plain + used, reply, reply_len);
  used += reply_len;
  const size_t pad = used <= MCC3_RES_PAD_SMALL ? MCC3_RES_PAD_SMALL : MCC3_RES_PAD_LARGE;
  mcc3Seal(key, nonce, raw, MCC3_RES_HEAD, plain, pad, plain);
  size_t n = mqttV2B64Encode(raw, MCC3_RES_SIZE(pad), out, out_size);
  memset(raw, 0, sizeof(raw));
  return n;
}

// ---- the mesh road --------------------------------------------------------------------

static inline bool mcc3MeshIsRequest(const uint8_t* data, size_t len) {
  return data != NULL && len > 4 && data[4] == MCC3_MESH_SUBTYPE;
}

// The node's side, in the spec's order, every refusal silent: 136 bytes of sub-type 0xC2
// (bad-fields), flags 0 (bad-version), a command key (`keys` NULL: no-owner-key), a counter
// above the last accepted (replay, before anything is decrypted), the command field
// (command-chars), the signature (sig-invalid). The node reads the first 136 bytes and
// ignores the cipher's block padding after them.
static inline MqttCtrlResult mcc3MeshOpen(const Mcc3Keys* keys, const uint8_t node_key[32],
                                          uint32_t last_counter, const uint8_t* data, size_t len,
                                          Mcc3Verifier verify, void* ctx, Mcc3Command* out) {
  if (len < MCC3_MESH_REQUEST || data[4] != MCC3_MESH_SUBTYPE) return MQTTCTRL_ERR_BAD_FIELDS;
  if (data[5] != 0) return MQTTCTRL_ERR_BAD_VERSION;
  if (keys == NULL) return MQTTCTRL_ERR_NO_OWNER_KEY;
  const uint32_t counter = mqttCtrlMeshU32(&data[6]);
  if (!mqttCtrlCounterAccepted(last_counter, counter)) return MQTTCTRL_ERR_REPLAY;

  uint8_t plain[MCC3_MESH_REQUEST - MCC3_MESH_HEAD];
  mcc3MeshStream(keys->mesh, counter, &data[MCC3_MESH_HEAD], sizeof(plain), plain);
  const uint8_t* field = plain + 4 + MCC3_SIG_LEN;
  size_t cmd_len = mcc3CommandIn(field, MCC3_MESH_FIELD, MCC3_MESH_MAX_COMMAND);
  if (cmd_len == 0) {
    memset(plain, 0, sizeof(plain));
    return MQTTCTRL_ERR_COMMAND_CHARS;
  }
  out->tag = mqttCtrlMeshU32(data);
  out->counter = counter;
  out->expiry = mqttCtrlMeshU32(plain);
  memset(out->rid, 0, MCC3_RID_LEN);
  memcpy(out->command, field, cmd_len);
  out->command[cmd_len] = 0;
  out->command_len = cmd_len;

  uint8_t msg[MCC3_MAX_SIGNED];
  size_t m = mcc3SignedBytes(node_key, MCC3_ROAD_MESH, 0, counter, out->expiry, NULL,
                             out->command, cmd_len, msg);
  const bool ok = verify(ctx, plain + 4, msg, m);
  memset(plain, 0, sizeof(plain));
  if (!ok) {
    memset(out, 0, sizeof(*out));
    return MQTTCTRL_ERR_SIG_INVALID;
  }
  return MQTTCTRL_OK;
}

// The owner's side, for the host suite and the vectors: the 136 bytes, the companion's tag
// first. False for a command no sender may build on this road.
static inline bool mcc3MeshBuildRequest(const Mcc3Keys* keys, const uint8_t node_key[32], uint32_t tag,
                                        uint32_t counter, uint32_t expiry, const char* command,
                                        Mcc3Signer sign, void* ctx, uint8_t out[MCC3_MESH_REQUEST]) {
  size_t cmd_len = strlen(command);
  if (cmd_len > MCC3_MESH_MAX_COMMAND || !mqttCtrlCommandCharsOk(command, cmd_len)) return false;
  memset(out, 0, MCC3_MESH_REQUEST);
  mqttCtrlMeshPutU32(out, tag);
  out[4] = MCC3_MESH_SUBTYPE;
  mqttCtrlMeshPutU32(&out[6], counter);
  uint8_t* plain = out + MCC3_MESH_HEAD;
  mqttCtrlMeshPutU32(plain, expiry);
  uint8_t msg[MCC3_MAX_SIGNED];
  size_t m = mcc3SignedBytes(node_key, MCC3_ROAD_MESH, 0, counter, expiry, NULL, command, cmd_len, msg);
  sign(ctx, plain + 4, msg, m);
  memcpy(plain + 4 + MCC3_SIG_LEN, command, cmd_len);
  mcc3MeshStream(keys->mesh, counter, plain, MCC3_MESH_REQUEST - MCC3_MESH_HEAD, plain);
  return true;
}

// The response, sealed under K_cmd: the companion that carries it cannot read it. `room` is
// what the datagram or path return holds (mqttCtrlMeshResponseRoom); the reply is cut to fit,
// on a character boundary. 0 when not even the head fits.
static inline size_t mcc3MeshBuildResponse(const uint8_t key[MCC3_KEY_LEN],
                                           const uint8_t nonce[MCC3_NONCE_LEN], uint32_t tag,
                                           uint32_t counter, int code, uint32_t clock,
                                           const char* reply, size_t room, uint8_t* out) {
  if (room < MCC3_MESH_RESP_OVERHEAD) return 0;
  size_t reply_len = reply != NULL ? mcc3Utf8Cut(reply, strlen(reply), room - MCC3_MESH_RESP_OVERHEAD) : 0;
  mqttCtrlMeshPutU32(out, tag);
  out[4] = MCC3_KIND_RESULT;
  memcpy(out + 5, nonce, MCC3_NONCE_LEN);
  uint8_t* plain = out + 5 + MCC3_NONCE_LEN;
  mqttCtrlMeshPutU32(plain, counter);
  plain[4] = (uint8_t)code;
  mqttCtrlMeshPutU32(plain + 5, clock);
  if (reply_len > 0) memcpy(plain + 9, reply, reply_len);
  mcc3Seal(key, nonce, out + 4, 1 + MCC3_NONCE_LEN, plain, 9 + reply_len, plain);
  return MCC3_MESH_RESP_OVERHEAD + reply_len;
}

// ---- alive ----------------------------------------------------------------------------

// What a node tells its owner every interval (`mcc/alive/<KEY>`, retained): the owner's only
// discovery. Sealed and padded to one length, so nobody else learns which nodes share an
// owner. The strings are cut on a character boundary; the region is folded to lower case.
struct Mcc3Alive {
  uint32_t boot;            // persisted, +1 every boot
  uint32_t sequence;        // since boot, from 1
  uint32_t uptime;          // seconds
  uint32_t clock;           // unix seconds, 0 while unset
  uint32_t last_counter;
  uint32_t interval;        // seconds
  uint8_t flags;            // MCC3_ALIVE_*
  uint8_t mesh;             // mqtt.cmd.mesh: 0 off, 1 on, 2 auto
  uint8_t fingerprint[4];   // the command key's first 4 bytes
  uint8_t via;              // MqttCtrlKeyVia
  const char* version;
  const char* region;
  const char* name;
};

#define MCC3_ALIVE_OLD_SCHEME  0x01    // the IATA-keyed v1/v2 topic is taken too (lou-20)
#define MCC3_ALIVE_UPLINK      0x02    // an Observer image (Wi-Fi and MQTT)
#define MCC3_ALIVE_AUTO_REPLY  0x04
#define MCC3_ALIVE_CLOCK_SET   0x08

// The alive message's mesh byte from the plane's own mode numbering (MqttCtrlMeshMode).
static inline uint8_t mcc3AliveMeshMode(uint8_t mode) {
  return mode == MQTTCTRL_MESH_OFF ? 0 : mode == MQTTCTRL_MESH_ON ? 1 : 2;
}

static inline size_t mcc3AlivePutString(uint8_t* at, const char* s, size_t limit, bool fold) {
  size_t n = s != NULL ? mcc3Utf8Cut(s, strlen(s), limit) : 0;
  at[0] = (uint8_t)n;
  for (size_t i = 0; i < n; i++) at[1 + i] = fold ? (uint8_t)tolower((unsigned char)s[i]) : (uint8_t)s[i];
  return 1 + n;
}

static inline size_t mcc3BuildAlive(const uint8_t key[MCC3_KEY_LEN], const uint8_t nonce[MCC3_NONCE_LEN],
                                    const Mcc3Alive* a, char* out, size_t out_size) {
  uint8_t raw[MCC3_ALIVE_SIZE] = {0};
  raw[0] = MCC3_KIND_ALIVE;
  memcpy(raw + 1, nonce, MCC3_NONCE_LEN);
  uint8_t* p = raw + 1 + MCC3_NONCE_LEN;
  const uint32_t words[6] = { a->boot, a->sequence, a->uptime, a->clock, a->last_counter, a->interval };
  for (int i = 0; i < 6; i++) mqttCtrlMeshPutU32(p + 4 * i, words[i]);
  p[24] = a->flags;
  p[25] = a->mesh;
  memcpy(p + 26, a->fingerprint, 4);
  p[30] = a->via;
  size_t at = 32;
  at += mcc3AlivePutString(p + at, a->version, MCC3_ALIVE_MAX_VERSION, false);
  at += mcc3AlivePutString(p + at, a->region, MCC3_ALIVE_MAX_REGION, true);
  mcc3AlivePutString(p + at, a->name, MCC3_ALIVE_MAX_NAME, false);
  mcc3Seal(key, nonce, raw, 1 + MCC3_NONCE_LEN, p, MCC3_ALIVE_PLAIN, p);
  return mqttV2B64Encode(raw, sizeof(raw), out, out_size);
}
