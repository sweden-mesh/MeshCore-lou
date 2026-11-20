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
//   K_fwd    HKDF-SHA256(S, salt empty, "mcc3/fwd/"   + KEY)   forwards through this node, and their results
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
#define MCC3_KIND_FORWARD      0x46
#define MCC3_KIND_FWD_RESULT   0x66

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
// One flag: answer with a single transmission and no path, for a sender that heard this
// node directly. Every other bit is refused; bit 0 stays reserved for delegation.
#define MCC3_MESH_SUBTYPE      0xC2
#define MCC3_MESH_FLAG_ZERO_HOP 0x02
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
  uint8_t fwd[MCC3_KEY_LEN];
};

// A command that opened and verified, on either road.
struct Mcc3Command {
  uint32_t tag;                              // the mesh road's companion tag, echoed back
  uint8_t flags;                             // the mesh road's: 0 or MCC3_MESH_FLAG_ZERO_HOP
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
  static const char* const labels[4] = { "mcc3/cmd/", "mcc3/mesh/", "mcc3/alive/", "mcc3/fwd/" };
  uint8_t* out[4] = { keys->cmd, keys->mesh, keys->alive, keys->fwd };
  char info[12 + 64 + 1];
  for (int i = 0; i < 4; i++) {
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
  out->flags = 0;
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
// (bad-fields), no flag but the zero-hop one (bad-version), a command key (`keys` NULL:
// no-owner-key), a counter above the last accepted (replay, before anything is decrypted),
// the command field (command-chars), the signature over the flags as they arrived
// (sig-invalid). The node reads the first 136 bytes and ignores the cipher's block padding
// after them.
static inline MqttCtrlResult mcc3MeshOpen(const Mcc3Keys* keys, const uint8_t node_key[32],
                                          uint32_t last_counter, const uint8_t* data, size_t len,
                                          Mcc3Verifier verify, void* ctx, Mcc3Command* out) {
  if (len < MCC3_MESH_REQUEST || data[4] != MCC3_MESH_SUBTYPE) return MQTTCTRL_ERR_BAD_FIELDS;
  if ((data[5] & ~MCC3_MESH_FLAG_ZERO_HOP) != 0) return MQTTCTRL_ERR_BAD_VERSION;
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
  out->flags = data[5];
  out->counter = counter;
  out->expiry = mqttCtrlMeshU32(plain);
  memset(out->rid, 0, MCC3_RID_LEN);
  memcpy(out->command, field, cmd_len);
  out->command[cmd_len] = 0;
  out->command_len = cmd_len;

  uint8_t msg[MCC3_MAX_SIGNED];
  size_t m = mcc3SignedBytes(node_key, MCC3_ROAD_MESH, out->flags, counter, out->expiry, NULL,
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
                                        Mcc3Signer sign, void* ctx, uint8_t out[MCC3_MESH_REQUEST],
                                        uint8_t flags = 0) {
  size_t cmd_len = strlen(command);
  if (cmd_len > MCC3_MESH_MAX_COMMAND || !mqttCtrlCommandCharsOk(command, cmd_len)) return false;
  memset(out, 0, MCC3_MESH_REQUEST);
  mqttCtrlMeshPutU32(out, tag);
  out[4] = MCC3_MESH_SUBTYPE;
  out[5] = flags;
  mqttCtrlMeshPutU32(&out[6], counter);
  uint8_t* plain = out + MCC3_MESH_HEAD;
  mqttCtrlMeshPutU32(plain, expiry);
  uint8_t msg[MCC3_MAX_SIGNED];
  size_t m = mcc3SignedBytes(node_key, MCC3_ROAD_MESH, flags, counter, expiry, NULL, command, cmd_len, msg);
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
#define MCC3_ALIVE_RELAY       0x10    // relays for its owner (`mqtt.relay own`, an Observer image)

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

// ---- the relay ------------------------------------------------------------------------
//
// A forward (kind 'F') arrives on the relay's own `mcc/cmd/<KEY>`, 278 bytes as the larger
// command is, and is told from a command by the kind byte before any key is used. It holds
// a mesh request for another node, the target, from its sub-type byte on: exactly what a
// companion is handed. The relay sends it as its own anonymous request and publishes what
// comes back as a forward result (kind 'f') on the reply topic the forward names. Both are
// sealed under K_fwd and that is their whole proof: a forward runs nothing on the relay,
// and the request inside carries the owner's signature for the target.
//
//   forward  kind, flags, nonce (the AAD) | counter, expiry, RID, target key, route, path
//            length, path (57), body length, body (132) | tag
//   result   kind, nonce (the AAD) | counter, status, clock, sent, SNR, path length, path (64),
//            response length, response (167), zeros to 256 | tag
#define MCC3_FWD_HEAD          (2 + MCC3_NONCE_LEN)
#define MCC3_FWD_PATH          57
#define MCC3_FWD_BODY          (MCC3_MESH_REQUEST - 4)
#define MCC3_FWD_MIN_BODY      (MQTTCTRL_MESH_HEAD - 4 + 1)    // a 0xC1 request of a one-byte command
#define MCC3_FWD_PLAIN         (4 + 4 + MCC3_RID_LEN + 32 + 1 + 1 + MCC3_FWD_PATH + 1 + MCC3_FWD_BODY)
#define MCC3_FWD_SIZE          (MCC3_FWD_HEAD + MCC3_FWD_PLAIN + MCC3_TAG_LEN)
#define MCC3_FWD_B64           MQTTV2_B64_LEN(MCC3_FWD_SIZE)
#define MCC3_FWD_RES_PLAIN     256
#define MCC3_FWD_RES_PATH      64
#define MCC3_FWD_RES_RESPONSE  167
#define MCC3_FWD_RES_SIZE      (1 + MCC3_NONCE_LEN + MCC3_FWD_RES_PLAIN + MCC3_TAG_LEN)
#define MCC3_FWD_RES_B64       MQTTV2_B64_LEN(MCC3_FWD_RES_SIZE)

#define MCC3_ROUTE_DIRECT        0    // along the path the forward carries; no hops when it is empty
#define MCC3_ROUTE_FLOOD_HOME    1    // flooded in the relay's region home
#define MCC3_ROUTE_FLOOD_DEFAULT 2    // flooded in the relay's default scope
#define MCC3_SENT_NOTHING        0
#define MCC3_SENT_DIRECT         1
#define MCC3_SENT_FLOOD          2
#define MCC3_SNR_NONE            (-128)
#define MCC3_PATH_NONE           0xFF

// A relay refuses an expiry further ahead of its clock than this, and waits this long for
// the target's answer. Fixed, as the budget is (operator 2026-11-20).
#define MCC3_FWD_MAX_AHEAD_SECS  300
#define MCC3_FWD_WAIT_MS         120000UL

// The result's status. Appended, never renumbered: mccontrol reads them as numbers.
enum Mcc3ForwardStatus {
  MCC3_FWD_ANSWERED = 0,     // the response is in the result
  MCC3_FWD_NO_ANSWER,        // sent, and nothing came back in time; the target may have run it
  MCC3_FWD_OFF,              // `mqtt.relay off`
  MCC3_FWD_EXPIRED,          // expiry passed, or too far ahead
  MCC3_FWD_REPLAY,
  MCC3_FWD_BAD_BODY,         // body, route, path or target refused
  MCC3_FWD_BUSY,             // another forward is waiting
  MCC3_FWD_RATE_LIMITED,
  MCC3_FWD_CLOCK_UNSET,
  MCC3_FWD_SEND_FAILED,      // no packet could be built or queued
};
#define MCC3_FWD_SEND          (-1)   // mcc3RelayAdmit: nothing refuses it

struct Mcc3Forward {
  uint32_t counter;
  uint32_t expiry;
  uint8_t rid[MCC3_RID_LEN];
  uint8_t target[32];
  uint8_t route;
  uint8_t path_len;                          // MeshCore's: bits 6-7 hash size - 1, bits 0-5 hash count
  uint8_t path[MCC3_FWD_PATH];
  uint8_t body_len;
  uint8_t body[MCC3_FWD_BODY];
};

struct Mcc3ForwardResult {
  uint32_t counter;
  uint8_t status;                            // Mcc3ForwardStatus
  uint32_t clock;                            // unix seconds, 0 while unset
  uint8_t sent;                              // MCC3_SENT_*
  int8_t snr;                                // of the answer as the relay heard it, quarter-dB
  uint8_t path_len;                          // of the path the answer taught, relay to target
  uint8_t path[MCC3_FWD_RES_PATH];
  uint8_t response_len;
  uint8_t response[MCC3_FWD_RES_RESPONSE];   // the target's answer after its 4-byte tag
};

// The first byte of an mcc3 payload, 0 when it has none. No key is used.
static inline uint8_t mcc3PayloadKind(const char* payload, size_t len) {
  uint8_t head[3];
  if (payload == NULL || len < 4 || mqttV2B64Decode(payload, 4, head, sizeof(head)) != 3) return 0;
  return head[0];
}

// The bytes a path length stands for, or -1 for the reserved hash size.
static inline int mcc3PathBytes(uint8_t path_len) {
  const int size = (path_len >> 6) + 1;
  return size == 4 ? -1 : size * (path_len & 63);
}

// What a relay sends on: a whole 0xC2 request or a 0xC1 one with a command in it, by a
// route it knows, along a path that fits its field, to a node other than itself.
static inline bool mcc3ForwardBodyOk(const Mcc3Forward* f, const uint8_t node_key[32]) {
  if (f->body[0] == MCC3_MESH_SUBTYPE) {
    if (f->body_len != MCC3_FWD_BODY) return false;
  } else if (f->body[0] != MQTTCTRL_MESH_SUBTYPE || f->body_len < MCC3_FWD_MIN_BODY
             || f->body_len > MCC3_FWD_BODY) {
    return false;
  }
  if (f->route > MCC3_ROUTE_FLOOD_DEFAULT) return false;
  const int path_bytes = mcc3PathBytes(f->path_len);
  if (path_bytes < 0 || path_bytes > MCC3_FWD_PATH) return false;
  return memcmp(f->target, node_key, 32) != 0;
}

// The relay's side, the checks that need no state, every refusal silent: base64url of 278
// bytes with kind 'F' (bad-fields: not a forward), flags 0 (bad-version), a command key
// (`keys` NULL: no-owner-key), the AEAD under K_fwd (sig-invalid). What opens is the
// owner's, and every outcome after that is answered (mcc3RelayAdmit).
static inline MqttCtrlResult mcc3OpenForward(const Mcc3Keys* keys, const char* payload, size_t len,
                                             Mcc3Forward* out) {
  uint8_t raw[MCC3_FWD_SIZE];
  if (mqttV2B64Decode(payload, len, raw, sizeof(raw)) != MCC3_FWD_SIZE || raw[0] != MCC3_KIND_FORWARD) {
    return MQTTCTRL_ERR_BAD_FIELDS;
  }
  if (raw[1] != 0) return MQTTCTRL_ERR_BAD_VERSION;
  if (keys == NULL) return MQTTCTRL_ERR_NO_OWNER_KEY;
  uint8_t* p = raw + MCC3_FWD_HEAD;
  if (!mcc3Open(keys->fwd, raw + 2, raw, MCC3_FWD_HEAD, p, MCC3_FWD_PLAIN, p)) {
    return MQTTCTRL_ERR_SIG_INVALID;
  }
  out->counter = mqttCtrlMeshU32(p);
  out->expiry = mqttCtrlMeshU32(p + 4);
  memcpy(out->rid, p + 8, MCC3_RID_LEN);
  p += 8 + MCC3_RID_LEN;
  memcpy(out->target, p, 32);
  out->route = p[32];
  out->path_len = p[33];
  memcpy(out->path, p + 34, MCC3_FWD_PATH);
  p += 34 + MCC3_FWD_PATH;
  out->body_len = p[0];
  memcpy(out->body, p + 1, MCC3_FWD_BODY);
  memset(raw, 0, sizeof(raw));
  return MQTTCTRL_OK;
}

// The owner's side, for the host suite and the vectors: a forward the relay takes. `f->path`
// and `f->body` are zero beyond their lengths. 0 for one a relay would answer bad-body.
static inline size_t mcc3BuildForward(const Mcc3Keys* keys, const uint8_t relay_key[32],
                                      const uint8_t nonce[MCC3_NONCE_LEN], const Mcc3Forward* f,
                                      char* out, size_t out_size) {
  if (!mcc3ForwardBodyOk(f, relay_key)) return 0;
  uint8_t raw[MCC3_FWD_SIZE] = {0};
  raw[0] = MCC3_KIND_FORWARD;
  memcpy(raw + 2, nonce, MCC3_NONCE_LEN);
  uint8_t* plain = raw + MCC3_FWD_HEAD;
  uint8_t* p = plain;
  mqttCtrlMeshPutU32(p, f->counter);
  mqttCtrlMeshPutU32(p + 4, f->expiry);
  memcpy(p + 8, f->rid, MCC3_RID_LEN);
  p += 8 + MCC3_RID_LEN;
  memcpy(p, f->target, 32);
  p[32] = f->route;
  p[33] = f->path_len;
  memcpy(p + 34, f->path, MCC3_FWD_PATH);
  p += 34 + MCC3_FWD_PATH;
  p[0] = f->body_len;
  memcpy(p + 1, f->body, MCC3_FWD_BODY);
  mcc3Seal(keys->fwd, nonce, raw, MCC3_FWD_HEAD, plain, MCC3_FWD_PLAIN, plain);
  return mqttV2B64Encode(raw, sizeof(raw), out, out_size);
}

// What a relay remembers between forwards, in RAM only: a relay is on MQTT, so it has NTP,
// and the expiry bounds what a reboot reopens to one forward of the last 300 s, which the
// target's own counter then refuses.
struct Mcc3Relay {
  uint32_t last_counter = 0;                 // the last forward counter accepted
  bool waiting = false;                      // a forward is out and its answer has not come
  MqttCtrlRelayBudget budget;
  uint32_t forwarded = 0;                    // since boot, for `get mqtt.relay`
  uint32_t answered = 0;
  uint32_t refused = 0;
};

// Everything between a forward that opened and its transmission, in the order the owner is
// told of: the switch, the clock, the expiry (not passed, at most 300 s ahead), the counter,
// the body, a forward already waiting, the budget. The counter is taken once the expiry
// held and before the body is judged, so a refused forward cannot be sent again either.
// The budget is asked and not spent: mcc3RelaySent spends it for a request that went out.
// MCC3_FWD_SEND, or the status to answer with.
static inline int mcc3RelayAdmit(Mcc3Relay* r, uint8_t mode, uint32_t now, const Mcc3Forward* f,
                                 const uint8_t node_key[32]) {
  if (mode != MQTTCTRL_RELAY_OWN) return MCC3_FWD_OFF;
  if (now < MQTTConnectionPolicy::kSyncedClockEpoch) return MCC3_FWD_CLOCK_UNSET;
  if (f->expiry < now || f->expiry - now > MCC3_FWD_MAX_AHEAD_SECS) return MCC3_FWD_EXPIRED;
  if (!mqttCtrlCounterAccepted(r->last_counter, f->counter)) return MCC3_FWD_REPLAY;
  r->last_counter = f->counter;
  if (!mcc3ForwardBodyOk(f, node_key)) return MCC3_FWD_BAD_BODY;
  if (r->waiting) return MCC3_FWD_BUSY;
  if (!r->budget.allows(now, f->route != MCC3_ROUTE_DIRECT)) return MCC3_FWD_RATE_LIMITED;
  return MCC3_FWD_SEND;
}

static inline void mcc3RelaySent(Mcc3Relay* r, uint32_t now, bool flood) {
  r->budget.spend(now, flood);
  r->waiting = true;
  r->forwarded++;
}

// millis(), and its wrap.
static inline bool mcc3RelayWaitOver(uint32_t since_ms, uint32_t now_ms) {
  return now_ms - since_ms >= MCC3_FWD_WAIT_MS;
}

static inline void mcc3ForwardResultInit(Mcc3ForwardResult* r, uint32_t counter, uint8_t status) {
  memset(r, 0, sizeof(*r));
  r->counter = counter;
  r->status = status;
  r->snr = MCC3_SNR_NONE;
  r->path_len = MCC3_PATH_NONE;
}

// The target's answer, only when it begins with the tag the relay wrote: what follows the
// tag, as decrypted, so with the cipher's zero padding. That can run past the 167 bytes a
// datagram holds, and then only padding is cut.
static inline bool mcc3RelayTakeResponse(uint32_t tag, const uint8_t* data, size_t len,
                                         Mcc3ForwardResult* r) {
  if (data == NULL || len < 4 || mqttCtrlMeshU32(data) != tag) return false;
  size_t n = len - 4;
  if (n > MCC3_FWD_RES_RESPONSE) n = MCC3_FWD_RES_RESPONSE;
  r->response_len = (uint8_t)n;
  memcpy(r->response, data + 4, n);
  return true;
}

// The path a path return taught; none for an encoding the result's field cannot hold.
static inline void mcc3ForwardResultPath(Mcc3ForwardResult* r, uint8_t path_len, const uint8_t* path) {
  const int n = path_len == MCC3_PATH_NONE ? -1 : mcc3PathBytes(path_len);
  if (n < 0 || n > MCC3_FWD_RES_PATH || (n > 0 && path == NULL)) {
    r->path_len = MCC3_PATH_NONE;
    return;
  }
  r->path_len = path_len;
  if (n > 0) memcpy(r->path, path, n);
}

// What the relay publishes on `mcc/r/<RID>` for every outcome after the forward opened:
// one length whatever it says, under a fresh random nonce as every result is.
static inline size_t mcc3BuildForwardResult(const uint8_t key[MCC3_KEY_LEN],
                                            const uint8_t nonce[MCC3_NONCE_LEN],
                                            const Mcc3ForwardResult* r, char* out, size_t out_size) {
  uint8_t raw[MCC3_FWD_RES_SIZE] = {0};
  raw[0] = MCC3_KIND_FWD_RESULT;
  memcpy(raw + 1, nonce, MCC3_NONCE_LEN);
  uint8_t* p = raw + 1 + MCC3_NONCE_LEN;
  mqttCtrlMeshPutU32(p, r->counter);
  p[4] = r->status;
  mqttCtrlMeshPutU32(p + 5, r->clock);
  p[9] = r->sent;
  p[10] = (uint8_t)r->snr;
  p[11] = r->path_len;
  const int path_bytes = r->path_len == MCC3_PATH_NONE ? 0 : mcc3PathBytes(r->path_len);
  if (path_bytes > 0 && path_bytes <= MCC3_FWD_RES_PATH) memcpy(p + 12, r->path, path_bytes);
  const size_t n = r->response_len < MCC3_FWD_RES_RESPONSE ? r->response_len : MCC3_FWD_RES_RESPONSE;
  p[12 + MCC3_FWD_RES_PATH] = (uint8_t)n;
  memcpy(p + 13 + MCC3_FWD_RES_PATH, r->response, n);
  mcc3Seal(key, nonce, raw, 1 + MCC3_NONCE_LEN, p, MCC3_FWD_RES_PLAIN, p);
  size_t b = mqttV2B64Encode(raw, sizeof(raw), out, out_size);
  memset(raw, 0, sizeof(raw));
  return b;
}

// The owner's side, for the host suite and the vectors: bad-fields for what is not a forward
// result or names a path or a response its fields cannot hold, sig-invalid for one that does
// not open under this relay's K_fwd.
static inline MqttCtrlResult mcc3OpenForwardResult(const uint8_t key[MCC3_KEY_LEN], const char* payload,
                                                   size_t len, Mcc3ForwardResult* out) {
  uint8_t raw[MCC3_FWD_RES_SIZE];
  if (mqttV2B64Decode(payload, len, raw, sizeof(raw)) != MCC3_FWD_RES_SIZE
      || raw[0] != MCC3_KIND_FWD_RESULT) {
    return MQTTCTRL_ERR_BAD_FIELDS;
  }
  uint8_t* p = raw + 1 + MCC3_NONCE_LEN;
  if (!mcc3Open(key, raw + 1, raw, 1 + MCC3_NONCE_LEN, p, MCC3_FWD_RES_PLAIN, p)) {
    return MQTTCTRL_ERR_SIG_INVALID;
  }
  const int path_bytes = p[11] == MCC3_PATH_NONE ? 0 : mcc3PathBytes(p[11]);
  const size_t n = p[12 + MCC3_FWD_RES_PATH];
  if (path_bytes < 0 || path_bytes > MCC3_FWD_RES_PATH || n > MCC3_FWD_RES_RESPONSE) {
    return MQTTCTRL_ERR_BAD_FIELDS;
  }
  mcc3ForwardResultInit(out, mqttCtrlMeshU32(p), p[4]);
  out->clock = mqttCtrlMeshU32(p + 5);
  out->sent = p[9];
  out->snr = (int8_t)p[10];
  out->path_len = p[11];
  memcpy(out->path, p + 12, path_bytes);
  out->response_len = (uint8_t)n;
  memcpy(out->response, p + 13 + MCC3_FWD_RES_PATH, n);
  return MQTTCTRL_OK;
}
