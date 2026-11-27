#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ChaChaPoly.h>
#include <HKDF.h>
#include <SHA256.h>

#include "MqttControlV3.h"

// The announce (lou-21): a node without Wi-Fi tells its owner that it exists, over the mesh,
// and any Observer node that hears it hands it to the command server, which keeps the newest
// of each node for the owner's tool to find (docs/mqtt-control.md, "Announcing"). An alive message cannot do it: such a node has no MQTT.
//
// It is an ANON_REQ flooded inside a region, 165 bytes of payload, which every repeater that
// holds the region forwards without reading:
//
//   0    1   the first byte of the node's key, where ANON_REQ has its destination hash
//   1   32   the node's key, where ANON_REQ has its sender
//   33   1   kind 0x4D
//   34   4   owner tag: SHA-256("mcc3/own|", command key, node key, boot, sequence)[0:4]
//   38   4   boot
//   42   4   sequence since boot, from 1
//   46  47   sealed under K_malive, nonce 00 x 4 | boot | sequence, AAD bytes 1..45:
//            uptime, clock, last command counter, flags, battery (mV, 0 for none),
//            version (length, at most 14), name (length, at most 16), zeros
//   93   8   the seal's tag, its first 8 bytes
//  101  64   Ed25519 by the node's identity over "mcc3/ann|" | bytes 1..100
//
//   K_malive  HKDF-SHA256(S, salt empty, "mcc3/malive/" + KEY)   S and KEY as MqttControlV3.h
//
// The nonce is a counter, so K_malive seals nothing else and (boot, sequence) never repeats.
// The signature lets anyone check that the node made the announce, the catching node first of
// all; who owns the node stays hidden, since the owner tag and the seal need the owner's key.
// The owner tag lets the owner's tool find its own nodes with one hash each, and anyone who
// knows the owner's public key can make one: the tag sorts, it proves nothing.
//
// Nothing here draws randomness, reads a clock or touches the node's state.

#define MALIVE_KIND            0x4D
#define MALIVE_PAYLOAD         165
#define MALIVE_AT_KIND         33
#define MALIVE_AT_OWNER_TAG    34
#define MALIVE_AT_BOOT         38
#define MALIVE_AT_SEQUENCE     42
#define MALIVE_AT_SEALED       46
#define MALIVE_SEALED          47
#define MALIVE_TAG_LEN         8
#define MALIVE_AT_SIG          (MALIVE_AT_SEALED + MALIVE_SEALED + MALIVE_TAG_LEN)
#define MALIVE_SIGNED          (MALIVE_AT_SIG - 1)
#define MALIVE_SIG_LABEL       "mcc3/ann|"
#define MALIVE_AAD_LEN         (MALIVE_AT_SEALED - 1)
#define MALIVE_MAX_VERSION     14
#define MALIVE_MAX_NAME        16
#define MALIVE_LABEL           "mcc3/malive/"
#define MALIVE_OWNER_LABEL     "mcc3/own|"
// The transport codes a scoped flood adds to the packet, which Packet::getRawLength counts
// only once the route is set.
#define MALIVE_TRANSPORT_BYTES 4

// The node's identity signs; anyone may verify (Mcc3Verifier, with the node's key).
typedef void (*MeshAliveSigner)(void* ctx, uint8_t sig[MCC3_SIG_LEN], const uint8_t* msg, size_t len);

struct MeshAlive {
  uint32_t boot;            // persisted, +1 every boot
  uint32_t sequence;        // since boot, from 1
  uint32_t uptime;          // seconds
  uint32_t clock;           // unix seconds, 0 while unset
  uint32_t last_counter;
  uint8_t flags;            // MCC3_ALIVE_*
  uint16_t battery_mv;      // 0 when the board cannot read it
  const char* version;
  const char* name;
};

struct MeshAliveOpened {
  uint8_t node_key[32];
  uint32_t boot, sequence, uptime, clock, last_counter;
  uint8_t flags;
  uint16_t battery_mv;
  char version[MALIVE_MAX_VERSION + 1];
  char name[MALIVE_MAX_NAME + 1];
};

static inline void meshAliveDeriveKey(const uint8_t shared[32], const char* label, const char* node_hex,
                                      uint8_t out[MCC3_KEY_LEN]) {
  char info[12 + 64 + 1];
  int n = snprintf(info, sizeof(info), "%s%s", label, node_hex);
  if (n < 0 || (size_t)n >= sizeof(info)) n = sizeof(info) - 1;
  hkdf<SHA256>(out, MCC3_KEY_LEN, shared, 32, NULL, 0, info, (size_t)n);
}

static inline void meshAliveOwnerTag(const uint8_t command_key[32], const uint8_t node_key[32],
                                     uint32_t boot, uint32_t sequence, uint8_t out[4]) {
  uint8_t counters[8], digest[32];
  mqttCtrlMeshPutU32(counters, boot);
  mqttCtrlMeshPutU32(counters + 4, sequence);
  SHA256 h;
  h.update(MALIVE_OWNER_LABEL, 9);
  h.update(command_key, 32);
  h.update(node_key, 32);
  h.update(counters, sizeof(counters));
  h.finalize(digest, sizeof(digest));
  memcpy(out, digest, 4);
}

static inline void meshAliveNonce(uint32_t boot, uint32_t sequence, uint8_t nonce[MCC3_NONCE_LEN]) {
  memset(nonce, 0, 4);
  mqttCtrlMeshPutU32(nonce + 4, boot);
  mqttCtrlMeshPutU32(nonce + 8, sequence);
}

// What the node's identity signs: the label, then bytes 1..100 of the announce.
static inline size_t meshAliveSignedBytes(const uint8_t* payload, uint8_t out[9 + MALIVE_SIGNED]) {
  memcpy(out, MALIVE_SIG_LABEL, 9);
  memcpy(out + 9, payload + 1, MALIVE_SIGNED);
  return 9 + MALIVE_SIGNED;
}

// The node's side: the 165 bytes of an ANON_REQ payload. The strings are cut on a character
// boundary.
static inline void meshAliveBuild(const uint8_t key[MCC3_KEY_LEN], const uint8_t command_key[32],
                                  const uint8_t node_key[32], const MeshAlive* a, MeshAliveSigner sign,
                                  void* sign_ctx, uint8_t out[MALIVE_PAYLOAD]) {
  memset(out, 0, MALIVE_PAYLOAD);
  out[0] = node_key[0];
  memcpy(out + 1, node_key, 32);
  out[MALIVE_AT_KIND] = MALIVE_KIND;
  meshAliveOwnerTag(command_key, node_key, a->boot, a->sequence, out + MALIVE_AT_OWNER_TAG);
  mqttCtrlMeshPutU32(out + MALIVE_AT_BOOT, a->boot);
  mqttCtrlMeshPutU32(out + MALIVE_AT_SEQUENCE, a->sequence);
  uint8_t* p = out + MALIVE_AT_SEALED;
  mqttCtrlMeshPutU32(p, a->uptime);
  mqttCtrlMeshPutU32(p + 4, a->clock);
  mqttCtrlMeshPutU32(p + 8, a->last_counter);
  p[12] = a->flags;
  p[13] = (uint8_t)(a->battery_mv & 0xFF);
  p[14] = (uint8_t)(a->battery_mv >> 8);
  size_t at = 15;
  at += mcc3AlivePutString(p + at, a->version, MALIVE_MAX_VERSION, false);
  mcc3AlivePutString(p + at, a->name, MALIVE_MAX_NAME, false);

  uint8_t nonce[MCC3_NONCE_LEN];
  meshAliveNonce(a->boot, a->sequence, nonce);
  ChaChaPoly c;
  c.setKey(key, MCC3_KEY_LEN);
  c.setIV(nonce, sizeof(nonce));
  c.addAuthData(out + 1, MALIVE_AAD_LEN);
  c.encrypt(p, p, MALIVE_SEALED);
  c.computeTag(out + MALIVE_AT_SEALED + MALIVE_SEALED, MALIVE_TAG_LEN);
  c.clear();
  uint8_t msg[9 + MALIVE_SIGNED];
  sign(sign_ctx, out + MALIVE_AT_SIG, msg, meshAliveSignedBytes(out, msg));
}

// What a catching node tests before anything else: the size and the kind byte.
static inline bool meshAliveIsAnnounce(const uint8_t* payload, size_t len) {
  return payload != NULL && len == MALIVE_PAYLOAD && payload[MALIVE_AT_KIND] == MALIVE_KIND;
}

// Then the signature, by the key the announce names. `verify` is called with that key's
// bytes as they are in the payload.
static inline bool meshAliveSignatureOk(const uint8_t* payload, Mcc3Verifier verify, void* ctx) {
  uint8_t msg[9 + MALIVE_SIGNED];
  return verify(ctx, payload + MALIVE_AT_SIG, msg, meshAliveSignedBytes(payload, msg));
}

// Whether an announce carries the tag of this command key.
static inline bool meshAliveForOwner(const uint8_t* payload, const uint8_t command_key[32]) {
  uint8_t tag[4];
  meshAliveOwnerTag(command_key, payload + 1, mqttCtrlMeshU32(payload + MALIVE_AT_BOOT),
                    mqttCtrlMeshU32(payload + MALIVE_AT_SEQUENCE), tag);
  return memcmp(tag, payload + MALIVE_AT_OWNER_TAG, 4) == 0;
}

// The owner's side, for the host suite and the vectors: false for what is no announce, is
// not signed by the node it names, has another owner's tag, does not open under this node's
// K_malive, or names a string longer than its field.
static inline bool meshAliveOpen(const uint8_t key[MCC3_KEY_LEN], const uint8_t command_key[32],
                                 const uint8_t* payload, size_t len, Mcc3Verifier verify, void* verify_ctx,
                                 MeshAliveOpened* out) {
  if (!meshAliveIsAnnounce(payload, len) || payload[0] != payload[1]
      || !meshAliveSignatureOk(payload, verify, verify_ctx) || !meshAliveForOwner(payload, command_key)) {
    return false;
  }
  const uint32_t boot = mqttCtrlMeshU32(payload + MALIVE_AT_BOOT);
  const uint32_t sequence = mqttCtrlMeshU32(payload + MALIVE_AT_SEQUENCE);
  uint8_t nonce[MCC3_NONCE_LEN], p[MALIVE_SEALED];
  meshAliveNonce(boot, sequence, nonce);
  ChaChaPoly c;
  c.setKey(key, MCC3_KEY_LEN);
  c.setIV(nonce, sizeof(nonce));
  c.addAuthData(payload + 1, MALIVE_AAD_LEN);
  c.decrypt(p, payload + MALIVE_AT_SEALED, MALIVE_SEALED);
  const bool ok = c.checkTag(payload + MALIVE_AT_SEALED + MALIVE_SEALED, MALIVE_TAG_LEN);
  c.clear();
  const size_t version_len = p[15];
  if (!ok || version_len > MALIVE_MAX_VERSION || p[16 + version_len] > MALIVE_MAX_NAME) {
    memset(p, 0, sizeof(p));
    return false;
  }
  const size_t name_len = p[16 + version_len];
  memcpy(out->node_key, payload + 1, 32);
  out->boot = boot;
  out->sequence = sequence;
  out->uptime = mqttCtrlMeshU32(p);
  out->clock = mqttCtrlMeshU32(p + 4);
  out->last_counter = mqttCtrlMeshU32(p + 8);
  out->flags = p[12];
  out->battery_mv = (uint16_t)(p[13] | (p[14] << 8));
  memcpy(out->version, p + 16, version_len);
  out->version[version_len] = 0;
  memcpy(out->name, p + 17 + version_len, name_len);
  out->name[name_len] = 0;
  return true;
}

// ---- when a node announces -------------------------------------------------------------
//
// 5 to 60 s after the node is ready to (it has started, or was given its command key, its
// `cmd on` or a region since), then every 23 hours with a tenth either way, so that nodes
// started together drift apart. A fixed number: at SF8 and 62.5 kHz an announce is about
// 1.6 s on the air for the node and for every repeater that forwards it. millis(), and its
// wrap.
#define MALIVE_SOON_MIN_MS     5000UL
#define MALIVE_SOON_MAX_MS     60000UL
#define MALIVE_INTERVAL_MS     (23UL * 3600UL * 1000UL)
#define MALIVE_SPREAD_MS       (MALIVE_INTERVAL_MS / 10)

struct MeshAliveClock {
  uint32_t due_ms;
  bool armed;
  bool ready;           // as last seen
};

// True when the node has just become ready to announce, or its command key changed while
// it was: the caller then brings the next announce close (meshAliveSoon).
static inline bool meshAliveBecameReady(MeshAliveClock* c, bool ready, bool key_changed) {
  const bool became = ready && (!c->ready || key_changed);
  c->ready = ready;
  return became;
}

// Brings the next announce close, and never puts one off.
static inline void meshAliveSoon(MeshAliveClock* c, uint32_t now_ms, uint32_t rnd) {
  const uint32_t at = now_ms + MALIVE_SOON_MIN_MS + rnd % (MALIVE_SOON_MAX_MS - MALIVE_SOON_MIN_MS + 1);
  if (!c->armed || (int32_t)(at - c->due_ms) < 0) c->due_ms = at;
  c->armed = true;
}

static inline bool meshAliveDue(const MeshAliveClock* c, uint32_t now_ms) {
  return c->armed && c->ready && (int32_t)(now_ms - c->due_ms) >= 0;
}

// An announce that was due and could not go out is tried again in a minute.
static inline void meshAliveLater(MeshAliveClock* c, uint32_t now_ms) {
  c->due_ms = now_ms + MALIVE_SOON_MAX_MS;
}

// The next announce in `interval_ms`, a tenth either way: 23 hours, or 12 for a node whose
// reports an Observer node nearby acks (MeshReportLogic.h).
static inline void meshAliveSentIn(MeshAliveClock* c, uint32_t now_ms, uint32_t interval_ms, uint32_t rnd) {
  const uint32_t spread = interval_ms / 10;
  c->due_ms = now_ms + interval_ms - spread + rnd % (2 * spread + 1);
  c->armed = true;
}

static inline void meshAliveSent(MeshAliveClock* c, uint32_t now_ms, uint32_t rnd) {
  meshAliveSentIn(c, now_ms, MALIVE_INTERVAL_MS, rnd);
}

// ---- the catching node -----------------------------------------------------------------
//
// Every Observer node on the plane that hears an announce signed by the node it names hands
// it to the command server, whoever owns the node, and keeps nothing about the node. It is
// published once, not retained, on `mcc/seen/<the Observer node's key>`:
//
//   base64url( 0x53 | the announce's bytes 1..164 | SNR i8, quarter dB | hops u8 | via u8 )
//
// `via` says how it came: a zero-hop state packet, a direct packet along a path, or a flood.
// The server adds the time it arrived, since the Observer node's clock is not trusted. While
// the server cannot be reached up to 8 wait in RAM, the oldest giving way, and are lost at a
// restart; at most one goes every 2 s. A (node key, boot, sequence) forwarded in the last
// 10 minutes is not forwarded again: the copies of a flood by other paths, and the tries of
// one report.
#define MALIVE_KIND_SEEN       0x53
#define MALIVE_VIA_ZERO_HOP    0
#define MALIVE_VIA_DIRECT      1
#define MALIVE_VIA_FLOOD       2
#define MALIVE_SEEN_SIZE       (1 + MALIVE_PAYLOAD - 1 + 3)
#define MALIVE_SEEN_B64        MQTTV2_B64_LEN(MALIVE_SEEN_SIZE)
#define MALIVE_SEEN_QUEUE      8
#define MALIVE_SEEN_GAP_MS     2000UL
#define MALIVE_RECENT          8
#define MALIVE_RECENT_SECS     600

static inline void meshAliveBuildSeen(const uint8_t announce[MALIVE_PAYLOAD], int8_t snr, uint8_t hops,
                                      uint8_t via, uint8_t out[MALIVE_SEEN_SIZE]) {
  out[0] = MALIVE_KIND_SEEN;
  memcpy(out + 1, announce + 1, MALIVE_PAYLOAD - 1);
  out[MALIVE_PAYLOAD] = (uint8_t)snr;
  out[MALIVE_PAYLOAD + 1] = hops;
  out[MALIVE_PAYLOAD + 2] = via;
}

// `mcc/seen/<the Observer node's key>`.
static inline bool meshAliveSeenTopic(const char* node_hex, char* out, size_t out_size) {
  return mcc3Topic("seen", node_hex, out, out_size);
}

// The server's side, for the host suite and the vectors: the announce as it was on the air,
// and what the Observer node said of it. False for what is not such a message.
static inline bool meshAliveOpenSeen(const char* payload, size_t len, uint8_t announce[MALIVE_PAYLOAD],
                                     int8_t* snr, uint8_t* hops, uint8_t* via) {
  uint8_t raw[MALIVE_SEEN_SIZE];
  if (payload == NULL || mqttV2B64Decode(payload, len, raw, sizeof(raw)) != MALIVE_SEEN_SIZE
      || raw[0] != MALIVE_KIND_SEEN || raw[MALIVE_PAYLOAD + 2] > MALIVE_VIA_FLOOD) {
    return false;
  }
  announce[0] = raw[1];
  memcpy(announce + 1, raw + 1, MALIVE_PAYLOAD - 1);
  *snr = (int8_t)raw[MALIVE_PAYLOAD];
  *hops = raw[MALIVE_PAYLOAD + 1];
  *via = raw[MALIVE_PAYLOAD + 2];
  return true;
}

// The announces forwarded in the last ten minutes, by the first 4 bytes of the node's key,
// boot and sequence: a window, not a table of nodes. `now_secs` is any clock that only moves
// forward (the uptime).
struct MeshAliveRecent {
  uint8_t key[MALIVE_RECENT][4];
  uint32_t boot[MALIVE_RECENT], sequence[MALIVE_RECENT], at[MALIVE_RECENT];
  uint8_t used, next;
};

// True, and remembered, for an announce not forwarded in the window.
static inline bool meshAliveRecentFresh(MeshAliveRecent* r, const uint8_t* announce, uint32_t now_secs) {
  const uint32_t boot = mqttCtrlMeshU32(announce + MALIVE_AT_BOOT);
  const uint32_t sequence = mqttCtrlMeshU32(announce + MALIVE_AT_SEQUENCE);
  for (uint8_t i = 0; i < r->used; i++) {
    if (memcmp(r->key[i], announce + 1, 4) == 0 && r->boot[i] == boot && r->sequence[i] == sequence
        && now_secs - r->at[i] < MALIVE_RECENT_SECS) {
      return false;
    }
  }
  const uint8_t i = r->next;
  memcpy(r->key[i], announce + 1, 4);
  r->boot[i] = boot;
  r->sequence[i] = sequence;
  r->at[i] = now_secs;
  r->next = (uint8_t)((i + 1) % MALIVE_RECENT);
  if (r->used < MALIVE_RECENT) r->used++;
  return true;
}

// What waits for the server, oldest first; a full queue drops its oldest.
struct MeshAliveSeenQueue {
  uint8_t item[MALIVE_SEEN_QUEUE][MALIVE_SEEN_SIZE];
  uint8_t head, count;
  uint32_t dropped;
};

static inline void meshAliveSeenPush(MeshAliveSeenQueue* q, const uint8_t item[MALIVE_SEEN_SIZE]) {
  if (q->count == MALIVE_SEEN_QUEUE) {
    q->head = (uint8_t)((q->head + 1) % MALIVE_SEEN_QUEUE);
    q->count--;
    q->dropped++;
  }
  memcpy(q->item[(q->head + q->count) % MALIVE_SEEN_QUEUE], item, MALIVE_SEEN_SIZE);
  q->count++;
}

static inline const uint8_t* meshAliveSeenFront(const MeshAliveSeenQueue* q) {
  return q->count == 0 ? NULL : q->item[q->head];
}

static inline void meshAliveSeenPop(MeshAliveSeenQueue* q) {
  if (q->count == 0) return;
  q->head = (uint8_t)((q->head + 1) % MALIVE_SEEN_QUEUE);
  q->count--;
}

// Whether the next may go: the first at once, then one in 2 s. millis(), and its wrap.
static inline bool meshAliveSeenDue(bool published_before, uint32_t last_ms, uint32_t now_ms) {
  return !published_before || now_ms - last_ms >= MALIVE_SEEN_GAP_MS;
}
