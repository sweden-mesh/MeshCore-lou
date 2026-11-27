#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <ChaChaPoly.h>
#include <HKDF.h>
#include <SHA256.h>

#include "MqttControlV3.h"
#include "SlidingBudget.h"

// The announce (lou-21): a node without Wi-Fi tells its owner that it exists, over the mesh,
// and an Observer node of the same owner that hears it publishes it to the command server
// (docs/mqtt-control.md, "Announcing"). An alive message cannot do it: such a node has no MQTT.
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
//   K_heard   HKDF-SHA256(S, salt empty, "mcc3/heard/"  + KEY)   the catching node's S and KEY
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

static inline void meshAliveSent(MeshAliveClock* c, uint32_t now_ms, uint32_t rnd) {
  c->due_ms = now_ms + MALIVE_INTERVAL_MS - MALIVE_SPREAD_MS + rnd % (2 * MALIVE_SPREAD_MS + 1);
  c->armed = true;
}

// ---- the catching node -----------------------------------------------------------------
//
// It keeps the announces made for its own command key, the newest of each node, and
// publishes each sealed to the owner (K_heard) on a slot of its own. It cannot open one, so
// it cannot tell a real announce from one made by somebody who knows the owner's public
// key: the table is small, a new node key is admitted four times an hour, and what a forger
// fills it with the owner's tool drops, since it does not open.
//
// Kept of an announce: everything after the node's key, the tag and the signature with it,
// so that the owner can check and open what is published.
#define MALIVE_KEPT            (MALIVE_PAYLOAD - MALIVE_AT_KIND)
#define MALIVE_TABLE           16
#define MALIVE_NEW_MAX         4
#define MALIVE_NEW_WINDOW_SECS 3600
#define MALIVE_HEARD_LABEL     "mcc3/heard/"
#define MALIVE_KIND_HEARD      0x48
// published: kind, nonce (the AAD) | node key, the kept bytes, heard at, SNR, hops of the
// announce, the same three of the node's last advert | tag
#define MALIVE_HEARD_PLAIN     (32 + MALIVE_KEPT + 6 + 6)
#define MALIVE_HEARD_SIZE      (1 + MCC3_NONCE_LEN + MALIVE_HEARD_PLAIN + MCC3_TAG_LEN)
#define MALIVE_HEARD_B64       MQTTV2_B64_LEN(MALIVE_HEARD_SIZE)
// One publish at most in this long, whatever is heard: the newest of a slot is what goes.
#define MALIVE_PUBLISH_GAP_MS  90000UL

struct MeshAliveEntry {
  bool used;
  uint8_t node_key[32];
  uint8_t kept[MALIVE_KEPT];
  uint32_t heard_at;        // the catching node's clock, 0 while unset
  int8_t snr;               // quarter-dB
  uint8_t hops;
  uint32_t advert_heard_at; // the node's last advert: 0 for none heard
  int8_t advert_snr;
  uint8_t advert_hops;
  uint32_t order;           // of hearing: the lowest was heard longest ago
};

struct MeshAliveTable {
  MeshAliveEntry entry[MALIVE_TABLE];
  uint32_t heard;                                  // announces kept since boot
  SlidingBudgetOf<MALIVE_NEW_MAX> admitted;
  MeshAliveTable() : heard(0), admitted(MALIVE_NEW_MAX, MALIVE_NEW_WINDOW_SECS) {
    memset(entry, 0, sizeof(entry));
  }
};

enum MeshAliveVerdict : uint8_t {
  MALIVE_NOT_ANNOUNCE = 0,
  MALIVE_OTHER_OWNER,
  MALIVE_OLD,            // not newer than the one kept: a copy by another path, or a replay
  MALIVE_LIMITED,        // a node key new to the table, and four were admitted this hour
  MALIVE_NEWER,          // replaced its node's entry
  MALIVE_ADDED,          // a node new to the table, in a free slot or the one heard longest ago
};

static inline bool meshAliveKept(MeshAliveVerdict v) { return v == MALIVE_NEWER || v == MALIVE_ADDED; }

static inline uint32_t meshAliveEntryBoot(const MeshAliveEntry* e) {
  return mqttCtrlMeshU32(e->kept + MALIVE_AT_BOOT - MALIVE_AT_KIND);
}
static inline uint32_t meshAliveEntrySequence(const MeshAliveEntry* e) {
  return mqttCtrlMeshU32(e->kept + MALIVE_AT_SEQUENCE - MALIVE_AT_KIND);
}

// A packet's payload as it was heard: `now_secs` is any clock that only moves forward (the
// uptime), for the hourly limit; `heard_at` is what the owner is told. `slot` is set for an
// announce that was kept.
static inline MeshAliveVerdict meshAliveTake(MeshAliveTable* t, const uint8_t command_key[32],
                                             const uint8_t* payload, size_t len, uint32_t heard_at,
                                             int8_t snr, uint8_t hops, uint32_t now_secs, int* slot) {
  if (!meshAliveIsAnnounce(payload, len)) return MALIVE_NOT_ANNOUNCE;
  if (!meshAliveForOwner(payload, command_key)) return MALIVE_OTHER_OWNER;
  const uint32_t boot = mqttCtrlMeshU32(payload + MALIVE_AT_BOOT);
  const uint32_t sequence = mqttCtrlMeshU32(payload + MALIVE_AT_SEQUENCE);

  int at = -1, free_slot = -1, oldest = 0;
  for (int i = 0; i < MALIVE_TABLE; i++) {
    const MeshAliveEntry* e = &t->entry[i];
    if (!e->used) {
      if (free_slot < 0) free_slot = i;
    } else if (memcmp(e->node_key, payload + 1, 32) == 0) {
      at = i;
    } else if (!t->entry[oldest].used || e->order < t->entry[oldest].order) {
      oldest = i;
    }
  }
  MeshAliveVerdict verdict = MALIVE_NEWER;
  if (at >= 0) {
    const uint32_t kept_boot = meshAliveEntryBoot(&t->entry[at]);
    if (boot < kept_boot || (boot == kept_boot && sequence <= meshAliveEntrySequence(&t->entry[at]))) {
      return MALIVE_OLD;
    }
  } else {
    if (!t->admitted.allow(now_secs)) return MALIVE_LIMITED;
    at = free_slot >= 0 ? free_slot : oldest;
    verdict = MALIVE_ADDED;
    memset(&t->entry[at], 0, sizeof(t->entry[at]));
  }
  MeshAliveEntry* e = &t->entry[at];
  e->used = true;
  memcpy(e->node_key, payload + 1, 32);
  memcpy(e->kept, payload + MALIVE_AT_KIND, MALIVE_KEPT);
  e->heard_at = heard_at;
  e->snr = snr;
  e->hops = hops;
  e->order = ++t->heard;
  if (slot != NULL) *slot = at;
  return verdict;
}

// `mcc/heard/<the catching node's key>/<slot>`.
static inline bool meshAliveHeardTopic(const char* node_hex, int slot, char* out, size_t out_size) {
  if (slot < 0 || slot >= MALIVE_TABLE) return false;
  int n = snprintf(out, out_size, "mcc/heard/%s/%d", node_hex, slot);
  return n > 0 && (size_t)n < out_size;
}

// What goes retained on an entry's slot, under a fresh random nonce as every sealed publish.
static inline size_t meshAliveBuildHeard(const uint8_t key[MCC3_KEY_LEN], const uint8_t nonce[MCC3_NONCE_LEN],
                                         const MeshAliveEntry* e, char* out, size_t out_size) {
  uint8_t raw[MALIVE_HEARD_SIZE] = {0};
  raw[0] = MALIVE_KIND_HEARD;
  memcpy(raw + 1, nonce, MCC3_NONCE_LEN);
  uint8_t* p = raw + 1 + MCC3_NONCE_LEN;
  memcpy(p, e->node_key, 32);
  memcpy(p + 32, e->kept, MALIVE_KEPT);
  uint8_t* h = p + 32 + MALIVE_KEPT;
  mqttCtrlMeshPutU32(h, e->heard_at);
  h[4] = (uint8_t)e->snr;
  h[5] = e->hops;
  mqttCtrlMeshPutU32(h + 6, e->advert_heard_at);
  h[10] = (uint8_t)e->advert_snr;
  h[11] = e->advert_hops;
  mcc3Seal(key, nonce, raw, 1 + MCC3_NONCE_LEN, p, MALIVE_HEARD_PLAIN, p);
  return mqttV2B64Encode(raw, sizeof(raw), out, out_size);
}

// The owner's side, for the host suite and the vectors: the entry, and the announce as it
// was on the air, to open with the announcing node's K_malive (meshAliveOpen). False for
// what is no such publish or does not open under this catching node's K_heard.
static inline bool meshAliveOpenHeard(const uint8_t key[MCC3_KEY_LEN], const char* payload, size_t len,
                                      MeshAliveEntry* out, uint8_t announce[MALIVE_PAYLOAD]) {
  uint8_t raw[MALIVE_HEARD_SIZE];
  if (mqttV2B64Decode(payload, len, raw, sizeof(raw)) != MALIVE_HEARD_SIZE || raw[0] != MALIVE_KIND_HEARD) {
    return false;
  }
  uint8_t* p = raw + 1 + MCC3_NONCE_LEN;
  if (!mcc3Open(key, raw + 1, raw, 1 + MCC3_NONCE_LEN, p, MALIVE_HEARD_PLAIN, p)) return false;
  memset(out, 0, sizeof(*out));
  out->used = true;
  memcpy(out->node_key, p, 32);
  memcpy(out->kept, p + 32, MALIVE_KEPT);
  const uint8_t* h = p + 32 + MALIVE_KEPT;
  out->heard_at = mqttCtrlMeshU32(h);
  out->snr = (int8_t)h[4];
  out->hops = h[5];
  out->advert_heard_at = mqttCtrlMeshU32(h + 6);
  out->advert_snr = (int8_t)h[10];
  out->advert_hops = h[11];
  announce[0] = p[0];
  memcpy(announce + 1, p, 32 + MALIVE_KEPT);
  return true;
}

// The catching node's publishing, one slot at a time: `dirty` has a bit for each slot whose
// retained message is behind the table. The lowest waiting slot when the gap since the last
// publish has passed, else -1. millis(), and its wrap.
static inline int meshAliveNextPublish(uint16_t dirty, bool published_before, uint32_t last_ms,
                                       uint32_t now_ms) {
  if (dirty == 0 || (published_before && now_ms - last_ms < MALIVE_PUBLISH_GAP_MS)) return -1;
  int slot = 0;
  while (!(dirty & (1u << slot))) slot++;
  return slot;
}
