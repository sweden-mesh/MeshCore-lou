#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "MeshAliveLogic.h"

// Reporting (lou-21): a node without Wi-Fi within reach of an Observer node reports its
// signed announce (MeshAliveLogic.h) to one, and is acknowledged, instead of flooding it
// over the county (docs/mqtt-control.md, "Reporting"). Every packet here is an addition:
// stock and older nodes forward or ignore it, and act on none.
//
// Zero-hop, MeshCore's PAYLOAD_TYPE_CONTROL with the top bit of the first byte set, which
// no repeater forwards and upstream reads only for 0x80 and 0x90:
//
//   state  0xA0 | the Observer node named (its key's first 2 bytes, 00 00 for none)
//               | the announce's bytes 1..164                                   167 bytes
//   ack    0xB0 | the reporting node's key, first 4 bytes | report id (4)
//               | the Observer node's key (32)                                   41 bytes
//
// Along a path, ANON_REQ with ROUTE_TYPE_DIRECT, which every repeater on the path sends on
// by its path and no node reads:
//
//   direct    the announce (165) | the Observer node named (2) | path length (1) | path
//             (node to Observer node, as sent): the second rung, at most 184 bytes
//   path ack  the node's first key byte | the Observer node's key (32) | kind 0x4B
//             | report id (4) | path length (1) | the path from the node to the Observer
//             node (16, zero after its bytes)                                    55 bytes
//
// The report id is the first 4 bytes of the announce's signature: the same for every try
// of one report. Acks are not signed: a forged one makes a node skip its fallback once.
//
// Nothing here draws randomness, reads a clock or touches the node's state.

#define MREPORT_CTL_STATE        0xA0
#define MREPORT_CTL_ACK          0xB0
#define MREPORT_STATE_SIZE       (3 + MALIVE_PAYLOAD - 1)
#define MREPORT_ACK_SIZE         (1 + 4 + 4 + 32)
#define MREPORT_ID_LEN           4
#define MREPORT_KIND_PATH_ACK    0x4B
#define MREPORT_PATH_ACK_PATH    16
#define MREPORT_PATH_ACK_SIZE    (1 + 32 + 1 + MREPORT_ID_LEN + 1 + MREPORT_PATH_ACK_PATH)
#define MREPORT_DIRECT_HEAD      (MALIVE_PAYLOAD + 3)
#define MREPORT_DIRECT_MAX       184     // MAX_PACKET_PAYLOAD

static inline const uint8_t* mreportId(const uint8_t* announce) { return announce + MALIVE_AT_SIG; }

// The bytes a MeshCore path length stands for, or -1 for the reserved hash size.
static inline int mreportPathBytes(uint8_t path_len) {
  const int size = (path_len >> 6) + 1;
  return size == 4 ? -1 : size * (path_len & 63);
}

// A path the other way: hash by hash, each of its own size.
static inline void mreportReversePath(const uint8_t* path, uint8_t path_len, uint8_t* out) {
  const int size = (path_len >> 6) + 1, count = path_len & 63;
  for (int i = 0; i < count; i++) memcpy(out + i * size, path + (count - 1 - i) * size, size);
}

// ---- the state packet and its ack ------------------------------------------------------

static inline void mreportBuildState(const uint8_t announce[MALIVE_PAYLOAD], const uint8_t* named,
                                     uint8_t out[MREPORT_STATE_SIZE]) {
  out[0] = MREPORT_CTL_STATE;
  if (named != NULL) memcpy(out + 1, named, 2); else memset(out + 1, 0, 2);
  memcpy(out + 3, announce + 1, MALIVE_PAYLOAD - 1);
}

// A state packet's announce, as the flood would carry it, when the payload is one.
static inline bool mreportStateAnnounce(const uint8_t* payload, size_t len, uint8_t announce[MALIVE_PAYLOAD]) {
  if (payload == NULL || len != MREPORT_STATE_SIZE || payload[0] != MREPORT_CTL_STATE) return false;
  announce[0] = payload[3];
  memcpy(announce + 1, payload + 3, MALIVE_PAYLOAD - 1);
  return meshAliveIsAnnounce(announce, MALIVE_PAYLOAD);
}

// Whom a state packet names: 1 this node, 0 nobody, -1 another.
static inline int mreportStateNamed(const uint8_t* payload, const uint8_t own_key[32]) {
  if (payload[1] == 0 && payload[2] == 0) return 0;
  return memcmp(payload + 1, own_key, 2) == 0 ? 1 : -1;
}

static inline void mreportBuildAck(const uint8_t* node_key, const uint8_t* report_id,
                                   const uint8_t observer_key[32], uint8_t out[MREPORT_ACK_SIZE]) {
  out[0] = MREPORT_CTL_ACK;
  memcpy(out + 1, node_key, 4);
  memcpy(out + 5, report_id, MREPORT_ID_LEN);
  memcpy(out + 9, observer_key, 32);
}

static inline bool mreportIsAck(const uint8_t* payload, size_t len) {
  return payload != NULL && len == MREPORT_ACK_SIZE && payload[0] == MREPORT_CTL_ACK;
}

// ---- along a path -----------------------------------------------------------------------

// The second rung: the announce, then whom it is for and the path it is sent along. 0 for a
// path that does not fit.
static inline size_t mreportBuildDirect(const uint8_t announce[MALIVE_PAYLOAD], const uint8_t observer_key[32],
                                        uint8_t path_len, const uint8_t* path, uint8_t* out) {
  const int n = mreportPathBytes(path_len);
  if (n <= 0 || MREPORT_DIRECT_HEAD + n > MREPORT_DIRECT_MAX) return 0;
  memcpy(out, announce, MALIVE_PAYLOAD);
  memcpy(out + MALIVE_PAYLOAD, observer_key, 2);
  out[MALIVE_PAYLOAD + 2] = path_len;
  memcpy(out + MREPORT_DIRECT_HEAD, path, n);
  return MREPORT_DIRECT_HEAD + n;
}

// Whether an ANON_REQ that arrived at the end of its path is a second rung for this node.
static inline bool mreportIsDirectFor(const uint8_t* payload, size_t len, const uint8_t own_key[32]) {
  if (payload == NULL || len <= MREPORT_DIRECT_HEAD || len > MREPORT_DIRECT_MAX) return false;
  if (!meshAliveIsAnnounce(payload, MALIVE_PAYLOAD) || memcmp(payload + MALIVE_PAYLOAD, own_key, 2) != 0) return false;
  const int n = mreportPathBytes(payload[MALIVE_PAYLOAD + 2]);
  return n > 0 && (size_t)(MREPORT_DIRECT_HEAD + n) == len;
}

// A path ack, for a path of at most 16 bytes; false when it does not fit.
static inline bool mreportBuildPathAck(const uint8_t node_key[32], const uint8_t observer_key[32],
                                       const uint8_t* report_id, uint8_t path_len, const uint8_t* path,
                                       uint8_t out[MREPORT_PATH_ACK_SIZE]) {
  const int n = mreportPathBytes(path_len);
  if (n < 0 || n > MREPORT_PATH_ACK_PATH) return false;
  memset(out, 0, MREPORT_PATH_ACK_SIZE);
  out[0] = node_key[0];
  memcpy(out + 1, observer_key, 32);
  out[33] = MREPORT_KIND_PATH_ACK;
  memcpy(out + 34, report_id, MREPORT_ID_LEN);
  out[38] = path_len;
  memcpy(out + 39, path, n);
  return true;
}

static inline bool mreportIsPathAck(const uint8_t* payload, size_t len) {
  if (payload == NULL || len != MREPORT_PATH_ACK_SIZE || payload[33] != MREPORT_KIND_PATH_ACK) return false;
  const int n = mreportPathBytes(payload[38]);
  return n >= 0 && n <= MREPORT_PATH_ACK_PATH;
}

// ---- who acks ---------------------------------------------------------------------------
//
// The Observer node a state packet names acks at once, after a turnaround of 100-300 ms.
// Any other that heard it waits 3 s and acks only if it heard no ack for the report; with
// nobody named each waits 0.5-3 s at random. A flood is acked only by the Observer node
// that would be named first, the one with the fewest hops and then the best SNR: each waits
// 3 s for every hop it heard the flood after, and up to 0.8 s more the weaker it heard it,
// and steps back when it hears another's ack. A flood heard with no hops is acked as a
// state packet is, zero-hop; one of 1 to 8 hops (and at most 8 bytes of path, what the
// node's table holds) by a path ack along it reversed; a longer one not at all.
#define MREPORT_ACKS             2
#define MREPORT_TURNAROUND_MS    100UL
#define MREPORT_TURNAROUND_SPAN  200UL
#define MREPORT_DEFER_MS         3000UL
#define MREPORT_OPEN_MIN_MS      500UL
#define MREPORT_OPEN_SPAN_MS     2500UL
#define MREPORT_FLOOD_HOP_MS     3000UL
#define MREPORT_ACK_PATH_MAX     8

enum MreportAckKind : uint8_t {
  MREPORT_ACK_ZERO_HOP = 0,     // 0xB0
  MREPORT_ACK_PATH,             // 0x4B, along `path` reversed
};

struct MreportAckPlan {
  bool pending;
  uint8_t kind;                 // MreportAckKind
  uint8_t node_key[32];
  uint8_t report[MREPORT_ID_LEN];
  uint8_t path_len;             // the path from the node, as heard
  uint8_t path[MREPORT_ACK_PATH_MAX];
  uint32_t due_ms;
};

struct MreportAcks {
  MreportAckPlan plan[MREPORT_ACKS];
};

// How long an Observer node waits before it acks a state packet: `named` as mreportStateNamed.
static inline uint32_t mreportStateAckDelay(int named, uint32_t rnd) {
  if (named > 0) return MREPORT_TURNAROUND_MS + rnd % (MREPORT_TURNAROUND_SPAN + 1);
  if (named < 0) return MREPORT_DEFER_MS + rnd % (MREPORT_TURNAROUND_SPAN + 1);
  return MREPORT_OPEN_MIN_MS + rnd % (MREPORT_OPEN_SPAN_MS + 1);
}

// ... and a flood, by its hops and SNR (quarter dB).
static inline uint32_t mreportFloodAckDelay(uint8_t hops, int8_t snr, uint32_t rnd) {
  const int s = snr < -100 ? -100 : snr > 60 ? 60 : snr;
  return MREPORT_TURNAROUND_MS + hops * MREPORT_FLOOD_HOP_MS + (uint32_t)(60 - s) * 5 + rnd % (MREPORT_TURNAROUND_SPAN + 1);
}

// Whether a flood of this path is acked at all.
static inline bool mreportFloodAckable(uint8_t path_len) {
  const int n = mreportPathBytes(path_len);
  return n >= 0 && n <= MREPORT_ACK_PATH_MAX && (path_len & 63) <= 8;
}

// An ack to send in `delay_ms`. One already planned for the report keeps the sooner of the
// two; with both places taken, the one due later gives way to a sooner one. False when it
// was not planned.
static inline bool mreportPlanAck(MreportAcks* a, uint8_t kind, const uint8_t* node_key, const uint8_t* report,
                                  uint8_t path_len, const uint8_t* path, uint32_t now_ms, uint32_t delay_ms) {
  const uint32_t due = now_ms + delay_ms;
  int at = -1;
  for (int i = 0; i < MREPORT_ACKS; i++) {
    MreportAckPlan* p = &a->plan[i];
    if (p->pending && memcmp(p->report, report, MREPORT_ID_LEN) == 0) {
      if ((int32_t)(due - p->due_ms) >= 0) return false;
      at = i;
      break;
    }
  }
  if (at < 0) {
    for (int i = 0; i < MREPORT_ACKS; i++) {
      if (!a->plan[i].pending) { at = i; break; }
      if (at < 0 || (int32_t)(a->plan[i].due_ms - a->plan[at].due_ms) > 0) at = i;
    }
    if (a->plan[at].pending && (int32_t)(due - a->plan[at].due_ms) >= 0) return false;
  }
  MreportAckPlan* p = &a->plan[at];
  memset(p, 0, sizeof(*p));
  p->pending = true;
  p->kind = kind;
  memcpy(p->node_key, node_key, 32);
  memcpy(p->report, report, MREPORT_ID_LEN);
  if (kind == MREPORT_ACK_PATH) {
    const int n = mreportPathBytes(path_len);
    if (n < 0 || n > MREPORT_ACK_PATH_MAX) { p->pending = false; return false; }
    p->path_len = path_len;
    memcpy(p->path, path, n);
  }
  p->due_ms = due;
  return true;
}

// Another's ack for the report was heard: this node's own is not needed.
static inline void mreportAckHeard(MreportAcks* a, const uint8_t* report) {
  for (int i = 0; i < MREPORT_ACKS; i++) {
    if (a->plan[i].pending && memcmp(a->plan[i].report, report, MREPORT_ID_LEN) == 0) a->plan[i].pending = false;
  }
}

// The ack due now, or NULL; the caller sends it and clears `pending`. millis(), and its wrap.
static inline MreportAckPlan* mreportAckDue(MreportAcks* a, uint32_t now_ms) {
  for (int i = 0; i < MREPORT_ACKS; i++) {
    if (a->plan[i].pending && (int32_t)(now_ms - a->plan[i].due_ms) >= 0) return &a->plan[i];
  }
  return NULL;
}
