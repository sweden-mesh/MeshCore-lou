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

// ---- the reporting node's table ---------------------------------------------------------
//
// The one thing a reporting node keeps, on flash (/mccobs): up to 4 Observer nodes that
// acked it, each with the SNR of its last ack, whether each of the node's last 4 reports got
// its ack on the first zero-hop try (a bit each, the newest lowest), and the path a path ack
// taught (0 for none: zero-hop only). Nothing about any other node.
//
//   version | 4 x ( key 32 | SNR i8 | first-try bits | path length | path 8 )     173 bytes
//
// Written only when an Observer node joins or leaves it, or its bits cross the line of the
// reliable rule: a few writes a day at most. A fifth gives way to the one with the fewest
// first-try acks, then the weakest SNR.
#define MREPORT_OBSERVERS        4
#define MREPORT_TABLE_PATH       8
#define MREPORT_TABLE_VER        1
#define MREPORT_ENTRY_SIZE       (32 + 1 + 1 + 1 + MREPORT_TABLE_PATH)
#define MREPORT_TABLE_SIZE       (1 + MREPORT_OBSERVERS * MREPORT_ENTRY_SIZE)

struct MreportObserver {
  uint8_t key[32];
  int8_t snr;
  uint8_t first_try;            // the last 4 reports, newest in bit 0
  uint8_t path_len;             // MeshCore's; 0 for none
  uint8_t path[MREPORT_TABLE_PATH];
};

struct MreportTable {
  MreportObserver entry[MREPORT_OBSERVERS];
  uint8_t count;
};

static inline int mreportFirstTries(const MreportObserver* o) {
  int n = 0;
  for (int b = 0; b < 4; b++) n += (o->first_try >> b) & 1;
  return n;
}

// Better to name: more first-try acks, then the stronger SNR.
static inline bool mreportBetter(const MreportObserver* a, const MreportObserver* b) {
  const int fa = mreportFirstTries(a), fb = mreportFirstTries(b);
  return fa != fb ? fa > fb : a->snr > b->snr;
}

// The Observer node to name in a state packet, or -1 for an empty table.
static inline int mreportBest(const MreportTable* t) {
  int best = -1;
  for (int i = 0; i < t->count; i++) if (best < 0 || mreportBetter(&t->entry[i], &t->entry[best])) best = i;
  return best;
}

// The one to try along a path, or -1 when none has one.
static inline int mreportBestPath(const MreportTable* t) {
  int best = -1;
  for (int i = 0; i < t->count; i++) {
    if (mreportPathBytes(t->entry[i].path_len) <= 0) continue;
    if (best < 0 || mreportBetter(&t->entry[i], &t->entry[best])) best = i;
  }
  return best;
}

static inline int mreportFind(const MreportTable* t, const uint8_t key[32]) {
  for (int i = 0; i < t->count; i++) if (memcmp(t->entry[i].key, key, 32) == 0) return i;
  return -1;
}

// An Observer node acked: its SNR and, from a path ack, its path. The index of its entry;
// `joined` says whether it is new there, which the caller writes to flash.
static inline int mreportLearn(MreportTable* t, const uint8_t key[32], int8_t snr, bool has_path,
                               uint8_t path_len, const uint8_t* path, bool* joined) {
  *joined = false;
  int i = mreportFind(t, key);
  if (i < 0) {
    if (t->count < MREPORT_OBSERVERS) {
      i = t->count++;
    } else {
      i = 0;
      for (int j = 1; j < t->count; j++) if (mreportBetter(&t->entry[i], &t->entry[j])) i = j;
    }
    memset(&t->entry[i], 0, sizeof(t->entry[i]));
    memcpy(t->entry[i].key, key, 32);
    *joined = true;
  }
  t->entry[i].snr = snr;
  if (has_path) {
    const int n = mreportPathBytes(path_len);
    if (n >= 0 && n <= MREPORT_TABLE_PATH && (n == 0 || path != NULL)) {
      t->entry[i].path_len = path_len;
      memset(t->entry[i].path, 0, sizeof(t->entry[i].path));
      if (n > 0) memcpy(t->entry[i].path, path, n);
    }
  }
  return i;
}

// The reliable rule: 3 of the last 4 reports acked on the first try by one Observer node, and
// not two rounds in a row that needed the path or the flood.
static inline bool mreportReliable(const MreportTable* t, uint8_t fallbacks) {
  if (fallbacks >= 2) return false;
  for (int i = 0; i < t->count; i++) if (mreportFirstTries(&t->entry[i]) >= 3) return true;
  return false;
}

// A report ended: each Observer node's bits move on, a 1 for the one that acked the first try.
static inline void mreportRoundEnd(MreportTable* t, int first_try_by) {
  for (int i = 0; i < t->count; i++) {
    t->entry[i].first_try = (uint8_t)(((t->entry[i].first_try << 1) | (i == first_try_by ? 1 : 0)) & 0x0F);
  }
}

static inline size_t mreportTableEncode(const MreportTable* t, uint8_t out[MREPORT_TABLE_SIZE]) {
  memset(out, 0, MREPORT_TABLE_SIZE);
  out[0] = MREPORT_TABLE_VER;
  for (int i = 0; i < t->count; i++) {
    uint8_t* e = out + 1 + i * MREPORT_ENTRY_SIZE;
    memcpy(e, t->entry[i].key, 32);
    e[32] = (uint8_t)t->entry[i].snr;
    e[33] = t->entry[i].first_try;
    e[34] = t->entry[i].path_len;
    memcpy(e + 35, t->entry[i].path, MREPORT_TABLE_PATH);
  }
  return MREPORT_TABLE_SIZE;
}

// An entry with an all-zero key is free; one whose path does not fit is kept without it.
static inline bool mreportTableDecode(const uint8_t* buf, size_t len, MreportTable* t) {
  memset(t, 0, sizeof(*t));
  if (buf == NULL || len < MREPORT_TABLE_SIZE || buf[0] != MREPORT_TABLE_VER) return false;
  static const uint8_t zero[32] = {0};
  for (int i = 0; i < MREPORT_OBSERVERS; i++) {
    const uint8_t* e = buf + 1 + i * MREPORT_ENTRY_SIZE;
    if (memcmp(e, zero, 32) == 0) continue;
    MreportObserver* o = &t->entry[t->count++];
    memcpy(o->key, e, 32);
    o->snr = (int8_t)e[32];
    o->first_try = e[33] & 0x0F;
    const int n = mreportPathBytes(e[34]);
    if (n >= 0 && n <= MREPORT_TABLE_PATH) {
      o->path_len = e[34];
      memcpy(o->path, e + 35, MREPORT_TABLE_PATH);
    }
  }
  return true;
}

// ---- the ladder -------------------------------------------------------------------------
//
// One report: up to 3 zero-hop state packets 8-20 s apart, each naming the best Observer
// node of the table; no ack, then the announce along the best learnt path, once, and 30 s
// for its path ack; still nothing, the region flood, and 90 s more for a path ack to teach
// a path for next time. Then the next report in 12 h when the reliable rule holds, else
// 23 h, a tenth either way.
#define MREPORT_ZERO_HOP_TRIES   3
#define MREPORT_TRY_GAP_MIN_MS   8000UL
#define MREPORT_TRY_GAP_SPAN_MS  12000UL
#define MREPORT_DIRECT_WAIT_MS   30000UL
#define MREPORT_FLOOD_WAIT_MS    90000UL
#define MREPORT_RELIABLE_MS      (12UL * 3600UL * 1000UL)

enum MreportRung : uint8_t {
  MREPORT_IDLE = 0,
  MREPORT_ZERO_HOP,
  MREPORT_PATH,
  MREPORT_FLOOD,
};

enum MreportAction : uint8_t {
  MREPORT_WAIT = 0,
  MREPORT_SEND_STATE,
  MREPORT_SEND_DIRECT,
  MREPORT_SEND_FLOOD,
  MREPORT_DONE,
};

struct MreportLadder {
  uint8_t rung;                 // MreportRung
  uint8_t tries;                // zero-hop tries sent
  uint8_t max_tries;            // zero-hop tries this report may send
  bool fallback;                // the path and the flood may follow them
  bool sent;                    // the path or the flood went
  bool acked;
  int first_try_by;             // the table entry that acked the first try, else -1
  uint8_t report[MREPORT_ID_LEN];
  uint32_t next_ms;
};

static inline void mreportStart(MreportLadder* l, const uint8_t* report, uint32_t now_ms) {
  memset(l, 0, sizeof(*l));
  l->rung = MREPORT_ZERO_HOP;
  l->max_tries = MREPORT_ZERO_HOP_TRIES;
  l->fallback = true;
  l->first_try_by = -1;
  memcpy(l->report, report, MREPORT_ID_LEN);
  l->next_ms = now_ms;
}

// ---- the battery ----------------------------------------------------------------------
//
// A node whose battery runs low reports less: under `announce.low` mV no 12 h rate, under
// `announce.critical` one zero-hop try, and the path and the flood only every second report,
// the first of them included, so the owner hears of it. The reading is the one the announce
// carries; 0 (a board that cannot read its battery) and a threshold of 0 switch the rule off.
// The thresholds are settings of /mqttcontrol (MqttControlLogic.h), 3600 and 3400 by default.
struct MreportBattery {
  uint8_t tries;                // zero-hop tries
  bool fallback;                // the path and the flood after them
  bool twelve_hours;            // the reliable rule may bring the next report in 12 h
};

static inline bool mreportBatteryBelow(uint16_t mv, uint16_t threshold_mv) {
  return mv != 0 && threshold_mv != 0 && mv < threshold_mv;
}

// `critical_rounds`, the caller's: reports in a row under `announce.critical`.
static inline MreportBattery mreportBattery(uint16_t mv, uint16_t low_mv, uint16_t critical_mv,
                                            uint8_t* critical_rounds) {
  MreportBattery b = { MREPORT_ZERO_HOP_TRIES, true, !mreportBatteryBelow(mv, low_mv) };
  if (!mreportBatteryBelow(mv, critical_mv)) {
    *critical_rounds = 0;
    return b;
  }
  b.tries = 1;
  b.fallback = (*critical_rounds & 1) == 0;
  *critical_rounds = (uint8_t)(*critical_rounds + 1);
  return b;
}

static inline void mreportLimit(MreportLadder* l, const MreportBattery* b) {
  l->max_tries = b->tries;
  l->fallback = b->fallback;
}

// What to do now. `has_path`: the table holds a path. The caller sends, then calls
// mreportSent, or mreportLater when it could not.
static inline uint8_t mreportStep(MreportLadder* l, uint32_t now_ms, bool has_path) {
  if (l->rung == MREPORT_IDLE) return MREPORT_WAIT;
  if (l->acked) return MREPORT_DONE;
  if ((int32_t)(now_ms - l->next_ms) < 0) return MREPORT_WAIT;
  if (l->rung == MREPORT_ZERO_HOP) {
    if (l->tries < l->max_tries) return MREPORT_SEND_STATE;
    if (!l->fallback) return MREPORT_DONE;
    l->rung = has_path ? MREPORT_PATH : MREPORT_FLOOD;
    l->sent = false;
  } else if (l->rung == MREPORT_PATH && (l->sent || !has_path)) {
    l->rung = MREPORT_FLOOD;
    l->sent = false;
  } else if (l->rung == MREPORT_FLOOD && l->sent) {
    return MREPORT_DONE;
  }
  return l->rung == MREPORT_PATH ? MREPORT_SEND_DIRECT : MREPORT_SEND_FLOOD;
}

static inline void mreportSent(MreportLadder* l, uint32_t now_ms, uint32_t rnd) {
  if (l->rung == MREPORT_ZERO_HOP) {
    l->tries++;
    l->next_ms = now_ms + MREPORT_TRY_GAP_MIN_MS + rnd % (MREPORT_TRY_GAP_SPAN_MS + 1);
  } else {
    l->sent = true;
    l->next_ms = now_ms + (l->rung == MREPORT_PATH ? MREPORT_DIRECT_WAIT_MS : MREPORT_FLOOD_WAIT_MS);
  }
}

// A send that could not go (the airtime budget, no packet) is tried again in a minute.
static inline void mreportLater(MreportLadder* l, uint32_t now_ms) {
  l->next_ms = now_ms + MALIVE_SOON_MAX_MS;
}

// An ack for this report: a zero-hop one by table entry `by`, or a path ack. True when it
// was this report's.
static inline bool mreportAck(MreportLadder* l, const uint8_t* report, int by) {
  if (l->rung == MREPORT_IDLE || memcmp(report, l->report, MREPORT_ID_LEN) != 0) return false;
  if (l->rung == MREPORT_ZERO_HOP && l->tries == 1 && !l->acked && by >= 0) l->first_try_by = by;
  l->acked = true;
  return true;
}

// Whether the report that ended needed the path or the flood, or went without an ack.
static inline bool mreportFellBack(const MreportLadder* l) { return l->rung >= MREPORT_PATH || !l->acked; }
