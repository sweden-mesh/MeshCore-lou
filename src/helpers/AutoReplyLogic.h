#pragma once

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "MQTTObserverValidation.h"

// Pure, dependency-free decisions behind the repeater's auto-reply. Factored out
// of examples/simple_repeater/AutoReply.cpp so the channel derivation, the
// per-sender cooldown and the trigger matching can be unit-tested on the host
// (see test/test_autoreply) rather than only over the air. The firmware keeps the
// state and does the I/O; every rule it applies is one of these functions.

// The channel is not configurable: it is this prefix plus the node's region code.
#ifndef AUTOREPLY_CHANNEL_PREFIX
  #define AUTOREPLY_CHANNEL_PREFIX  "#test-"
#endif

// Build the auto-reply channel name for a region: '#test-' plus the node's IATA
// code, folded to lower case because clients only accept lower-case channel
// names. Returns false, leaving 'out' empty, when the node has no region set:
// 'XXX' is the placeholder the MQTT topic router also treats as unconfigured, and
// without a region there is no per-region channel to answer on. Deriving the name
// rather than accepting one is what keeps every repeater off the mesh-wide
// '#test', where a reply from each of them would be spam.
static inline bool autoReplyDeriveChannel(const char* iata, char* out, size_t out_size) {
  if (out == NULL || out_size == 0) return false;
  out[0] = 0;
  if (!mqttIataValid(iata) || strcasecmp(iata, "XXX") == 0) return false;

  size_t prefix_len = strlen(AUTOREPLY_CHANNEL_PREFIX);
  if (prefix_len + strlen(iata) >= out_size) return false;

  memcpy(out, AUTOREPLY_CHANNEL_PREFIX, prefix_len);
  size_t i = 0;
  for (; iata[i]; i++) out[prefix_len + i] = tolower(iata[i]);
  out[prefix_len + i] = 0;
  return true;
}

// A sender that was recently answered. The firmware holds a fixed ring of these,
// so one person retrying cannot spend everyone else's share of the global limit.
struct AutoReplySender {
  uint32_t id;
  uint32_t last_reply;
};

// FNV-1a over the case-folded name, so 'Louie' and 'louie' are one sender. The
// name prefix of a group text is the only sender identity the packet carries.
static inline uint32_t autoReplySenderId(const char* name, size_t len) {
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < len; i++) {
    h ^= (uint8_t)tolower(name[i]);
    h *= 16777619u;
  }
  return h;
}

// The same hash over a public key, for a private request: the packet names its
// sender by key, which nobody else can type, so the cooldown is charged to the key
// and not to a display name. Bytes are hashed as they are -- folding is for text.
static inline uint32_t autoReplyKeyId(const uint8_t* key, size_t len) {
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < len; i++) {
    h ^= key[i];
    h *= 16777619u;
  }
  return h;
}

// Charge a reply to 'id' against the per-sender cooldown. Returns false while that
// sender is still inside its window; otherwise records the reply and returns true.
// A sender not in the ring takes the next slot, evicting the oldest entry.
static inline bool autoReplySenderAllowed(AutoReplySender* senders, uint8_t count,
                                          uint8_t& next_slot, uint32_t id, uint32_t now,
                                          uint32_t window_secs) {
  if (senders == NULL || count == 0) return true;

  for (uint8_t i = 0; i < count; i++) {
    if (senders[i].id == id) {
      if (now < senders[i].last_reply + window_secs) return false;
      senders[i].last_reply = now;
      return true;
    }
  }

  senders[next_slot % count].id = id;
  senders[next_slot % count].last_reply = now;
  next_slot = (next_slot + 1) % count;
  return true;
}

// A correlation id is exactly this many hex characters. Fixed rather than ranged
// so the reply budget can be reasoned about, and so a half-typed id is a
// non-trigger rather than a shorter id.
#define AUTOREPLY_ID_LEN  8

// How a request asks to be answered. A requester picks one with a single letter
// after the id; a request that names none takes the node's configured default,
// which is what AUTOREPLY_MODE_DEFAULT stands for in a parsed request.
//
// FLOOD is the reply every node makes today, a group text flooded on the channel.
// PRIVATE and DIRECT are a text message addressed to the requester alone -- the
// first flooded so it finds them wherever they are, the second sent down a known
// return path. SILENT asks for no reply at all: the node still hears the request
// and its observer uplink still reports it, so a probe that wants only "who heard
// me" costs the mesh nothing but its own transmission.
enum {
  AUTOREPLY_MODE_DEFAULT = 0,
  AUTOREPLY_MODE_FLOOD,
  AUTOREPLY_MODE_PRIVATE,
  AUTOREPLY_MODE_DIRECT,
  AUTOREPLY_MODE_SILENT,
};

// A reply slot, assigned by the operator over the control plane. Slots exist so the
// repeaters that answer one request take the air one after another instead of drawing
// random waits that sometimes coincide: two nodes in distinct slots cannot collide,
// where two random draws collide at the birthday rate -- 34% across fifteen nodes.
//
// 0 means unassigned, and it is the default. An unassigned node derives a slot from
// its own public key instead (see autoReplySlotFromKey), so a mesh where nobody hands
// out slots still spreads its replies evenly and needs no configuration at all. That
// is the difference the assignment buys: unassigned is as good as random, assigned is
// collision-free.
#define AUTOREPLY_SLOT_UNASSIGNED 0
#define AUTOREPLY_SLOT_MAX        64

// True for a value an operator may set. The upper bound is the widest slot count the
// firmware will accept rather than the count in use, which is a separate setting: a
// slot above the current count is not wrong, only unused until the count grows.
static inline bool autoReplySlotValid(long slot) {
  return slot >= 0 && slot <= AUTOREPLY_SLOT_MAX;
}

// What a stored byte means when it is read back. A value outside the range is a
// truncated or corrupt config file, and unassigned is the safe reading of it: the node
// falls back to its key-derived slot, which is always a legal one. Refusing to answer,
// or answering at slot 0 as though assigned, would both be worse -- the first silences
// a node the mesh is trying to measure, the second puts it on top of whoever holds it.
static inline uint8_t autoReplyStoredSlot(uint8_t stored) {
  return autoReplySlotValid(stored) ? stored : (uint8_t)AUTOREPLY_SLOT_UNASSIGNED;
}

// How many slots the window is divided into, unless the operator says otherwise.
// Sixteen covers the fifteen repliers JKG has today with room for growth, and divides
// a 110 s window into ~6.9 s slots -- wider than one reply's own flood footprint.
#define AUTOREPLY_SLOTS_DEF 16
#define AUTOREPLY_SLOTS_MIN 1
#define AUTOREPLY_SLOTS_MAX AUTOREPLY_SLOT_MAX

// A slot is not used raw: it is rotated by the day, so the same node does not answer
// first every single test for the rest of its life. Adding one offset to every node is
// a rotation of the whole order, so distinct slots stay distinct -- which is the
// property the whole scheme rests on, and which picking a per-node offset would break.
//
// The offset changes at midnight and holds for the whole day (operator, 2026-09-19):
// an order that reshuffles per request is fairer still, but nobody watching a test can
// anticipate it, and a human tester should be able to. A node whose clock has not
// synced passes day 0 and lands on a legal ordering rather than refusing to answer.
static inline uint8_t autoReplyRotatedSlot(uint8_t index, uint8_t slots, uint32_t day) {
  if (slots == 0) return 0;
  return (uint8_t)(((uint32_t)index + day) % slots);
}

// The slot a node uses when nobody has assigned it one -- which is every node on a
// mesh with no orchestration behind it. Flash the firmware, configure nothing, and
// replies still spread across the window instead of landing together.
//
// **This is not as good as an assignment, and it is not meant to be.** A key byte is
// effectively a uniform draw, so two unassigned nodes share a slot at the birthday
// rate: about a third of the time across fifteen nodes at sixteen slots. What it buys
// over a plain random wait is that the spread is even and bounded, and that the choice
// is *predictable* -- the same node picks the same slot all day, and an observer who
// knows the key and the date can say which. An orchestrated mesh hands out slots and
// gets no collisions at all; that is the difference the assignment is worth.
//
// The byte is chosen by the day rather than by the request, so an unassigned node is
// as stable through a day as an assigned one. `key_len` is passed in rather than
// assuming 32, because this header knows nothing about MeshCore's key sizes.
static inline uint8_t autoReplySlotFromKey(const uint8_t* key, size_t key_len,
                                           uint8_t slots, uint32_t day) {
  if (key == NULL || key_len == 0 || slots == 0) return 0;
  return (uint8_t)(key[day % key_len] % slots);
}

// The window, in seconds after the request, that all replies land inside.
//
// The start clears the request's own flood -- each hop costs up to ~1.35 s of
// retransmit delay plus airtime -- and clears the ~9 s in which nodes on the released
// firmware answer, since a mesh runs mixed builds for months. The end is where CLAUDE
// .md's "a repeater may wait 5-10 minutes" budget is spent, bounded here by what the
// test system records: a reply arriving after the capture closes reads as never
// delivered, which is the one failure this project must not manufacture.
#define AUTOREPLY_WINDOW_START_DEF 10
#define AUTOREPLY_WINDOW_END_DEF   120
#define AUTOREPLY_WINDOW_MAX       600

// A window needs room for every slot to hold a reply and its guards, and the bound is
// arithmetic rather than taste. Two nodes in adjacent slots are separated by their two
// guards, an eighth of a slot each, so the clear air between them is width/4. That has
// to exceed one reply's airtime -- ~0.9 s for a 97-byte reply at SF8/BW62.5/CR4:8 --
// which puts the floor at 3.6 s and rounds to 4.
//
// The measurement agrees: 48 slots in a 110 s window is 2.3 s each, and there even
// assigned nodes collide (planning/firmware/slot-collisions-measured.md). This suite
// caught the constant when it was set to 2 by hand.
#define AUTOREPLY_SLOT_MIN_SECS 4

static inline bool autoReplyWindowValid(long start_s, long end_s, uint8_t slots) {
  if (start_s < 0 || end_s <= start_s || end_s > AUTOREPLY_WINDOW_MAX) return false;
  if (slots == 0) return false;
  return (end_s - start_s) / (long)slots >= AUTOREPLY_SLOT_MIN_SECS;
}

static inline bool autoReplySlotsValid(long slots, long start_s, long end_s) {
  if (slots < AUTOREPLY_SLOTS_MIN || slots > AUTOREPLY_SLOTS_MAX) return false;
  return autoReplyWindowValid(start_s, end_s, (uint8_t)slots);
}

// The day number the rotation turns on, from the node's own clock.
//
// A node whose clock has never synced reports something near zero, and dividing that
// by a day still gives a legal day number -- but every unsynced node would then agree
// on day 0 *and* on the rotation, which is fine: they are distinct slots regardless.
// The threshold is only there so a garbage clock cannot produce a wild day that makes
// one node's order differ from the mesh's for a century.
#define AUTOREPLY_EPOCH_SANE 1600000000UL   // 2020-09-13; older than any real fix
#define AUTOREPLY_SECS_PER_DAY 86400UL

static inline uint32_t autoReplyDayNumber(uint32_t epoch_secs) {
  if (epoch_secs < AUTOREPLY_EPOCH_SANE) return 0;
  return epoch_secs / AUTOREPLY_SECS_PER_DAY;
}

// Which slot index this node answers in: its assignment when it has one, and the
// key-derived slot when it does not. Assigned slots are 1-based as the operator types
// them, so slot 1 is index 0 and no assignment can silently mean "the first slot".
static inline uint8_t autoReplySlotIndex(uint8_t assigned, const uint8_t* key,
                                         size_t key_len, uint8_t slots, uint32_t day) {
  if (slots == 0) return 0;
  if (assigned == AUTOREPLY_SLOT_UNASSIGNED) {
    return autoReplySlotFromKey(key, key_len, slots, day);
  }
  return (uint8_t)((assigned - 1) % slots);
}

// Where in the window a rotated slot sits, in milliseconds after the request.
//
// The window runs from `start_ms` to `end_ms` and is cut into `slots` equal pieces. A
// reply leaves in the middle of its own piece: a guard of an eighth at each edge keeps
// two neighbours apart even though they hear the request at different moments -- each
// hop adds up to ~1.35 s of retransmit delay plus airtime, so slot edges smear across
// the mesh. `entropy` fills the jittered middle; any source will do, and the firmware
// passes the radio's RNG.
//
// Jitter is deliberately not the whole slot. Without a guard the scheme would spread
// the *average* while still letting neighbours touch at the edges, which is the thing
// a collision-free order is for.
static inline uint32_t autoReplySlotDelayMs(uint8_t rotated, uint8_t slots,
                                            uint32_t start_ms, uint32_t end_ms,
                                            uint32_t entropy) {
  if (slots == 0 || end_ms <= start_ms) return start_ms;
  const uint32_t width = (end_ms - start_ms) / slots;
  const uint32_t guard = width / 8;
  const uint32_t base = start_ms + (uint32_t)rotated * width + guard;
  const uint32_t jitter_span = width - 2 * guard;
  return jitter_span ? base + (entropy % jitter_span) : base;
}

// ---- the stored config, as bytes ---------------------------------------------
//
// The layout lives here rather than in AutoReply.cpp so the host suite can test it.
// AutoReply.cpp needs a filesystem and the suite has none, and that gap had grown to
// seven file versions resting on nothing but a target compile. load() and save() now
// read and write one buffer and call these.
//
//   v1  name[32] hops                       the channel was named, not derived
//   v2  enabled hops
//   v3  enabled hops direct_flood
//   v4  ... retired region[32]              `retired` was autoreply.delay
//   v5  ... mode
//   v6  ... private
//   v7  ... slot window_start(LE16) window_end(LE16) slots
//
// Append-only from v4: a later version adds fields after the ones before it, never
// between them, so a file written by *newer* firmware is read by the fields this one
// knows and the rest ignored. That is what stops a rollback switching the feature off
// in silence.
#ifndef AUTOREPLY_MAX_REGION
  #define AUTOREPLY_MAX_REGION 31
#endif
#define AUTOREPLY_CONFIG_VERSION   7
#define AUTOREPLY_CONFIG_MAX_BYTES 64
#define AUTOREPLY_HOPS_DEF         8

struct AutoReplyStoredConfig {
  bool enabled;
  uint8_t hops;
  bool direct_flood;
  char region[AUTOREPLY_MAX_REGION + 1];
  uint8_t mode;
  bool priv;
  uint8_t slot;
  uint16_t window_start;
  uint16_t window_end;
  uint8_t slots;
};

static inline void autoReplyConfigDefaults(AutoReplyStoredConfig* c) {
  memset(c, 0, sizeof(*c));
  c->hops = AUTOREPLY_HOPS_DEF;
  c->direct_flood = true;
  c->mode = AUTOREPLY_MODE_FLOOD;
  c->slot = AUTOREPLY_SLOT_UNASSIGNED;
  c->window_start = AUTOREPLY_WINDOW_START_DEF;
  c->window_end = AUTOREPLY_WINDOW_END_DEF;
  c->slots = AUTOREPLY_SLOTS_DEF;
}

// Reads a stored config of any version into `out`, which should hold the defaults on
// entry: a field the file does not carry keeps whatever was there. Returns false for
// an empty buffer or a version this has never heard of, leaving `out` untouched.
//
// A short file stops where it runs out rather than reading past the end; whatever was
// not reached keeps its default. The file.read() calls this replaced would have left
// those fields holding whatever the constructor put there, which came to the same
// thing by luck rather than by design.
static inline bool autoReplyConfigDecode(const uint8_t* buf, size_t len,
                                         AutoReplyStoredConfig* out) {
  if (buf == NULL || out == NULL || len < 1) return false;
  const uint8_t ver = buf[0];
  size_t at = 1;
  #define AR_HAS(n) (at + (n) <= len)

  if (ver >= 4) {
    if (AR_HAS(1)) out->enabled = buf[at++] != 0;
    if (AR_HAS(1)) out->hops = buf[at++];
    if (AR_HAS(1)) out->direct_flood = buf[at++] != 0;
    if (AR_HAS(1)) at++;                                   // the retired delay byte
    if (AR_HAS(sizeof(out->region))) {
      memcpy(out->region, &buf[at], sizeof(out->region));
      at += sizeof(out->region);
    }
    out->region[sizeof(out->region) - 1] = 0;
    if (ver >= 5 && AR_HAS(1)) out->mode = buf[at++];
    if (ver >= 6 && AR_HAS(1)) out->priv = buf[at++] != 0;
    if (ver >= 7 && AR_HAS(6)) {
      out->slot = buf[at++];
      out->window_start = (uint16_t)(buf[at] | (buf[at + 1] << 8)); at += 2;
      out->window_end = (uint16_t)(buf[at] | (buf[at + 1] << 8)); at += 2;
      out->slots = buf[at++];
    }
    // Only a standing mode is stored; anything else is a damaged file and takes the
    // reply every node sends today.
    if (out->mode != AUTOREPLY_MODE_PRIVATE && out->mode != AUTOREPLY_MODE_DIRECT) {
      out->mode = AUTOREPLY_MODE_FLOOD;
    }
    out->slot = autoReplyStoredSlot(out->slot);
    // A window that cannot hold its slots would put every repeater in range on one
    // instant -- the thing slots exist to prevent -- so all three fall back together.
    if (!autoReplySlotsValid(out->slots, out->window_start, out->window_end)) {
      out->window_start = AUTOREPLY_WINDOW_START_DEF;
      out->window_end = AUTOREPLY_WINDOW_END_DEF;
      out->slots = AUTOREPLY_SLOTS_DEF;
    }
  } else if (ver == 3) {
    if (AR_HAS(1)) out->enabled = buf[at++] != 0;
    if (AR_HAS(1)) out->hops = buf[at++];
    if (AR_HAS(1)) out->direct_flood = buf[at++] != 0;
  } else if (ver == 2) {
    if (AR_HAS(1)) out->enabled = buf[at++] != 0;
    if (AR_HAS(1)) out->hops = buf[at++];
  } else if (ver == 1) {
    // v1 named the channel to switch the feature on, so a node that had one named
    // wanted it on. The name itself is dropped: it is derived now.
    if (AR_HAS(32)) { out->enabled = buf[at] != 0; at += 32; }
    if (AR_HAS(1)) out->hops = buf[at++];
  } else {
    return false;
  }
  #undef AR_HAS
  return true;
}

// Writes the current version. Returns the bytes written, or 0 if `size` is too small.
static inline size_t autoReplyConfigEncode(const AutoReplyStoredConfig* c, uint8_t* buf,
                                           size_t size) {
  const size_t need = 1 + 4 + sizeof(c->region) + 1 + 1 + 6;
  if (c == NULL || buf == NULL || size < need) return 0;
  size_t at = 0;
  buf[at++] = AUTOREPLY_CONFIG_VERSION;
  buf[at++] = c->enabled ? 1 : 0;
  buf[at++] = c->hops;
  buf[at++] = c->direct_flood ? 1 : 0;
  buf[at++] = 0;                                 // was autoreply.delay; keeps its place
  memcpy(&buf[at], c->region, sizeof(c->region)); at += sizeof(c->region);
  buf[at++] = c->mode;
  buf[at++] = c->priv ? 1 : 0;
  buf[at++] = c->slot;
  buf[at++] = (uint8_t)(c->window_start & 0xFF); buf[at++] = (uint8_t)(c->window_start >> 8);
  buf[at++] = (uint8_t)(c->window_end & 0xFF);   buf[at++] = (uint8_t)(c->window_end >> 8);
  buf[at++] = c->slots;
  return at;
}

// The letter a requester types, either case. Anything else is DEFAULT, which the
// trigger parser treats as "not a mode token" rather than as a choice.
static inline uint8_t autoReplyModeFromLetter(char c) {
  switch (tolower((unsigned char)c)) {
    case 'f': return AUTOREPLY_MODE_FLOOD;
    case 'p': return AUTOREPLY_MODE_PRIVATE;
    case 'd': return AUTOREPLY_MODE_DIRECT;
    case 's': return AUTOREPLY_MODE_SILENT;
    default:  return AUTOREPLY_MODE_DEFAULT;
  }
}

// The letter for a mode, for a probe this node originates; 0 for DEFAULT, which
// names nothing and so has no letter to send.
static inline char autoReplyModeLetter(uint8_t mode) {
  switch (mode) {
    case AUTOREPLY_MODE_FLOOD:   return 'F';
    case AUTOREPLY_MODE_PRIVATE: return 'P';
    case AUTOREPLY_MODE_DIRECT:  return 'D';
    case AUTOREPLY_MODE_SILENT:  return 'S';
    default:                     return 0;
  }
}

// A group text, split into who sent it and whether it asked for a reply. 'sender',
// 'message' and 'id' point into the text buffer passed to autoReplyParseRequest().
struct AutoReplyRequest {
  bool is_trigger;
  const char* sender;
  size_t sender_len;
  const char* message;
  const char* id;        // NULL for a bare keyword
  size_t id_len;
  uint8_t mode;          // AUTOREPLY_MODE_DEFAULT unless the request named one
  const char* pubkey_hex; // 64 hex characters, or NULL: where a private reply goes
};

// Does the message ask for a reply, and does it carry a correlation id or a mode?
//
// The forms accepted are the bare keyword, the keyword and exactly AUTOREPLY_ID_LEN
// hex characters, and either of those followed by one mode letter -- each part
// separated by a single space. A private mode (P or D) may then carry the
// requester's public key as 64 hex characters, because a group text names its
// sender only by an unauthenticated display name and a private reply has to be
// addressed to a key. **The bare form must keep working indefinitely.** Flashing
// this fleet takes months, so probes stay bare until adoption is high; a firmware
// that only answered the id form would silently drop every un-flashed node out of
// the measurement, and those are exactly the nodes whose connectivity is least
// understood.
//
// The tail is matched strictly -- one space between parts, then end of string.
// Anything looser ('test me', 'test 123', a second letter, trailing text, a key
// after F or S) stays a non-trigger, which is what keeps ordinary chat on the
// channel from costing everyone airtime. A mode letter and an id cannot be
// confused: an id is exactly eight hex digits, and a mode is exactly one letter.
//
// 'mode' may be NULL for a caller that has no use for one. Such a caller keeps
// exactly the two older forms: a request that names a mode is a non-trigger there,
// never a trigger with the mode quietly dropped. 'pubkey_hex' likewise: a caller
// that cannot address a private reply treats a request carrying a key as chat.
static inline bool autoReplyMatchTrigger(const char* msg, const char* keyword,
                                         const char** id, size_t* id_len,
                                         uint8_t* mode = NULL,
                                         const char** pubkey_hex = NULL) {
  *id = NULL;
  *id_len = 0;
  if (mode) *mode = AUTOREPLY_MODE_DEFAULT;
  if (pubkey_hex) *pubkey_hex = NULL;
  if (msg == NULL || keyword == NULL) return false;

  size_t klen = strlen(keyword);
  if (strncasecmp(msg, keyword, klen) != 0) return false;
  if (msg[klen] == 0) return true;                 // the bare keyword
  if (msg[klen] != ' ') return false;

  const char* tail = msg + klen + 1;
  size_t n = 0;
  while (n < AUTOREPLY_ID_LEN && isxdigit((unsigned char)tail[n])) n++;
  if (n == AUTOREPLY_ID_LEN && (tail[n] == 0 || tail[n] == ' ')) {
    *id = tail;
    *id_len = n;
    if (tail[n] == 0) return true;                 // keyword and id
    tail += n + 1;
  }

  uint8_t m = autoReplyModeFromLetter(tail[0]);
  bool ok = mode != NULL && m != AUTOREPLY_MODE_DEFAULT;
  if (ok && tail[1] == ' ') {
    // Only a private reply needs an address, so only P and D may carry one.
    bool addressable = m == AUTOREPLY_MODE_PRIVATE || m == AUTOREPLY_MODE_DIRECT;
    ok = addressable && pubkey_hex != NULL && mqttOwnerKeyValid(tail + 2);
    if (ok) *pubkey_hex = tail + 2;
  } else if (ok) {
    ok = tail[1] == 0;
  }
  if (!ok) {
    *id = NULL;                                    // a non-trigger carries nothing
    *id_len = 0;
    return false;
  }
  *mode = m;
  return true;
}

// The mode a reply is actually sent in, given what the request asked for and how
// the node is configured. A request that named nothing takes the node's default.
// A private reply needs somewhere to go: with no key to address it to, P and D
// fall back to the flood reply rather than to silence, because a probe that goes
// unanswered for an addressing gap looks exactly like a dead repeater.
static inline uint8_t autoReplyResolveMode(uint8_t requested, uint8_t node_default,
                                           bool has_pubkey) {
  uint8_t m = requested == AUTOREPLY_MODE_DEFAULT ? node_default : requested;
  if (m == AUTOREPLY_MODE_DEFAULT) m = AUTOREPLY_MODE_FLOOD;
  if ((m == AUTOREPLY_MODE_PRIVATE || m == AUTOREPLY_MODE_DIRECT) && !has_pubkey) {
    return AUTOREPLY_MODE_FLOOD;
  }
  return m;
}

// Parse `trigger <keyword>` / `trigger <keyword> <8 hex>`, the command a signed
// MQTT envelope carries to make this node originate a probe.
//
// The id is **echoed, never generated here**. The requester mints it, so the
// requester is the one who can tie the replies that come back to the request it
// sent -- the same decision already taken for the auto-reply correlation id, and
// for the same reason. A node inventing its own id would produce a number nobody
// asked for and nobody can match.
//
// Reuses autoReplyMatchTrigger for the tail so the accepted id and mode grammar is
// defined once: whatever a node accepts in a request, it accepts in a trigger. A
// key is the one thing a trigger never carries -- the probe's requester is this
// node, and it knows its own key -- so a command with one is refused.
static inline bool autoReplyParseTrigger(const char* command, const char* keyword,
                                         const char** id, size_t* id_len,
                                         uint8_t* mode = NULL) {
  *id = NULL;
  *id_len = 0;
  if (mode) *mode = AUTOREPLY_MODE_DEFAULT;
  if (command == NULL || keyword == NULL) return false;

  static const char PREFIX[] = "trigger ";
  const size_t plen = sizeof(PREFIX) - 1;
  if (strncasecmp(command, PREFIX, plen) != 0) return false;

  return autoReplyMatchTrigger(command + plen, keyword, id, id_len, mode);
}

// Parse `trigger private <64 hex key> [<8 hex id>]`, the command that makes this node
// send a private test request to the node with that key -- the requester's side of
// the private exchange, over the same signed control plane the channel probe uses.
// The key is the target's, not ours: our own goes in the packet by construction.
// The id is echoed, never generated, for the reason autoReplyParseTrigger gives.
// Matched as strictly as everything else here: one space between parts, exactly
// 64 hex, then either the end or one space and exactly AUTOREPLY_ID_LEN hex.
static inline bool autoReplyParsePrivateTrigger(const char* command, const char** pubkey_hex,
                                                const char** id, size_t* id_len) {
  *pubkey_hex = NULL;
  *id = NULL;
  *id_len = 0;
  if (command == NULL) return false;

  static const char PREFIX[] = "trigger private ";
  const size_t plen = sizeof(PREFIX) - 1;
  if (strncasecmp(command, PREFIX, plen) != 0) return false;

  const char* key = command + plen;
  size_t klen = 0;
  while (isxdigit((unsigned char)key[klen])) klen++;
  if (klen != 64) return false;
  if (key[klen] == 0) {
    *pubkey_hex = key;
    return true;
  }
  if (key[klen] != ' ') return false;

  const char* tail = key + klen + 1;
  size_t n = 0;
  while (n < AUTOREPLY_ID_LEN && isxdigit((unsigned char)tail[n])) n++;
  if (n != AUTOREPLY_ID_LEN || tail[n] != 0) return false;

  *pubkey_hex = key;
  *id = tail;
  *id_len = n;
  return true;
}

// Build the probe body: the keyword alone, or the keyword and the echoed id, and
// after either a mode letter and, for a private mode, the key the reply should
// come back to -- this node's own.
//
// This is the same text a person sends by hand, deliberately: the probe has to be
// indistinguishable from an ordinary request, or the nodes that answer it would be
// answering something else and the measurement would not compare. A probe names
// no mode unless asked to, for the reason a request does not: an un-flashed
// repeater matches the bare forms only.
//
// Returns the length written, or 0 if it would not fit.
static inline size_t autoReplyBuildProbe(char* out, size_t out_size, const char* sender,
                                         const char* keyword, const char* id, size_t id_len,
                                         uint8_t mode = AUTOREPLY_MODE_DEFAULT,
                                         const char* pubkey_hex = NULL) {
  if (out == NULL || out_size == 0 || keyword == NULL) return 0;
  out[0] = 0;

  // The sender prefix is not decoration. autoReplyParseRequest splits the text at
  // ": " to find who asked, and a repeater echoes that name back inside the
  // reply's [brackets]. Without it every reply to this probe comes back
  // anonymous, and a reply that cannot name the node it answers is worth much
  // less than one that can -- with two probes in flight nothing tells them apart.
  //
  // Measured on air 2026-09-01: a triggered probe sent as bare `test` drew
  // `SNR 7.75 RSSI -106 1h 70` where a client's probe draws
  // `[SE-JKG-LouHome-A] SNR ...`. The probe has to look like the one a person
  // sends, prefix included, or it is not measuring the same thing.
  char letter = autoReplyModeLetter(mode);
  bool keyed = letter && (mode == AUTOREPLY_MODE_PRIVATE || mode == AUTOREPLY_MODE_DIRECT)
               && pubkey_hex != NULL;
  size_t slen = (sender != NULL && sender[0] != 0) ? strlen(sender) : 0;
  size_t klen = strlen(keyword);
  size_t hlen = keyed ? strlen(pubkey_hex) : 0;
  size_t need = (slen ? slen + 2 : 0) + klen + (id != NULL && id_len > 0 ? 1 + id_len : 0)
                + (letter ? 2 : 0) + (keyed ? 1 + hlen : 0);
  if (need == 0 || need + 1 > out_size) return 0;   // never truncate a probe

  size_t n = 0;
  if (slen) {
    memcpy(out, sender, slen);
    n = slen;
    out[n++] = ':';
    out[n++] = ' ';
  }
  memcpy(out + n, keyword, klen);
  n += klen;
  if (id != NULL && id_len > 0) {
    out[n++] = ' ';
    memcpy(out + n, id, id_len);
    n += id_len;
  }
  if (letter) {
    out[n++] = ' ';
    out[n++] = letter;
  }
  if (keyed) {
    out[n++] = ' ';
    memcpy(out + n, pubkey_hex, hlen);
    n += hlen;
  }
  out[n] = 0;
  return n;
}


// Split a group text into its name prefix and message, and test the message against
// the trigger keyword. Group texts are "<sender>: <message>" (see
// BaseChatMesh::sendGroupMessage), and a text without that prefix is treated as all
// message and no sender. 'text' is modified in place: whitespace around the message
// is trimmed before the comparison, so " test " still triggers.
//
// A reply can never trigger a reply: a reply body begins with the bracketed
// requester name, or with "SNR" when there was none, and neither can match the
// keyword. Widening the match to accept a correlation id and a mode letter does not
// change that, and test/test_autoreply pins it.
static inline AutoReplyRequest autoReplyParseRequest(char* text, const char* keyword) {
  AutoReplyRequest req = { false, text, 0, text, NULL, 0, AUTOREPLY_MODE_DEFAULT, NULL };
  if (text == NULL || keyword == NULL) return req;

  char* msg = strstr(text, ": ");
  if (msg) {
    req.sender_len = msg - text;
    msg += 2;
  } else {
    msg = text;
  }

  while (*msg == ' ') msg++;
  char* end = msg + strlen(msg);
  while (end > msg && (end[-1] == ' ' || end[-1] == '\n' || end[-1] == '\r')) end--;
  *end = 0;

  req.message = msg;
  req.is_trigger = autoReplyMatchTrigger(msg, keyword, &req.id, &req.id_len, &req.mode,
                                         &req.pubkey_hex);
  return req;
}

// The body of a private test request -- the text an anonymous request carries after
// its sub-type byte -- against the trigger keyword. Only the bare keyword and the
// keyword with an id are requests here: the packet already names its sender by key
// and already makes the reply private, so a mode letter or a key in the body has
// nothing to say and is refused as chat, exactly as a mode-less caller refuses them
// on the channel. There is no name prefix to split either; a key is the sender.
// 'text' is trimmed in place like a channel request, so a stray line ending or
// trailing space does not turn a request into chat.
static inline bool autoReplyParsePrivateTest(char* text, const char* keyword,
                                             const char** id, size_t* id_len) {
  *id = NULL;
  *id_len = 0;
  if (text == NULL || keyword == NULL) return false;

  char* msg = text;
  while (*msg == ' ') msg++;
  char* end = msg + strlen(msg);
  while (end > msg && (end[-1] == ' ' || end[-1] == '\n' || end[-1] == '\r')) end--;
  *end = 0;

  return autoReplyMatchTrigger(msg, keyword, id, id_len);
}

// Read an 'on' or 'off' argument, the form every boolean setting in this feature
// takes. The token ends at the first space or line ending, so a value typed with
// trailing whitespace still reads, while a word that merely starts with 'on' does
// not. 'out' is left alone unless a whole valid token was found.
static inline bool autoReplyParseOnOff(const char* arg, bool* out) {
  if (arg == NULL || out == NULL) return false;

  while (*arg == ' ') arg++;
  size_t len = 0;
  while (arg[len] && arg[len] != ' ' && arg[len] != '\r' && arg[len] != '\n') len++;

  if (len == 2 && strncasecmp(arg, "on", 2) == 0) {
    *out = true;
    return true;
  }
  if (len == 3 && strncasecmp(arg, "off", 3) == 0) {
    *out = false;
    return true;
  }
  return false;
}

// The name a mode is configured and reported by. Silent is deliberately absent:
// it is something a request asks for, never a node's standing answer -- a node
// that should answer nobody is switched off, not configured to stay quiet while
// still parsing every request. Anything unrecognised is DEFAULT.
static inline const char* autoReplyModeName(uint8_t mode) {
  switch (mode) {
    case AUTOREPLY_MODE_FLOOD:   return "flood";
    case AUTOREPLY_MODE_PRIVATE: return "private";
    case AUTOREPLY_MODE_DIRECT:  return "direct";
    case AUTOREPLY_MODE_SILENT:  return "silent";
    default:                     return "default";
  }
}

// Read a mode name as `set autoreply.mode` takes it. Measured the same way an
// on/off argument is, so 'flooding' does not pass as 'flood'; and only the three
// standing modes are accepted, for the reason autoReplyModeName gives. 'out' is
// left alone unless a whole valid token was found.
static inline bool autoReplyParseModeName(const char* arg, uint8_t* out) {
  if (arg == NULL || out == NULL) return false;

  while (*arg == ' ') arg++;
  size_t len = 0;
  while (arg[len] && arg[len] != ' ' && arg[len] != '\r' && arg[len] != '\n') len++;

  static const uint8_t standing[] = {
    AUTOREPLY_MODE_FLOOD, AUTOREPLY_MODE_PRIVATE, AUTOREPLY_MODE_DIRECT,
  };
  for (size_t i = 0; i < sizeof(standing); i++) {
    const char* name = autoReplyModeName(standing[i]);
    if (len == strlen(name) && strncasecmp(arg, name, len) == 0) {
      *out = standing[i];
      return true;
    }
  }
  return false;
}

// The route back to a requester whose flood arrived along 'path'. A flood collects
// the hash of each repeater that carried it, first to last, so read backwards it
// is the path from here to the requester -- and that is the only route a private
// direct reply has. 'path_len' is the packet's encoded length byte (hash size in
// the top two bits, count in the rest), returned unchanged so the caller can hand
// both straight to sendDirect(). Hashes are reversed whole, never their bytes.
//
// The same links carried the request the other way, and this mesh is asymmetric
// as a matter of course, so a reply sent down the reverse path can fail where a
// flood would not. That is the trade the requester makes by asking for D.
static inline uint8_t autoReplyReversePath(const uint8_t* path, uint8_t path_len,
                                           uint8_t* out) {
  uint8_t size = (path_len >> 6) + 1;
  uint8_t count = path_len & 63;
  for (uint8_t i = 0; i < count; i++) {
    memcpy(out + i * size, path + (count - 1 - i) * size, size);
  }
  return path_len;
}

// A request from further away than 'max_hops' is ignored. Answering it means
// flooding, and every repeater that heard it floods a reply of its own, so this is
// the setting that bounds what one 'test' costs the mesh.
static inline bool autoReplyHopsAllowed(uint8_t hop_count, uint8_t max_hops) {
  return hop_count <= max_hops;
}

// A request that arrived direct can be answered with a single packet no repeater
// will retransmit, which costs the mesh nothing but reaches only what this node can
// reach. Hearing a request is no promise the requester can hear the answer - it may
// sit in far worse noise than a repeater does - so 'direct_flood' trades that packet
// for a flooded one that a neighbouring repeater can carry back.
static inline bool autoReplyReplyIsZeroHop(uint8_t hop_count, bool direct_flood) {
  return hop_count == 0 && !direct_flood;
}

// Mode M's answer rides the same block that answers a login, a regions query, an
// owner query and a clock query, and that block sends everything on one fixed
// delay. Only the test is an auto-reply. Only the test is staggered.
//
// The distinction matters in one direction: a login, regions, owner or clock
// request has a person waiting at a keyboard for it, and making them sit through a
// mesh-wide stagger measured in tens of seconds would read as a dead node, not as
// politeness. A test has nobody waiting, and every repeater in range answers the
// same request, which is exactly the case the stagger exists for.
//
// The sub-type is data[4] of the request. A login is identified by that byte being
// 0 (an empty password) or any printable character, so the safe rule is the narrow
// one: stagger the test sub-type and nothing else.
#define AUTOREPLY_ANON_TEST_SUBTYPE 0x04

static inline bool autoReplyAnonReplyIsStaggered(uint8_t sub_type) {
  return sub_type == AUTOREPLY_ANON_TEST_SUBTYPE;
}

// A command matched with memcmp alone accepts anything that starts with it, so a
// test for "set autoreply.channel" also swallows "set autoreply.channelfoo". The
// commands that take an argument end in a space and match at a boundary by
// construction; a command that takes none has no boundary unless it is given one.
//
// strncmp rather than memcmp because it stops at the terminator: a command shorter
// than the name being tested compares only the bytes that exist, instead of reading
// whatever follows it in the buffer.
static inline bool autoReplyCommandIs(const char* command, const char* name) {
  size_t n = strlen(name);
  return strncmp(command, name, n) == 0 && (command[n] == 0 || command[n] == ' ');
}
