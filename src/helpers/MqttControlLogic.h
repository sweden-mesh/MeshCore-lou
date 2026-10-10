#pragma once

#include "SlidingBudget.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <strings.h>

#include "MQTTObserverValidation.h"   // mqttOwnerKeyValid

// Pure, dependency-free decisions behind the MQTT control plane. Factored out of
// examples/simple_repeater/MqttControl.cpp so the envelope split, the replay
// window, the expiry window and the command allowlist can be attacked on the host
// (see test/test_mqtt_control) rather than only on a device that is hard to reach.
// The firmware holds the state, owns the key and does the I/O; every rule it
// applies is one of these functions.
//
// A login to the broker this rides on costs nothing to make, and any login may
// publish a command to any node. Nothing here may ever trust the transport: the
// signature is the only thing that says who sent a command, and these functions run in the order given
// in the workspace root's docs/architecture/decisions/001-mqtt-control-envelope.md
// (that tree is outside this repo, alongside it) -- cheap before
// expensive, and the signature before anything it protects.

// The envelope is deliberately not JSON. Signing a JSON document needs
// canonicalisation, and every canonicalisation bug is a signature-bypass bug.
// Here the signed region is a literal byte range of the payload as received.
#define MQTTCTRL_VERSION_TAG    "v1"
#define MQTTCTRL_FIELD_SEP      '|'

// Ed25519 signature, hex-encoded the way JWTHelper already emits one.
#define MQTTCTRL_SIG_HEX_LEN    128
#define MQTTCTRL_SIG_BYTES      64

// Bounds every buffer here. The broker's own ceiling is 896 bytes
// (MQTTBridge.cpp:4248-4251); staying well inside it keeps the staging buffer
// static, which the DRAM fragmentation note in docs/mbedtls-tls-footprint.md
// makes a requirement rather than a preference.
#define MQTTCTRL_MAX_PAYLOAD    512
#define MQTTCTRL_MAX_TOPIC      160
#define MQTTCTRL_MAX_COMMAND    160
#define MQTTCTRL_MAX_REPLY      160
// r1|counter|code|command|reply, plus the separators and a terminator.
#define MQTTCTRL_MAX_RESULT     (2 + 12 + 6 + MQTTCTRL_MAX_COMMAND + MQTTCTRL_MAX_REPLY + 8 + 129)   // + "|" and a 128-hex signature (r2)
#define MQTTCTRL_MAX_SIGNED     (MQTTCTRL_MAX_TOPIC + 1 + MQTTCTRL_MAX_PAYLOAD)

// A command may not claim to be valid indefinitely: a signer cannot mint one that
// outlives its usefulness and waits to be replayed at a worse moment.
#define MQTTCTRL_MAX_FUTURE_SECS  3600

// Two rate limits, because the two kinds of command cost different things. A
// parameter change costs a flash write; a trigger costs the whole mesh airtime
// and provokes a reply storm from every repeater in range, so it is capped far
// harder. Both apply to *validly signed* commands: a key that leaks must not
// become a flood weapon, and the airtime is not ours to spend.
#define MQTTCTRL_CMD_MAX          10
#define MQTTCTRL_CMD_WINDOW_SECS  3600
#define MQTTCTRL_TRIGGER_MAX      2
#define MQTTCTRL_TRIGGER_WINDOW   3600

// The QoS a result is published at, and it is not about delivery. In this bridge
// QoS 0 is a *synchronous* socket write from whichever task calls publish, and a
// result is published from the loop task while the bridge's own task is writing
// packets to the same socket. Two writers interleave, the broker reads a malformed
// packet and drops the node -- once per command, observed 2026-09-19 on both nodes
// that could be commanded. Anything above 0 takes the outbox instead and is written
// by the MQTT task alone. Costs one PUBACK per command, against ten an hour.
#define MQTTCTRL_RESULT_QOS       1

// The command budget is the shared sliding one; see SlidingBudget.h for why a fixed
// window is not enough here. The alias keeps the name the control plane's own code and
// tests use.
typedef SlidingBudget MqttCtrlBudget;

// Why a command was refused. Returned rather than logged so the caller decides
// what is safe to publish back -- a rejection reason is not secret, but the
// caller is the one that knows whether the result topic is public.
enum MqttCtrlResult {
  MQTTCTRL_OK = 0,
  MQTTCTRL_ERR_EMPTY,
  MQTTCTRL_ERR_TOO_LONG,
  MQTTCTRL_ERR_NO_SIGNATURE,
  MQTTCTRL_ERR_BAD_SIG_LEN,
  MQTTCTRL_ERR_BAD_SIG_HEX,
  MQTTCTRL_ERR_BAD_VERSION,
  MQTTCTRL_ERR_BAD_FIELDS,
  MQTTCTRL_ERR_BAD_COUNTER,
  MQTTCTRL_ERR_REPLAY,
  MQTTCTRL_ERR_EXPIRED,
  MQTTCTRL_ERR_FUTURE,
  MQTTCTRL_ERR_NO_CLOCK,
  MQTTCTRL_ERR_COMMAND_CHARS,
  MQTTCTRL_ERR_NOT_ALLOWED,
  // Appended, never renumbered: test_mqtt_control and panopticon/control.py both
  // read these as numbers, so an inserted value would silently re-label every
  // stored result.
  MQTTCTRL_ERR_NO_OWNER_KEY,
  // A signature that parsed as hex but did not verify. Distinct from
  // MQTTCTRL_ERR_BAD_SIG_HEX, which means the field was malformed: one is a
  // forgery or the wrong key, the other is a broken publisher, and a caller
  // watching a public broker wants to tell those apart.
  MQTTCTRL_ERR_SIG_INVALID,
  // Budget exhausted. Distinct from MQTTCTRL_ERR_NOT_ALLOWED, which means the
  // command is not on the allowlist: one is "ask again later", the other is
  // "never". Reporting both as NOT_ALLOWED made a throttled node look like a
  // node refusing the command outright.
  MQTTCTRL_ERR_RATE_LIMITED,
  // A transmit command addressed to every node in the region at once. Refused on
  // principle rather than on budget -- see mqttCtrlTransmitTopicResult.
  MQTTCTRL_ERR_BROADCAST_TRANSMIT,
};

// Can a staged command be examined at all?
//
// Without a provisioned owner key there is nothing to verify a signature against,
// so the command cannot be executed -- but it must still be *resolved*. The
// caller owns a single staging slot that only clears when the command is
// disposed of, and returning early here left it latched: every later command was
// dropped for the life of the boot, including after a key was finally
// provisioned. The bug was silent, and the documentation said the opposite
// ("every command is refused"), which is why the rule now lives in a function
// with a name and a test rather than in an early return.
//
// Unset, empty and malformed are one case, not three: none of them can verify a
// signature, and `mesh::Utils::fromHex` would refuse the last a moment later.
// `mqttOwnerKeyValid` already rejects NULL and the empty string, so guarding
// those separately here was dead code -- a mutation that deleted the guard left
// every test green, which is how it was found.
static inline MqttCtrlResult mqttCtrlOwnerReady(const char* owner_hex) {
  return mqttOwnerKeyValid(owner_hex) ? MQTTCTRL_OK : MQTTCTRL_ERR_NO_OWNER_KEY;
}

// One parsed envelope. Pointers refer into the caller's payload buffer, which
// must outlive this struct -- the same convention AutoReplyRequest uses.
struct MqttCtrlEnvelope {
  uint32_t counter;
  uint32_t expiry;
  const char* command;
  size_t command_len;
  const char* signed_part;    // the bytes the signature covers, after the topic
  size_t signed_len;
  uint8_t signature[MQTTCTRL_SIG_BYTES];
};

// One hex pair to a byte, or -1. Rejects anything that is not strictly two hex
// digits: strtol would accept leading spaces and a sign, which would let two
// different payloads carry the same signature bytes.
static inline int mqttCtrlHexByte(char hi, char lo) {
  int out = 0;
  for (int i = 0; i < 2; i++) {
    char c = (i == 0) ? hi : lo;
    int v;
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    else return -1;
    out = (out << 4) | v;
  }
  return out;
}

// Decode the 128 hex characters of a signature. Length is checked by the caller.
static inline bool mqttCtrlDecodeSignature(const char* hex, uint8_t* out) {
  for (int i = 0; i < MQTTCTRL_SIG_BYTES; i++) {
    int b = mqttCtrlHexByte(hex[i * 2], hex[i * 2 + 1]);
    if (b < 0) return false;
    out[i] = (uint8_t)b;
  }
  return true;
}

// Parse an unsigned decimal that occupies the whole span. Rejects empty spans,
// non-digits, leading '+'/'-'/whitespace and anything that overflows: a counter
// that wrapped or a length-prefixed sneak would each break the replay window.
static inline bool mqttCtrlParseU32(const char* start, size_t len, uint32_t* out) {
  if (len == 0 || len > 10) return false;
  uint64_t acc = 0;
  for (size_t i = 0; i < len; i++) {
    if (start[i] < '0' || start[i] > '9') return false;
    acc = acc * 10 + (uint64_t)(start[i] - '0');
    if (acc > 0xFFFFFFFFULL) return false;
  }
  *out = (uint32_t)acc;
  return true;
}

// The MQTT slot commands arrive on and results leave by, as 'set mqtt.cmd.slot'
// takes it: 0 for none, else 1..slot_count. One slot, not all of them, because the
// stats presets refuse subscriptions -- the control plane rides a broker of its own.
// 'slot_count' is the board's runtime slot array, not its active cap: the cap counts
// connections, not indices, so slot 3 can be one of a non-PSRAM board's two.
static inline bool mqttCtrlParseSlot(const char* text, int slot_count, uint8_t* out) {
  if (text == NULL || out == NULL || slot_count < 0) return false;
  uint32_t value = 0;
  if (!mqttCtrlParseU32(text, strlen(text), &value)) return false;
  if (value > (uint32_t)slot_count) return false;
  *out = (uint8_t)value;
  return true;
}

// A command may hold only printable ASCII, and never the field separator, so the
// split that found the signature cannot be steered by the command itself.
static inline bool mqttCtrlCommandCharsOk(const char* cmd, size_t len) {
  if (len == 0 || len > MQTTCTRL_MAX_COMMAND) return false;
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)cmd[i];
    if (c < 0x20 || c > 0x7E) return false;      // control chars, NUL, high bytes
    if (c == MQTTCTRL_FIELD_SEP) return false;
  }
  return true;
}

// Split "<signed-part>|<sig-hex>" and decode the signature, without yet trusting
// any of it. Splits at the LAST separator so a command cannot manufacture a
// second split point, and the signed span is a literal byte range of what
// arrived -- we verify exactly the bytes we received.
//
// Nothing here is authenticated. Everything this fills in stays untrusted until
// mqttCtrlBuildSignedMessage feeds it to Identity::verify.
static inline MqttCtrlResult mqttCtrlParseEnvelope(const char* payload, size_t len,
                                                   MqttCtrlEnvelope* out) {
  if (payload == NULL || out == NULL || len == 0) return MQTTCTRL_ERR_EMPTY;
  if (len > MQTTCTRL_MAX_PAYLOAD) return MQTTCTRL_ERR_TOO_LONG;

  size_t split = len;
  for (size_t i = len; i > 0; i--) {
    if (payload[i - 1] == MQTTCTRL_FIELD_SEP) { split = i - 1; break; }
  }
  if (split == len) return MQTTCTRL_ERR_NO_SIGNATURE;

  size_t sig_len = len - split - 1;
  if (sig_len != MQTTCTRL_SIG_HEX_LEN) return MQTTCTRL_ERR_BAD_SIG_LEN;
  if (!mqttCtrlDecodeSignature(payload + split + 1, out->signature)) {
    return MQTTCTRL_ERR_BAD_SIG_HEX;
  }

  out->signed_part = payload;
  out->signed_len = split;

  // "v1|<counter>|<expiry>|<command>" -- three separators inside the signed part.
  size_t tag_len = strlen(MQTTCTRL_VERSION_TAG);
  if (split < tag_len + 1) return MQTTCTRL_ERR_BAD_VERSION;
  if (memcmp(payload, MQTTCTRL_VERSION_TAG, tag_len) != 0) return MQTTCTRL_ERR_BAD_VERSION;
  if (payload[tag_len] != MQTTCTRL_FIELD_SEP) return MQTTCTRL_ERR_BAD_VERSION;

  size_t p = tag_len + 1;
  size_t c_end = p;
  while (c_end < split && payload[c_end] != MQTTCTRL_FIELD_SEP) c_end++;
  if (c_end >= split) return MQTTCTRL_ERR_BAD_FIELDS;
  if (!mqttCtrlParseU32(payload + p, c_end - p, &out->counter)) return MQTTCTRL_ERR_BAD_COUNTER;

  size_t e_start = c_end + 1;
  size_t e_end = e_start;
  while (e_end < split && payload[e_end] != MQTTCTRL_FIELD_SEP) e_end++;
  if (e_end >= split) return MQTTCTRL_ERR_BAD_FIELDS;
  if (!mqttCtrlParseU32(payload + e_start, e_end - e_start, &out->expiry)) {
    return MQTTCTRL_ERR_BAD_FIELDS;
  }

  out->command = payload + e_end + 1;
  out->command_len = split - (e_end + 1);
  if (!mqttCtrlCommandCharsOk(out->command, out->command_len)) {
    return MQTTCTRL_ERR_COMMAND_CHARS;
  }
  return MQTTCTRL_OK;
}

// The topics this node listens and answers on: meshcore/{IATA}/{leaf}/{suffix}.
//
// The leaf is the node's FULL public key, 64 upper-case hex characters, as the
// observer's own status and packet topics name it (`setDeviceID`). Until
// 2026-10-08 it was the first four bytes; the whole key is what a broker needs so
// that one ACL pattern -- the login username `v1_<key>` must appear in the topic --
// keeps each node to its own `cmd` and `res`. The 8-hex id stays what people see.
// The longest form, `meshcore/XXXX/<64 hex>/cmd`, is 82 characters, inside
// MQTTCTRL_MAX_TOPIC. The broadcast leaf is the word `all`.
static inline bool mqttCtrlBuildTopic(const char* iata, const char* leaf, const char* suffix,
                                      char* out, size_t out_size) {
  if (iata == NULL || iata[0] == 0 || leaf == NULL || leaf[0] == 0 || suffix == NULL ||
      out == NULL || out_size == 0) return false;
  int n = snprintf(out, out_size, "meshcore/%s/%s/%s", iata, leaf, suffix);
  return n > 0 && (size_t)n < out_size && (size_t)n <= MQTTCTRL_MAX_TOPIC;
}

// Which MQTT slot `set mqtt.cmd on` takes when none is configured (2026-10-08):
// the first of slots 3..6 whose preset is `none`. `presets` is the per-slot preset
// name, `slot_count` how many the build has. Returns the 0-based index, or -1 when
// every candidate is in use -- then the caller says so rather than picks.
//
// Slot 1 is the observer's and is never taken. Slot 2 is taken first, but only on a
// board that runs two slots at once (no PSRAM; operator 2026-10-10): there the two
// that run are the observer's and the plane's, and slot 2 is free for it when it holds
// nothing or the Observer's own default, `analyzer-eu` -- an uplink the owner did not
// choose. Any other preset there is a collector the owner did choose, and is left
// alone. With PSRAM slot 2 is never taken, whatever it holds.
#define MQTTCTRL_FIRST_AUTO_SLOT 2
#define MQTTCTRL_SLOT2_DEFAULT   "analyzer-eu"

static inline bool mqttCtrlPresetFree(const char* name) {
  return name == NULL || name[0] == 0 || strcasecmp(name, "none") == 0;
}

static inline int mqttCtrlPickSlot(const char* const* presets, int slot_count,
                                   bool two_slot_board) {
  if (presets == NULL) return -1;
  if (two_slot_board && slot_count >= 2
      && (mqttCtrlPresetFree(presets[1]) || strcasecmp(presets[1], MQTTCTRL_SLOT2_DEFAULT) == 0)) {
    return 1;
  }
  for (int i = MQTTCTRL_FIRST_AUTO_SLOT; i < slot_count; i++) {
    if (mqttCtrlPresetFree(presets[i])) return i;
  }
  return -1;
}

// Does this command change the MQTT slot the command plane rides? Any form does it:
// `set mqttN.<anything>` for that slot, and `set mqtt.analyzer.us|eu ...`, which write
// slots 1 and 2 whatever they hold. Each would take the plane off its slot in silence --
// over the plane itself, a command that cuts the line it arrived on -- so the caller
// refuses it with the reason. Moving the plane is `set mqtt.cmd.slot`, serial only.
// Matched on the command with leading spaces dropped and runs of spaces collapsed,
// since the CLI's own parser reads `set mqtt.analyzer.eu  off` as an off.
static inline bool mqttCtrlTouchesSlot(const char* command, int cmd_slot) {
  if (command == NULL || cmd_slot <= 0) return false;
  char norm[32];
  size_t n = 0;
  for (const char* p = command; *p && n < sizeof(norm) - 1; p++) {
    if (*p == ' ' && (n == 0 || norm[n - 1] == ' ')) continue;
    norm[n++] = *p;
  }
  norm[n] = 0;
  if (strncmp(norm, "set mqtt", 8) == 0 && norm[8] >= '1' && norm[8] <= '9' && norm[9] == '.') {
    return norm[8] - '0' == cmd_slot;
  }
  const char* analyzer = cmd_slot == 1 ? "set mqtt.analyzer.us" : cmd_slot == 2 ? "set mqtt.analyzer.eu" : NULL;
  if (analyzer == NULL) return false;
  size_t len = strlen(analyzer);
  return strncmp(norm, analyzer, len) == 0 && (norm[len] == ' ' || norm[len] == 0);
}

// ---- `mqtt.cmd ping` (operator 2026-10-10) -------------------------------------------
//
// Proves the whole plane on the spot: the node publishes `ping|<nonce>` on
// meshcore/<IATA>/<own key>/ping, and the command broker -- never another client --
// answers `pong|<nonce>` on the node's own /cmd. A pong is not a command. It is
// recognised before any signature parsing, so it costs a compare and not an Ed25519
// verify; it is never staged, executed, answered or logged; and it counts only when
// it carries the nonce of the one ping in flight, which it then consumes, so a second
// pong (a bridged broker's echo, a replay) is ignored.
#define MQTTCTRL_PING_TIMEOUT_MS  10000
#define MQTTCTRL_PING_NONCE_LEN   8
#define MQTTCTRL_PONG_PREFIX      "pong|"
#define MQTTCTRL_PING_PREFIX      "ping|"

struct MqttCtrlPing {
  char nonce[MQTTCTRL_PING_NONCE_LEN + 1];
  volatile bool in_flight;             // set on the loop task, cleared by the pong's task
  volatile uint32_t answered_ms;       // millis() the pong was taken
};

static inline bool mqttCtrlIsPong(const uint8_t* payload, size_t len) {
  const size_t n = sizeof(MQTTCTRL_PONG_PREFIX) - 1;
  return payload != NULL && len >= n && memcmp(payload, MQTTCTRL_PONG_PREFIX, n) == 0;
}

// Arms `ping` with `nonce` (8 hex) and writes the payload to publish. The nonce is
// stored before the ping is marked in flight, so a pong racing the publish finds it.
static inline bool mqttCtrlArmPing(MqttCtrlPing* ping, const char* nonce, char* out,
                                   size_t out_size) {
  if (ping == NULL || nonce == NULL || out == NULL) return false;
  if (strlen(nonce) != MQTTCTRL_PING_NONCE_LEN) return false;
  for (size_t i = 0; i < MQTTCTRL_PING_NONCE_LEN; i++) {
    if (!isxdigit((unsigned char)nonce[i])) return false;
  }
  int n = snprintf(out, out_size, MQTTCTRL_PING_PREFIX "%s", nonce);
  if (n <= 0 || (size_t)n >= out_size) return false;
  memcpy(ping->nonce, nonce, MQTTCTRL_PING_NONCE_LEN + 1);
  ping->in_flight = true;
  return true;
}

// Takes a pong for the ping in flight. True only for exactly `pong|<that nonce>`;
// anything else -- no ping in flight, another nonce, a trailing byte -- changes nothing.
static inline bool mqttCtrlTakePong(MqttCtrlPing* ping, const uint8_t* payload, size_t len,
                                    uint32_t now_ms) {
  const size_t n = sizeof(MQTTCTRL_PONG_PREFIX) - 1;
  if (ping == NULL || !ping->in_flight || !mqttCtrlIsPong(payload, len)) return false;
  if (len != n + MQTTCTRL_PING_NONCE_LEN) return false;
  if (strncasecmp((const char *) &payload[n], ping->nonce, MQTTCTRL_PING_NONCE_LEN) != 0) return false;
  ping->answered_ms = now_ms;
  ping->in_flight = false;
  return true;
}

// The step that failed, so the console says what is wrong.
enum MqttCtrlPingStep {
  MQTTCTRL_PING_OK,
  MQTTCTRL_PING_OFF,               // no plane: not on, or no slot
  MQTTCTRL_PING_NOT_CONNECTED,
  MQTTCTRL_PING_PUBLISH_REFUSED,
  MQTTCTRL_PING_NO_PONG,
};

static inline void mqttCtrlPingAnswer(MqttCtrlPingStep step, int slot, uint32_t elapsed_ms,
                                      const char* link, char* out, size_t out_size) {
  if (out == NULL || out_size == 0) return;
  switch (step) {
    case MQTTCTRL_PING_OK:
      snprintf(out, out_size, "OK - pong in %u ms on slot %d (%s)", (unsigned)elapsed_ms, slot,
               link != NULL ? link : "?");
      break;
    case MQTTCTRL_PING_OFF:
      snprintf(out, out_size, "Err - the command plane is off: set mqtt.cmd on");
      break;
    case MQTTCTRL_PING_NOT_CONNECTED:
      snprintf(out, out_size, "Err - slot %d not connected", slot);
      break;
    case MQTTCTRL_PING_PUBLISH_REFUSED:
      snprintf(out, out_size, "Err - publish refused");
      break;
    default:
      snprintf(out, out_size, "Err - no pong in %d s: /cmd is not subscribed or the broker "
                              "is not answering", MQTTCTRL_PING_TIMEOUT_MS / 1000);
      break;
  }
}

// Assemble the exact bytes the signature covers: the topic, a newline, then the
// signed part of the payload.
//
// The topic is inside the signature so one signature is valid for exactly one
// destination. Without it, a command signed for one node could be captured and
// republished on another node's topic, or a per-node command replayed as a
// broadcast -- the two cases the counter alone cannot see, because each node
// keeps its own counter.
static inline bool mqttCtrlBuildSignedMessage(const char* topic, const MqttCtrlEnvelope* env,
                                              uint8_t* out, size_t out_size, size_t* out_len) {
  if (topic == NULL || env == NULL || out == NULL || out_len == NULL) return false;
  size_t topic_len = strlen(topic);
  if (topic_len == 0 || topic_len > MQTTCTRL_MAX_TOPIC) return false;
  size_t total = topic_len + 1 + env->signed_len;
  if (total > out_size) return false;

  memcpy(out, topic, topic_len);
  out[topic_len] = '\n';
  memcpy(out + topic_len + 1, env->signed_part, env->signed_len);
  *out_len = total;
  return true;
}

// The replay window. Strictly greater, never equal: unlike the LoRa admin path
// there is no delivery uncertainty here to forgive, so an equal counter is a
// replay rather than a retry.
//
// The caller must persist the new value BEFORE executing the command. A counter
// held only in RAM reopens the whole window on the next reboot, and reboots are
// routine; a counter persisted after execution reopens it for whatever crashed
// mid-command. The cost is that a crashed command is not retried, which is the
// right trade: a silently repeated 'trigger test' spends airtime nobody asked for.
static inline bool mqttCtrlCounterAccepted(uint32_t last_seen, uint32_t offered) {
  return offered > last_seen;
}

// Expiry, bounded at both ends. 'now' of 0 means the clock has never synced, and
// then this fails closed: without a trustworthy clock the expiry check means
// nothing, and accepting on a guess would be worse than refusing.
static inline MqttCtrlResult mqttCtrlCheckExpiry(uint32_t now, uint32_t expiry) {
  if (now == 0) return MQTTCTRL_ERR_NO_CLOCK;
  if (expiry < now) return MQTTCTRL_ERR_EXPIRED;
  if (expiry - now > MQTTCTRL_MAX_FUTURE_SECS) return MQTTCTRL_ERR_FUTURE;
  return MQTTCTRL_OK;
}

// Does 'command' start with 'prefix' and then stop at a boundary -- end of
// string, a space, or a '.'? The dot matters: the settings are 'set autoreply',
// 'set autoreply.hops', 'set autoreply.direct.flood', so a space-only boundary
// would admit the bare command and reject every parameter under it.
//
// Requiring *some* boundary is what stops 'set autoreplyX' riding in on
// 'set autoreply'. Allowing '.' deliberately opens the whole 'autoreply.'
// namespace, which is ours and which the CLI validates itself; it does not open
// any other namespace, because the prefix before the dot still has to match.
static inline bool mqttCtrlPrefixWithBoundary(const char* command, size_t len,
                                              const char* prefix) {
  size_t plen = strlen(prefix);
  if (len < plen) return false;
  if (strncasecmp(command, prefix, plen) != 0) return false;
  if (len == plen) return true;
  return command[plen] == ' ' || command[plen] == '.';
}

// The command surface: a deny list over admitted verbs.
//
// Until 2026-10-08 this was an allowlist of fourteen entries. The operator's
// decision that day (planning/mccontrol/u17-blacklist-proposal.md in the
// workspace) makes the control plane a command centre: every repeater command
// travels this way EXCEPT what is listed here as denied. The list is the thing
// to review, so it is grouped by why, and each group is pinned by a test.
//
// This remains the security boundary, and it remains independent of the
// sender_timestamp policy: the remote path never passes 0, so `set prv.key`,
// `erase`, `log`, the `stats-*` dumps and the command key stay serial-only even
// if a line here were lost. Both gates must be wrong for one of those to run.
//
// Three rules shape the lists:
//  1. A command must start with an ADMITTED VERB (`set`, `get`, `region`, ...).
//     A verb the CLI grows later does not reach the mesh until someone adds it.
//  2. It must match no DENIED FAMILY. Families use the boundary rule, so
//     `set mqtt.cmd` denies `set mqtt.cmd`, `set mqtt.cmd.slot 2` and
//     `set mqtt.cmd.pubkey ...` alike, and `set radio` denies every `radio.*`.
//  3. Reads of credentials are denied by family too, and the per-slot broker
//     credentials (`get mqttN.password`, `.token`, `.username`) by a digit rule,
//     since there are six slots and the number is not part of the name.
struct MqttCtrlAllowEntry {
  const char* text;
  bool exact;
};

// The bare command, and nothing after it.
static inline bool mqttCtrlExactCommand(const char* command, size_t len, const char* text) {
  size_t tlen = strlen(text);
  return len == tlen && strncasecmp(command, text, tlen) == 0;
}

// `get mqttN.<leaf>` for any slot digit N: the credential reads of a broker slot.
static inline bool mqttCtrlIsSlotCredentialRead(const char* command, size_t len) {
  static const char* const leaves[] = { ".password", ".token", ".username" };
  const char* head = "get mqtt";
  size_t hlen = strlen(head);
  if (len < hlen + 2 || strncasecmp(command, head, hlen) != 0) return false;
  if (command[hlen] < '0' || command[hlen] > '9') return false;
  const char* rest = command + hlen + 1;
  size_t rlen = len - hlen - 1;
  for (size_t i = 0; i < sizeof(leaves) / sizeof(leaves[0]); i++) {
    size_t llen = strlen(leaves[i]);
    if (rlen >= llen && strncasecmp(rest, leaves[i], llen) == 0 &&
        (rlen == llen || rest[llen] == ' ' || rest[llen] == '.')) return true;
  }
  return false;
}

static inline bool mqttCtrlCommandDenied(const char* command, size_t len) {
  static const char* const denied[] = {
    // identity: a changed key is a different node; the fleet, the maps and every
    // history line lose it.
    "set prv.key", "set public.key",
    // the plane itself: a signed command that repoints the key or the slot the
    // node listens on silently removes it from control, and only a serial visit
    // undoes that. The standard Observer MQTT settings (mqttN.*, mqtt.presets,
    // mqtt.iata, mqtt.*) are deliberately NOT here: a broker may go away and
    // another must be reachable without a visit (operator, 2026-10-08).
    "set mqtt.cmd", "get mqtt.cmd.pubkey",
    // credentials and ownership: a result is published where anyone can read it,
    // and a write of these is a takeover of something other than the node.
    "set wifi.pwd", "get wifi.pwd", "set wifi.ssid", "get wifi.ssid",
    "set password", "get password", "password",
    "set guest.password", "get guest.password",
    "set alert.psk", "get alert.psk",
    "set bridge.secret", "get bridge.secret",
    "set snmp.community", "get snmp.community",
    "set mqtt.email", "get mqtt.email", "set mqtt.owner", "get mqtt.owner",
    "set owner.info", "get owner.info",
    "set tls", "get tls", "tls.bundletest", "get prv.key",
    // destructive, or no way back from the road. `reboot` and `clkreboot` are
    // admitted (operator, 2026-10-08): settings need them to apply. `ota check`
    // is admitted; `ota update` waits for a signed image and rollback
    // (planning/firmware/TODO.md section 11).
    "erase", "start", "ota update", "poweroff", "shutdown", "set bootloader.ver",
    // position and role: position is evidence the whole mesh relies on, and
    // `repeat off` is how a leaked key silences a region in ten commands. The
    // position read stays out too: whether a node publishes where it is belongs
    // to its owner per node (the advert), not to a signed read whose result is
    // public on the broker.
    "set lat", "set lon", "get lat", "get lon", "set role", "set repeat",
    // radio: a wrong value takes the node off the mesh with no remote way back.
    "set freq", "set radio", "set tx", "set extra.sf", "set dutycycle", "tempradio",
    // airtime: `trigger` is the one sanctioned transmit, on its own budget.
    "advert", "alert", "set advert.interval", "set flood.advert.interval",
    // the clock: expiry is judged against it. `time <epoch>` steps it forward by
    // any amount; `clock sync` steps it to the node's own now and is harmless.
    "time",
    // serial-only already (sender_timestamp == 0); listed so the two gates agree.
    "log", "stats-core", "stats-packets", "stats-radio", "stats-radio-diag",
  };
  for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); i++) {
    if (mqttCtrlPrefixWithBoundary(command, len, denied[i])) return true;
  }
  // The secrets, denied by bare prefix with no boundary at all: the CLI's own
  // matching is an unbounded memcmp, so `get prv.keyx` would reach the key's
  // handler, and nothing legitimate starts with these letters.
  static const char* const secrets[] = {
    "get prv", "set prv", "get password", "set password", "get guest.password",
    "get wifi.pwd", "set wifi.pwd", "get alert.psk", "set alert.psk",
    "get bridge.secret", "set bridge.secret", "get snmp.community", "set snmp.community",
    "get mqtt.cmd.pubkey", "set mqtt.cmd", "get tls", "set tls",
  };
  for (size_t i = 0; i < sizeof(secrets) / sizeof(secrets[0]); i++) {
    size_t plen = strlen(secrets[i]);
    if (len >= plen && strncasecmp(command, secrets[i], plen) == 0) return true;
  }
  return mqttCtrlIsSlotCredentialRead(command, len);
}

static inline bool mqttCtrlCommandAllowed(const char* command, size_t len) {
  if (!mqttCtrlCommandCharsOk(command, len)) return false;
  if (mqttCtrlCommandDenied(command, len)) return false;

  // A bare `set` or `get`, or one with nothing after the space, names no setting;
  // refused here so a typo never reaches the CLI's unbounded memcmp.
  if (mqttCtrlExactCommand(command, len, "set") || mqttCtrlExactCommand(command, len, "get") ||
      mqttCtrlExactCommand(command, len, "set ") || mqttCtrlExactCommand(command, len, "get ")) return false;

  static const MqttCtrlAllowEntry verbs[] = {
    // Families. The boundary rule is load-bearing: make `set` exact and nothing
    // after it travels; make `trigger test` exact and the correlation id stops.
    { "set", false },
    { "get", false },
    { "region", false },           // the whole map: read, put, allowf, denyf, remove, save
    { "trigger test", false },     // the optional 8-hex correlation id and mode
    { "trigger private", false },  // the target key, and the optional id after it
    { "neighbor.remove", false },  // one entry of the neighbour table; it refills
    { "sensor", false },           // sensor get/set
    { "gps", false },              // gps on/off
    { "powersaving", false },      // powersaving on/off
    { "clock", false },            // the clock, and `clock sync` to the node's own now
    // Exact: the bare command and nothing else.
    { "ver", true },
    { "reboot", true },
    { "clkreboot", true },
    { "neighbors", true },
    { "board", true },
    { "memory", true },
    { "clear stats", true },       // resets counters, nothing else
    { "ota check", true },         // reports the available build; flashes nothing
    { "mqtt.cmd ping", true },     // a ping to the broker and back; nothing on the air
  };
  for (size_t i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++) {
    bool ok = verbs[i].exact
                ? mqttCtrlExactCommand(command, len, verbs[i].text)
                : mqttCtrlPrefixWithBoundary(command, len, verbs[i].text);
    if (ok) return true;
  }
  return false;
}

// Does this command put a packet on the air? Triggers are limited separately and
// much more tightly than parameter changes, so the caller needs to know which
// budget to spend before it executes anything.
static inline bool mqttCtrlIsTransmitCommand(const char* command, size_t len) {
  return mqttCtrlPrefixWithBoundary(command, len, "trigger");
}

// The whole decision except the signature itself, which needs the node's key and
// so belongs to the firmware. Runs the order from the ADR, stopping at the first
// refusal. The caller checks the signature between parsing and this call, then
// persists the counter, then executes.
static inline MqttCtrlResult mqttCtrlAuthorise(const MqttCtrlEnvelope* env,
                                               uint32_t last_counter, uint32_t now) {
  if (env == NULL) return MQTTCTRL_ERR_EMPTY;
  if (!mqttCtrlCounterAccepted(last_counter, env->counter)) return MQTTCTRL_ERR_REPLAY;

  MqttCtrlResult expiry = mqttCtrlCheckExpiry(now, env->expiry);
  if (expiry != MQTTCTRL_OK) return expiry;

  if (!mqttCtrlCommandAllowed(env->command, env->command_len)) return MQTTCTRL_ERR_NOT_ALLOWED;
  return MQTTCTRL_OK;
}

// The published result: `r1|<counter>|<code>|<command>|<reply>`.
//
// A `get` reply on its own is "> 0.5" -- true of whatever was asked, which with
// one requester polling several nodes is not enough to act on. The topic names
// the node, so what is missing is the question. The counter answers it: it is
// already persisted per node, already strictly increasing, and already what the
// requester chose, which makes it the natural correlation id -- the same role the
// 8-hex id plays on the auto-reply path.
//
// Flat rather than JSON, and clamped rather than discarded. The existing payload
// builders have a hard 768-byte budget and *drop* a payload that exceeds it
// (MQTTPayloadBuilder.cpp:9-21); inheriting that would mean the longest replies --
// the interesting ones -- silently never arrive. Truncation here yields a shorter
// line that still parses, because the reply is last and every earlier field is
// bounded.
//
// Splitting on the separator is unambiguous: mqttCtrlCommandCharsOk refuses a
// command containing one, so only the trailing reply can, and a parser takes the
// remainder of the line as the reply rather than splitting it further.
//
// Returns the number of bytes written, never more than out_size - 1.
static inline size_t mqttCtrlFormatResult(char* out, size_t out_size, uint32_t counter,
                                          int code, const char* command, const char* reply) {
  if (out == NULL || out_size == 0) return 0;
  out[0] = 0;
  int n = snprintf(out, out_size, "r1%c%u%c%d%c%s%c%s",
                   MQTTCTRL_FIELD_SEP, (unsigned)counter,
                   MQTTCTRL_FIELD_SEP, code,
                   MQTTCTRL_FIELD_SEP, command != NULL ? command : "",
                   MQTTCTRL_FIELD_SEP, reply != NULL ? reply : "");
  if (n < 0) { out[0] = 0; return 0; }
  return ((size_t)n >= out_size) ? out_size - 1 : (size_t)n;
}

// The signed result (2026-10-08, ships with ar-11): `r2|counter|code|command|reply|<sig>`,
// the signature 128 hex of Ed25519 by the node's own identity key over
// "<result topic>\n" + "r2|counter|code|command|reply" -- the same shape as a
// command's signature, so one verifier serves both. A result line is published
// where anyone can read and anyone can write, so an unsigned `r1` lets a stranger
// publish "ok" in a node's name; `r2` lets a tool check the node said it, with the
// key the node's topic already names. Tools accept both for the mixed field; an
// `r1` is shown as "unverified result".
//
// The signer is a callback so this stays host-testable: the firmware passes the
// identity's sign; a test passes its own key. The reply is last and shortens
// first: the line is cut so the separator and the whole signature always fit.
typedef void (*MqttCtrlSigner)(void* ctx, uint8_t sig[64], const uint8_t* msg, size_t msg_len);

static inline size_t mqttCtrlFormatSignedResult(char* out, size_t out_size, const char* topic,
                                                uint32_t counter, int code, const char* command,
                                                const char* reply, MqttCtrlSigner sign, void* ctx) {
  if (out == NULL || out_size == 0 || topic == NULL || sign == NULL) return 0;
  out[0] = 0;
  const size_t tail = 1 + 2 * 64;                       // "|" + 128 hex
  if (out_size <= tail + 1) return 0;
  size_t budget = out_size - 1 - tail;                   // what the unsigned line may take
  int n = snprintf(out, budget + 1, "r2%c%u%c%d%c%s%c%s",
                   MQTTCTRL_FIELD_SEP, (unsigned)counter,
                   MQTTCTRL_FIELD_SEP, code,
                   MQTTCTRL_FIELD_SEP, command != NULL ? command : "",
                   MQTTCTRL_FIELD_SEP, reply != NULL ? reply : "");
  if (n < 0) { out[0] = 0; return 0; }
  size_t line_len = ((size_t)n > budget) ? budget : (size_t)n;

  // the bytes under the signature: topic, newline, the (possibly cut) line
  size_t topic_len = strlen(topic);
  if (topic_len == 0 || topic_len > MQTTCTRL_MAX_TOPIC) { out[0] = 0; return 0; }
  uint8_t msg[MQTTCTRL_MAX_TOPIC + 1 + MQTTCTRL_MAX_RESULT];
  if (topic_len + 1 + line_len > sizeof(msg)) { out[0] = 0; return 0; }
  memcpy(msg, topic, topic_len);
  msg[topic_len] = '\n';
  memcpy(msg + topic_len + 1, out, line_len);

  uint8_t sig[64];
  sign(ctx, sig, msg, topic_len + 1 + line_len);
  static const char hex_digits[] = "0123456789ABCDEF";   // not HEX: Arduino's Print.h defines it
  char* p = out + line_len;
  *p++ = MQTTCTRL_FIELD_SEP;
  for (int i = 0; i < 64; i++) { *p++ = hex_digits[sig[i] >> 4]; *p++ = hex_digits[sig[i] & 0x0F]; }
  *p = 0;
  return line_len + tail;
}

// The bytes a verifier of `r2` checks: "<topic>\n" + everything before the last
// separator. Returns the signature's hex start, or NULL when the line is not an r2.
static inline const char* mqttCtrlSignedResultSplit(const char* line, size_t len, size_t* line_len) {
  if (line == NULL || len < 2 + 1 + 128 || strncmp(line, "r2", 2) != 0) return NULL;
  if (line[len - 129] != MQTTCTRL_FIELD_SEP) return NULL;
  *line_len = len - 129;
  return line + len - 128;
}

// Is this the broadcast topic, meshcore/{IATA}/all/cmd, rather than one node's?
// The per-node leaf is the node's key in hex (8 or 64 characters), which can never
// spell "all", so matching the tail is unambiguous.
static inline bool mqttCtrlTopicIsBroadcast(const char* topic) {
  if (topic == NULL) return false;
  static const char SUFFIX[] = "/all/cmd";
  size_t tlen = strlen(topic);
  size_t slen = sizeof(SUFFIX) - 1;
  return tlen >= slen && strcmp(topic + tlen - slen, SUFFIX) == 0;
}

// A transmit command may be addressed to one node, never to all of them.
//
// The rate limits are per node: four triggers an hour each. That bounds what any
// single node does and says nothing about what happens when one publish reaches
// every node in a region at once -- each of them then transmits, inside the same
// few seconds, every one of them within budget. The workspace rule is explicit
// that "any design that scales transmissions with the number of nodes is wrong",
// and a broadcast trigger is exactly that shape: the more of the mesh adopts this
// firmware, the worse the storm it enables.
//
// So this is refused on principle, not on budget, and the refusal is stateless --
// it runs before the limiters, which spend when asked.
//
// Reversible if a real use appears: broadcasting a *parameter* change is fine and
// stays allowed, because setting a value costs no airtime. Only transmitting does.
static inline MqttCtrlResult mqttCtrlTransmitTopicResult(bool is_transmit, const char* topic) {
  if (is_transmit && mqttCtrlTopicIsBroadcast(topic)) return MQTTCTRL_ERR_BROADCAST_TRANSMIT;
  return MQTTCTRL_OK;
}

// The sender_timestamp an MQTT command executes with. **Never 0.**
//
// Zero is not a clock reading in this CLI, it is a privilege marker: it means the
// caller is physically present (serial, ethernet, the web portal), and it is what
// gates `get prv.key`, `set prv.key`, `set mqtt.cmd.pubkey` and `erase`. A remote
// command that reached the CLI with 0 would be handed exactly the privilege those
// gates exist to withhold.
//
// The dangerous case is not the ordinary one. A node whose clock has never synced
// reports 0, so the naive `runCommand(now, ...)` grants full local privilege to a
// remote caller precisely when NTP is down -- an outage becomes a privilege
// escalation. Mapping 0 to 1 costs a second of accuracy and removes that entirely.
//
// Lives here rather than as a static in MqttControl.cpp so it can be tested: this
// is the single line that keeps every privilege gate in CommonCLI meaningful
// against MQTT, and it was previously unreachable from any test.
static inline uint32_t mqttCtrlSenderStamp(uint32_t now) {
  return now == 0 ? 1 : now;
}

// Rate limiting, as a decision the caller makes with limiters it owns. Split out
// rather than folded into mqttCtrlAuthorise because the limiters are stateful and
// consume budget when asked -- so the caller must run every stateless check
// first, and only then spend. Asking a limiter about a command that was going to
// be refused anyway would let anyone drain the budget with garbage.
//
// 'allow_general' and 'allow_transmit' are the results of MqttCtrlBudget::allow on
// the caller's two limiters. **The budgets are disjoint** (operator, 2026-09-13): a
// transmit spends only the transmit budget, a parameter change only the command one.
// They used to share, so two triggers an hour also took a fifth of the budget for
// reading settings -- at 20 and 4 that was merely wrong, at 10 and 2 it would bite.
// The caller must therefore ask only the limiter that applies; see
// mqttCtrlSpendsCommandBudget, which is the rule the caller branches on.
//
// Returns a result rather than a bool so the refusal carries its own code. The
// name changed with the return type on purpose: the old bool was read as
// `if (!mqttCtrlRateAccepted(...))`, and MQTTCTRL_OK is 0, so a same-named
// function returning an enum would have inverted every call site in silence.
// Which budget a command spends. A limiter spends when asked, so this decides which
// one the caller may ask -- getting it wrong does not refuse anything, it quietly
// drains the wrong budget, which is the kind of bug that shows up as a node that
// stops answering on the hour.
static inline bool mqttCtrlSpendsCommandBudget(bool is_transmit) { return !is_transmit; }

static inline bool mqttCtrlSpendsTransmitBudget(bool is_transmit) { return is_transmit; }

static inline MqttCtrlResult mqttCtrlRateResult(bool is_transmit, bool allow_general,
                                                bool allow_transmit) {
  if (!allow_general) return MQTTCTRL_ERR_RATE_LIMITED;
  if (is_transmit && !allow_transmit) return MQTTCTRL_ERR_RATE_LIMITED;
  return MQTTCTRL_OK;
}
