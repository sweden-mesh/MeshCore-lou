#pragma once

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>

// Which way a broker slot authenticates -- one rule, in one place, reachable from the
// host test suite.
//
// A slot signs in with a JWT when its preset says so, or when it has *no* preset and an
// audience is set: on a custom slot the audience is the switch. That second half is the
// surprise. `set mqttN.preset custom` does not clear the audience, so a slot moved off a
// JWT preset goes on presenting a token -- over TLS, to a plain broker -- while
// `get mqttN.preset` and `get mqttN.server` read exactly as intended. Found 2026-09-01; it
// cost an evening on a bench with a console attached, and on a deployed node it would not
// have been findable at all. The rule is upstream's and is left alone; what was missing
// was any way to see its result, which is what mqttSlotAuthLabel is for.
//
// A preset that is *not* JWT ignores a stale audience. MQTTBridge.cpp used to disagree
// with itself about that in one place (the keepalive tuning), which is how this header
// came to exist.
static inline bool mqttSlotUsesJwt(bool has_preset, bool preset_is_jwt, bool has_audience) {
  if (has_preset) return preset_is_jwt;
  return has_audience;
}

// Short, because `get mqtt.stats` is clamped to one reply and the per-slot list is what
// gets cut first.
static inline const char* mqttSlotAuthLabel(bool uses_jwt) { return uses_jwt ? "jwt" : "pw"; }

// The client id a slot connects with: the node's 8-hex id, the slot number and a tag
// only the node can compute, `A0586238-3-9F04C21B`. Left to esp-mqtt every client on a
// board is `ESP32_<3 MAC bytes>`, so two slots of one node on one broker -- an Observer
// slot and the command plane's -- shared it, and the broker refused the second login for
// as long as the first held the id. The tag is what keeps the id from being public: a
// broker closes the older session when a new one takes its id, and on a broker whose
// credentials are public (meshat.se) an id anyone could compute from the node's key would
// let anyone knock the node's Observer slot off. The caller derives the tag from the
// node's private key, so it is stable across reboots and reflashes and needs no storage.
// 21 characters, inside the 23 every MQTT 3.1.1 broker must accept.
// False, leaving esp-mqtt's default, while the device id or the tag is not yet known.
#define MQTT_SLOT_CLIENT_ID_SIZE 24
#define MQTT_SLOT_CLIENT_TAG_LEN 8

static inline bool mqttSlotHex(const char* s, int n) {
  if (s == NULL) return false;
  for (int i = 0; i < n; i++) {
    if (!isxdigit((unsigned char)s[i])) return false;
  }
  return true;
}

static inline bool mqttSlotClientId(const char* device_id, const char* tag, int slot_index,
                                    char* out, size_t size) {
  if (out == NULL || size < MQTT_SLOT_CLIENT_ID_SIZE) return false;
  if (slot_index < 0 || slot_index > 8) return false;
  if (!mqttSlotHex(device_id, 8) || !mqttSlotHex(tag, MQTT_SLOT_CLIENT_TAG_LEN)) return false;
  snprintf(out, size, "%.8s-%d-%.8s", device_id, slot_index + 1, tag);
  return true;
}
