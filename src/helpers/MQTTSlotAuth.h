#pragma once

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
