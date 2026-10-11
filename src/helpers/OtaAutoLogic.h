#pragma once
// Automatic pull OTA, paced (2026-10-08, ships with ar-11): a node with `ota.auto on`
// checks the channel every `ota.check.hours` and, when a newer signed build is on
// offer, updates -- but never all at once and never at night. The whole policy is
// here as pure functions of the clock, so it is host-tested and the firmware only
// asks "is it time?" and "may I now?".
//
// Pacing is per node, by its own key: the node waits a hold-off of 0..60 minutes
// drawn from its public key, so a region's nodes spread across the hour instead of
// all flashing in the same minute of the same check; a bad release reaches a
// region a node at a time. The night window (00:00-06:00 node-local) is when the
// mesh is measured, and a reboot there would be a hole in the night's record.
#include <stdint.h>
#include <stddef.h>

#define OTA_AUTO_CHECK_HOURS_DEFAULT 24
#define OTA_AUTO_CHECK_HOURS_MIN     1
#define OTA_AUTO_CHECK_HOURS_MAX     168
#define OTA_AUTO_HOLDOFF_MAX_SECS    3600
#define OTA_NIGHT_START_HOUR         0
#define OTA_NIGHT_END_HOUR           6

// Is a check due? `last_check` and `now` in unix seconds; a never-checked node
// (last_check 0) is due once the clock is set (now > 0).
static inline bool otaAutoCheckDue(uint32_t now, uint32_t last_check, uint32_t check_hours) {
  if (now == 0) return false;
  if (check_hours < OTA_AUTO_CHECK_HOURS_MIN) check_hours = OTA_AUTO_CHECK_HOURS_MIN;
  if (check_hours > OTA_AUTO_CHECK_HOURS_MAX) check_hours = OTA_AUTO_CHECK_HOURS_MAX;
  if (last_check == 0) return true;
  return now - last_check >= check_hours * 3600UL;
}

// The node's own hold-off within the hour, 0..3599 s, from its public key: fixed
// per node, different across a region, costing no entropy at run time.
static inline uint32_t otaAutoHoldoffSecs(const uint8_t* pub_key, size_t key_len) {
  if (pub_key == NULL || key_len == 0) return 0;
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < key_len; i++) { h ^= pub_key[i]; h *= 16777619u; }
  return h % OTA_AUTO_HOLDOFF_MAX_SECS;
}

// Is this a time the node may reboot into a new image? Not in the night window,
// node-local: `local_now` is unix seconds plus the node's UTC offset.
static inline bool otaAutoOutsideNight(uint32_t local_now) {
  uint32_t hour = (local_now / 3600UL) % 24UL;
  return !(hour >= OTA_NIGHT_START_HOUR && hour < OTA_NIGHT_END_HOUR);
}

// When an update found at `found_at` may start: after the hold-off, and not in the
// night; a start that would fall into the night waits for 06:00. Returns the
// earliest unix second (local) the update may begin.
static inline uint32_t otaAutoStartAt(uint32_t found_at_local, uint32_t holdoff_secs) {
  uint32_t at = found_at_local + holdoff_secs;
  if (otaAutoOutsideNight(at)) return at;
  uint32_t day = at - (at % 86400UL);
  return day + OTA_NIGHT_END_HOUR * 3600UL;
}

// The settings live in their own file, /ota: a version byte, then ota.auto and
// ota.check.hours. OTA is in every Observer image of this fork, with or without the
// command plane, so its settings cannot live in the plane's file; up to ar-13 they did,
// appended to /mqttcontrol as its version 3, and a node that has no /ota yet reads them
// from there. That file is read, never written, for it: it belongs to the plane.
#define OTA_AUTO_FILE_VER        1
#define OTA_AUTO_FILE_LEN        3
// /mqttcontrol v3: version, enabled, counter (4), slot, the command key (64 hex + NUL),
// then the two OTA bytes.
#define OTA_AUTO_LEGACY_OFFSET   72
#define OTA_AUTO_LEGACY_LEN      (OTA_AUTO_LEGACY_OFFSET + 2)

static inline void otaAutoEncode(uint8_t out[OTA_AUTO_FILE_LEN], bool on, uint8_t check_hours) {
  out[0] = OTA_AUTO_FILE_VER;
  out[1] = on ? 1 : 0;
  out[2] = check_hours;
}

// An unset interval (0) reads as the default, as /mqttcontrol always read it.
static inline bool otaAutoDecode(const uint8_t* buf, size_t len, bool* on, uint8_t* check_hours) {
  if (buf == NULL || on == NULL || check_hours == NULL) return false;
  if (len < OTA_AUTO_FILE_LEN || buf[0] < OTA_AUTO_FILE_VER) return false;
  *on = buf[1] != 0;
  *check_hours = buf[2] ? buf[2] : OTA_AUTO_CHECK_HOURS_DEFAULT;
  return true;
}

// The same two settings from a /mqttcontrol file; false for one older than v3, which
// had none, and for a file cut short.
static inline bool otaAutoDecodeLegacy(const uint8_t* buf, size_t len, bool* on,
                                       uint8_t* check_hours) {
  if (buf == NULL || on == NULL || check_hours == NULL) return false;
  if (len < OTA_AUTO_LEGACY_LEN || buf[0] < 3) return false;
  *on = buf[OTA_AUTO_LEGACY_OFFSET] != 0;
  const uint8_t h = buf[OTA_AUTO_LEGACY_OFFSET + 1];
  *check_hours = h ? h : OTA_AUTO_CHECK_HOURS_DEFAULT;
  return true;
}

// A newly flashed image is pending until it proves itself; until then any reboot
// returns to the previous one. With the command plane the proof is a verified signed
// command. Without it, it is the bridge: some slot has published since boot, which
// takes the radio, WiFi, TLS and a broker, and the image has stayed up ten minutes,
// long enough to have met the watchdog and the reconnect ladder.
#define OTA_PROOF_UPTIME_MS      (10UL * 60UL * 1000UL)

static inline bool otaImageProvenByBridge(uint32_t uptime_ms, bool any_slot_published) {
  return any_slot_published && uptime_ms >= OTA_PROOF_UPTIME_MS;
}
