#pragma once

// The fork's features, chosen when an image is built and never at runtime:
//
//   WITH_AUTO_SCOPE     as  auto-scope (reserved: there is no code for it yet)
//   WITH_AUTO_REPLY     ar  auto-reply, the regional test channel and private tests
//   WITH_MQTT_COMMAND   rc  remote command, signed commands over the Observer's MQTT
//
// Each is set with -D by the build script (PLATFORMIO_BUILD_FLAGS), never in a
// variant's platformio.ini, so every board builds every combination unchanged. A
// feature that is off contributes no code, no CLI command and no file access: its
// settings file is left exactly as the last build that had it wrote it. Signed
// pull OTA is not a feature: every Observer image of this fork carries it (docs/fork.md).

#if defined(WITH_MQTT_COMMAND) && !defined(WITH_MQTT_BRIDGE)
  #error "WITH_MQTT_COMMAND needs the Observer MQTT bridge (WITH_MQTT_BRIDGE)"
#endif
#if defined(WITH_AUTO_SCOPE)
  #error "WITH_AUTO_SCOPE is reserved: auto-scope has no code in this tree yet"
#endif

#ifdef WITH_AUTO_SCOPE
  #define FORK_AUTO_SCOPE   1
#else
  #define FORK_AUTO_SCOPE   0
#endif
#ifdef WITH_AUTO_REPLY
  #define FORK_AUTO_REPLY   1
#else
  #define FORK_AUTO_REPLY   0
#endif
#ifdef WITH_MQTT_COMMAND
  #define FORK_MQTT_COMMAND 1
#else
  #define FORK_MQTT_COMMAND 0
#endif

// The combination as it appears in an image name and in `ver`: the two-letter codes
// in the fixed order as, ar, rc, run together ("arrc"), or "" with none. The order
// is what makes a name unique per combination, so it is never sorted or reordered.
static inline const char* forkFeatureToken(bool auto_scope, bool auto_reply, bool mqtt_command) {
  static const char* const tokens[8] = { "", "rc", "ar", "arrc", "as", "asrc", "asar", "asarrc" };
  return tokens[(auto_scope ? 4 : 0) | (auto_reply ? 2 : 0) | (mqtt_command ? 1 : 0)];
}

#define FORK_FEATURE_TOKEN  forkFeatureToken(FORK_AUTO_SCOPE, FORK_AUTO_REPLY, FORK_MQTT_COMMAND)
