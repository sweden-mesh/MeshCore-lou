#pragma once

#include <stddef.h>
#include <string.h>

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

// The features a version string names: `<mcu>-v1.17.1-lou-<nn>-<features>-<hash>` (TODO 22a
// ruling 8). Copies the token into 'out' and returns true only when it is one of the
// combinations' tokens; false for a version without `-lou-<nn>-`, such as ar-13 and before,
// which carried both features but did not say so.
static inline bool forkFeaturesOfVersion(const char* version, char* out, size_t out_size) {
  if (version == NULL || out == NULL || out_size == 0) return false;
  out[0] = 0;
  const char* p = strstr(version, "-lou-");
  if (p == NULL) return false;
  p += 5;
  if (*p < '0' || *p > '9') return false;
  while (*p >= '0' && *p <= '9') p++;
  if (*p++ != '-') return false;
  const char* end = strchr(p, '-');
  if (end == NULL) return false;
  size_t n = (size_t)(end - p);
  for (int bits = 1; bits < 8; bits++) {
    const char* t = forkFeatureToken(bits & 4, bits & 2, bits & 1);
    if (strlen(t) == n && strncmp(t, p, n) == 0 && n < out_size) {
      memcpy(out, p, n);
      out[n] = 0;
      return true;
    }
  }
  return false;
}
