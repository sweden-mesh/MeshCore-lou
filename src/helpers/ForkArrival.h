#pragma once
// Arriving at an image with more features than the one before. From lou-21 an Observer
// board has one image, the full one, and its nodes on ar and rc reach it by their ordinary
// update. A feature the old image did not have starts switched off, once, whatever its
// settings file says (owner's ruling 2026-11-25): that file was left by an install before
// the old image, and the owner has chosen an image without the feature since. Only "on"
// is changed; the rest of the file is kept, the command key included. A node that already
// had the feature is not touched.
//
// The new image learns where it came from in one of two ways, and never guesses:
//   1. the marker FORK_ARRIVAL_FILE, holding the old image's feature token. The old image
//      writes it when it has taken an update whose version names a feature it lacks itself
//      (forkArrivalMarkerWanted). Images from lou-21 do; lou-20 and before do not.
//   2. the old image itself, on the first start after an update, when it still lies whole
//      in the other slot: it holds its own update name, `<env>-<features>` (OTA_VARIANT),
//      as text, and ForkVariantScan finds it. This is what tells a node from lou-20.
// With neither, nothing is switched: a cable flash, a later start, a new node.
// Whichever image starts next removes the marker: the new one after using it; the old one
// after a rollback, where it names that image's own features and so switches nothing.
#include <ForkFeatures.h>
#include <stdint.h>

#define FORK_ARRIVAL_FILE       "/ota_from"
#define FORK_ARRIVAL_TOKEN_MAX  8     // the longest token, "asarrc", and its NUL

#define FORK_BIT_MQTT_COMMAND   1     // forkFeatureToken's own order
#define FORK_BIT_AUTO_REPLY     2

// The features a token names, as bits; -1 when it is not a token. "" is the image with none.
static inline int forkFeatureBits(const char* token, size_t len) {
  if (token == NULL) return -1;
  for (int bits = 0; bits < 8; bits++) {
    const char* t = forkFeatureToken(bits & 4, bits & 2, bits & 1);
    if (strlen(t) == len && strncmp(t, token, len) == 0) return bits;
  }
  return -1;
}

// Does the running image leave a marker for the update it has just taken? Only when the
// version on offer names a feature this image lacks. An image with no feature leaves none:
// no release is built that way, and an empty marker would read as a failed write.
static inline bool forkArrivalMarkerWanted(const char* own_token, const char* incoming_version) {
  char incoming[FORK_ARRIVAL_TOKEN_MAX];
  if (own_token == NULL || !forkFeaturesOfVersion(incoming_version, incoming, sizeof(incoming))) return false;
  const int own = forkFeatureBits(own_token, strlen(own_token));
  const int in = forkFeatureBits(incoming, strlen(incoming));
  return own > 0 && in > 0 && (in & ~own) != 0;
}

// The marker as read: the token without the line end an editor or a tool may have added.
static inline size_t forkArrivalTokenLen(const uint8_t* buf, size_t len) {
  if (buf == NULL) return 0;
  while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' ' || buf[len - 1] == 0)) len--;
  return len;
}

struct ForkArrival {
  bool known;             // the token named an image
  bool auto_reply_off;    // this image has auto-reply and the one before did not
  bool mqtt_command_off;  // ... remote command
};

// What to switch off in an image of 'own_token' that came from one of 'from'. Nothing when
// 'from' is no token or the empty one, and nothing for a feature the old image had.
static inline ForkArrival forkArrivalFrom(const char* own_token, const char* from, size_t from_len) {
  ForkArrival a = { false, false, false };
  const int own = own_token ? forkFeatureBits(own_token, strlen(own_token)) : -1;
  const int old = forkFeatureBits(from, from_len);
  if (own < 0 || old <= 0) return a;
  a.known = true;
  a.auto_reply_off = ((own & ~old) & FORK_BIT_AUTO_REPLY) != 0;
  a.mqtt_command_off = ((own & ~old) & FORK_BIT_MQTT_COMMAND) != 0;
  return a;
}

// ---- the old image's update name, read out of the image -------------------------------
// Every image holds its OTA_VARIANT as one NUL-ended text, `<env>-<features>`, and no other
// combination's (checked on the 99 Observer images of lou-20). The new image is the same
// board, so it knows the `<env>-` to look for from its own name.

#define FORK_SCAN_NAME_MAX  96                        // a manifest's variant, as the board reads it
#define FORK_SCAN_TAIL      (FORK_SCAN_NAME_MAX + 16) // longer than a name and its NUL

struct ForkVariantScan {
  char prefix[FORK_SCAN_NAME_MAX];   // "<env>-"
  size_t prefix_len;
  uint8_t tail[FORK_SCAN_TAIL];      // the end of what was fed, for a name across two chunks
  size_t have;
};

// False when this image's own name does not end in "-<its token>": then there is no env to
// look for.
static inline bool forkVariantScanBegin(ForkVariantScan* s, const char* own_variant, const char* own_token) {
  if (s == NULL || own_variant == NULL || own_token == NULL) return false;
  const size_t v = strlen(own_variant), t = strlen(own_token);
  if (t == 0 || v <= t + 1 || v >= FORK_SCAN_NAME_MAX) return false;
  if (own_variant[v - t - 1] != '-' || strcmp(own_variant + v - t, own_token) != 0) return false;
  s->prefix_len = v - t;
  memcpy(s->prefix, own_variant, s->prefix_len);
  s->prefix[s->prefix_len] = 0;
  s->have = 0;
  return true;
}

// `<env>-<token>` and its NUL, whole within 'buf': the token goes to 'out'. A name cut off
// by the end of the buffer is not one, and neither is the prefix before anything but a token.
static inline bool forkVariantTokenFind(const ForkVariantScan* s, const uint8_t* buf, size_t len,
                                        char* out, size_t out_size) {
  for (size_t i = 0; i + s->prefix_len < len; i++) {
    if (buf[i] != (uint8_t)s->prefix[0] || memcmp(buf + i, s->prefix, s->prefix_len) != 0) continue;
    const uint8_t* token = buf + i + s->prefix_len;
    const size_t room = len - i - s->prefix_len;
    size_t n = 0;
    while (n < room && n < FORK_ARRIVAL_TOKEN_MAX && token[n] != 0) n++;
    if (n == room || n == FORK_ARRIVAL_TOKEN_MAX) continue;
    if (n == 0 || n >= out_size || forkFeatureBits((const char *)token, n) <= 0) continue;
    memcpy(out, token, n);
    out[n] = 0;
    return true;
  }
  return false;
}

// The image, fed in order in chunks of any size. True, with the token in 'out', at the
// first name found.
static inline bool forkVariantScanFeed(ForkVariantScan* s, const uint8_t* chunk, size_t n,
                                       char* out, size_t out_size) {
  uint8_t seam[2 * FORK_SCAN_TAIL];
  const size_t head = n < FORK_SCAN_TAIL ? n : FORK_SCAN_TAIL;
  memcpy(seam, s->tail, s->have);
  memcpy(seam + s->have, chunk, head);
  if (forkVariantTokenFind(s, seam, s->have + head, out, out_size)) return true;
  if (forkVariantTokenFind(s, chunk, n, out, out_size)) return true;
  if (n >= FORK_SCAN_TAIL) {
    memcpy(s->tail, chunk + n - FORK_SCAN_TAIL, FORK_SCAN_TAIL);
    s->have = FORK_SCAN_TAIL;
  } else {
    const size_t keep = s->have + n > FORK_SCAN_TAIL ? FORK_SCAN_TAIL - n : s->have;
    memmove(s->tail, s->tail + s->have - keep, keep);
    memcpy(s->tail + keep, chunk, n);
    s->have = keep + n;
  }
  return false;
}
