#pragma once

#include <stdint.h>

// How many allowances a budget can remember. A budget asked for more than this is
// capped to it, because the memory is the guarantee: what is not remembered cannot
// be bounded. Ten covers both users -- the control plane's ten commands an hour and
// auto-reply's ten replies per five minutes.
#define SLIDING_BUDGET_SLOTS 10

// A rate limit that bounds every window, not just the ones that start on a boundary.
//
// Upstream's RateLimiter is a fixed window: its count resets all at once when the
// window rolls, so a full budget late in one window and a full budget early in the
// next both pass. Against two transmits an hour that is three floods in two seconds,
// which is the weapon the limit exists to deny.
//
// This remembers when each of the last `maximum` allowances was given and refuses
// while the oldest of them is younger than the window, so **no span of `secs` ever
// holds more than `maximum`**, wherever it starts.
//
// Ours rather than a change to RateLimiter.h: that file is upstream's and other code
// uses it, so a private one costs nothing at the next merge.
//
// A refusal spends nothing. A clock that steps backwards -- an RTC corrected after a
// bad sync -- must not mint budget, so every remembered time that is now in the future
// is pulled back to `now`: the cost is at most one window of refusals, never an extra
// allowance.
struct SlidingBudget {
  uint32_t stamps[SLIDING_BUDGET_SLOTS];
  uint32_t secs;
  uint8_t  maximum;
  uint8_t  used;

  SlidingBudget(uint8_t max_allowed, uint32_t window_secs)
      : secs(window_secs),
        maximum(max_allowed > SLIDING_BUDGET_SLOTS ? SLIDING_BUDGET_SLOTS : max_allowed),
        used(0) {}

  bool allow(uint32_t now) {
    uint8_t oldest = 0;
    for (uint8_t i = 0; i < used; i++) {
      if (stamps[i] > now) stamps[i] = now;
      if (stamps[i] < stamps[oldest]) oldest = i;
    }
    if (used < maximum) {
      stamps[used++] = now;
      return true;
    }
    if (maximum == 0 || now - stamps[oldest] < secs) return false;
    stamps[oldest] = now;
    return true;
  }
};
