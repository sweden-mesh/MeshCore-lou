#pragma once
// The failed-login throttle (operator 2026-11-17): a sender key that gives a wrong password
// 5 times is refused, without its password being read, for 10 minutes from the fifth. A
// login costs an attacker one packet, so without this a weak admin password falls to online
// guessing at the speed of the air.
//
// Per sender key, so nobody can lock the owner out: a login is decrypted with the sender's
// own key before it is read, and a key nobody holds cannot send one. A table of bounded
// size, in RAM; a full table gives up the entry that failed longest ago. Guessing from many
// keys at once is not stopped by this; each key still gets only 5 tries in 10 minutes.
//
// Times are millis(), and every comparison is a difference, so the wrap after 49 days
// is harmless. Pure, and host-tested in test_login_throttle.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define LOGIN_THROTTLE_SLOTS     16
#define LOGIN_THROTTLE_FAILURES  5
#define LOGIN_THROTTLE_MILLIS    (10UL * 60UL * 1000UL)
#define LOGIN_THROTTLE_KEY_LEN   8       // of the sender's public key

struct LoginThrottleEntry {
  uint8_t key[LOGIN_THROTTLE_KEY_LEN];
  uint8_t failures;                      // 0 = slot free
  uint32_t last;                         // millis() of the last failure
};

struct LoginThrottle {
  LoginThrottleEntry entries[LOGIN_THROTTLE_SLOTS];
};

static inline LoginThrottleEntry* loginThrottleFind(LoginThrottle* t, const uint8_t* pub_key) {
  for (int i = 0; i < LOGIN_THROTTLE_SLOTS; i++) {
    LoginThrottleEntry* e = &t->entries[i];
    if (e->failures > 0 && memcmp(e->key, pub_key, LOGIN_THROTTLE_KEY_LEN) == 0) return e;
  }
  return NULL;
}

// An entry whose last failure is a whole window old counts for nothing: the count starts
// again, so a mistyped password once a day never adds up to a lockout.
static inline bool loginThrottleStale(const LoginThrottleEntry* e, uint32_t now) {
  return (uint32_t)(now - e->last) >= LOGIN_THROTTLE_MILLIS;
}

// Refused now, before the password is compared.
static inline bool loginThrottled(LoginThrottle* t, const uint8_t* pub_key, uint32_t now) {
  if (t == NULL || pub_key == NULL) return false;
  const LoginThrottleEntry* e = loginThrottleFind(t, pub_key);
  return e != NULL && e->failures >= LOGIN_THROTTLE_FAILURES && !loginThrottleStale(e, now);
}

static inline void loginThrottleFailed(LoginThrottle* t, const uint8_t* pub_key, uint32_t now) {
  if (t == NULL || pub_key == NULL) return;
  LoginThrottleEntry* e = loginThrottleFind(t, pub_key);
  if (e == NULL) {
    e = &t->entries[0];
    for (int i = 0; i < LOGIN_THROTTLE_SLOTS; i++) {
      LoginThrottleEntry* c = &t->entries[i];
      if (c->failures == 0) { e = c; break; }
      if ((uint32_t)(now - c->last) > (uint32_t)(now - e->last)) e = c;
    }
    memcpy(e->key, pub_key, LOGIN_THROTTLE_KEY_LEN);
    e->failures = 0;
  } else if (loginThrottleStale(e, now)) {
    e->failures = 0;
  }
  if (e->failures < LOGIN_THROTTLE_FAILURES) e->failures++;
  e->last = now;
}

// The admin password was right: whatever the key got wrong before is forgotten.
static inline void loginThrottleClear(LoginThrottle* t, const uint8_t* pub_key) {
  if (t == NULL || pub_key == NULL) return;
  LoginThrottleEntry* e = loginThrottleFind(t, pub_key);
  if (e != NULL) e->failures = 0;
}
