// The failed-login throttle (src/helpers/LoginThrottle.h), on a clock the test moves.
#include <gtest/gtest.h>
#include <string.h>

#include "helpers/LoginThrottle.h"

static void keyOf(uint8_t* key, uint8_t n) {
  memset(key, 0, 32);
  key[0] = n;
  key[1] = 0xA5;
  key[31] = n;
}

struct Clock {
  uint32_t ms;
  explicit Clock(uint32_t start = 1000) : ms(start) { }
  void advance(uint32_t by) { ms += by; }
};

static void fail(LoginThrottle* t, const uint8_t* key, Clock& clock, int times) {
  for (int i = 0; i < times; i++) {
    loginThrottleFailed(t, key, clock.ms);
    clock.advance(1000);
  }
}

TEST(LoginThrottle, FiveFailuresThenTenMinutesRefused) {
  LoginThrottle t = {};
  uint8_t key[32];
  keyOf(key, 1);
  Clock clock;
  fail(&t, key, clock, 4);
  EXPECT_FALSE(loginThrottled(&t, key, clock.ms));     // four is not enough
  loginThrottleFailed(&t, key, clock.ms);              // the fifth, at this moment
  const uint32_t fifth = clock.ms;
  EXPECT_TRUE(loginThrottled(&t, key, clock.ms));
  EXPECT_TRUE(loginThrottled(&t, key, fifth + LOGIN_THROTTLE_MILLIS - 1));
  EXPECT_FALSE(loginThrottled(&t, key, fifth + LOGIN_THROTTLE_MILLIS));
}

TEST(LoginThrottle, AfterThePauseTheCountStartsAgain) {
  LoginThrottle t = {};
  uint8_t key[32];
  keyOf(key, 1);
  Clock clock;
  fail(&t, key, clock, 5);
  clock.advance(LOGIN_THROTTLE_MILLIS);
  EXPECT_FALSE(loginThrottled(&t, key, clock.ms));
  fail(&t, key, clock, 1);                             // one more wrong guess is one, not six
  EXPECT_FALSE(loginThrottled(&t, key, clock.ms));
  fail(&t, key, clock, 4);
  EXPECT_TRUE(loginThrottled(&t, key, clock.ms));
}

TEST(LoginThrottle, SlowMistakesNeverAddUp) {
  LoginThrottle t = {};
  uint8_t key[32];
  keyOf(key, 1);
  Clock clock;
  for (int i = 0; i < 20; i++) {
    loginThrottleFailed(&t, key, clock.ms);
    EXPECT_FALSE(loginThrottled(&t, key, clock.ms)) << i;
    clock.advance(LOGIN_THROTTLE_MILLIS);
  }
}

TEST(LoginThrottle, PerSenderKey) {
  LoginThrottle t = {};
  uint8_t attacker[32], owner[32];
  keyOf(attacker, 1);
  keyOf(owner, 2);
  Clock clock;
  fail(&t, attacker, clock, 5);
  EXPECT_TRUE(loginThrottled(&t, attacker, clock.ms));
  EXPECT_FALSE(loginThrottled(&t, owner, clock.ms));   // the owner is never locked out by it
}

TEST(LoginThrottle, TheRightAdminPasswordForgetsTheFailures) {
  LoginThrottle t = {};
  uint8_t key[32];
  keyOf(key, 1);
  Clock clock;
  fail(&t, key, clock, 4);
  loginThrottleClear(&t, key);
  fail(&t, key, clock, 4);
  EXPECT_FALSE(loginThrottled(&t, key, clock.ms));
  fail(&t, key, clock, 1);
  EXPECT_TRUE(loginThrottled(&t, key, clock.ms));
}

TEST(LoginThrottle, AcrossTheMillisWrap) {
  LoginThrottle t = {};
  uint8_t key[32];
  keyOf(key, 1);
  Clock clock(0xFFFFFFFFu - 2000);
  fail(&t, key, clock, 5);                             // the clock wraps during these
  EXPECT_TRUE(loginThrottled(&t, key, clock.ms));
  EXPECT_TRUE(loginThrottled(&t, key, clock.ms + LOGIN_THROTTLE_MILLIS - 2000));
  EXPECT_FALSE(loginThrottled(&t, key, clock.ms + LOGIN_THROTTLE_MILLIS));
}

TEST(LoginThrottle, AFullTableGivesUpTheOldestEntry) {
  LoginThrottle t = {};
  Clock clock;
  uint8_t first[32];
  keyOf(first, 0);
  fail(&t, first, clock, 5);
  for (int i = 1; i < LOGIN_THROTTLE_SLOTS; i++) {
    uint8_t key[32];
    keyOf(key, (uint8_t)i);
    fail(&t, key, clock, 5);
  }
  EXPECT_TRUE(loginThrottled(&t, first, clock.ms));     // a full table still holds it
  uint8_t newcomer[32];
  keyOf(newcomer, 200);
  fail(&t, newcomer, clock, 1);
  EXPECT_FALSE(loginThrottled(&t, first, clock.ms));    // the oldest made room
  uint8_t second[32];
  keyOf(second, 1);
  EXPECT_TRUE(loginThrottled(&t, second, clock.ms));    // and only it
  fail(&t, newcomer, clock, 4);
  EXPECT_TRUE(loginThrottled(&t, newcomer, clock.ms));
}

TEST(LoginThrottle, DegenerateInput) {
  LoginThrottle t = {};
  uint8_t key[32];
  keyOf(key, 1);
  EXPECT_FALSE(loginThrottled(NULL, key, 0));
  EXPECT_FALSE(loginThrottled(&t, NULL, 0));
  loginThrottleFailed(NULL, key, 0);
  loginThrottleFailed(&t, NULL, 0);
  loginThrottleClear(NULL, key);
  loginThrottleClear(&t, NULL);
  EXPECT_FALSE(loginThrottled(&t, key, 0));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
