// Host tests for OtaAutoLogic.h: the paced automatic update's schedule.
#include <gtest/gtest.h>
#include "helpers/OtaAutoLogic.h"

TEST(OtaAuto, ACheckIsDueAtTheIntervalAndOnceAtFirstBootWithAClock) {
  EXPECT_FALSE(otaAutoCheckDue(0, 0, 24));                     // no clock: never
  EXPECT_TRUE(otaAutoCheckDue(1700000000, 0, 24));             // never checked: now
  EXPECT_FALSE(otaAutoCheckDue(1700000000 + 86399, 1700000000, 24));
  EXPECT_TRUE(otaAutoCheckDue(1700000000 + 86400, 1700000000, 24));
  EXPECT_TRUE(otaAutoCheckDue(1700000000 + 3600, 1700000000, 0));    // clamped to 1 h
  EXPECT_FALSE(otaAutoCheckDue(1700000000 + 168 * 3600 - 1, 1700000000, 999));  // clamped to a week
}

TEST(OtaAuto, TheHoldoffIsFixedPerKeyAndSpreadsARegion) {
  uint8_t a[32], b[32];
  for (int i = 0; i < 32; i++) { a[i] = (uint8_t)i; b[i] = (uint8_t)(i + 1); }
  uint32_t ha = otaAutoHoldoffSecs(a, 32), hb = otaAutoHoldoffSecs(b, 32);
  EXPECT_LT(ha, 3600u); EXPECT_LT(hb, 3600u);
  EXPECT_NE(ha, hb);
  EXPECT_EQ(ha, otaAutoHoldoffSecs(a, 32));                     // the same node, the same minute
  EXPECT_EQ(0u, otaAutoHoldoffSecs(NULL, 32));
}

TEST(OtaAuto, NeverInTheNightWindow) {
  const uint32_t day = 1700006400;                              // a midnight (local), 2023-11-15
  EXPECT_FALSE(otaAutoOutsideNight(day + 0));
  EXPECT_FALSE(otaAutoOutsideNight(day + 5 * 3600 + 3599));
  EXPECT_TRUE(otaAutoOutsideNight(day + 6 * 3600));
  EXPECT_TRUE(otaAutoOutsideNight(day + 23 * 3600 + 3599));
  // found at 23:30 with a 45 min hold-off: would start 00:15, waits for 06:00
  EXPECT_EQ(day + 6 * 3600, otaAutoStartAt(day - 1800, 2700));
  // found at 14:00 with a 10 min hold-off: 14:10
  EXPECT_EQ(day + 14 * 3600 + 600, otaAutoStartAt(day + 14 * 3600, 600));
  // found at 05:00: 06:00 at the earliest, whatever the hold-off
  EXPECT_EQ(day + 6 * 3600, otaAutoStartAt(day + 5 * 3600, 0));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
