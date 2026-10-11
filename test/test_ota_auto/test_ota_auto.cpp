// Host tests for OtaAutoLogic.h: the paced automatic update's schedule.
#include <gtest/gtest.h>
#include "helpers/OtaAutoLogic.h"
#include <string.h>

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

TEST(OtaAutoFile, RoundTripsAndReadsAnUnsetIntervalAsTheDefault) {
  uint8_t buf[OTA_AUTO_FILE_LEN];
  bool on = false;
  uint8_t hours = 0;
  otaAutoEncode(buf, true, 6);
  ASSERT_TRUE(otaAutoDecode(buf, sizeof(buf), &on, &hours));
  EXPECT_TRUE(on);
  EXPECT_EQ(6, hours);
  otaAutoEncode(buf, false, 0);
  ASSERT_TRUE(otaAutoDecode(buf, sizeof(buf), &on, &hours));
  EXPECT_FALSE(on);
  EXPECT_EQ(OTA_AUTO_CHECK_HOURS_DEFAULT, hours);
}

TEST(OtaAutoFile, AShortOrVersionlessFileIsNotRead) {
  uint8_t buf[OTA_AUTO_FILE_LEN] = { 0, 1, 6 };
  bool on = false;
  uint8_t hours = 9;
  EXPECT_FALSE(otaAutoDecode(buf, sizeof(buf), &on, &hours));       // version 0
  otaAutoEncode(buf, true, 6);
  EXPECT_FALSE(otaAutoDecode(buf, sizeof(buf) - 1, &on, &hours));
  EXPECT_FALSE(otaAutoDecode(NULL, sizeof(buf), &on, &hours));
  EXPECT_FALSE(on);
  EXPECT_EQ(9, hours);                                              // left alone on refusal
}

// A /mqttcontrol file as MqttControl::save() writes it.
static size_t mqttControlFile(uint8_t* out, uint8_t ver, bool ota_on, uint8_t ota_hours) {
  size_t n = 0;
  out[n++] = ver;
  out[n++] = 1;                                   // enabled
  uint32_t counter = 1234;
  memcpy(&out[n], &counter, 4); n += 4;
  if (ver < 2) return n;
  out[n++] = 3;                                   // slot
  memset(&out[n], 'a', 64); n += 64;
  out[n++] = 0;
  if (ver < 3) return n;
  out[n++] = ota_on ? 1 : 0;
  out[n++] = ota_hours;
  return n;
}

TEST(OtaAutoFile, TheSettingsUpToAr13AreReadFromTheCommandPlanesFile) {
  uint8_t buf[96];
  bool on = false;
  uint8_t hours = 0;
  size_t n = mqttControlFile(buf, 3, true, 12);
  EXPECT_EQ((size_t)OTA_AUTO_LEGACY_LEN, n);
  ASSERT_TRUE(otaAutoDecodeLegacy(buf, n, &on, &hours));
  EXPECT_TRUE(on);
  EXPECT_EQ(12, hours);
  n = mqttControlFile(buf, 3, false, 0);
  ASSERT_TRUE(otaAutoDecodeLegacy(buf, n, &on, &hours));
  EXPECT_FALSE(on);
  EXPECT_EQ(OTA_AUTO_CHECK_HOURS_DEFAULT, hours);
}

TEST(OtaAutoFile, AnOlderOrShortCommandPlaneFileHasNoSettings) {
  uint8_t buf[96];
  bool on = false;
  uint8_t hours = 0;
  EXPECT_FALSE(otaAutoDecodeLegacy(buf, mqttControlFile(buf, 2, true, 12), &on, &hours));
  EXPECT_FALSE(otaAutoDecodeLegacy(buf, mqttControlFile(buf, 1, true, 12), &on, &hours));
  EXPECT_FALSE(otaAutoDecodeLegacy(buf, mqttControlFile(buf, 3, true, 12) - 1, &on, &hours));
}

TEST(OtaProof, WithoutThePlaneTheBridgeAndTenMinutesProveAnImage) {
  EXPECT_FALSE(otaImageProvenByBridge(0, true));
  EXPECT_FALSE(otaImageProvenByBridge(10UL * 60UL * 1000UL - 1, true));
  EXPECT_TRUE(otaImageProvenByBridge(10UL * 60UL * 1000UL, true));
  EXPECT_FALSE(otaImageProvenByBridge(24UL * 3600UL * 1000UL, false));   // up a day, never published
}

TEST(OtaProof, AVerifiedCommandAlwaysProvesAnImage) {
  EXPECT_TRUE(otaImageProven(true, true, 0, false));
  EXPECT_TRUE(otaImageProven(true, false, 0, false));
}

TEST(OtaProof, WhileThePlaneListensOnlyACommandDoes) {
  const uint32_t day = 24UL * 3600UL * 1000UL;
  EXPECT_FALSE(otaImageProven(false, true, day, true));
}

TEST(OtaProof, APlaneThatIsOffOrSlotlessFallsBackToTheBridge) {
  // An rc image with mqtt.cmd off or no slot, topics or key: no command can come, so
  // without the bridge proof every new image would roll back at the next reboot and,
  // with ota.auto on, be pulled again -- the loop this rule exists to break.
  const uint32_t ten = 10UL * 60UL * 1000UL;
  EXPECT_FALSE(otaImageProven(false, false, ten - 1, true));
  EXPECT_TRUE(otaImageProven(false, false, ten, true));
  EXPECT_FALSE(otaImageProven(false, false, 24UL * 3600UL * 1000UL, false));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
