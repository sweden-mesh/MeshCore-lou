#include <gtest/gtest.h>
#include <string.h>

#include "helpers/MQTTSlotAuth.h"

// (has_preset, preset_is_jwt, has_audience)

TEST(SlotAuth, AJwtPresetIsJwtWithOrWithoutAnAudience) {
  EXPECT_TRUE(mqttSlotUsesJwt(true, true, false));
  EXPECT_TRUE(mqttSlotUsesJwt(true, true, true));
}

TEST(SlotAuth, APasswordPresetIgnoresAStaleAudience) {
  // The keepalive tuning used to read this case as JWT while token creation and
  // renewal read it as not; one slot, two answers.
  EXPECT_FALSE(mqttSlotUsesJwt(true, false, true));
  EXPECT_FALSE(mqttSlotUsesJwt(true, false, false));
}

TEST(SlotAuth, OnACustomSlotTheAudienceIsTheSwitch) {
  // 2026-09-01: LOUTEST moved from the meshat.se preset to a plain custom broker and
  // went on opening TLS against a plain port, because the audience was still set.
  EXPECT_TRUE(mqttSlotUsesJwt(false, false, true));
  EXPECT_FALSE(mqttSlotUsesJwt(false, false, false));
}

TEST(SlotAuth, WithNoPresetTheJwtFlagOfAPresetThatIsNotThereMeansNothing) {
  EXPECT_FALSE(mqttSlotUsesJwt(false, true, false));
}

TEST(SlotAuth, TheLabelIsShortAndSaysWhichOne) {
  EXPECT_STREQ("jwt", mqttSlotAuthLabel(true));
  EXPECT_STREQ("pw", mqttSlotAuthLabel(false));
  // `get mqtt.stats` is one clamped reply; three characters a slot is the budget.
  EXPECT_LE(strlen(mqttSlotAuthLabel(true)), 3u);
}

// ---- one client id per slot (firmware TODO 13) ----------------------------

static const char* KEY = "A0586238E1C2D3F4A0586238E1C2D3F4A0586238E1C2D3F4A0586238E1C2D3F4";

TEST(SlotClientId, IsTheNodeIdAndTheSlotNumber) {
  char id[MQTT_SLOT_CLIENT_ID_SIZE];
  ASSERT_TRUE(mqttSlotClientId(KEY, 0, id, sizeof(id)));
  EXPECT_STREQ("A0586238-1", id);
  ASSERT_TRUE(mqttSlotClientId(KEY, 5, id, sizeof(id)));
  EXPECT_STREQ("A0586238-6", id);
}

TEST(SlotClientId, NoTwoSlotsOfOneNodeShareOne) {
  // The broker refuses a second login under a held client id, so an Observer slot and
  // the command plane's on one broker must never present the same one.
  char ids[6][MQTT_SLOT_CLIENT_ID_SIZE];
  for (int i = 0; i < 6; i++) ASSERT_TRUE(mqttSlotClientId(KEY, i, ids[i], sizeof(ids[i])));
  for (int i = 0; i < 6; i++) {
    for (int j = i + 1; j < 6; j++) EXPECT_STRNE(ids[i], ids[j]) << i << " and " << j;
  }
}

TEST(SlotClientId, TwoNodesDoNotShareOneEither) {
  char a[MQTT_SLOT_CLIENT_ID_SIZE], b[MQTT_SLOT_CLIENT_ID_SIZE];
  ASSERT_TRUE(mqttSlotClientId("0723BA17", 2, a, sizeof(a)));
  ASSERT_TRUE(mqttSlotClientId("0106809E", 2, b, sizeof(b)));
  EXPECT_STRNE(a, b);
}

TEST(SlotClientId, LeavesTheDefaultUntilTheDeviceIdIsAKey) {
  // The bridge starts with a placeholder; a shared id built from it would be worse than
  // esp-mqtt's per-board default.
  char id[MQTT_SLOT_CLIENT_ID_SIZE];
  EXPECT_FALSE(mqttSlotClientId("DEVICE_ID_PLACEHOLDER", 0, id, sizeof(id)));
  EXPECT_FALSE(mqttSlotClientId("A05862", 0, id, sizeof(id)));
  EXPECT_FALSE(mqttSlotClientId(nullptr, 0, id, sizeof(id)));
  EXPECT_FALSE(mqttSlotClientId(KEY, -1, id, sizeof(id)));
  EXPECT_FALSE(mqttSlotClientId(KEY, 0, id, 4));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
