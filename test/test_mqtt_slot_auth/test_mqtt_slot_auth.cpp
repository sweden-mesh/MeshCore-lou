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

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
