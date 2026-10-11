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
static const char* TAG = "9F04C21B";

TEST(SlotClientId, IsTheNodeIdTheSlotNumberAndThePrivateTag) {
  char id[MQTT_SLOT_CLIENT_ID_SIZE];
  ASSERT_TRUE(mqttSlotClientId(KEY, TAG, 0, id, sizeof(id)));
  EXPECT_STREQ("A0586238-1-9F04C21B", id);
  ASSERT_TRUE(mqttSlotClientId(KEY, TAG, 5, id, sizeof(id)));
  EXPECT_STREQ("A0586238-6-9F04C21B", id);
  EXPECT_LE(strlen(id), 23u);                  // every MQTT 3.1.1 broker accepts 23
}

TEST(SlotClientId, NoTwoSlotsOfOneNodeShareOne) {
  // The broker refuses a second login under a held client id, so an Observer slot and
  // the command plane's on one broker must never present the same one.
  char ids[6][MQTT_SLOT_CLIENT_ID_SIZE];
  for (int i = 0; i < 6; i++) ASSERT_TRUE(mqttSlotClientId(KEY, TAG, i, ids[i], sizeof(ids[i])));
  for (int i = 0; i < 6; i++) {
    for (int j = i + 1; j < 6; j++) EXPECT_STRNE(ids[i], ids[j]) << i << " and " << j;
  }
}

TEST(SlotClientId, IsNotComputableFromThePublicKeyAlone) {
  // Two nodes, or one node and a stranger who knows its key, with different tags: the
  // public part alone does not name the session.
  char a[MQTT_SLOT_CLIENT_ID_SIZE], b[MQTT_SLOT_CLIENT_ID_SIZE];
  ASSERT_TRUE(mqttSlotClientId(KEY, TAG, 2, a, sizeof(a)));
  ASSERT_TRUE(mqttSlotClientId(KEY, "00000000", 2, b, sizeof(b)));
  EXPECT_STRNE(a, b);
}

TEST(SlotClientId, LeavesTheDefaultUntilTheIdAndTagAreKnown) {
  char id[MQTT_SLOT_CLIENT_ID_SIZE];
  EXPECT_FALSE(mqttSlotClientId("DEVICE_ID_PLACEHOLDER", TAG, 0, id, sizeof(id)));
  EXPECT_FALSE(mqttSlotClientId(KEY, "", 0, id, sizeof(id)));        // no tag yet
  EXPECT_FALSE(mqttSlotClientId(KEY, "9F04C2", 0, id, sizeof(id)));
  EXPECT_FALSE(mqttSlotClientId(nullptr, TAG, 0, id, sizeof(id)));
  EXPECT_FALSE(mqttSlotClientId(KEY, nullptr, 0, id, sizeof(id)));
  EXPECT_FALSE(mqttSlotClientId(KEY, TAG, -1, id, sizeof(id)));
  EXPECT_FALSE(mqttSlotClientId(KEY, TAG, 0, id, 12));
}

// ---- a refused SUBACK (ar-13) ------------------------------------------------

TEST(Suback, GrantedOnlyWhenNoCodeRefuses) {
  const uint8_t qos1[] = { 0x01 }, qos0[] = { 0x00 }, two[] = { 0x01, 0x00 };
  EXPECT_TRUE(mqttSubackGranted(qos1, 1));
  EXPECT_TRUE(mqttSubackGranted(qos0, 1));
  EXPECT_TRUE(mqttSubackGranted(two, 2));
  const uint8_t refused[] = { 0x80 }, mixed[] = { 0x01, 0x80 };
  EXPECT_FALSE(mqttSubackGranted(refused, 1));
  EXPECT_FALSE(mqttSubackGranted(mixed, 2));
  // no codes delivered: the event's own word, "subscribed", stands
  EXPECT_TRUE(mqttSubackGranted(qos1, 0));
  EXPECT_TRUE(mqttSubackGranted(nullptr, 0));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
