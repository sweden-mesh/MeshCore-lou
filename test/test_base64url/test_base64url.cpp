// Host tests for src/helpers/Base64Url.h: the unpadded base64url every mcc3 payload on MQTT
// is written in.
#include <gtest/gtest.h>
#include <string.h>
#include "helpers/Base64Url.h"

TEST(Base64Url, RoundTripsWithoutPadding) {
  uint8_t in[5] = {0xFB, 0xFF, 0x00, 0x10, 0x83};
  char out[16];
  for (size_t n = 0; n <= 5; n++) {
    size_t len = mqttV2B64Encode(in, n, out, sizeof(out));
    EXPECT_EQ(MQTTV2_B64_LEN(n), len);
    EXPECT_EQ(nullptr, strchr(out, '='));
    uint8_t back[8];
    EXPECT_EQ(n, mqttV2B64Decode(out, len, back, sizeof(back)));
    EXPECT_EQ(0, memcmp(in, back, n));
  }
  mqttV2B64Encode(in, 3, out, sizeof(out));
  EXPECT_STREQ("-_8A", out);
  uint8_t back[8];
  EXPECT_EQ(0u, mqttV2B64Decode("-_8=", 4, back, sizeof(back)));   // padding is not ours
  EXPECT_EQ(0u, mqttV2B64Decode("A", 1, back, sizeof(back)));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
