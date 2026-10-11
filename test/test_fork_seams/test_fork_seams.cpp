// Where the fork's features meet: the switches and the token that names a combination.
#include <gtest/gtest.h>
#include <string.h>
#include <string>

#include <ForkFeatures.h>
#include "helpers/ForkText.h"

TEST(ForkFeatureToken, EveryCombinationHasItsName) {
  EXPECT_STREQ(forkFeatureToken(false, false, false), "");
  EXPECT_STREQ(forkFeatureToken(false, false, true), "rc");
  EXPECT_STREQ(forkFeatureToken(false, true, false), "ar");
  EXPECT_STREQ(forkFeatureToken(false, true, true), "arrc");
  EXPECT_STREQ(forkFeatureToken(true, false, false), "as");
  EXPECT_STREQ(forkFeatureToken(true, false, true), "asrc");
  EXPECT_STREQ(forkFeatureToken(true, true, false), "asar");
  EXPECT_STREQ(forkFeatureToken(true, true, true), "asarrc");
}

// The codes always run as, ar, rc: a token is read two letters at a time, and a
// second spelling of one combination would be a second image name for it.
TEST(ForkFeatureToken, CodesInFixedOrderAndNeverADash) {
  static const char* const order[] = { "as", "ar", "rc" };
  for (int bits = 0; bits < 8; bits++) {
    const bool on[3] = { (bits & 4) != 0, (bits & 2) != 0, (bits & 1) != 0 };
    std::string want;
    for (int i = 0; i < 3; i++) if (on[i]) want += order[i];
    const char* got = forkFeatureToken(on[0], on[1], on[2]);
    EXPECT_EQ(want, got) << bits;
    EXPECT_EQ(nullptr, strchr(got, '-')) << got;
  }
}

TEST(ForkFeatureToken, ThisBuildNamesItsOwnSwitches) {
  std::string want;
#ifdef WITH_AUTO_REPLY
  want += "ar";
#endif
#ifdef WITH_MQTT_COMMAND
  want += "rc";
#endif
  EXPECT_EQ(want, FORK_FEATURE_TOKEN);
}

// ---- reading an on/off argument --------------------------------------------

TEST(ParseOnOff, AcceptsBothValuesInAnyCase) {
  bool v = false;
  EXPECT_TRUE(forkParseOnOff("on", &v));
  EXPECT_TRUE(v);
  EXPECT_TRUE(forkParseOnOff("off", &v));
  EXPECT_FALSE(v);
  EXPECT_TRUE(forkParseOnOff("ON", &v));
  EXPECT_TRUE(v);
  EXPECT_TRUE(forkParseOnOff("Off", &v));
  EXPECT_FALSE(v);
}

TEST(ParseOnOff, ToleratesWhitespaceATerminalMayAdd) {
  bool v = false;
  EXPECT_TRUE(forkParseOnOff("on\r\n", &v));
  EXPECT_TRUE(v);
  EXPECT_TRUE(forkParseOnOff("  off  ", &v));
  EXPECT_FALSE(v);
}

TEST(ParseOnOff, RejectsAWordThatMerelyStartsWithTheValue) {
  bool v = true;
  EXPECT_FALSE(forkParseOnOff("onions", &v));
  EXPECT_FALSE(forkParseOnOff("offset", &v));
  EXPECT_TRUE(v);   // a rejected argument leaves the setting alone
}

TEST(ParseOnOff, RejectsEmptyAndDegenerateInput) {
  bool v = true;
  EXPECT_FALSE(forkParseOnOff("", &v));
  EXPECT_FALSE(forkParseOnOff("   ", &v));
  EXPECT_FALSE(forkParseOnOff("o", &v));
  EXPECT_FALSE(forkParseOnOff(NULL, &v));
  EXPECT_FALSE(forkParseOnOff("on", NULL));
  EXPECT_TRUE(v);
}

// ---- the fixed-length codes auto-reply reads ---------------------------------------

TEST(FixedLength, ARegionCodeIsThreeAlphanumerics) {
  EXPECT_TRUE(forkAlnumOfLength("JKG", 3));
  EXPECT_TRUE(forkAlnumOfLength("se1", 3));
  EXPECT_FALSE(forkAlnumOfLength("JK", 3));
  EXPECT_FALSE(forkAlnumOfLength("JKGX", 3));
  EXPECT_FALSE(forkAlnumOfLength("J-G", 3));
  EXPECT_FALSE(forkAlnumOfLength("", 3));
  EXPECT_FALSE(forkAlnumOfLength(NULL, 3));
}

TEST(FixedLength, AKeyIsSixtyFourHexDigits) {
  const std::string key(64, 'a');
  EXPECT_TRUE(forkHexOfLength(key.c_str(), 64));
  EXPECT_TRUE(forkHexOfLength(std::string(64, 'F').c_str(), 64));
  EXPECT_FALSE(forkHexOfLength(std::string(63, 'a').c_str(), 64));
  EXPECT_FALSE(forkHexOfLength(std::string(65, 'a').c_str(), 64));
  EXPECT_FALSE(forkHexOfLength((std::string(63, 'a') + "g").c_str(), 64));
  EXPECT_FALSE(forkHexOfLength(NULL, 64));
}

TEST(ForkFeatureToken, TheVersionNamesTheFeatures) {
  char f[8];
  EXPECT_TRUE(forkFeaturesOfVersion("esp32s3-v1.17.1-lou-14-arrc-1a2b3c4d", f, sizeof(f)));
  EXPECT_STREQ("arrc", f);
  EXPECT_TRUE(forkFeaturesOfVersion("esp32s3-v1.17.1-lou-14-ar-1a2b3c4d", f, sizeof(f)));
  EXPECT_STREQ("ar", f);
  // As an Observer image embeds it: build.sh puts the base's own tag before the hash.
  EXPECT_TRUE(forkFeaturesOfVersion("esp32s3-v1.17.1-lou-14-rc-observer-1a2b3c4d", f, sizeof(f)));
  EXPECT_STREQ("rc", f);
  EXPECT_TRUE(forkFeaturesOfVersion("nrf52-v1.17.1-lou-15-asarrc-1a2b3c4d", f, sizeof(f)));
  EXPECT_STREQ("asarrc", f);
  EXPECT_FALSE(forkFeaturesOfVersion("esp32s3-v1.17.1-ar-13-16a05810", f, sizeof(f)));
  EXPECT_STREQ("", f);
  EXPECT_FALSE(forkFeaturesOfVersion("esp32s3-v1.17.1-lou-14-rcar-1a2b3c4d", f, sizeof(f)));  // wrong order
  EXPECT_FALSE(forkFeaturesOfVersion("esp32s3-v1.17.1-lou-14-1a2b3c4d", f, sizeof(f)));       // no features
  EXPECT_FALSE(forkFeaturesOfVersion("esp32s3-v1.17.1-lou-14-arrc", f, sizeof(f)));           // no hash
  EXPECT_FALSE(forkFeaturesOfVersion("esp32s3-v1.17.1-lou-14-arrc-x", f, 4));                 // no room
  EXPECT_FALSE(forkFeaturesOfVersion(NULL, f, sizeof(f)));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
