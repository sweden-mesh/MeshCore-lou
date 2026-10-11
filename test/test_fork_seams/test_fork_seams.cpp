// Where the fork's features meet: the switches and the token that names a combination.
#include <gtest/gtest.h>
#include <string.h>
#include <string>

#include <ForkFeatures.h>

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

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
