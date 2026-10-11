// Where the fork's features meet: the switches and the token that names a combination.
#include <gtest/gtest.h>
#include <string.h>
#include <string>

#include <ForkFeatures.h>
#include "helpers/AutoReplyLogic.h"
#include "helpers/ForkText.h"
#include "helpers/MqttControlLogic.h"

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

// ---- a trigger sent over the command plane: where the two features meet ------

TEST(TriggerOverThePlane, ATrailingKeyCommandRidesThroughTheAllowlistAndDiesAtTheHandler) {
  const char* cmd = "trigger test set prv.key 00";
  // Worth stating exactly, because the obvious guess is wrong and I guessed it:
  // the allowlist admits `trigger test set prv.key 00`. Entries match as prefixes
  // with a boundary, so anything beginning "trigger test " is admitted -- the same
  // way "set autoreply" admits "set autoreply.hops 8". The allowlist decides which
  // *family* of command may arrive, not whether one is well formed.
  EXPECT_TRUE(mqttCtrlCommandAllowed(cmd, strlen(cmd), true));

  // The form is checked one layer down, and that is what refuses it: the trigger
  // parser accepts a bare keyword or a keyword and eight hex characters, nothing
  // else. So the string reaches no handler that would act on the tail.
  const char* id = NULL; size_t id_len = 0;
  EXPECT_FALSE(autoReplyParseTrigger("trigger test set prv.key 00", "test", &id, &id_len));

  // It is not a `set` to any CLI either -- it begins "trigger", so CommonCLI's
  // handleSetCmd is never reached and the whole string falls through as unknown.
  EXPECT_NE(0, memcmp("trigger test set prv.key 00", "set ", 4));

  // Residual, recorded rather than fixed: it is classed as a transmit and so
  // spends a trigger token before being refused. Not an escalation -- sending it
  // at all requires the owner key, and whoever holds that can trigger legitimately
  // -- but it is why the allowlist is not the only thing standing here.
  EXPECT_TRUE(mqttCtrlIsTransmitCommand("trigger test set prv.key 00", 26));
}

TEST(TriggerOverThePlane, WithoutAutoReplyItNeverReachesTheHandler) {
  // An rc image has no trigger to run, so the plane refuses the family outright.
  const char* cmds[] = { "trigger test", "trigger test A1B2C3D4", "trigger test set prv.key 00" };
  for (const char* c : cmds) {
    EXPECT_TRUE(mqttCtrlCommandAllowed(c, strlen(c), true)) << c;
    EXPECT_FALSE(mqttCtrlCommandAllowed(c, strlen(c), false)) << c;
  }
}

TEST(TriggerOverThePlane, ThisImageAdmitsATriggerOnlyWithAutoReply) {
  // What MqttControl passes is FORK_AUTO_REPLY, the image's own switch.
  EXPECT_EQ(FORK_AUTO_REPLY == 1, mqttCtrlCommandAllowed("trigger test", 12, FORK_AUTO_REPLY));
#ifdef WITH_AUTO_REPLY
  EXPECT_EQ(1, FORK_AUTO_REPLY);
#else
  EXPECT_EQ(0, FORK_AUTO_REPLY);
#endif
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
