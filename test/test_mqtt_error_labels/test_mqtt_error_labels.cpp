#include "helpers/bridges/MQTTErrorLabels.h"

#include <gtest/gtest.h>

#include <string.h>

using namespace MQTTErrorLabels;

namespace {

bool labelIs(const char* actual, const char* expected) {
  return actual != nullptr && strcmp(actual, expected) == 0;
}

} // namespace

// F14: these four were the mislabels found in review. 201 is "no AP found"
// (usually a wrong/hidden SSID), not a security mismatch; 202 is an auth
// failure (usually a wrong password), not a rejected auth mode.
TEST(MQTTErrorLabels, WifiReasonsMatchTheSdkMeaning) {
  EXPECT_TRUE(labelIs(wifiReason(201), "SSID not found"));
  EXPECT_TRUE(labelIs(wifiReason(202), "auth failed (check password)"));
  EXPECT_TRUE(labelIs(wifiReason(39), "802.11 timeout"));      // was "SSID not found"
  EXPECT_TRUE(labelIs(wifiReason(34), "AP saw no acks"));      // was "AP state mismatch"
}

TEST(MQTTErrorLabels, TlsErrorsMatchTheSdkMeaning) {
  EXPECT_TRUE(labelIs(tlsError(0x8008), "server closed connection"));   // was "connection timeout"
  EXPECT_TRUE(labelIs(tlsError(0x8010), "cert chain partly parsed"));   // was "mbedTLS error"
  EXPECT_TRUE(labelIs(tlsError(0x8006), "connection timeout"));
  EXPECT_TRUE(labelIs(tlsError(0x8001), "DNS failed"));
  EXPECT_TRUE(labelIs(tlsError(0x801A), "TLS handshake failed"));
}

// An unknown code must fall through to the caller's raw-number formatting
// rather than borrow a neighbouring code's label. 0x800B is the one the review
// caught: no such esp-tls error exists, but it was labelled "cert verify failed".
TEST(MQTTErrorLabels, UnknownCodesHaveNoLabel) {
  EXPECT_EQ(nullptr, tlsError(0x800B));
  EXPECT_EQ(nullptr, tlsError(0));
  EXPECT_EQ(nullptr, tlsError(-1));
  EXPECT_EQ(nullptr, tlsError(0x8099));

  EXPECT_EQ(nullptr, wifiReason(0));
  EXPECT_EQ(nullptr, wifiReason(61));    // not defined by the installed SDK
  EXPECT_EQ(nullptr, wifiReason(88));
  EXPECT_EQ(nullptr, wifiReason(168));
  EXPECT_EQ(nullptr, wifiReason(255));
}

TEST(MQTTErrorLabels, ConnackReasonsCoverTheRefusalCodes) {
  EXPECT_TRUE(labelIs(connackReason(1), "protocol rejected"));
  EXPECT_TRUE(labelIs(connackReason(2), "client id rejected"));
  EXPECT_TRUE(labelIs(connackReason(3), "server unavailable"));
  EXPECT_TRUE(labelIs(connackReason(4), "bad user/password"));
  EXPECT_TRUE(labelIs(connackReason(5), "not authorized"));
  EXPECT_EQ(nullptr, connackReason(0));   // accepted: not an error to report
  EXPECT_EQ(nullptr, connackReason(6));
}

// Labels share a bounded LoRa reply with the rest of the diagnostic line.
TEST(MQTTErrorLabels, LabelsStayShortEnoughForABoundedReply) {
  for (int i = 0; i <= 255; i++) {
    const char* w = wifiReason((uint8_t)i);
    if (w) EXPECT_LE(strlen(w), 30u) << "wifi reason " << i;
    const char* c = connackReason((uint8_t)i);
    if (c) EXPECT_LE(strlen(c), 30u) << "connack code " << i;
  }
  for (int32_t e = 0x8000; e <= 0x8040; e++) {
    const char* t = tlsError(e);
    if (t) EXPECT_LE(strlen(t), 30u) << "tls error " << e;
  }
}

TEST(ClockLabels, AJwtRefusalOnAnUnverifiedClockSuspectsTheClock) {
  EXPECT_TRUE(refusalSuspectsClock(true, 4, false));
  EXPECT_TRUE(refusalSuspectsClock(true, 5, false));
  // A server confirmed the clock: the refusal is about something else.
  EXPECT_FALSE(refusalSuspectsClock(true, 4, true));
  EXPECT_FALSE(refusalSuspectsClock(true, 5, true));
  // A password does not depend on the clock.
  EXPECT_FALSE(refusalSuspectsClock(false, 4, false));
  EXPECT_FALSE(refusalSuspectsClock(false, 5, false));
  // Not refused, or refused for a reason no clock explains.
  EXPECT_FALSE(refusalSuspectsClock(true, 0, false));
  EXPECT_FALSE(refusalSuspectsClock(true, 1, false));
  EXPECT_FALSE(refusalSuspectsClock(true, 2, false));
  EXPECT_FALSE(refusalSuspectsClock(true, 3, false));
  EXPECT_FALSE(refusalSuspectsClock(true, 6, false));
}

TEST(ClockLabels, TheStatusStateNamesTheClock) {
  EXPECT_TRUE(labelIs(disconnectedSlotState(false, false, false), "disc"));
  EXPECT_TRUE(labelIs(disconnectedSlotState(false, false, true), "fail"));
  // The clock outranks the breaker: "fail" would hide the one thing to mend.
  EXPECT_TRUE(labelIs(disconnectedSlotState(false, true, false), "refused: clock?"));
  EXPECT_TRUE(labelIs(disconnectedSlotState(false, true, true), "refused: clock?"));
  // Held back before any login was tried.
  EXPECT_TRUE(labelIs(disconnectedSlotState(true, false, false), "no clock"));
  EXPECT_TRUE(labelIs(disconnectedSlotState(true, true, true), "no clock"));
}

TEST(ClockLabels, TheLabelsFitTheirReplies) {
  // `get mqtt.status` holds six slots in 160 bytes; the stats JSON prints the state bare.
  for (int i = 0; i < 8; i++) {
    const char* st = disconnectedSlotState(i & 1, i & 2, i & 4);
    EXPECT_LE(strlen(st), 15u);
    EXPECT_EQ(nullptr, strpbrk(st, "\"\\"));
  }
  // The diag line: state, counters, the refusal and this, with room for the age.
  EXPECT_LE(strlen(kDiagClockNotVerified), 50u);
  EXPECT_LE(strlen(kDiagClockNotSet), 50u);
  EXPECT_TRUE(labelIs(kDiagClockNotVerified, "clock not verified: run time <epoch> or check NTP"));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
