#include <gtest/gtest.h>
#include <stdint.h>
#include <limits>

#include "helpers/MQTTConnectionPolicy.h"

namespace Policy = MQTTConnectionPolicy;

TEST(MQTTConnectionPolicy, ElapsedTimeHandlesNormalAndWrappedClocks) {
  EXPECT_EQ(4000U, Policy::elapsedMs(5000U, 1000U));

  const uint32_t before_wrap = std::numeric_limits<uint32_t>::max() - 99U;
  EXPECT_EQ(150U, Policy::elapsedMs(50U, before_wrap));
}

TEST(MQTTConnectionPolicy, CrossSlotReconnectGuardHasExactBoundary) {
  EXPECT_TRUE(Policy::reconnectGuardActive(14999U, 0U));
  EXPECT_FALSE(Policy::reconnectGuardActive(15000U, 0U));

  const uint32_t last = std::numeric_limits<uint32_t>::max() - 9999U;
  EXPECT_TRUE(Policy::reconnectGuardActive(4999U, last));
  EXPECT_FALSE(Policy::reconnectGuardActive(5000U, last));
}

TEST(MQTTConnectionPolicy, StableResetRequiresARealStartAndFullWindow) {
  EXPECT_FALSE(Policy::stableConnection(500000U, 0U));
  EXPECT_FALSE(Policy::stableConnection(120999U, 1000U));
  EXPECT_TRUE(Policy::stableConnection(121000U, 1000U));
}

TEST(MQTTConnectionPolicy, StableResetWindowSurvivesMillisRollover) {
  const uint32_t connected_at = std::numeric_limits<uint32_t>::max() - 59999U;
  EXPECT_FALSE(Policy::stableConnection(59999U, connected_at));
  EXPECT_TRUE(Policy::stableConnection(60000U, connected_at));
}

TEST(MQTTConnectionPolicy, BackoffLadderSaturatesAtFiveMinutes) {
  EXPECT_EQ(10000U, Policy::reconnectBackoffMs(0));
  EXPECT_EQ(30000U, Policy::reconnectBackoffMs(1));
  EXPECT_EQ(60000U, Policy::reconnectBackoffMs(2));
  EXPECT_EQ(120000U, Policy::reconnectBackoffMs(3));
  EXPECT_EQ(300000U, Policy::reconnectBackoffMs(4));
  EXPECT_EQ(300000U, Policy::reconnectBackoffMs(5));
  EXPECT_EQ(300000U, Policy::reconnectBackoffMs(255));
}

TEST(MQTTConnectionPolicy, LaterSlotsReceiveThreeSecondStagger) {
  EXPECT_EQ(10000U, Policy::reconnectDelayMs(0, 0));
  EXPECT_EQ(13000U, Policy::reconnectDelayMs(0, 1));
  EXPECT_EQ(315000U, Policy::reconnectDelayMs(5, 5));
}

TEST(MQTTConnectionPolicy, ReconnectDueUsesDelayBoundaryAndWrapSafeElapsedTime) {
  EXPECT_FALSE(Policy::reconnectDue(12999U, 0U, 0, 1));
  EXPECT_TRUE(Policy::reconnectDue(13000U, 0U, 0, 1));

  const uint32_t last = std::numeric_limits<uint32_t>::max() - 4999U;
  EXPECT_FALSE(Policy::reconnectDue(4999U, last, 0, 0));
  EXPECT_TRUE(Policy::reconnectDue(5000U, last, 0, 0));
}

TEST(MQTTConnectionPolicy, BackoffAdvanceClimbsThenCountsFailuresAtMaximum) {
  Policy::BackoffAdvance first = Policy::advanceBackoff(0, 0);
  EXPECT_EQ(1, first.reconnect_backoff);
  EXPECT_EQ(0, first.max_backoff_failures);
  EXPECT_FALSE(first.circuit_breaker_tripped);
  EXPECT_TRUE(first.should_reconnect);

  Policy::BackoffAdvance enters_maximum = Policy::advanceBackoff(4, 0);
  EXPECT_EQ(5, enters_maximum.reconnect_backoff);
  EXPECT_EQ(0, enters_maximum.max_backoff_failures);
  EXPECT_FALSE(enters_maximum.circuit_breaker_tripped);
  EXPECT_TRUE(enters_maximum.should_reconnect);

  Policy::BackoffAdvance first_max_failure = Policy::advanceBackoff(5, 0);
  EXPECT_EQ(5, first_max_failure.reconnect_backoff);
  EXPECT_EQ(1, first_max_failure.max_backoff_failures);
  EXPECT_FALSE(first_max_failure.circuit_breaker_tripped);
  EXPECT_TRUE(first_max_failure.should_reconnect);
}

TEST(MQTTConnectionPolicy, ThirdFailureAtMaximumTripsWithoutAnotherHandshake) {
  Policy::BackoffAdvance result = Policy::advanceBackoff(5, 2);
  EXPECT_EQ(5, result.reconnect_backoff);
  EXPECT_EQ(3, result.max_backoff_failures);
  EXPECT_TRUE(result.circuit_breaker_tripped);
  EXPECT_FALSE(result.should_reconnect);
}

TEST(MQTTConnectionPolicy, CircuitBreakerProbeHasExactThirtyMinuteBoundary) {
  EXPECT_FALSE(Policy::circuitBreakerProbeDue(1799999U, 0U));
  EXPECT_TRUE(Policy::circuitBreakerProbeDue(1800000U, 0U));

  const uint32_t last = std::numeric_limits<uint32_t>::max() - 899999U;
  EXPECT_FALSE(Policy::circuitBreakerProbeDue(899999U, last));
  EXPECT_TRUE(Policy::circuitBreakerProbeDue(900000U, last));
}

TEST(MQTTConnectionPolicy, LinkRecoveryMakesCurrentBackoffDueImmediately) {
  const uint32_t now = 1234U;
  const uint32_t last = Policy::immediateRetryLastAttempt(now, false, 4, 2);
  EXPECT_TRUE(Policy::reconnectDue(now, last, 4, 2));
  EXPECT_FALSE(Policy::circuitBreakerProbeDue(now, last));
}

TEST(MQTTConnectionPolicy, LinkRecoveryMakesBreakerProbeDueWithoutClearingIt) {
  const uint32_t now = 1234U;
  const uint32_t last = Policy::immediateRetryLastAttempt(now, true, 5, 2);
  EXPECT_TRUE(Policy::circuitBreakerProbeDue(now, last));
}

TEST(MQTTConnectionPolicy, JwtLifetimeUsesCappedPerSlotStagger) {
  EXPECT_EQ(86400U, Policy::jwtLifetimeSecs(86400U, 0));
  EXPECT_EQ(86100U, Policy::jwtLifetimeSecs(86400U, 1));
  EXPECT_EQ(84900U, Policy::jwtLifetimeSecs(86400U, 5));
}

TEST(MQTTConnectionPolicy, ShortJwtLifetimeUsesFivePercentPerSlot) {
  EXPECT_EQ(3300U, Policy::jwtLifetimeSecs(3300U, 0));
  EXPECT_EQ(3135U, Policy::jwtLifetimeSecs(3300U, 1));
  EXPECT_EQ(2970U, Policy::jwtLifetimeSecs(3300U, 2));
  EXPECT_EQ(85U, Policy::jwtLifetimeSecs(100U, 3));
}

TEST(MQTTConnectionPolicy, JwtLifetimeCannotUnderflowForUnexpectedSlotInput) {
  EXPECT_EQ(0U, Policy::jwtLifetimeSecs(100U, 255));
}

TEST(MQTTConnectionPolicy, RenewalBufferHasOneMinuteFloorAndFiveMinuteCap) {
  EXPECT_EQ(60U, Policy::renewalBufferSecs(0U));
  EXPECT_EQ(60U, Policy::renewalBufferSecs(599U));
  EXPECT_EQ(60U, Policy::renewalBufferSecs(600U));
  EXPECT_EQ(299U, Policy::renewalBufferSecs(2999U));
  EXPECT_EQ(300U, Policy::renewalBufferSecs(3000U));
  EXPECT_EQ(300U, Policy::renewalBufferSecs(86400U));
}

TEST(MQTTConnectionPolicy, UnsynchronizedClockOnlyCreatesAMissingToken) {
  EXPECT_TRUE(Policy::tokenNeedsRenewal(false, 0U, 0U, 300U));
  EXPECT_FALSE(Policy::tokenNeedsRenewal(false, 0U, 1735693200U, 300U));
}

TEST(MQTTConnectionPolicy, SyncedClockRenewsInvalidExpiredOrImminentTokens) {
  const uint32_t expires = 1735693200U;
  EXPECT_TRUE(Policy::tokenNeedsRenewal(true, 1735689000U, 0U, 300U));
  EXPECT_TRUE(Policy::tokenNeedsRenewal(true, 1735689000U, 999999999U, 300U));
  EXPECT_FALSE(Policy::tokenNeedsRenewal(true, expires - 301U, expires, 300U));
  EXPECT_TRUE(Policy::tokenNeedsRenewal(true, expires - 300U, expires, 300U));
  EXPECT_TRUE(Policy::tokenNeedsRenewal(true, expires, expires, 300U));
  EXPECT_TRUE(Policy::tokenNeedsRenewal(true, expires + 1U, expires, 300U));
}

TEST(MQTTConnectionPolicy, JwtReconnectReusesOnlyProvenValidCredentials) {
  const uint32_t now = 1735689600U;
  const uint32_t usable_expiry = now + Policy::kJwtReconnectSafetyMarginSecs + 1U;

  // Buffer 0 gates on the flat margin alone, which is what these cases cover.
  EXPECT_TRUE(Policy::canReuseJwtForReconnect(true, true, false, now, usable_expiry, 0U));
  EXPECT_FALSE(Policy::canReuseJwtForReconnect(
      true, true, false, now, Policy::kMinimumValidEpoch - 1U, 0U));
  EXPECT_FALSE(Policy::canReuseJwtForReconnect(true, true, false, now, 0U, 0U));
  EXPECT_FALSE(Policy::canReuseJwtForReconnect(
      true, true, false, now, now + Policy::kJwtReconnectSafetyMarginSecs, 0U));
  EXPECT_FALSE(Policy::canReuseJwtForReconnect(true, true, false, now, now - 1U, 0U));
  EXPECT_FALSE(Policy::canReuseJwtForReconnect(true, false, false, now, usable_expiry, 0U));
  EXPECT_FALSE(Policy::canReuseJwtForReconnect(false, true, false, now, usable_expiry, 0U));
  EXPECT_FALSE(Policy::canReuseJwtForReconnect(true, true, true, now, usable_expiry, 0U));
}

TEST(MQTTConnectionPolicy, JwtReuseRefusesATokenTheRenewalPathIsAboutToBounce) {
  const uint32_t now = 1735689600U;
  const uint32_t buffer = Policy::renewalBufferSecs(3300U);  // waev's 55-minute tokens
  ASSERT_EQ(buffer, 300U);
  const uint32_t floor_secs = buffer + Policy::kJwtReconnectSafetyMarginSecs;

  // The observed defect (d3, 2026-08-17T14:31): reused at 302 s remaining under the
  // flat 60 s margin, then renewed five seconds later, which bounced the slot.
  EXPECT_FALSE(Policy::canReuseJwtForReconnect(true, true, false, now, now + 302U, buffer));

  // Anything the renewal path would act on is refused, and so is the slack above it.
  EXPECT_FALSE(Policy::canReuseJwtForReconnect(true, true, false, now, now + buffer, buffer));
  EXPECT_FALSE(
      Policy::canReuseJwtForReconnect(true, true, false, now, now + floor_secs, buffer));
  const uint32_t tightest_reuse = now + floor_secs + 1U;
  EXPECT_TRUE(Policy::canReuseJwtForReconnect(true, true, false, now, tightest_reuse, buffer));

  // What the margin above the buffer buys: the tightest token reuse will accept is still
  // not due for renewal a full margin later, so no renewal can bounce in behind it.
  EXPECT_FALSE(Policy::tokenNeedsRenewal(
      true, now + Policy::kJwtReconnectSafetyMarginSecs, tightest_reuse, buffer));

  // A buffer that would wrap the floor has to fail closed, not reuse a doomed token.
  EXPECT_FALSE(Policy::canReuseJwtForReconnect(
      true, true, false, now, now + 100000U, std::numeric_limits<uint32_t>::max()));
}

TEST(MQTTConnectionPolicy, RenewalThrottleHasExactBoundaryAndHandlesRollover) {
  EXPECT_FALSE(Policy::renewalAttemptAllowed(59999U, 0U));
  EXPECT_TRUE(Policy::renewalAttemptAllowed(60000U, 0U));

  const uint32_t last = std::numeric_limits<uint32_t>::max() - 29999U;
  EXPECT_FALSE(Policy::renewalAttemptAllowed(29999U, last));
  EXPECT_TRUE(Policy::renewalAttemptAllowed(30000U, last));
}

using Policy::ClockTrust;

TEST(ClockTrust, AJwtSlotWaitsForAClockSomebodySet) {
  EXPECT_FALSE(Policy::jwtClockAvailable(ClockTrust::NeverSet));
  // Kept over a soft reset, read from a chip or set by hand: good enough to try.
  EXPECT_TRUE(Policy::jwtClockAvailable(ClockTrust::Unverified));
  EXPECT_TRUE(Policy::jwtClockAvailable(ClockTrust::Verified));
}

TEST(ClockTrust, APasswordSlotNeedsNoClock) {
  EXPECT_TRUE(Policy::slotMayStart(false, ClockTrust::NeverSet));
  EXPECT_TRUE(Policy::slotMayStart(false, ClockTrust::Unverified));
  EXPECT_TRUE(Policy::slotMayStart(false, ClockTrust::Verified));
  EXPECT_FALSE(Policy::slotMayStart(true, ClockTrust::NeverSet));
  EXPECT_TRUE(Policy::slotMayStart(true, ClockTrust::Unverified));
  EXPECT_TRUE(Policy::slotMayStart(true, ClockTrust::Verified));
}

TEST(ClockTrust, OnlyAServersAnswerVerifies) {
  EXPECT_FALSE(Policy::clockVerified(ClockTrust::NeverSet));
  EXPECT_FALSE(Policy::clockVerified(ClockTrust::Unverified));
  EXPECT_TRUE(Policy::clockVerified(ClockTrust::Verified));

  EXPECT_EQ(ClockTrust::Verified, Policy::clockTrustAfterSync(ClockTrust::NeverSet, true, false));
  EXPECT_EQ(ClockTrust::Verified, Policy::clockTrustAfterSync(ClockTrust::Unverified, true, false));
  EXPECT_EQ(ClockTrust::Verified, Policy::clockTrustAfterSync(ClockTrust::Verified, true, true));
}

TEST(ClockTrust, AFallbackClockIsBelievedButNotVerified) {
  EXPECT_EQ(ClockTrust::Unverified,
            Policy::clockTrustAfterSync(ClockTrust::NeverSet, false, true));
  EXPECT_EQ(ClockTrust::Unverified,
            Policy::clockTrustAfterSync(ClockTrust::Unverified, false, true));
}

TEST(ClockTrust, NoServerAndNoClockChangesNothing) {
  EXPECT_EQ(ClockTrust::NeverSet,
            Policy::clockTrustAfterSync(ClockTrust::NeverSet, false, false));
  EXPECT_EQ(ClockTrust::Unverified,
            Policy::clockTrustAfterSync(ClockTrust::Unverified, false, false));
}

TEST(ClockTrust, OneAnswerVerifiesForGood) {
  // The hourly refresh reaching no server does not start the 30 s asking again.
  EXPECT_EQ(ClockTrust::Verified,
            Policy::clockTrustAfterSync(ClockTrust::Verified, false, true));
  EXPECT_EQ(ClockTrust::Verified,
            Policy::clockTrustAfterSync(ClockTrust::Verified, false, false));
}

TEST(MQTTConnectionPolicy, WifiBackoffLadderStartsAtFifteenSecondsAndSaturates) {
  EXPECT_EQ(15000U, Policy::wifiReconnectBackoffMs(0));
  EXPECT_EQ(30000U, Policy::wifiReconnectBackoffMs(1));
  EXPECT_EQ(60000U, Policy::wifiReconnectBackoffMs(2));
  EXPECT_EQ(120000U, Policy::wifiReconnectBackoffMs(3));
  EXPECT_EQ(300000U, Policy::wifiReconnectBackoffMs(4));
  // Clamps at the 300 s rung for the saturated attempt count and beyond.
  EXPECT_EQ(300000U, Policy::wifiReconnectBackoffMs(5));
  EXPECT_EQ(300000U, Policy::wifiReconnectBackoffMs(200));
}

TEST(MQTTConnectionPolicy, WifiBackoffAttemptClimbsThenSaturatesAtFive) {
  uint8_t attempt = 0;
  for (uint8_t expected = 1; expected <= 5; ++expected) {
    attempt = Policy::nextWifiBackoffAttempt(attempt);
    EXPECT_EQ(expected, attempt);
  }
  // Saturated: never advances past 5 (index stays clamped at the 300 s rung).
  EXPECT_EQ(5U, Policy::nextWifiBackoffAttempt(attempt));
  EXPECT_EQ(5U, Policy::nextWifiBackoffAttempt(5));
}

TEST(MQTTConnectionPolicy, WifiReconnectRequiresBothDownAndSinceAttemptToClearRung) {
  const uint32_t down_since = 1000U;
  const uint32_t last_attempt = 1000U;
  const uint8_t attempt = 0;  // 15 s rung
  // Neither interval has elapsed yet.
  EXPECT_FALSE(Policy::wifiReconnectDue(1000U + 14999U, down_since, last_attempt, attempt));
  // Down long enough, but an attempt was made only 5 s ago (since-attempt short).
  EXPECT_FALSE(Policy::wifiReconnectDue(1000U + 15000U, down_since, 1000U + 10000U, attempt));
  // Both cleared at the exact boundary: due.
  EXPECT_TRUE(Policy::wifiReconnectDue(1000U + 15000U, down_since, last_attempt, attempt));
}

TEST(MQTTConnectionPolicy, WifiOutageStartStickyAcrossReconnectAttempts) {
  // First observe-down (or connected→down) records `now`. Further down samples
  // — including STA backoff WiFi.disconnect() — must keep that start so
  // AlertReporter quotes the outage, not the last attempt / boot event.
  EXPECT_EQ(0U, Policy::wifiCurrentOutageStartMs(5000, true, false, 0, false));
  EXPECT_EQ(5000U, Policy::wifiCurrentOutageStartMs(5000, false, false, 0, false));

  const uint32_t start = 9000U;
  EXPECT_EQ(start, Policy::wifiCurrentOutageStartMs(start, false, true, 0, true));
  EXPECT_EQ(start, Policy::wifiCurrentOutageStartMs(start + 15000U, false, false, start, true));
  EXPECT_EQ(start, Policy::wifiCurrentOutageStartMs(start + 2U * 3600U * 1000U,
                                                    false, false, start, true));
  EXPECT_EQ(0U, Policy::wifiCurrentOutageStartMs(start + 1000U, true, false, start, true));
}

TEST(MQTTConnectionPolicy, WifiReconnectDueSurvivesMillisRollover) {
  const uint32_t down_since = std::numeric_limits<uint32_t>::max() - 100U;
  const uint32_t last_attempt = down_since;
  const uint8_t attempt = 0;  // 15 s rung
  const uint32_t now = down_since + 15000U;  // wraps past zero
  EXPECT_TRUE(Policy::wifiReconnectDue(now, down_since, last_attempt, attempt));
  EXPECT_FALSE(Policy::wifiReconnectDue(down_since + 14999U, down_since, last_attempt, attempt));
}

// --- classifySlotActivation: the "will this slot connect on this hardware" rule
// the CLI uses to warn at `set mqttN.preset` time. Non-PSRAM Heltec V3 is the
// motivating case: RUNTIME_MQTT_SLOTS=3 but only 2 concurrent connections. ---

using Policy::SlotActivation;

TEST(SlotActivation, NonPsramV3FirstTwoConnectThirdIsOverCap) {
  // slot_count = 3 (runtime array), max_active = 2 (concurrent cap).
  const bool enabled[6] = {true, true, true, false, false, false};
  EXPECT_EQ(SlotActivation::Connects,      Policy::classifySlotActivation(0, enabled, 3, 2));
  EXPECT_EQ(SlotActivation::Connects,      Policy::classifySlotActivation(1, enabled, 3, 2));
  // slot 3 (index 2) is the case in the field log: iterated, but skipped.
  EXPECT_EQ(SlotActivation::OverActiveCap, Policy::classifySlotActivation(2, enabled, 3, 2));
}

TEST(SlotActivation, NonPsramSlotsBeyondRuntimeArrayAreNeverIterated) {
  const bool enabled[6] = {true, true, true, true, false, false};
  // mqtt4/5/6 (index 3-5) are outside the 3-slot runtime array on non-PSRAM.
  EXPECT_EQ(SlotActivation::BeyondArray, Policy::classifySlotActivation(3, enabled, 3, 2));
  EXPECT_EQ(SlotActivation::BeyondArray, Policy::classifySlotActivation(5, enabled, 3, 2));
}

TEST(SlotActivation, RankCountsOnlyEnabledLowerSlots) {
  // Only slot index 2 enabled (1 and 2 disabled): it is the first enabled slot,
  // so it connects even though its index equals the cap.
  const bool enabled[6] = {false, false, true, false, false, false};
  EXPECT_EQ(SlotActivation::Connects, Policy::classifySlotActivation(2, enabled, 3, 2));

  // Gap in the middle: slots 0 and 2 enabled, slot 1 off. Slot 2 is rank 2 <= 2.
  const bool enabled2[6] = {true, false, true, false, false, false};
  EXPECT_EQ(SlotActivation::Connects, Policy::classifySlotActivation(2, enabled2, 3, 2));
}

TEST(SlotActivation, PsramFiveOfSixConnect) {
  // PSRAM: slot_count = 6, max_active = 5. Sixth enabled slot is over the cap.
  const bool enabled[6] = {true, true, true, true, true, true};
  EXPECT_EQ(SlotActivation::Connects,      Policy::classifySlotActivation(4, enabled, 6, 5));
  EXPECT_EQ(SlotActivation::OverActiveCap, Policy::classifySlotActivation(5, enabled, 6, 5));
}

TEST(SlotActivation, DisabledAndOutOfRangeSlots) {
  const bool enabled[6] = {true, false, true, false, false, false};
  EXPECT_EQ(SlotActivation::Disabled, Policy::classifySlotActivation(1, enabled, 3, 2));
  EXPECT_EQ(SlotActivation::Disabled, Policy::classifySlotActivation(-1, enabled, 3, 2));
  EXPECT_EQ(SlotActivation::Disabled, Policy::classifySlotActivation(0, nullptr, 3, 2));
}

using Policy::StaleTokenAction;

TEST(StaleToken, ConnectedSlotOnAnExpEnforcingBrokerBounces) {
  // The broker will reject the stale token, and esp-mqtt refuses reconnect() from
  // CONNECTED, so the transport has to close first.
  EXPECT_EQ(StaleTokenAction::Bounce,
            Policy::classifyStaleToken(/*minted=*/true, /*connected=*/true,
                                       /*broker_enforces_exp=*/true));
}

TEST(StaleToken, ConnectedSlotOnATolerantBrokerKeepsItsSession) {
  // waev leaves live sessions alone past exp. Bouncing would spend a 16 KiB
  // contiguous handshake to replace a session the broker was not going to drop.
  EXPECT_EQ(StaleTokenAction::KeepAlive,
            Policy::classifyStaleToken(true, true, /*broker_enforces_exp=*/false));
}

TEST(StaleToken, DisconnectedSlotReconnectsRegardlessOfBrokerPolicy) {
  EXPECT_EQ(StaleTokenAction::Reconnect, Policy::classifyStaleToken(true, false, true));
  EXPECT_EQ(StaleTokenAction::Reconnect, Policy::classifyStaleToken(true, false, false));
}

TEST(StaleToken, FailedMintNeverReconnects) {
  // Reconnecting here would re-present the credentials the correction invalidated.
  // Every combination defers — including the disconnected one, which is the case
  // that previously reconnected on the stale token.
  EXPECT_EQ(StaleTokenAction::Defer, Policy::classifyStaleToken(false, false, true));
  EXPECT_EQ(StaleTokenAction::Defer, Policy::classifyStaleToken(false, false, false));
  EXPECT_EQ(StaleTokenAction::Defer, Policy::classifyStaleToken(false, true, true));
  EXPECT_EQ(StaleTokenAction::Defer, Policy::classifyStaleToken(false, true, false));
}

using Policy::ClockSource;

// 2026-01-01, the bridge's plausibility floor, and what ESP32RTCClock::begin() stamps
// into libc on a power-on reset (RTC_TIME_MIN, 1 March 2026): past the floor, so only
// clockNeverSet() tells it from a clock somebody set.
static const uint32_t kFloor = 1767225600;
static const uint32_t kPowerOn = Policy::kPowerOnClockEpoch;
static const uint32_t kPlausibleNow = 1795000000;
static const uint32_t kMargin = Policy::kClockNeverSetMarginSecs;

TEST(FallbackClock, ThePowerOnValueIsTheBoardsOwn) {
  // The number in ESP32Board.h; MQTTBridge.cpp static_asserts the header against it.
  EXPECT_EQ(1772323200u, Policy::kPowerOnClockEpoch);
  EXPECT_GT(Policy::kPowerOnClockEpoch, kFloor);
}

TEST(ClockNeverSet, ThePlaceholderCountingUpWasNeverSet) {
  EXPECT_TRUE(Policy::clockNeverSet(kPowerOn, kPowerOn, 0));
  EXPECT_TRUE(Policy::clockNeverSet(kPowerOn + 40, kPowerOn, 40));
  // A week up, nine months short of the real date.
  EXPECT_TRUE(Policy::clockNeverSet(kPowerOn + 7 * 86400, kPowerOn, 7 * 86400));
  // Earlier than the placeholder is no clock either.
  EXPECT_TRUE(Policy::clockNeverSet(kPowerOn - 1, kPowerOn, 0));
  EXPECT_TRUE(Policy::clockNeverSet(0, kPowerOn, 0));
}

TEST(ClockNeverSet, TheMarginIsExact) {
  EXPECT_TRUE(Policy::clockNeverSet(kPowerOn + 30 + kMargin, kPowerOn, 30));
  EXPECT_FALSE(Policy::clockNeverSet(kPowerOn + 30 + kMargin + 1, kPowerOn, 30));
}

TEST(ClockNeverSet, AClockThatWasSetIsFarPastThePlaceholder) {
  EXPECT_FALSE(Policy::clockNeverSet(kPlausibleNow, kPowerOn, 0));
  EXPECT_FALSE(Policy::clockNeverSet(kPlausibleNow, kPowerOn, 30 * 86400));
  // Real time restored by a soft reset: uptime starts again, the clock does not.
  EXPECT_FALSE(Policy::clockNeverSet(kPlausibleNow + 5, kPowerOn, 5));
}

TEST(ClockNeverSet, ASoftResetDoesNotLaunderANeverSetClock) {
  // Ten minutes up on the placeholder, then a restart: the clock comes back at
  // placeholder + 600 with the uptime at zero. Against the placeholder that looks set;
  // against the reading carried over the reset it does not.
  const uint32_t carried = kPowerOn + 600;
  EXPECT_FALSE(Policy::clockNeverSet(carried + 20, kPowerOn, 20));
  EXPECT_TRUE(Policy::clockNeverSet(carried + 20, carried, 20));
  EXPECT_FALSE(Policy::clockNeverSet(kPlausibleNow, carried, 20));
}

TEST(ClockNeverSet, NoBaselineJudgesNothing) {
  // A board that seeds no placeholder passes 0, and the floor alone decides.
  EXPECT_FALSE(Policy::clockNeverSet(kPlausibleNow, 0, 3600));
  // No wrap at the top of the range.
  EXPECT_TRUE(Policy::clockNeverSet(0xFFFFFFFFu, 0xFFFFFFF0u, 0xFFFFFFFFu));
}

TEST(FallbackClock, PrefersTheSystemClockWhenItIsUsable) {
  // A clock SNTP set recently outranks an RTC that may have drifted.
  EXPECT_EQ(ClockSource::System,
            Policy::chooseFallbackClock(false, kPlausibleNow, kPlausibleNow - 900, kFloor,
                                        kPowerOn, 3600));
}

TEST(FallbackClock, ANeverSetSystemClockIsNotAClock) {
  // The lockout: a power cycle, no NTP server in reach, and logins minted from March.
  EXPECT_EQ(ClockSource::None,
            Policy::chooseFallbackClock(false, kPowerOn + 45, 0, kFloor, kPowerOn, 45));
  // A board without a chip hands the same system clock in as its RTC.
  EXPECT_EQ(ClockSource::None,
            Policy::chooseFallbackClock(false, kPowerOn + 45, kPowerOn + 45, kFloor,
                                        kPowerOn, 45));
  EXPECT_EQ(ClockSource::None,
            Policy::chooseFallbackClock(false, kPowerOn + 86400, kPowerOn + 86400, kFloor,
                                        kPowerOn, 86400));
}

TEST(FallbackClock, AValidChipWinsOverANeverSetSystemClock) {
  // A cold boot: libc holds the placeholder while a detected chip holds real time.
  EXPECT_EQ(ClockSource::Rtc,
            Policy::chooseFallbackClock(false, kPowerOn + 45, kPlausibleNow, kFloor,
                                        kPowerOn, 45));
}

TEST(FallbackClock, AClockThatSurvivedASoftResetIsKept) {
  EXPECT_EQ(ClockSource::System,
            Policy::chooseFallbackClock(false, kPlausibleNow, 0, kFloor, kPowerOn, 12));
  EXPECT_EQ(ClockSource::System,
            Policy::chooseFallbackClock(false, kPlausibleNow, kPlausibleNow, kFloor,
                                        kPowerOn, 12));
}

TEST(FallbackClock, NothingUsableStaysUnsynced) {
  EXPECT_EQ(ClockSource::None,
            Policy::chooseFallbackClock(false, kFloor - 5, kFloor - 5, kFloor, 0, 0));
  // rtc_time 0 is how a board with no clock to consult is passed in.
  EXPECT_EQ(ClockSource::None,
            Policy::chooseFallbackClock(false, kFloor - 5, 0, kFloor, 0, 0));
}

TEST(FallbackClock, ServerValidationNeverAcceptsALocalClock) {
  // `set mqtt.ntp` asks whether that host answers. No clock can answer for it,
  // however plausible: this is the path where a typo has to fail.
  EXPECT_EQ(ClockSource::None,
            Policy::chooseFallbackClock(true, kPlausibleNow, kPlausibleNow, kFloor,
                                        kPowerOn, 3600));
}

TEST(FallbackClock, TheFloorItselfIsAccepted) {
  // With no placeholder to judge against, as on a board that seeds none.
  EXPECT_EQ(ClockSource::System, Policy::chooseFallbackClock(false, kFloor, 0, kFloor, 0, 0));
  EXPECT_EQ(ClockSource::Rtc,
            Policy::chooseFallbackClock(false, kFloor - 1, kFloor, kFloor, 0, 0));
  EXPECT_EQ(ClockSource::None,
            Policy::chooseFallbackClock(false, kFloor - 1, kFloor - 1, kFloor, 0, 0));
}

TEST(FallbackClock, TheSystemClockIsNotWrittenBackOnEveryRetry) {
  // A server's answer and a chip's reading are always written.
  EXPECT_TRUE(Policy::acceptedClockNeedsWriting(true, ClockSource::None, ClockTrust::Verified));
  EXPECT_TRUE(Policy::acceptedClockNeedsWriting(false, ClockSource::Rtc, ClockTrust::Unverified));
  // The system clock as its own fallback: once, so a chip gets it, then left alone.
  EXPECT_TRUE(Policy::acceptedClockNeedsWriting(false, ClockSource::System, ClockTrust::NeverSet));
  EXPECT_FALSE(
      Policy::acceptedClockNeedsWriting(false, ClockSource::System, ClockTrust::Unverified));
  EXPECT_FALSE(Policy::acceptedClockNeedsWriting(false, ClockSource::System, ClockTrust::Verified));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
