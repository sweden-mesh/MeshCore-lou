#include <gtest/gtest.h>

#include "helpers/NetworkPolicy.h"

TEST(NetworkPolicy, MqttDownDisconnectsSlotsWithoutRequestingImmediateRetry) {
  const auto actions = NetworkPolicy::mqttActions(NetworkTransition::Down);
  EXPECT_TRUE(actions.disconnect_started_slots);
  EXPECT_FALSE(actions.retry_disconnected_slots_now);
  EXPECT_FALSE(actions.reset_reconnect_backoff);
}

TEST(NetworkPolicy, MqttUpRetriesWithoutClearingBrokerCircuitBreaker) {
  const auto actions = NetworkPolicy::mqttActions(NetworkTransition::Up);
  EXPECT_FALSE(actions.disconnect_started_slots);
  EXPECT_TRUE(actions.retry_disconnected_slots_now);
  EXPECT_FALSE(actions.reset_reconnect_backoff);
}

TEST(NetworkPolicy, NoTransitionHasNoMqttSideEffects) {
  const auto actions = NetworkPolicy::mqttActions(NetworkTransition::None);
  EXPECT_FALSE(actions.disconnect_started_slots);
  EXPECT_FALSE(actions.retry_disconnected_slots_now);
  EXPECT_FALSE(actions.reset_reconnect_backoff);
}

TEST(NetworkPolicy, LinkSwitchReconnectsMqttSlotsImmediately) {
  const auto actions = NetworkPolicy::mqttActions(NetworkTransition::Switched);
  EXPECT_TRUE(actions.disconnect_started_slots);
  EXPECT_TRUE(actions.retry_disconnected_slots_now);
  EXPECT_TRUE(actions.reset_reconnect_backoff);
}

TEST(NetworkPolicy, MediumNamesAreStableForTransitionLogs) {
  EXPECT_STREQ("none", NetworkPolicy::mediumName(NetworkMedium::None));
  EXPECT_STREQ("ethernet", NetworkPolicy::mediumName(NetworkMedium::Ethernet));
  EXPECT_STREQ("wifi", NetworkPolicy::mediumName(NetworkMedium::WiFi));
}

TEST(NetworkPolicy, BootPrefersEthernetAndOtherwiseUsesConfiguredWifi) {
  EXPECT_EQ(NetworkMedium::Ethernet, NetworkPolicy::bootSelection(true, true));
  EXPECT_EQ(NetworkMedium::WiFi, NetworkPolicy::bootSelection(false, true));
  EXPECT_EQ(NetworkMedium::None, NetworkPolicy::bootSelection(false, false));
}

TEST(NetworkPolicy, EthernetBootProbeUsesFullDeadlineForLinkOrUnknownState) {
  EXPECT_TRUE(NetworkPolicy::ethernetBootProbePending(
      true, false, false, false, 1500, 8000));
  EXPECT_TRUE(NetworkPolicy::ethernetBootProbePending(
      true, false, true, true, 7999, 8000));
  EXPECT_FALSE(NetworkPolicy::ethernetBootProbePending(
      true, false, true, true, 8000, 8000));
  EXPECT_FALSE(NetworkPolicy::ethernetBootProbePending(
      true, true, true, true, 100, 8000));
  EXPECT_FALSE(NetworkPolicy::ethernetBootProbePending(
      false, false, false, false, 100, 8000));
}

TEST(NetworkPolicy, EthernetBootProbeStopsEarlyOnKnownCableDown) {
  EXPECT_TRUE(NetworkPolicy::ethernetBootProbePending(
      true, false, true, false,
      NetworkPolicy::kEthernetNoLinkBootGraceMs - 1, 8000));
  EXPECT_FALSE(NetworkPolicy::ethernetBootProbePending(
      true, false, true, false,
      NetworkPolicy::kEthernetNoLinkBootGraceMs, 8000));
}

TEST(NetworkPolicy, EthernetInitRetryUsesBoundedExponentialBackoff) {
  EXPECT_EQ(0u, NetworkPolicy::ethernetInitRetryDelayMs(0));
  EXPECT_EQ(5000u, NetworkPolicy::ethernetInitRetryDelayMs(1));
  EXPECT_EQ(10000u, NetworkPolicy::ethernetInitRetryDelayMs(2));
  EXPECT_EQ(300000u, NetworkPolicy::ethernetInitRetryDelayMs(8));
  EXPECT_EQ(300000u, NetworkPolicy::ethernetInitRetryDelayMs(255));

  EXPECT_FALSE(NetworkPolicy::ethernetInitRetryDue(1, 4999, 0));
  EXPECT_TRUE(NetworkPolicy::ethernetInitRetryDue(1, 5000, 0));
  EXPECT_TRUE(NetworkPolicy::ethernetInitRetryDue(1, 10, 10u - 5000u));
}

TEST(NetworkPolicy, EthernetNoIpRecoveryRequiresSustainedCarrier) {
  const uint32_t timeout = NetworkPolicy::kEthernetNoIpRecoveryMs;
  EXPECT_FALSE(NetworkPolicy::ethernetNoIpRecoveryDue(
      true, true, false, timeout, 0));
  EXPECT_FALSE(NetworkPolicy::ethernetNoIpRecoveryDue(
      true, true, false, timeout, 1));
  EXPECT_TRUE(NetworkPolicy::ethernetNoIpRecoveryDue(
      true, true, false, timeout + 1, 1));
  EXPECT_FALSE(NetworkPolicy::ethernetNoIpRecoveryDue(
      true, false, false, timeout + 1, 1));
  EXPECT_FALSE(NetworkPolicy::ethernetNoIpRecoveryDue(
      true, true, true, timeout + 1, 1));
  EXPECT_TRUE(NetworkPolicy::ethernetNoIpRecoveryDue(
      true, true, false, 100, 100u - timeout));
}

TEST(NetworkPolicy, EthernetFailureWaitsForGraceAndConnectedWifi) {
  NetworkPolicy::AutomaticSelectionInput input = {
      NetworkMedium::Ethernet, false, true, true, false, 0,
      NetworkPolicy::kEthernetDownGraceMs - 1};
  EXPECT_EQ(NetworkMedium::Ethernet, NetworkPolicy::automaticSelection(input));
  input.selected_down_ms = NetworkPolicy::kEthernetDownGraceMs;
  EXPECT_EQ(NetworkMedium::WiFi, NetworkPolicy::automaticSelection(input));
}

TEST(NetworkPolicy, FailbackRequiresStableEthernet) {
  NetworkPolicy::AutomaticSelectionInput input = {
      NetworkMedium::WiFi, true, true, true, false,
      NetworkPolicy::kEthernetFailbackStableMs - 1, 0};
  EXPECT_EQ(NetworkMedium::WiFi, NetworkPolicy::automaticSelection(input));
  input.ethernet_stable_ms = NetworkPolicy::kEthernetFailbackStableMs;
  EXPECT_EQ(NetworkMedium::Ethernet, NetworkPolicy::automaticSelection(input));
}

TEST(NetworkPolicy, DeadWifiFailsBackToReadyEthernetImmediately) {
  const NetworkPolicy::AutomaticSelectionInput input = {
      NetworkMedium::WiFi, true, false, true, false, 0, 0};
  EXPECT_EQ(NetworkMedium::Ethernet, NetworkPolicy::automaticSelection(input));
}

TEST(NetworkPolicy, SwitchingLockPinsTheCurrentMedium) {
  const NetworkPolicy::AutomaticSelectionInput input = {
      NetworkMedium::WiFi, true, true, true, true,
      NetworkPolicy::kEthernetFailbackStableMs, 0};
  EXPECT_EQ(NetworkMedium::WiFi, NetworkPolicy::automaticSelection(input));
}

TEST(NetworkPolicy, DiagnosticsIdentifyEthernetFallbackCause) {
  using Reason = NetworkDiagnosticReason;
  EXPECT_EQ(Reason::EthernetInitFailed,
            NetworkPolicy::automaticDiagnosticReason(
                false, false, false, false, NetworkMedium::WiFi, false, 0));
  EXPECT_EQ(Reason::EthernetLinkUnknown,
            NetworkPolicy::automaticDiagnosticReason(
                true, false, false, false, NetworkMedium::WiFi, false, 0));
  EXPECT_EQ(Reason::EthernetLinkDown,
            NetworkPolicy::automaticDiagnosticReason(
                true, true, false, false, NetworkMedium::WiFi, false, 0));
  EXPECT_EQ(Reason::EthernetAwaitingIp,
            NetworkPolicy::automaticDiagnosticReason(
                true, true, true, false, NetworkMedium::WiFi, false, 0));
}

TEST(NetworkPolicy, DiagnosticsExplainWhyReadyEthernetHasNotBeenSelected) {
  using Reason = NetworkDiagnosticReason;
  EXPECT_EQ(Reason::SwitchingLocked,
            NetworkPolicy::automaticDiagnosticReason(
                true, true, true, true, NetworkMedium::WiFi, true,
                NetworkPolicy::kEthernetFailbackStableMs));
  EXPECT_EQ(Reason::EthernetStabilizing,
            NetworkPolicy::automaticDiagnosticReason(
                true, true, true, true, NetworkMedium::WiFi, false,
                NetworkPolicy::kEthernetFailbackStableMs - 1));
  EXPECT_EQ(Reason::EthernetReady,
            NetworkPolicy::automaticDiagnosticReason(
                true, true, true, true, NetworkMedium::WiFi, false,
                NetworkPolicy::kEthernetFailbackStableMs));
  EXPECT_EQ(Reason::EthernetActive,
            NetworkPolicy::automaticDiagnosticReason(
                true, true, true, true, NetworkMedium::Ethernet, false, 0));
}

TEST(NetworkPolicy, NtpIsScheduledOncePerConnectivityEdge) {
  EXPECT_TRUE(NetworkPolicy::ntpPendingAfterConnectivitySample(
      false, false, false, true));
  EXPECT_FALSE(NetworkPolicy::ntpPendingAfterConnectivitySample(
      false, false, true, true));
  EXPECT_TRUE(NetworkPolicy::ntpPendingAfterConnectivitySample(
      false, true, true, true));
  EXPECT_FALSE(NetworkPolicy::ntpPendingAfterConnectivitySample(
      true, false, false, true));
}

TEST(NetworkPolicy, FailedNtpSyncWaitsForThirtySecondRetryBoundary) {
  EXPECT_FALSE(NetworkPolicy::ntpRetryDue(false, true, 29999, 0));
  EXPECT_TRUE(NetworkPolicy::ntpRetryDue(false, true, 30000, 0));
  EXPECT_FALSE(NetworkPolicy::ntpRetryDue(true, true, 60000, 0));
  EXPECT_FALSE(NetworkPolicy::ntpRetryDue(false, false, 60000, 0));
  EXPECT_TRUE(NetworkPolicy::ntpRetryDue(false, true, 10, 0xffff8000u));
}

TEST(NetworkPolicy, NtpKeepsAskingUntilAServerHasAnswered) {
  // The flag is "a server answered". A node on a fallback clock is not verified, so the
  // 30 s retry and the sync on a link coming up both go on; one answer ends them.
  const bool unverified = false, verified = true;
  EXPECT_TRUE(NetworkPolicy::ntpRetryDue(unverified, true, 30000, 0));
  EXPECT_TRUE(NetworkPolicy::ntpRetryDue(unverified, true, 90000, 60000));
  EXPECT_FALSE(NetworkPolicy::ntpRetryDue(verified, true, 90000, 0));
  EXPECT_TRUE(NetworkPolicy::ntpPendingAfterConnectivitySample(unverified, false, false, true));
  EXPECT_FALSE(NetworkPolicy::ntpPendingAfterConnectivitySample(verified, false, false, true));
}

TEST(NetworkPolicy, TheNtpRetryThinsOutToFifteenMinutes) {
  EXPECT_EQ(30000u, NetworkPolicy::ntpRetryIntervalMs(0));
  EXPECT_EQ(60000u, NetworkPolicy::ntpRetryIntervalMs(1));
  EXPECT_EQ(300000u, NetworkPolicy::ntpRetryIntervalMs(2));
  EXPECT_EQ(900000u, NetworkPolicy::ntpRetryIntervalMs(3));
  EXPECT_EQ(900000u, NetworkPolicy::ntpRetryIntervalMs(255));

  // The bridge's loop: a first sync at 0 that reaches no server, then the retries.
  uint32_t last = 0;
  uint8_t retries = 0;
  uint32_t at[6];
  int n = 0;
  for (uint32_t now = 0; now <= 3600000u && n < 6; now += 1000) {
    if (!NetworkPolicy::ntpRetryDue(false, true, now, last, retries)) continue;
    last = now;
    retries = NetworkPolicy::ntpRetriesAfterRetry(retries);
    at[n++] = now / 1000;
  }
  ASSERT_EQ(6, n);
  const uint32_t want[6] = { 30, 90, 390, 1290, 2190, 3090 };
  for (int i = 0; i < 6; i++) EXPECT_EQ(want[i], at[i]) << i;

  // The count stops at the last step and does not wrap back to the short interval.
  uint8_t r = 0;
  for (int i = 0; i < 600; i++) r = NetworkPolicy::ntpRetriesAfterRetry(r);
  EXPECT_EQ(NetworkPolicy::kNtpRetrySteps, r);
  // A network that came up or a clock set by hand starts over: the count is 0 again.
  EXPECT_FALSE(NetworkPolicy::ntpRetryDue(false, true, 4000000u + 29999, 4000000u, 0));
  EXPECT_TRUE(NetworkPolicy::ntpRetryDue(false, true, 4000000u + 30000, 4000000u, 0));
  EXPECT_FALSE(NetworkPolicy::ntpRetryDue(false, true, 4000000u + 899999, 4000000u, r));
  EXPECT_TRUE(NetworkPolicy::ntpRetryDue(false, true, 4000000u + 900000, 4000000u, r));
  // A server's answer or a lost network ends it at any step.
  EXPECT_FALSE(NetworkPolicy::ntpRetryDue(true, true, 4000000u + 900000, 4000000u, r));
  EXPECT_FALSE(NetworkPolicy::ntpRetryDue(false, false, 4000000u + 900000, 4000000u, r));
}

TEST(NetworkPolicy, ARetryOnARunningClockAsksEachServerOnce) {
  EXPECT_EQ(2, NetworkPolicy::ntpRetryAttemptsPerServer(false));
  EXPECT_EQ(1, NetworkPolicy::ntpRetryAttemptsPerServer(true));
}

TEST(NetworkPolicy, StartOtaUsesReachableSelectedNetworkByDefault) {
  EXPECT_TRUE(NetworkPolicy::startOtaUsesSelectedNetwork(false, true));
  EXPECT_FALSE(NetworkPolicy::startOtaUsesSelectedNetwork(false, false));
}

TEST(NetworkPolicy, StartOtaForceApOverridesAReachableSelectedNetwork) {
  EXPECT_FALSE(NetworkPolicy::startOtaUsesSelectedNetwork(true, true));
  EXPECT_FALSE(NetworkPolicy::startOtaUsesSelectedNetwork(true, false));
}

TEST(NetworkPolicy, ManualOtaTimeoutIsUploadSafeAndWrapSafe) {
  const uint32_t timeout = NetworkPolicy::kManualOtaSessionTimeoutMs;
  EXPECT_FALSE(NetworkPolicy::manualOtaTimeoutDue(timeout - 1, 0, false));
  EXPECT_TRUE(NetworkPolicy::manualOtaTimeoutDue(timeout, 0, false));
  EXPECT_FALSE(NetworkPolicy::manualOtaTimeoutDue(timeout, 0, true));
  EXPECT_TRUE(NetworkPolicy::manualOtaTimeoutDue(
      100, 100 - timeout, false));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
