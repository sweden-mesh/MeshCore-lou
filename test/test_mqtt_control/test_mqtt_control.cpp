// Host tests for the MQTT control-plane logic (src/helpers/MqttControlLogic.h):
// the envelope split, the bytes the signature covers, the replay window, the
// expiry window and the command allowlist. These are the exact functions
// examples/simple_repeater/MqttControl.cpp calls.
//
// The broker this rides on publishes its own credentials, so every one of these
// functions is reachable by anyone. Most of what follows is therefore hostile
// input rather than happy path: a bug here is a remote mesh-flood capability.
// The design is docs/architecture/decisions/001-mqtt-control-envelope.md in the
// workspace root, which is the directory above this repo, not a path inside it.
#include <gtest/gtest.h>
#include <vector>

#include <algorithm>
#include <string>
#include <ForkFeatures.h>
#include "helpers/MqttControlLogic.h"
#include "helpers/AutoReplyLogic.h"   // a trigger is checked one layer down
// The limiter itself, so the budgets are exercised rather than only their decision
// function. Header-only and Arduino-free, and the native env has -I src alone, so
// it comes in by relative path rather than by a platformio.ini change.
#include "../../examples/simple_repeater/RateLimiter.h"

extern "C" {
#include "ed25519/ed_25519.h"
}

// 128 hex characters, the length JWTHelper already emits.
static std::string sig(char fill = 'A') { return std::string(MQTTCTRL_SIG_HEX_LEN, fill); }

static std::string envelope(const std::string& signed_part) {
  return signed_part + "|" + sig();
}

static MqttCtrlResult parse(const std::string& payload, MqttCtrlEnvelope* out) {
  return mqttCtrlParseEnvelope(payload.data(), payload.size(), out);
}

// MqttCtrlEnvelope points into the payload buffer, which must outlive it. Tests
// that keep an envelope past the statement that made it hold the bytes here --
// a temporary std::string would leave every pointer dangling.
struct Held {
  std::string bytes;
  MqttCtrlEnvelope env;
  explicit Held(const std::string& signed_part) : bytes(envelope(signed_part)) {
    EXPECT_EQ(MQTTCTRL_OK, mqttCtrlParseEnvelope(bytes.data(), bytes.size(), &env));
  }
};

// ---- the happy path, so the hostile cases mean something --------------------

TEST(ParseEnvelope, AcceptsAWellFormedCommand) {
  MqttCtrlEnvelope e;
  ASSERT_EQ(MQTTCTRL_OK, parse(envelope("v1|7|1788200000|trigger test"), &e));
  EXPECT_EQ(7u, e.counter);
  EXPECT_EQ(1788200000u, e.expiry);
  EXPECT_EQ(std::string("trigger test"), std::string(e.command, e.command_len));
}

TEST(ParseEnvelope, SignedSpanExcludesTheSignature) {
  // The signed span must be a literal byte range of what arrived: we verify
  // exactly the bytes received, with no canonicalisation step to get wrong.
  const std::string signed_part = "v1|1|1788200000|get autoreply";
  Held h(signed_part);
  EXPECT_EQ(signed_part.size(), h.env.signed_len);
  EXPECT_EQ(signed_part, std::string(h.env.signed_part, h.env.signed_len));
}

TEST(ParseEnvelope, DecodesSignatureBytes) {
  MqttCtrlEnvelope e;
  std::string hex(MQTTCTRL_SIG_HEX_LEN, '0');
  hex[0] = 'f'; hex[1] = 'f'; hex[2] = 'A'; hex[3] = 'b';
  ASSERT_EQ(MQTTCTRL_OK, parse("v1|1|1788200000|get autoreply|" + hex, &e));
  EXPECT_EQ(0xFF, e.signature[0]);
  EXPECT_EQ(0xAB, e.signature[1]);   // hex decoding is case-insensitive
  EXPECT_EQ(0x00, e.signature[63]);
}

// ---- malformed and hostile envelopes ---------------------------------------

TEST(ParseEnvelope, RejectsEmptyAndOversized) {
  MqttCtrlEnvelope e;
  EXPECT_EQ(MQTTCTRL_ERR_EMPTY, mqttCtrlParseEnvelope(NULL, 10, &e));
  EXPECT_EQ(MQTTCTRL_ERR_EMPTY, mqttCtrlParseEnvelope("x", 0, &e));
  std::string huge = "v1|1|1788200000|" + std::string(MQTTCTRL_MAX_PAYLOAD, 'a') + "|" + sig();
  EXPECT_EQ(MQTTCTRL_ERR_TOO_LONG, parse(huge, &e));
}

TEST(ParseEnvelope, RejectsMissingOrWrongLengthSignature) {
  MqttCtrlEnvelope e;
  EXPECT_EQ(MQTTCTRL_ERR_NO_SIGNATURE, parse("v1 1 1788200000 trigger test", &e));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_SIG_LEN, parse("v1|1|1788200000|trigger test|ABCD", &e));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_SIG_LEN,
            parse("v1|1|1788200000|trigger test|" + std::string(127, 'A'), &e));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_SIG_LEN,
            parse("v1|1|1788200000|trigger test|" + std::string(129, 'A'), &e));
}

TEST(ParseEnvelope, RejectsNonHexSignature) {
  MqttCtrlEnvelope e;
  std::string bad = sig();
  bad[64] = 'g';
  EXPECT_EQ(MQTTCTRL_ERR_BAD_SIG_HEX, parse("v1|1|1788200000|trigger test|" + bad, &e));
  // ' 1' would satisfy strtol; it must not satisfy this.
  std::string spaced = sig();
  spaced[0] = ' '; spaced[1] = '1';
  EXPECT_EQ(MQTTCTRL_ERR_BAD_SIG_HEX, parse("v1|1|1788200000|trigger test|" + spaced, &e));
}

TEST(ParseEnvelope, RejectsWrongVersionTag) {
  MqttCtrlEnvelope e;
  EXPECT_EQ(MQTTCTRL_ERR_BAD_VERSION, parse(envelope("v2|1|1788200000|trigger test"), &e));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_VERSION, parse(envelope("|1|1788200000|trigger test"), &e));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_VERSION, parse(envelope("v1x|1|1788200000|trigger test"), &e));
}

TEST(ParseEnvelope, RejectsMissingFields) {
  MqttCtrlEnvelope e;
  EXPECT_EQ(MQTTCTRL_ERR_BAD_FIELDS, parse(envelope("v1|1"), &e));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_FIELDS, parse(envelope("v1|1|1788200000"), &e));
}

TEST(ParseEnvelope, RejectsCounterThatIsNotAPlainNumber) {
  MqttCtrlEnvelope e;
  EXPECT_EQ(MQTTCTRL_ERR_BAD_COUNTER, parse(envelope("v1||1788200000|trigger test"), &e));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_COUNTER, parse(envelope("v1|-1|1788200000|trigger test"), &e));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_COUNTER, parse(envelope("v1|+1|1788200000|trigger test"), &e));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_COUNTER, parse(envelope("v1| 1|1788200000|trigger test"), &e));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_COUNTER, parse(envelope("v1|0x10|1788200000|trigger test"), &e));
  // A counter that wrapped would silently reopen the replay window.
  EXPECT_EQ(MQTTCTRL_ERR_BAD_COUNTER, parse(envelope("v1|4294967296|1788200000|trigger test"), &e));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_COUNTER, parse(envelope("v1|99999999999|1788200000|trigger test"), &e));
}

TEST(ParseEnvelope, SplitsAtTheLastSeparatorNotTheFirst) {
  // A command containing '|' must not be able to manufacture a second split
  // point and steer which bytes the signature is taken to cover.
  MqttCtrlEnvelope e;
  EXPECT_EQ(MQTTCTRL_ERR_COMMAND_CHARS,
            parse("v1|1|1788200000|trigger test|" + sig() + "|" + sig(), &e));
}

TEST(ParseEnvelope, RejectsControlCharactersInCommand) {
  MqttCtrlEnvelope e;
  EXPECT_EQ(MQTTCTRL_ERR_COMMAND_CHARS, parse(envelope("v1|1|1788200000|get autoreply\n"), &e));
  EXPECT_EQ(MQTTCTRL_ERR_COMMAND_CHARS, parse(envelope("v1|1|1788200000|get\tautoreply"), &e));
  EXPECT_EQ(MQTTCTRL_ERR_COMMAND_CHARS, parse(envelope("v1|1|1788200000|"), &e));

  // An embedded NUL must not truncate the command into something else.
  std::string with_nul = "v1|1|1788200000|get autoreply";
  with_nul[20] = '\0';
  EXPECT_EQ(MQTTCTRL_ERR_COMMAND_CHARS, parse(with_nul + "|" + sig(), &e));
}

// ---- the bytes the signature covers ----------------------------------------

TEST(SignedMessage, BindsTheTopicSoOneSignatureFitsOneDestination) {
  Held h("v1|1|1788200000|trigger test");
  MqttCtrlEnvelope& e = h.env;

  uint8_t a[MQTTCTRL_MAX_SIGNED], b[MQTTCTRL_MAX_SIGNED];
  size_t alen = 0, blen = 0;
  ASSERT_TRUE(mqttCtrlBuildSignedMessage("meshcore/JKG/AA04/cmd", &e, a, sizeof(a), &alen));
  ASSERT_TRUE(mqttCtrlBuildSignedMessage("meshcore/JKG/BB05/cmd", &e, b, sizeof(b), &blen));

  // Same payload, different node: the verified bytes must differ, so a command
  // captured from one node cannot be replayed at another.
  ASSERT_EQ(alen, blen);
  EXPECT_NE(0, memcmp(a, b, alen));
}

TEST(SignedMessage, PerNodeAndBroadcastAreDistinct) {
  Held h("v1|1|1788200000|trigger test");
  MqttCtrlEnvelope& e = h.env;
  uint8_t one[MQTTCTRL_MAX_SIGNED], all[MQTTCTRL_MAX_SIGNED];
  size_t l1 = 0, l2 = 0;
  ASSERT_TRUE(mqttCtrlBuildSignedMessage("meshcore/JKG/AA04/cmd", &e, one, sizeof(one), &l1));
  ASSERT_TRUE(mqttCtrlBuildSignedMessage("meshcore/JKG/all/cmd", &e, all, sizeof(all), &l2));
  EXPECT_FALSE(l1 == l2 && memcmp(one, all, l1) == 0);
}

TEST(SignedMessage, LaysOutTopicNewlineSignedPart) {
  Held h("v1|1|1788200000|trigger test");
  MqttCtrlEnvelope& e = h.env;
  uint8_t out[MQTTCTRL_MAX_SIGNED];
  size_t len = 0;
  ASSERT_TRUE(mqttCtrlBuildSignedMessage("t/x", &e, out, sizeof(out), &len));
  EXPECT_EQ(std::string("t/x\nv1|1|1788200000|trigger test"), std::string((char*)out, len));
}

TEST(SignedMessage, RefusesToOverrunOrTakeAnEmptyTopic) {
  Held h("v1|1|1788200000|trigger test");
  MqttCtrlEnvelope& e = h.env;
  uint8_t small[8];
  size_t len = 0;
  EXPECT_FALSE(mqttCtrlBuildSignedMessage("meshcore/JKG/AA04/cmd", &e, small, sizeof(small), &len));
  uint8_t out[MQTTCTRL_MAX_SIGNED];
  EXPECT_FALSE(mqttCtrlBuildSignedMessage("", &e, out, sizeof(out), &len));
  EXPECT_FALSE(mqttCtrlBuildSignedMessage(std::string(MQTTCTRL_MAX_TOPIC + 1, 'x').c_str(),
                                          &e, out, sizeof(out), &len));
}

// ---- the replay window -----------------------------------------------------

TEST(Replay, RequiresStrictlyGreaterNeverEqual) {
  EXPECT_TRUE(mqttCtrlCounterAccepted(5, 6));
  EXPECT_FALSE(mqttCtrlCounterAccepted(5, 5));   // an equal counter is a replay
  EXPECT_FALSE(mqttCtrlCounterAccepted(5, 4));
  EXPECT_FALSE(mqttCtrlCounterAccepted(5, 0));
}

TEST(Replay, AFreshNodeAcceptsTheFirstCommandButNotZero) {
  EXPECT_TRUE(mqttCtrlCounterAccepted(0, 1));
  EXPECT_FALSE(mqttCtrlCounterAccepted(0, 0));
}

TEST(Replay, SurvivesARebootOnlyIfTheCallerPersisted) {
  // The window is only as good as the stored value. A counter kept in RAM comes
  // back as 0 after a power cycle and every past command becomes replayable --
  // this test documents the requirement the firmware side has to meet.
  const uint32_t persisted = 42;
  EXPECT_FALSE(mqttCtrlCounterAccepted(persisted, 42));
  const uint32_t ram_only_after_reboot = 0;
  EXPECT_TRUE(mqttCtrlCounterAccepted(ram_only_after_reboot, 42));
}

// ---- expiry ----------------------------------------------------------------

TEST(Expiry, FailsClosedWhenTheClockHasNeverSynced) {
  EXPECT_EQ(MQTTCTRL_ERR_NO_CLOCK, mqttCtrlCheckExpiry(0, 1788200000));
}

TEST(Expiry, AcceptsInsideTheWindowAndRejectsOutside) {
  const uint32_t now = 1788200000;
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlCheckExpiry(now, now));
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlCheckExpiry(now, now + 60));
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlCheckExpiry(now, now + MQTTCTRL_MAX_FUTURE_SECS));
  EXPECT_EQ(MQTTCTRL_ERR_EXPIRED, mqttCtrlCheckExpiry(now, now - 1));
  EXPECT_EQ(MQTTCTRL_ERR_EXPIRED, mqttCtrlCheckExpiry(now, 0));
}

TEST(Expiry, RefusesACommandMintedToLastForever) {
  // Bounding the future end stops a signer minting a command that waits
  // indefinitely for a worse moment to be delivered.
  const uint32_t now = 1788200000;
  EXPECT_EQ(MQTTCTRL_ERR_FUTURE, mqttCtrlCheckExpiry(now, now + MQTTCTRL_MAX_FUTURE_SECS + 1));
  EXPECT_EQ(MQTTCTRL_ERR_FUTURE, mqttCtrlCheckExpiry(now, 0xFFFFFFFF));
}

// ---- the allowlist ---------------------------------------------------------

static bool allowed(const std::string& cmd) {
  return mqttCtrlCommandAllowed(cmd.data(), cmd.size(), true);
}

// The same list in an image built without auto-reply (rc without ar).
static bool allowedWithoutAutoReply(const std::string& cmd) {
  return mqttCtrlCommandAllowed(cmd.data(), cmd.size(), false);
}

TEST(Allowlist, WithoutAutoReplyItsTriggersAndSettingsAreNotAllowed) {
  const char* theirs[] = {
    "trigger test", "trigger test A1B2C3D4", "trigger test a1b2c3d4 S", "trigger test F",
    "trigger private 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "set autoreply on", "set autoreply.region se-jkp", "set autoreply.legacy off",
    "get autoreply", "get autoreply.channel", "GET AUTOREPLY.hops",
  };
  for (const char* c : theirs) {
    EXPECT_TRUE(allowed(c)) << c;
    EXPECT_FALSE(allowedWithoutAutoReply(c)) << c;
  }
}

TEST(Allowlist, WithoutAutoReplyEverythingElseIsUnchanged) {
  // Only auto-reply's own commands change verdict; the boundary rule still decides what
  // is one of them, so `get autoreplyx` and `triggerX` were never admitted either way.
  const char* others[] = {
    "ver", "get name", "region", "neighbors", "get mqtt.cmd", "get stats", "get ota",
    "set ota.auto on", "mqtt.cmd ping", "region put se-jkp *", "set mqtt.iata JKG", "reboot",
    "set prv.key 00", "erase", "advert", "get autoreplyx", "triggerX", "set autoreplyX on",
  };
  for (const char* c : others) {
    EXPECT_EQ(allowed(c), allowedWithoutAutoReply(c)) << c;
  }
}

TEST(Allowlist, WithoutAutoReplyATriggerIsRefusedBeforeAnyBudget) {
  // mqttCtrlAuthorise runs before the limiters are asked, so a refused trigger costs
  // the transmit budget nothing.
  MqttCtrlEnvelope env = {};
  env.counter = 9;
  env.expiry = 1788200060;
  env.command = "trigger test";
  env.command_len = 12;
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthorise(&env, 8, 1788200000, true));
  EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthorise(&env, 8, 1788200000, false));
}

TEST(Allowlist, AcceptsAutoReplyParametersAndTheTrigger) {
  EXPECT_TRUE(allowed("trigger test"));
  EXPECT_TRUE(allowed("set autoreply on"));
  EXPECT_TRUE(allowed("set autoreply off"));
  EXPECT_TRUE(allowed("set autoreply.hops 8"));
  EXPECT_TRUE(allowed("set autoreply.direct.flood off"));
  EXPECT_TRUE(allowed("get autoreply"));
  EXPECT_TRUE(allowed("get autoreply.channel"));
  // The reply-mode work: a mode on the trigger, the standing mode, and the
  // private request. Each rides an existing family or its own.
  EXPECT_TRUE(allowed("trigger test a1b2c3d4 S"));
  EXPECT_TRUE(allowed("set autoreply.mode private"));
  EXPECT_TRUE(allowed("set autoreply.private on"));
  EXPECT_TRUE(allowed("trigger private "
                      "AA04792D7804529FABF230B32DC8F7FA494D1B3280F153B2215C305E4FD654DC a1b2c3d4"));
  EXPECT_FALSE(allowed("triggerprivate x"));   // the boundary rule, as for the others
}

TEST(Allowlist, AdmitsTheWholeRegionFamily) {
  // Operator decision 2026-10-07: complete control of the region map over the control
  // plane, so a scope rollout is a signed publish per node. One family entry; every
  // subcommand rides its boundary rule.
  EXPECT_TRUE(allowed("region"));
  EXPECT_TRUE(allowed("region put se-jkp *"));
  EXPECT_TRUE(allowed("region allowf se-jkp"));
  EXPECT_TRUE(allowed("region denyf *"));
  EXPECT_TRUE(allowed("region remove se06"));
  EXPECT_TRUE(allowed("region default se-jkp-mul"));
  EXPECT_TRUE(allowed("region home se-jkp"));
  EXPECT_TRUE(allowed("region save"));
  EXPECT_TRUE(allowed("region def se-jkp"));
  EXPECT_FALSE(allowed("regions"));            // the boundary rule: not the family
  EXPECT_FALSE(allowed("regionx put se"));
  // A `region def` line with the tree syntax carries '|', the envelope's field
  // separator, and is refused before the allowlist is consulted. `region put` is the
  // way to add a name remotely, which is also what leaves existing names alone.
  EXPECT_FALSE(allowed("region def se-jkp-mul|* se-jkp|* se|* eu"));
  EXPECT_FALSE(mqttCtrlIsTransmitCommand("region put se-jkp *", strlen("region put se-jkp *")));
}

TEST(Allowlist, AdmitsTheNodeNameAsAnExactRead) {
  // Operator decision 2026-10-07. The name is already in every advert the node floods,
  // so reading it back over the control plane reveals nothing the air does not.
  EXPECT_TRUE(allowed("get name"));
  EXPECT_TRUE(allowed("set name x"));          // a name is a label, not identity (2026-10-08)
  EXPECT_TRUE(allowed("get name.x"));          // a read; the CLI answers or does not
}

TEST(Allowlist, AdmitsVerAsAnExactRead) {
  // Operator decision 2026-10-07: a tool asks a fleet which firmware each node runs.
  EXPECT_TRUE(allowed("ver"));
  EXPECT_FALSE(allowed("ver x"));            // exact: nothing after it
  EXPECT_FALSE(allowed("version"));          // not a verb the list admits
  EXPECT_FALSE(mqttCtrlIsTransmitCommand("ver", 3));
}

TEST(Allowlist, AdmitsTheSlotSettingsThroughTheAutoReplyFamily) {
  // Sprint F04 added three settings, and the point of checking rather than assuming
  // is that nobody touched this list: the "set autoreply" family entry admits them
  // through its boundary rule. If that ever stops being true, slot assignment stops
  // working over the control plane and the only clue would be a node that never
  // answers where it was told to.
  EXPECT_TRUE(allowed("set autoreply.slot 7"));
  EXPECT_TRUE(allowed("set autoreply.window 10 120"));
  EXPECT_TRUE(allowed("set autoreply.slots 16"));
  EXPECT_TRUE(allowed("get autoreply.slot"));
  EXPECT_TRUE(allowed("get autoreply.window"));
  EXPECT_TRUE(allowed("get autoreply.slots"));
}

TEST(Allowlist, TheRetiredDelayCommandIsStillAdmittedAndTheNodeRefusesIt) {
  // "set autoreply.delay 60" still rides the family, because the family is a prefix
  // rule and the command no longer exists to be listed separately. That is the right
  // outcome: the node answers with an error, which is how a stale provisioning script
  // finds out. The allowlist is not the place to hide a removed command.
  EXPECT_TRUE(allowed("set autoreply.delay 60"));
}

TEST(Allowlist, BlocksTheCommandsThatWouldOwnTheNode) {
  // The whole point of the list. Each of these is reachable from the CLI and
  // must never be reachable from a public broker.
  EXPECT_FALSE(allowed("set prv.key 00112233"));
  EXPECT_FALSE(allowed("erase"));
  EXPECT_FALSE(allowed("set mqtt.owner AABB"));
  EXPECT_FALSE(allowed("set freq 869.618"));
  EXPECT_FALSE(allowed("set password hunter2"));
  EXPECT_FALSE(allowed("start webconfig"));
  EXPECT_FALSE(allowed("set repeat off"));
  EXPECT_TRUE(allowed("reboot"));              // admitted 2026-10-08: settings need it to apply
}

TEST(Allowlist, TheControlPlaneCannotBeSwitchedOffRemotely) {
  // A signed `set mqtt.cmd.slot 0`, or a slot with no broker behind it, would
  // leave the node listening nowhere, and only someone at its serial port could
  // undo that. The commands that decide where the node listens stay local.
  EXPECT_FALSE(allowed("set mqtt.cmd off"));
  EXPECT_FALSE(allowed("set mqtt.cmd.slot 0"));
  EXPECT_FALSE(allowed("set mqtt.cmd.slot 2"));
}

TEST(Allowlist, TheCommandKeyIsNeitherWritableNorReadable) {
  // Rotating the key that authorises signed commands must not itself be a signed
  // command. MqttControl also refuses both to any non-zero sender_timestamp, which
  // mqttCtrlSenderStamp guarantees every MQTT command carries.
  EXPECT_FALSE(allowed("set mqtt.cmd.pubkey "
                       "AA04792D7804529FABF230B32DC8F7FA494D1B3280F153B2215C305E4FD654DC"));
  EXPECT_FALSE(allowed("set mqtt.cmd.pubkey"));
  EXPECT_FALSE(allowed("get mqtt.cmd.pubkey"));
}

// ---- the slot the control plane rides --------------------------------------

static bool slot(const char* text, int slot_count, uint8_t* out) {
  return mqttCtrlParseSlot(text, slot_count, out);
}

TEST(ControlSlot, ZeroMeansNoneAndEverySlotTheBoardHasIsAccepted) {
  uint8_t out = 99;
  EXPECT_TRUE(slot("0", 3, &out));
  EXPECT_EQ(out, 0);
  EXPECT_TRUE(slot("1", 3, &out));
  EXPECT_EQ(out, 1);
  EXPECT_TRUE(slot("3", 3, &out));
  EXPECT_EQ(out, 3);
  EXPECT_TRUE(slot("6", 6, &out));
  EXPECT_EQ(out, 6);
}

TEST(ControlSlot, ASlotPastTheBoardsArrayIsRefused) {
  // A non-PSRAM board has three slots. Accepting 4 would store a slot that can
  // never connect, and the node would listen nowhere without saying so.
  uint8_t out = 99;
  EXPECT_FALSE(slot("4", 3, &out));
  EXPECT_FALSE(slot("7", 6, &out));
  EXPECT_FALSE(slot("256", 6, &out));    // would wrap to 0 in a uint8_t
  EXPECT_FALSE(slot("4294967297", 6, &out));
  EXPECT_EQ(out, 99);
}

TEST(ControlSlot, OnlyAPlainNumberIsASlot) {
  uint8_t out = 99;
  EXPECT_FALSE(slot("", 6, &out));
  EXPECT_FALSE(slot("-1", 6, &out));
  EXPECT_FALSE(slot("+2", 6, &out));
  EXPECT_FALSE(slot(" 2", 6, &out));
  EXPECT_FALSE(slot("2 ", 6, &out));
  EXPECT_FALSE(slot("two", 6, &out));
  EXPECT_FALSE(slot("mqtt2", 6, &out));
  EXPECT_EQ(out, 99);
}

TEST(ControlSlot, DegenerateInputIsRefused) {
  uint8_t out = 99;
  EXPECT_FALSE(slot(NULL, 6, &out));
  EXPECT_FALSE(slot("1", 6, NULL));
  EXPECT_FALSE(slot("1", -1, &out));
  EXPECT_TRUE(slot("0", 0, &out));       // a build with no slots can still say none
  EXPECT_FALSE(slot("1", 0, &out));
}

TEST(Allowlist, IsNotFooledByPrefixTricks) {
  // Boundary matching on the verbs: `trigger tests` is not `trigger test`, and a
  // verb run into another word is no verb. A `set` of a key the CLI does not
  // know travels and is answered "unknown", which is the blacklist's bargain.
  EXPECT_FALSE(allowed("trigger tests"));
  EXPECT_FALSE(allowed("trigger testing"));
  EXPECT_FALSE(allowed("regionx put se"));
  EXPECT_FALSE(allowed("setautoreply on"));
  // And the secrets are denied by bare prefix, so no suffix reaches them.
  EXPECT_FALSE(allowed("get prv.keyx"));
  EXPECT_FALSE(allowed("set passwordx y"));
  EXPECT_FALSE(allowed("get mqtt.cmd.pubkeyx"));
}

TEST(Allowlist, RequiresTheCommandToStartWithTheAllowedText) {
  // A denied command must not be smuggled in by putting an allowed one in front
  // of it or behind it.
  EXPECT_FALSE(allowed(" set autoreply on"));
  EXPECT_FALSE(allowed("erase; set autoreply on"));
  EXPECT_FALSE(allowed("set prv.key 00 set autoreply on"));
}

TEST(Allowlist, MatchesCaseInsensitivelyLikeTheCli) {
  EXPECT_TRUE(allowed("SET AUTOREPLY ON"));
  EXPECT_TRUE(allowed("Trigger Test"));
  // Case folding must not open a hole either.
  EXPECT_FALSE(allowed("SET PRV.KEY 00"));
}

TEST(Allowlist, RejectsEmptyOverlongAndNonPrintable) {
  EXPECT_FALSE(allowed(""));
  EXPECT_FALSE(allowed("set autoreply " + std::string(MQTTCTRL_MAX_COMMAND, '1')));
  EXPECT_FALSE(allowed("set autoreply on\n"));
  EXPECT_FALSE(allowed(std::string("set autoreply o\0n", 17)));
}

// ---- the whole decision, in order ------------------------------------------

TEST(Authorise, AcceptsAFreshAllowedCommand) {
  Held h("v1|9|1788200060|trigger test");
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthorise(&h.env, 8, 1788200000, true));
}

TEST(Authorise, StopsAtTheFirstRefusalInOrder) {
  // Replay is checked before expiry, and expiry before the allowlist: a replayed
  // command reports replay even when it is also expired and also forbidden, so a
  // caller publishing the reason cannot be used to probe the later checks.
  Held replayed("v1|5|1|erase");
  EXPECT_EQ(MQTTCTRL_ERR_REPLAY, mqttCtrlAuthorise(&replayed.env, 5, 1788200000, true));

  Held expired("v1|9|1|erase");
  EXPECT_EQ(MQTTCTRL_ERR_EXPIRED, mqttCtrlAuthorise(&expired.env, 8, 1788200000, true));

  Held forbidden("v1|9|1788200060|erase");
  EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthorise(&forbidden.env, 8, 1788200000, true));
}

TEST(Authorise, RefusesEverythingWithoutAClock) {
  Held h("v1|9|1788200060|trigger test");
  EXPECT_EQ(MQTTCTRL_ERR_NO_CLOCK, mqttCtrlAuthorise(&h.env, 8, 0, true));
}

TEST(Authorise, HandlesANullEnvelope) {
  EXPECT_EQ(MQTTCTRL_ERR_EMPTY, mqttCtrlAuthorise(NULL, 0, 1788200000, true));
}

// ---- rate limiting ---------------------------------------------------------

TEST(RateLimit, TriggersAreClassifiedApartFromParameterChanges) {
  EXPECT_TRUE(mqttCtrlIsTransmitCommand("trigger test", 12));
  EXPECT_FALSE(mqttCtrlIsTransmitCommand("set autoreply.hops 8", 20));
  EXPECT_FALSE(mqttCtrlIsTransmitCommand("get autoreply", 13));
  // A parameter change costs a flash write; a trigger costs the whole mesh
  // airtime, so the two must never share one budget.
  EXPECT_FALSE(mqttCtrlIsTransmitCommand("triggerX", 8));
}

TEST(RateLimit, ATransmitSpendsOnlyTheTransmitBudget) {
  // Changed 2026-09-19 (F04 T-08, operator decision of 2026-09-13). The two budgets
  // are disjoint: two triggers an hour must not also consume a fifth of the ten
  // commands a caller has for reading settings.
  EXPECT_TRUE(mqttCtrlSpendsTransmitBudget(true));
  EXPECT_FALSE(mqttCtrlSpendsCommandBudget(true));
  EXPECT_EQ(mqttCtrlRateResult(true, true, true), MQTTCTRL_OK);
  EXPECT_EQ(mqttCtrlRateResult(true, true, false), MQTTCTRL_ERR_RATE_LIMITED);  // its own budget
}

TEST(RateLimit, AParameterChangeSpendsOnlyTheCommandBudget) {
  EXPECT_TRUE(mqttCtrlSpendsCommandBudget(false));
  EXPECT_FALSE(mqttCtrlSpendsTransmitBudget(false));
}

TEST(RateLimit, TheBudgetsAreWhatTheOperatorAskedFor) {
  // Named here so a change to either constant has to come past a test that says what
  // they were chosen to be: 2 transmits an hour is ~10.2 s of mesh airtime including
  // the reply storms each one provokes, 0.28% of the hour.
  EXPECT_EQ(MQTTCTRL_CMD_MAX, 10);
  EXPECT_EQ(MQTTCTRL_TRIGGER_MAX, 2);
  EXPECT_EQ(MQTTCTRL_CMD_WINDOW_SECS, 3600);
  EXPECT_EQ(MQTTCTRL_TRIGGER_WINDOW, 3600);
}

TEST(RateLimit, ParameterChangesIgnoreTheTriggerBudget) {
  EXPECT_EQ(mqttCtrlRateResult(false, true, false), MQTTCTRL_OK);
  EXPECT_EQ(mqttCtrlRateResult(false, false, true), MQTTCTRL_ERR_RATE_LIMITED);
}

TEST(RateLimit, TheThirdTransmitInAnHourIsRefusedWhileReadsStillWork) {
  // The shape the operator asked for, exercised on a real limiter rather than on the
  // decision function alone.
  MqttCtrlBudget transmits(MQTTCTRL_TRIGGER_MAX, MQTTCTRL_TRIGGER_WINDOW);
  MqttCtrlBudget commands(MQTTCTRL_CMD_MAX, MQTTCTRL_CMD_WINDOW_SECS);
  const uint32_t now = 1788200000;
  EXPECT_TRUE(transmits.allow(now));
  EXPECT_TRUE(transmits.allow(now + 60));
  EXPECT_FALSE(transmits.allow(now + 120));          // the third in the hour
  for (int i = 0; i < MQTTCTRL_CMD_MAX; i++) {
    EXPECT_TRUE(commands.allow(now + 130 + i)) << "read " << i << " should still work";
  }
  EXPECT_FALSE(commands.allow(now + 200));
  // and the windows roll independently: the transmit window opened at `now` and has
  // expired by +3700, while the command window opened at +130 and has not. Taking the
  // same instant for both is the point -- at +3730 they would both have rolled and the
  // test would pass without showing anything.
  EXPECT_TRUE(transmits.allow(now + 3700));
  EXPECT_FALSE(commands.allow(now + 3700));
}

// ---- the result must not be written from the loop task --------------------------

TEST(Result, IsPublishedThroughTheOutboxNotStraightToTheSocket) {
  // MQTTBridge::publishToSlot takes `async = (qos > 0)`. At 0 the loop task writes to
  // a socket the bridge task is also writing to, and the broker drops the node for a
  // malformed packet on every command. This pins the side of that line we are on.
  EXPECT_GT(MQTTCTRL_RESULT_QOS, 0);
  EXPECT_LE(MQTTCTRL_RESULT_QOS, 1);   // QoS 2 buys nothing: a repeated result is harmless
}

// ---- a window boundary must not double the budget ------------------------------

TEST(RateLimit, UpstreamsFixedWindowLetsThreeFloodsThroughInTwoSeconds) {
  // Why the control plane stopped using RateLimiter. Not a test of our code: a
  // record of the defect, so nobody swaps it back in for tidiness.
  RateLimiter fixed(MQTTCTRL_TRIGGER_MAX, MQTTCTRL_TRIGGER_WINDOW);
  const uint32_t t0 = 1788200000;
  int allowed = 0;
  allowed += fixed.allow(t0);
  allowed += fixed.allow(t0 + MQTTCTRL_TRIGGER_WINDOW - 1);
  allowed += fixed.allow(t0 + MQTTCTRL_TRIGGER_WINDOW);
  allowed += fixed.allow(t0 + MQTTCTRL_TRIGGER_WINDOW + 1);
  EXPECT_EQ(4, allowed);   // three of them inside two seconds
}

TEST(RateLimit, NoSpanOfOneWindowEverHoldsMoreThanTheBudget) {
  MqttCtrlBudget transmits(MQTTCTRL_TRIGGER_MAX, MQTTCTRL_TRIGGER_WINDOW);
  const uint32_t t0 = 1788200000;
  EXPECT_TRUE(transmits.allow(t0));
  EXPECT_TRUE(transmits.allow(t0 + MQTTCTRL_TRIGGER_WINDOW - 1));
  EXPECT_FALSE(transmits.allow(t0 + MQTTCTRL_TRIGGER_WINDOW - 1));
  // The first has aged out exactly now, so one -- and only one -- comes back.
  EXPECT_TRUE(transmits.allow(t0 + MQTTCTRL_TRIGGER_WINDOW));
  EXPECT_FALSE(transmits.allow(t0 + MQTTCTRL_TRIGGER_WINDOW + 1));
}

TEST(RateLimit, TheBoundHoldsHoweverTheAttemptsAreSpaced) {
  // Hammer it once a second for three windows and slide a window over what got
  // through. A property, because the defect was a boundary nobody thought to pick.
  for (uint32_t max = 1; max <= MQTTCTRL_CMD_MAX; max += 3) {
    MqttCtrlBudget budget((uint8_t)max, 600);
    std::vector<uint32_t> allowed;
    for (uint32_t t = 1000; t < 1000 + 3 * 600; t++) {
      if (budget.allow(t)) allowed.push_back(t);
    }
    EXPECT_EQ(3 * max, allowed.size()) << "max " << max << ": the budget must also refill";
    for (size_t i = 0; i + max < allowed.size(); i++) {
      EXPECT_GE(allowed[i + max] - allowed[i], 600u) << "max " << max << " at " << allowed[i];
    }
  }
}

TEST(RateLimit, ARefusedCommandSpendsNothing) {
  MqttCtrlBudget budget(1, 600);
  EXPECT_TRUE(budget.allow(1000));
  for (uint32_t t = 1001; t < 1600; t++) EXPECT_FALSE(budget.allow(t));
  EXPECT_TRUE(budget.allow(1600));   // refusals at 1599 must not have pushed this out
}

TEST(RateLimit, AClockSteppingBackwardsMintsNoBudget) {
  MqttCtrlBudget budget(2, 600);
  EXPECT_TRUE(budget.allow(5000));
  EXPECT_TRUE(budget.allow(5001));
  // The RTC is corrected an hour back. The two already spent still count, from now.
  EXPECT_FALSE(budget.allow(1400));
  EXPECT_FALSE(budget.allow(1999));
  EXPECT_TRUE(budget.allow(2000));   // and the lockout is one window, not for ever
}

TEST(RateLimit, ABudgetOfZeroAllowsNothingAndABudgetTooLargeIsCapped) {
  MqttCtrlBudget none(0, 600);
  EXPECT_FALSE(none.allow(1000));
  MqttCtrlBudget huge(200, 600);
  int allowed = 0;
  for (int i = 0; i < 250; i++) allowed += huge.allow(1000);
  EXPECT_EQ(SLIDING_BUDGET_SLOTS, allowed);
}

// ---- the two overloaded codes, now split -------------------------------------
//
// Both refusals used to borrow a code that already meant something else, so a
// caller watching a public broker could not tell a forgery from a broken
// publisher, nor "ask again later" from "never".

TEST(ErrorCodes, ExhaustedBudgetIsNotTheSameAsUnauthorised) {
  // NOT_ALLOWED means the command is not on the allowlist -- a permanent no.
  // RATE_LIMITED means the budget is spent -- a temporary one. A caller that
  // conflates them either retries forever or gives up on a command that works.
  EXPECT_NE(MQTTCTRL_ERR_RATE_LIMITED, MQTTCTRL_ERR_NOT_ALLOWED);
  EXPECT_EQ(mqttCtrlRateResult(true, false, false), MQTTCTRL_ERR_RATE_LIMITED);

  MqttCtrlEnvelope env;
  ASSERT_EQ(MQTTCTRL_OK, parse(envelope("v1|7|1788200000|set prv.key deadbeef"), &env));
  EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthorise(&env, 6, 1788199000, true));
}

TEST(ErrorCodes, AForgedSignatureIsNotTheSameAsAMalformedOne) {
  // BAD_SIG_HEX is still produced at parse time for a field that is not 128 hex
  // characters; SIG_INVALID is reserved for one that parsed and did not verify.
  MqttCtrlEnvelope env;
  EXPECT_EQ(MQTTCTRL_ERR_BAD_SIG_LEN, parse("v1|7|1788200000|get txdelay|zzzz", &env));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_SIG_HEX,
            parse("v1|7|1788200000|get txdelay|" + sig('z'), &env));
  EXPECT_NE(MQTTCTRL_ERR_SIG_INVALID, MQTTCTRL_ERR_BAD_SIG_HEX);
}

TEST(ErrorCodes, TheNewCodesAreAppendedAndNothingShifted) {
  EXPECT_EQ((int)MQTTCTRL_ERR_BAD_SIG_HEX, 5);
  EXPECT_EQ((int)MQTTCTRL_ERR_NOT_ALLOWED, 14);
  EXPECT_EQ((int)MQTTCTRL_ERR_NO_OWNER_KEY, 15);
  EXPECT_EQ((int)MQTTCTRL_ERR_SIG_INVALID, 16);
  EXPECT_EQ((int)MQTTCTRL_ERR_RATE_LIMITED, 17);
}

TEST(ErrorCodes, TheCodesDocumentedInMqttControlMdKeepTheirNumbers) {
  // docs/mqtt-control.md publishes these numbers for a requester to parse, and
  // a stored result keeps its meaning only while they hold. Counting them by
  // hand got the table wrong once already.
  EXPECT_EQ((int)MQTTCTRL_OK, 0);
  EXPECT_EQ((int)MQTTCTRL_ERR_REPLAY, 9);
  EXPECT_EQ((int)MQTTCTRL_ERR_EXPIRED, 10);
  EXPECT_EQ((int)MQTTCTRL_ERR_FUTURE, 11);
  EXPECT_EQ((int)MQTTCTRL_ERR_NO_CLOCK, 12);
}

TEST(RateLimit, TriggerCapIsTighterThanTheGeneralCap) {
  // The constants themselves are the defence: a leaked key bounded only by the
  // general cap could still put 20 floods an hour on a shared network.
  EXPECT_LT(MQTTCTRL_TRIGGER_MAX, MQTTCTRL_CMD_MAX);
}

// ---- the cross-check: does the Python signer produce what this accepts? ------

// Generated by panopticon/control.py with a fixed seed and a fixed clock. Two
// independent implementations of one envelope is exactly where a project like
// this goes wrong quietly: a canonicalisation difference of one byte produces a
// signature that never verifies, and the failure looks like a broken radio.
static const char* GOLDEN_PUB =
    "C9571EEB4AA9DE1159858BC6A3D4A626C4F4845E8EEBD5F554B2EC0F50C68860";
static const char* GOLDEN_TOPIC = "meshcore/JKG/AA04792D/cmd";
static const char* GOLDEN_PAYLOAD =
    "v1|42|1788000600|set autoreply.hops 5|"
    "D6E615B85660933377ACE10C946A42DFABFFC5CF9736CA6D6FEF25B863170241"
    "A4FFA470C77D30CFD1D47F37D1E3DB380287AE108E243C452D83993B619DB408";

static void hexToBytes(const char* hex, uint8_t* out, size_t n) {
  for (size_t i = 0; i < n; i++) out[i] = (uint8_t)mqttCtrlHexByte(hex[i * 2], hex[i * 2 + 1]);
}

TEST(GoldenEnvelope, PythonSignerVerifiesAgainstTheRealEd25519) {
  MqttCtrlEnvelope env;
  ASSERT_EQ(MQTTCTRL_OK,
            mqttCtrlParseEnvelope(GOLDEN_PAYLOAD, strlen(GOLDEN_PAYLOAD), &env));
  EXPECT_EQ(42u, env.counter);
  EXPECT_EQ(1788000600u, env.expiry);
  EXPECT_EQ(std::string("set autoreply.hops 5"), std::string(env.command, env.command_len));

  uint8_t signed_bytes[MQTTCTRL_MAX_SIGNED];
  size_t signed_len = 0;
  ASSERT_TRUE(mqttCtrlBuildSignedMessage(GOLDEN_TOPIC, &env, signed_bytes,
                                         sizeof(signed_bytes), &signed_len));

  uint8_t pub[32];
  hexToBytes(GOLDEN_PUB, pub, sizeof(pub));
  EXPECT_EQ(1, ed25519_verify(env.signature, signed_bytes, signed_len, pub));
}

TEST(GoldenEnvelope, TheSameSignatureIsRefusedAtAnotherNode) {
  MqttCtrlEnvelope env;
  ASSERT_EQ(MQTTCTRL_OK,
            mqttCtrlParseEnvelope(GOLDEN_PAYLOAD, strlen(GOLDEN_PAYLOAD), &env));
  uint8_t signed_bytes[MQTTCTRL_MAX_SIGNED];
  size_t signed_len = 0;
  ASSERT_TRUE(mqttCtrlBuildSignedMessage("meshcore/JKG/BB05DEAD/cmd", &env,
                                         signed_bytes, sizeof(signed_bytes), &signed_len));
  uint8_t pub[32];
  hexToBytes(GOLDEN_PUB, pub, sizeof(pub));
  EXPECT_EQ(0, ed25519_verify(env.signature, signed_bytes, signed_len, pub));
}

TEST(GoldenEnvelope, ATamperedCommandIsRefused) {
  std::string tampered(GOLDEN_PAYLOAD);
  tampered.replace(tampered.find("hops 5"), 6, "hops 1");
  MqttCtrlEnvelope env;
  ASSERT_EQ(MQTTCTRL_OK, mqttCtrlParseEnvelope(tampered.data(), tampered.size(), &env));
  uint8_t signed_bytes[MQTTCTRL_MAX_SIGNED];
  size_t signed_len = 0;
  ASSERT_TRUE(mqttCtrlBuildSignedMessage(GOLDEN_TOPIC, &env, signed_bytes,
                                         sizeof(signed_bytes), &signed_len));
  uint8_t pub[32];
  hexToBytes(GOLDEN_PUB, pub, sizeof(pub));
  EXPECT_EQ(0, ed25519_verify(env.signature, signed_bytes, signed_len, pub));
}

// ---- get stats: the node's counters as one line ---------------------------------

TEST(NodeStats, OneLineOfShortPairsInTheStatusBlocksOrder) {
  char buf[160];
  mqttCtrlFormatNodeStats(buf, sizeof(buf), 4261, 1496188, -114, 5518, 25369, 9065, 44345, 10, 13369, 0);
  EXPECT_STREQ("> batt=4261mV up=1496188s noise=-114 tx=5518s rx=25369s sent=9065 recv=44345 err=10 rxerr=13369 q=0", buf);
}

TEST(NodeStats, TheLargestValuesFitTheReplyBuffer) {
  // Every counter is 32-bit; the noise floor is a small negative. The CLI's reply
  // buffer and the control plane's reply clamp are both 160 bytes.
  char buf[160];
  const long big = 4294967295L;
  mqttCtrlFormatNodeStats(buf, sizeof(buf), big, big, -999 + 1, big, big, big, big, big, big, big);
  EXPECT_LT(strlen(buf), 160u);
  EXPECT_LE(strlen(buf), 152u);                       // the measured worst case: 8 bytes of headroom
  EXPECT_NE(nullptr, strstr(buf, " q=4294967295"));     // the last pair survived
}

TEST(NodeStats, AnUnknownValueIsLeftOutAndNoneAtAllSaysSo) {
  char buf[160];
  mqttCtrlFormatNodeStats(buf, sizeof(buf), 4000, -1, -999, -1, -1, -1, -1, -1, -1, -1);
  EXPECT_STREQ("> batt=4000mV", buf);
  mqttCtrlFormatNodeStats(buf, sizeof(buf), -1, -1, -999, -1, -1, -1, -1, -1, -1, -1);
  EXPECT_STREQ("> (no stats sources)", buf);
}

TEST(NodeStats, ATinyBufferIsClampedNotOverrun) {
  char mem[12 + 8];
  memset(mem, 0xAA, sizeof(mem));
  mqttCtrlFormatNodeStats(mem, 12, 4261, 1496188, -114, 5518, 25369, 9065, 44345, 10, 13369, 0);
  EXPECT_EQ(11u, strlen(mem));
  for (size_t i = 12; i < sizeof(mem); i++) EXPECT_EQ(0xAA, (unsigned char)mem[i]) << i;
}

// ---- a trigger sent over the command plane: where the two features meet ------
// Kept with the plane: it needs both features' headers, and only builds with the plane
// have the plane's.

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


// ---- the owner key, and the staging slot it used to wedge --------------------
//
// Without a key there is nothing to verify against, so a staged command cannot
// run. It must still be resolved: the slot holds exactly one command and clears
// only when that command is disposed of. The firmware used to return early here,
// latching the slot for the life of the boot and dropping every command after it
// -- including the ones sent once a key had finally been provisioned.

TEST(OwnerReady, AValidKeyIsReady) {
  const char* key = "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789abcdef";
  EXPECT_EQ(strlen(key), 64u);
  EXPECT_EQ(mqttCtrlOwnerReady(key), MQTTCTRL_OK);
}

TEST(OwnerReady, AnUnsetKeyIsRefusedRatherThanIgnored) {
  EXPECT_EQ(mqttCtrlOwnerReady(""), MQTTCTRL_ERR_NO_OWNER_KEY);
  EXPECT_EQ(mqttCtrlOwnerReady(NULL), MQTTCTRL_ERR_NO_OWNER_KEY);
}

TEST(OwnerReady, AMalformedKeyIsTheSameCaseAsNoKey) {
  // fromHex would refuse these a moment later; refusing here keeps one rule in
  // one place, and both paths must resolve the slot.
  EXPECT_EQ(mqttCtrlOwnerReady("abc"), MQTTCTRL_ERR_NO_OWNER_KEY);
  EXPECT_EQ(mqttCtrlOwnerReady("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"),
            MQTTCTRL_ERR_NO_OWNER_KEY);   // 63
  EXPECT_EQ(mqttCtrlOwnerReady("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"),
            MQTTCTRL_ERR_NO_OWNER_KEY);   // 65
  EXPECT_EQ(mqttCtrlOwnerReady("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"),
            MQTTCTRL_ERR_NO_OWNER_KEY);   // non-hex
}

TEST(OwnerReady, TheRefusalHasItsOwnCodeAndDoesNotCollide) {
  // A caller publishing the refusal must be able to say why. Reusing an existing
  // code would make "no key" indistinguishable from a malformed payload.
  EXPECT_NE(MQTTCTRL_ERR_NO_OWNER_KEY, MQTTCTRL_OK);
  EXPECT_NE(MQTTCTRL_ERR_NO_OWNER_KEY, MQTTCTRL_ERR_EMPTY);
  EXPECT_NE(MQTTCTRL_ERR_NO_OWNER_KEY, MQTTCTRL_ERR_NOT_ALLOWED);
  EXPECT_NE(MQTTCTRL_ERR_NO_OWNER_KEY, MQTTCTRL_ERR_BAD_SIG_HEX);
}

TEST(OwnerReady, ExistingCodesKeepTheirNumbers) {
  // panopticon/control.py and stored results read these as numbers, so the new
  // code is appended and nothing before it may shift.
  EXPECT_EQ((int)MQTTCTRL_OK, 0);
  EXPECT_EQ((int)MQTTCTRL_ERR_EMPTY, 1);
  EXPECT_EQ((int)MQTTCTRL_ERR_NOT_ALLOWED, 14);
  EXPECT_EQ((int)MQTTCTRL_ERR_NO_OWNER_KEY, 15);
}

// ---- the published result -----------------------------------------------------
//
// The topic names the node; the counter names the question. Without it a `get`
// answer is "> 0.5" -- true of whatever was asked, which is not enough to act on
// when one requester is polling several nodes.

TEST(FormatResult, CarriesCounterCodeCommandAndReply) {
  char out[MQTTCTRL_MAX_RESULT];
  size_t n = mqttCtrlFormatResult(out, sizeof(out), 42, 0, "get txdelay", "> 0.5");
  EXPECT_EQ(std::string("r1|42|0|get txdelay|> 0.5"), std::string(out));
  EXPECT_EQ(n, strlen(out));
}

TEST(FormatResult, ARefusalStillNamesItsRequest) {
  // No command ran, so the reply is empty -- but the counter and the code are
  // what make a refusal distinguishable from a node that never answered.
  char out[MQTTCTRL_MAX_RESULT];
  mqttCtrlFormatResult(out, sizeof(out), 9, (int)MQTTCTRL_ERR_RATE_LIMITED,
                       "trigger test", "");
  EXPECT_EQ(std::string("r1|9|17|trigger test|"), std::string(out));
}

TEST(FormatResult, TruncatesRatherThanDiscarding) {
  // The existing payload builders drop a payload over budget rather than
  // shortening it, which would mean the longest replies never arrive. Here the
  // reply is last and every earlier field is bounded, so a clamp leaves a line
  // that still parses.
  std::string huge(400, 'x');
  char out[64];
  size_t n = mqttCtrlFormatResult(out, sizeof(out), 7, 0, "get radio", huge.c_str());
  EXPECT_EQ(n, sizeof(out) - 1);
  EXPECT_EQ(strlen(out), sizeof(out) - 1);
  EXPECT_EQ(std::string("r1|7|0|get radio|"), std::string(out).substr(0, 17));
}

TEST(FormatResult, TheFieldsBeforeTheReplyCannotBeAmbiguous) {
  // mqttCtrlCommandCharsOk refuses a command containing the separator, so only
  // the trailing reply can hold one and a parser takes the rest of the line.
  EXPECT_FALSE(mqttCtrlCommandCharsOk("get a|b", 7));

  char out[MQTTCTRL_MAX_RESULT];
  mqttCtrlFormatResult(out, sizeof(out), 1, 0, "get radio", "a|b|c");
  std::string s(out);
  EXPECT_EQ(std::string("r1|1|0|get radio|a|b|c"), s);

  // Split on the first four separators; whatever follows is the reply, however
  // many separators it happens to contain.
  size_t pos = 0;
  for (int i = 0; i < 4; i++) pos = s.find('|', pos) + 1;
  EXPECT_EQ(std::string("a|b|c"), s.substr(pos));
  EXPECT_EQ(std::string("get radio"), s.substr(7, pos - 8));
}

TEST(FormatResult, RefusesABufferItCannotUse) {
  char out[8];
  EXPECT_EQ(0u, mqttCtrlFormatResult(NULL, sizeof(out), 1, 0, "x", "y"));
  EXPECT_EQ(0u, mqttCtrlFormatResult(out, 0, 1, 0, "x", "y"));
}

TEST(FormatResult, ANullCommandOrReplyIsAnEmptyField) {
  char out[MQTTCTRL_MAX_RESULT];
  mqttCtrlFormatResult(out, sizeof(out), 3, 0, NULL, NULL);
  EXPECT_EQ(std::string("r1|3|0||"), std::string(out));
}

TEST(FormatResult, TheBufferFitsTheLongestPossibleLine) {
  std::string cmd(MQTTCTRL_MAX_COMMAND, 'c');
  std::string rep(MQTTCTRL_MAX_REPLY - 1, 'r');
  char out[MQTTCTRL_MAX_RESULT];
  size_t n = mqttCtrlFormatResult(out, sizeof(out), 4294967295u, 17,
                                  cmd.c_str(), rep.c_str());
  EXPECT_LT(n, sizeof(out) - 1) << "MQTTCTRL_MAX_RESULT must not clamp a legal line";
}

// ---- guard rails on the trigger -----------------------------------------------

TEST(BroadcastGuard, RecognisesTheBroadcastTopic) {
  EXPECT_TRUE(mqttCtrlTopicIsBroadcast("meshcore/JKG/all/cmd"));
  EXPECT_FALSE(mqttCtrlTopicIsBroadcast("meshcore/JKG/a1b2c3d4/cmd"));
  EXPECT_FALSE(mqttCtrlTopicIsBroadcast("meshcore/JKG/all/res"));
  EXPECT_FALSE(mqttCtrlTopicIsBroadcast("all/cmd"));   // no region segment
  EXPECT_FALSE(mqttCtrlTopicIsBroadcast(NULL));
}

TEST(BroadcastGuard, ARegionCommandMayBeAddressedToEveryNode) {
  // A scope rollout is one signed publish to meshcore/{IATA}/all/cmd: every node that
  // verifies it adds the name. Setting a value costs no airtime, so the broadcast guard
  // has nothing to say about it; only a trigger is refused that way.
  const char* cmd = "region put se-jkp *";
  bool transmit = mqttCtrlIsTransmitCommand(cmd, strlen(cmd));
  EXPECT_FALSE(transmit);
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlTransmitTopicResult(transmit, "meshcore/JKG/all/cmd"));
}

TEST(BroadcastGuard, ATransmitCommandMayNotBeAddressedToEveryNode) {
  // The rate limits are per node -- four triggers an hour each. That bounds one
  // node and says nothing about one publish reaching every node in a region, each
  // then transmitting inside the same few seconds and each within budget. The
  // workspace rule is that no design may scale transmissions with the node count.
  EXPECT_EQ(MQTTCTRL_ERR_BROADCAST_TRANSMIT,
            mqttCtrlTransmitTopicResult(true, "meshcore/JKG/all/cmd"));
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlTransmitTopicResult(true, "meshcore/JKG/a1b2c3d4/cmd"));
}

TEST(BroadcastGuard, ABroadcastParameterChangeIsStillAllowed) {
  // Setting a value costs no airtime, so fleet-wide configuration stays possible.
  // Only transmitting is refused.
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlTransmitTopicResult(false, "meshcore/JKG/all/cmd"));
  EXPECT_FALSE(mqttCtrlIsTransmitCommand("set autoreply.delay 8", 21));
  EXPECT_TRUE(mqttCtrlIsTransmitCommand("trigger test", 12));
}

TEST(BroadcastGuard, TheRefusalHasItsOwnAppendedCode) {
  EXPECT_EQ((int)MQTTCTRL_ERR_BROADCAST_TRANSMIT, 18);
  EXPECT_NE(MQTTCTRL_ERR_BROADCAST_TRANSMIT, MQTTCTRL_ERR_NOT_ALLOWED);
  EXPECT_NE(MQTTCTRL_ERR_BROADCAST_TRANSMIT, MQTTCTRL_ERR_RATE_LIMITED);
}

TEST(BroadcastGuard, ARefusalIsPublishableRatherThanSilent) {
  // It is refused after the signature verified, so T-05 publishes it: a requester
  // learns the node exists and declined, which is not what silence would say.
  char out[MQTTCTRL_MAX_RESULT];
  size_t n = mqttCtrlFormatResult(out, sizeof(out), 5,
                                  (int)MQTTCTRL_ERR_BROADCAST_TRANSMIT, "trigger test", "");
  EXPECT_GT(n, 0u);
  EXPECT_EQ(std::string("r1|5|18|trigger test|"), std::string(out));
}

// ---- the read-only additions to the allowlist ---------------------------------

TEST(Allowlist, AdmitsTheReadOnlyParameterGets) {
  EXPECT_TRUE(allowed("get txdelay"));
  EXPECT_TRUE(allowed("get direct.txdelay"));
  EXPECT_TRUE(allowed("get rxdelay"));
  EXPECT_TRUE(allowed("get af"));
  EXPECT_TRUE(allowed("get cad"));
  EXPECT_TRUE(allowed("get int.thresh"));
  EXPECT_TRUE(allowed("get radio"));
}

TEST(Allowlist, TheTuningWritesTravelAndTheRadioOnesDoNot) {
  // The blacklist admits the timing and flood tuning (what the control plane is
  // for), and keeps the radio parameters out: a wrong value there takes the node
  // off the mesh with no remote way back.
  EXPECT_TRUE(allowed("set txdelay 0.5"));
  EXPECT_TRUE(allowed("set direct.txdelay 0.3"));
  EXPECT_TRUE(allowed("set rxdelay 0"));
  EXPECT_TRUE(allowed("set af 9.0"));
  EXPECT_TRUE(allowed("set cad on"));
  EXPECT_TRUE(allowed("set int.thresh 1"));
  EXPECT_TRUE(allowed("set flood.max 8"));
  EXPECT_FALSE(allowed("set radio 869.618,62.5,8,8"));
  EXPECT_FALSE(allowed("set radio.rxgain 1"));
  EXPECT_FALSE(allowed("set freq 869.618"));
  EXPECT_FALSE(allowed("set tx 20"));
  EXPECT_FALSE(allowed("set extra.sf 1"));
  EXPECT_FALSE(allowed("set dutycycle 10"));
  EXPECT_FALSE(allowed("tempradio 869.618 62.5 8 8"));
}

TEST(Allowlist, ADeniedFamilyCannotBeReachedByRunningIntoAnotherWord) {
  // The deny list uses the boundary rule, so `set radio` denies `set radio.rxgain`
  // but not a setting that merely starts with the letters; and the other way, a
  // denied name cannot be dodged by a suffix: the boundary is what the CLI's own
  // unbounded memcmp would then match, so both sides are pinned.
  EXPECT_FALSE(allowed("set radio.fem.rxgain 1"));
  EXPECT_FALSE(allowed("set mqtt.cmd.slot 2"));
  EXPECT_TRUE(allowed("set radio.watchdog on") == false);   // under the radio family, denied
  EXPECT_TRUE(allowed("set mqtt.interval 5"));              // not mqtt.cmd
  EXPECT_TRUE(allowed("set latency 1") == true);            // `set lat` with a boundary only
  EXPECT_FALSE(allowed("set lat 57.78"));
  EXPECT_FALSE(allowed("set lat.x 1"));
}

TEST(Allowlist, NothingAResultMayNeverCarryCanBeRead) {
  // A result is published on a broker anyone can subscribe to, so whatever a read
  // returns is public. docs/mqtt-control.md lists what must therefore never be
  // readable; this is that list, and a widening that admits one of them fails here.
  const char* never[] = {
    "get prv.key", "get password", "get guest.password",
    "get wifi.pwd", "get wifi.ssid", "get bridge.secret", "get alert.psk",
    "get snmp.community", "get mqtt.email",
    "get mqtt.owner", "get mqtt.cmd.pubkey", "get owner.info", "get tls.x",
    "get mqtt1.password", "get mqtt1.username", "get mqtt1.token",
    "get mqtt2.password", "get mqtt6.token", "get mqtt3.username x",
    "get lat", "get lon",
  };
  for (const char* command : never) EXPECT_FALSE(allowed(command)) << command;
  // The public key is what names the node to the whole mesh, so it is readable;
  // a broker's host name is settable over this plane now, so reading it back is
  // part of the same job. `get mqtt.cmd` is state and counter, not the key.
  EXPECT_TRUE(allowed("get public.key"));
  EXPECT_TRUE(allowed("get mqtt1.server"));
  EXPECT_TRUE(allowed("get mqtt1.preset"));
  EXPECT_TRUE(allowed("get mqtt.cmd"));
}

TEST(Allowlist, TheWideningAddedNoPrivilegedCommand) {
  // Re-pinned after the widening: these must still be refused, and the reads
  // must not have opened a path to them.
  EXPECT_FALSE(allowed("set prv.key 00112233"));
  EXPECT_FALSE(allowed("erase"));
  EXPECT_FALSE(allowed("set mqtt.owner AABB"));
  EXPECT_FALSE(allowed("get prv.key"));
  EXPECT_FALSE(allowed("get mqtt.owner"));
  EXPECT_FALSE(allowed("get"));
  EXPECT_FALSE(allowed("get "));
  EXPECT_FALSE(allowed("set"));
  EXPECT_FALSE(allowed("set "));
}

// ---- the deny list of 2026-10-08, group by group ------------------------------

TEST(Denylist, TheStandardMqttSettingsTravelButTheControlSlotAndKeyDoNot) {
  // A broker may go away; another must be reachable without a visit.
  EXPECT_TRUE(allowed("set mqtt1.preset meshat.se"));
  EXPECT_TRUE(allowed("set mqtt2.server mqtt.example.org"));
  EXPECT_TRUE(allowed("set mqtt2.username mcoar"));
  EXPECT_TRUE(allowed("set mqtt2.password x"));       // a write, to a broker the signer chose
  EXPECT_TRUE(allowed("set mqtt.presets 2"));
  EXPECT_TRUE(allowed("set mqtt.iata GOT"));
  EXPECT_TRUE(allowed("set mqtt.interval 10"));
  EXPECT_TRUE(allowed("set mqtt.status on"));
  EXPECT_FALSE(allowed("set mqtt.cmd off"));
  EXPECT_FALSE(allowed("set mqtt.cmd.slot 0"));
  EXPECT_FALSE(allowed("set mqtt.cmd.pubkey 00"));
}

TEST(Denylist, RebootIsAdmittedAndTheRestOfTheDestructiveGroupIsNot) {
  EXPECT_TRUE(allowed("reboot"));
  EXPECT_TRUE(allowed("clkreboot"));
  EXPECT_FALSE(allowed("reboot now"));                 // exact: nothing after it
  EXPECT_FALSE(allowed("erase"));
  EXPECT_FALSE(allowed("start webconfig"));
  EXPECT_FALSE(allowed("start ota"));
  EXPECT_FALSE(allowed("start ota ap"));
  EXPECT_FALSE(allowed("poweroff"));
  EXPECT_FALSE(allowed("shutdown"));
  EXPECT_FALSE(allowed("set bootloader.ver 2"));
  EXPECT_FALSE(allowed("password hunter2"));
  EXPECT_FALSE(allowed("set password hunter2"));
}

TEST(Denylist, OtaCheckIsAReadAndOtaUpdateWaitsForASignedImage) {
  EXPECT_TRUE(allowed("ota check"));
  EXPECT_FALSE(allowed("ota check x"));
  EXPECT_FALSE(allowed("ota update"));
  EXPECT_FALSE(allowed("ota"));
}

TEST(Denylist, PositionAndRoleStayLocal) {
  EXPECT_FALSE(allowed("set lat 57.78"));
  EXPECT_FALSE(allowed("set lon 14.27"));
  EXPECT_FALSE(allowed("set role repeater"));
  EXPECT_FALSE(allowed("set repeat off"));
  EXPECT_FALSE(allowed("set repeat on"));
  EXPECT_TRUE(allowed("get repeat"));
}

TEST(Denylist, NothingThatTransmitsExceptTheTrigger) {
  EXPECT_FALSE(allowed("advert"));
  EXPECT_FALSE(allowed("advert.zerohop"));
  EXPECT_FALSE(allowed("alert test"));
  EXPECT_FALSE(allowed("set advert.interval 1"));
  EXPECT_FALSE(allowed("set flood.advert.interval 1"));
  EXPECT_TRUE(allowed("set alert.hashtag x"));         // the reporter's settings, not its secret
  EXPECT_FALSE(allowed("set alert.psk 00"));
  EXPECT_TRUE(allowed("trigger test"));
}

TEST(Denylist, TheClockCannotBeSteppedByAnyAmount) {
  // Expiry is judged against the node's clock. `time <epoch>` moves it forward
  // arbitrarily; `clock sync` moves it to the node's own now, which is nothing.
  EXPECT_FALSE(allowed("time 1900000000"));
  EXPECT_TRUE(allowed("clock"));
  EXPECT_TRUE(allowed("clock sync"));
}

TEST(Denylist, TheSerialOnlyDumpsAreListedSoTheTwoGatesAgree) {
  EXPECT_FALSE(allowed("log"));
  EXPECT_FALSE(allowed("stats-core"));
  EXPECT_FALSE(allowed("stats-packets"));
  EXPECT_FALSE(allowed("stats-radio"));
  EXPECT_FALSE(allowed("stats-radio-diag"));
  EXPECT_FALSE(allowed("tls.bundletest"));
}

TEST(Denylist, TheAdmittedBareCommandsAndNothingUnlisted) {
  EXPECT_TRUE(allowed("neighbors"));
  EXPECT_TRUE(allowed("neighbor.remove 4AC61A7F"));
  EXPECT_TRUE(allowed("board"));
  EXPECT_TRUE(allowed("memory"));
  EXPECT_TRUE(allowed("clear stats"));
  EXPECT_FALSE(allowed("clear"));
  EXPECT_TRUE(allowed("gps on"));
  EXPECT_TRUE(allowed("powersaving off"));
  EXPECT_TRUE(allowed("sensor get gps"));
  EXPECT_FALSE(allowed("neighborsx"));
  EXPECT_FALSE(allowed("floodscan"));                  // a verb nobody listed
  EXPECT_FALSE(allowed("setx autoreply on"));
}

// ---- the boundary rule itself -------------------------------------------------
//
// Tested directly rather than only through the allowlist, because
// docs/mqtt-control.md now names it as the reason the allowlist is the tighter of
// the two gates: CommonCLI's own handleGetCmd matches with an unbounded memcmp.

TEST(PrefixBoundary, AcceptsAnExactMatch) {
  EXPECT_TRUE(mqttCtrlPrefixWithBoundary("get af", 6, "get af"));
}

TEST(PrefixBoundary, AcceptsASpaceOrDotAfterThePrefix) {
  EXPECT_TRUE(mqttCtrlPrefixWithBoundary("get af 1", 8, "get af"));
  EXPECT_TRUE(mqttCtrlPrefixWithBoundary("set autoreply.hops 8", 20, "set autoreply"));
  EXPECT_TRUE(mqttCtrlPrefixWithBoundary("set autoreply on", 16, "set autoreply"));
}

TEST(PrefixBoundary, RefusesAPrefixThatRunsIntoAnotherWord) {
  // The whole point: `get afxyz` must not ride in on `get af`.
  EXPECT_FALSE(mqttCtrlPrefixWithBoundary("get afxyz", 9, "get af"));
  EXPECT_FALSE(mqttCtrlPrefixWithBoundary("set autoreplyx", 14, "set autoreply"));
  EXPECT_FALSE(mqttCtrlPrefixWithBoundary("triggerx", 8, "trigger"));
}

TEST(PrefixBoundary, RefusesSomethingShorterThanThePrefix) {
  EXPECT_FALSE(mqttCtrlPrefixWithBoundary("get a", 5, "get af"));
  EXPECT_FALSE(mqttCtrlPrefixWithBoundary("", 0, "get af"));
}

TEST(PrefixBoundary, IsCaseInsensitive) {
  EXPECT_TRUE(mqttCtrlPrefixWithBoundary("GET AF", 6, "get af"));
  EXPECT_TRUE(mqttCtrlPrefixWithBoundary("Trigger Test", 12, "trigger"));
}

TEST(PrefixBoundary, UsesTheGivenLengthNotTheTerminator) {
  // The command is a byte range inside the envelope, not a C string, so a prefix
  // must not be judged by what happens to follow the range in memory.
  EXPECT_TRUE(mqttCtrlPrefixWithBoundary("get afxyz", 6, "get af"));
}

TEST(PrefixBoundary, ShorterThanThePrefixNeverReadsPastTheCommand) {
  // The command points into the received payload and is NOT terminated: the byte
  // after it is the next field. Without the length guard, comparing the full
  // prefix walks past the command's own end into whatever followed it on the
  // wire -- and if those bytes happen to complete the prefix, a five-byte
  // command matches a six-byte allowlist entry.
  //
  // Written as an explicit range because a C string literal cannot show this:
  // the terminator hides the bug that the guard exists to prevent.
  const char payload[] = "get af get autoreply";
  EXPECT_FALSE(mqttCtrlPrefixWithBoundary(payload, 5, "get af")) << "matched past the command";
  EXPECT_TRUE(mqttCtrlPrefixWithBoundary(payload, 6, "get af"));
}

// ---- the exact command T-12 sends ---------------------------------------------
//
// The golden fixture above covers `set autoreply.hops 5`, which existed before this
// sprint. T-12 reads a value back with `get txdelay` -- a command that only became
// sendable when T-09 widened the allowlist -- so it gets its own fixture, produced
// by panopticon/control.py and verified here by the firmware's own Ed25519.
//
// Proving this offline removes the whole class of on-hardware surprises where a
// signature never verifies and the node simply stays silent, which is
// indistinguishable from a node that was never listening.

static const char* READ_PUB =
    "6B734A8EFF246FE734B38D4046C148EEE5F04FE87B3A0A423955A77956DE066B";
static const char* READ_TOPIC = "meshcore/JKG/AA04792D/cmd";
static const char* READ_PAYLOAD =
    "v1|43|1788000600|get txdelay|"
    "2C22F81168EE96B8598B70B29B951DF365876413AC6C1B6CE1C14CB3E7D3E2BD"
    "563F7F0905EE12EE5E41273B3CA515E50504CFD96D57D16A12DBD07D0BCDFD04";

TEST(GoldenRead, TheCommandT12SendsVerifiesAndIsAllowed) {
  MqttCtrlEnvelope env;
  ASSERT_EQ(MQTTCTRL_OK,
            mqttCtrlParseEnvelope(READ_PAYLOAD, strlen(READ_PAYLOAD), &env));
  EXPECT_EQ(43u, env.counter);
  EXPECT_EQ(std::string("get txdelay"), std::string(env.command, env.command_len));

  uint8_t signed_bytes[MQTTCTRL_MAX_SIGNED];
  size_t signed_len = 0;
  ASSERT_TRUE(mqttCtrlBuildSignedMessage(READ_TOPIC, &env, signed_bytes,
                                         sizeof(signed_bytes), &signed_len));
  uint8_t pub[32];
  hexToBytes(READ_PUB, pub, sizeof(pub));
  EXPECT_EQ(1, ed25519_verify(env.signature, signed_bytes, signed_len, pub));

  // Verifying is not enough -- it must also survive authorisation, which is where
  // a command absent from the allowlist would be refused.
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthorise(&env, 42, 1788000100, true));

  // And it must not be treated as a transmit, or it would spend a trigger slot
  // and be refused on the broadcast topic.
  EXPECT_FALSE(mqttCtrlIsTransmitCommand(env.command, env.command_len));
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlTransmitTopicResult(false, READ_TOPIC));
}

TEST(GoldenRead, TheSameReadIsRefusedAtAnotherNode) {
  // The topic is inside the signature, so a read captured off the public broker
  // cannot be replayed at a different node.
  MqttCtrlEnvelope env;
  ASSERT_EQ(MQTTCTRL_OK,
            mqttCtrlParseEnvelope(READ_PAYLOAD, strlen(READ_PAYLOAD), &env));

  uint8_t signed_bytes[MQTTCTRL_MAX_SIGNED];
  size_t signed_len = 0;
  ASSERT_TRUE(mqttCtrlBuildSignedMessage("meshcore/JKG/BB05C3D1/cmd", &env,
                                         signed_bytes, sizeof(signed_bytes), &signed_len));
  uint8_t pub[32];
  hexToBytes(READ_PUB, pub, sizeof(pub));
  EXPECT_EQ(0, ed25519_verify(env.signature, signed_bytes, signed_len, pub));
}

// ---- the private key is not reachable over MQTT -------------------------------
//
// Operator requirement, 2026-09-01: the node's identity key must be neither
// readable nor writable over MQTT. Two independent guards enforce it, and each is
// pinned separately here -- the point of having two is that either alone suffices,
// so a test that only proves their conjunction would not notice one of them dying.

TEST(PrivateKey, GuardOne_AnMqttCommandNeverCarriesTheLocalPrivilegeMarker) {
  // sender_timestamp 0 is not a clock reading, it is "the caller is physically
  // present". It gates get/set prv.key, get/set mqtt.cmd.pubkey and erase.
  // If an MQTT command could execute with 0, every one of those gates would open.
  EXPECT_NE(0u, mqttCtrlSenderStamp(0));

  // The case that matters: a node whose clock has never synced reports 0, so
  // passing `now` through unchanged would hand a remote caller full local
  // privilege exactly when NTP is down -- an outage becoming an escalation.
  EXPECT_EQ(1u, mqttCtrlSenderStamp(0));

  // Every real reading is passed through untouched.
  EXPECT_EQ(1u, mqttCtrlSenderStamp(1));
  EXPECT_EQ(1788000600u, mqttCtrlSenderStamp(1788000600));
  EXPECT_EQ(0xFFFFFFFFu, mqttCtrlSenderStamp(0xFFFFFFFFu));
}

TEST(PrivateKey, GuardTwo_NeitherReadingNorWritingItIsOnTheAllowlist) {
  EXPECT_FALSE(allowed("get prv.key"));
  EXPECT_FALSE(allowed("set prv.key 00112233"));

  // And not by any spelling the boundary rule might let through.
  EXPECT_FALSE(allowed("GET PRV.KEY"));
  EXPECT_FALSE(allowed("SET PRV.KEY 00112233"));
  EXPECT_FALSE(allowed("get prv"));
  EXPECT_FALSE(allowed("set prv.key"));
  EXPECT_FALSE(allowed("get prv.keyx"));

  // A key command behind an admitted one travels as a `get` whose tail the CLI
  // ignores (there is no command separator in the CLI), and the first word is
  // what both gates judge: `get autoreply` answers, and nothing reads the key.
  EXPECT_TRUE(allowed("get autoreply; get prv.key"));
  EXPECT_NE(0, memcmp("get autoreply; get prv.key", "get prv.key", 11));
  EXPECT_FALSE(allowed("get prv.key x"));
  EXPECT_FALSE(allowed("get prv.key.x"));
}

TEST(PrivateKey, ASignedRequestForItIsRefusedAtAuthorisation) {
  // End of the chain: even a perfectly signed, fresh, unexpired envelope asking
  // for the key is refused -- and refused as NOT_ALLOWED, which is permanent,
  // rather than as anything a requester should retry.
  MqttCtrlEnvelope env;
  ASSERT_EQ(MQTTCTRL_OK, parse(envelope("v1|9|1788200000|get prv.key"), &env));
  EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthorise(&env, 8, 1788199000, true));

  ASSERT_EQ(MQTTCTRL_OK, parse(envelope("v1|9|1788200000|set prv.key deadbeef"), &env));
  EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthorise(&env, 8, 1788199000, true));
}

// ---- exact entries admit the command they name, and nothing else --------------
//
// Operator review, 2026-09-01: the allowlist is read to decide what a node exposes,
// so an entry admitting more than it says defeats the reading. `get radio` was
// admitting two children and a junk tail through the boundary rule.

TEST(ExactEntries, AReadAdmitsOnlyTheBareCommand) {
  EXPECT_TRUE(allowed("get radio"));
  EXPECT_TRUE(allowed("get af"));
  EXPECT_TRUE(allowed("get int.thresh"));       // the dot is in the name, not a boundary
  EXPECT_TRUE(allowed("get direct.txdelay"));
}

TEST(ExactEntries, ChildrenOfAReadAreAdmittedUnderTheBlacklist) {
  // Under the allowlist these were refused so that the list stayed reviewable.
  // Under the blacklist (2026-10-08) every read not naming a secret travels: a
  // `get radio.rxgain` reveals a gain setting, and a `get af.thing` added to the
  // CLI later answers or does not. What a result may never carry is pinned in
  // NothingAResultMayNeverCarryCanBeRead, which is now the list to review.
  EXPECT_TRUE(allowed("get radio.rxgain"));
  EXPECT_TRUE(allowed("get radio.fem.rxgain"));
  EXPECT_TRUE(allowed("get af.anything"));
  EXPECT_TRUE(allowed("get radio foo"));          // the CLI ignores the tail and answers
}

TEST(ExactEntries, TheFamiliesStillMatchAsPrefixes) {
  // The boundary rule is load-bearing on these three; making them exact would
  // break the sprint's own features.
  EXPECT_TRUE(allowed("set autoreply on"));
  EXPECT_TRUE(allowed("set autoreply.hops 8"));
  EXPECT_TRUE(allowed("set autoreply.delay 12"));
  EXPECT_TRUE(allowed("set autoreply.direct.flood off"));
  EXPECT_TRUE(allowed("set autoreply.region JKG"));
  EXPECT_TRUE(allowed("get autoreply"));
  EXPECT_TRUE(allowed("get autoreply.channel"));
  EXPECT_TRUE(allowed("trigger test"));
  EXPECT_TRUE(allowed("trigger test a1b2c3d4"));
}

TEST(ExactEntries, ExactMatchingIsStillCaseInsensitive) {
  EXPECT_TRUE(allowed("GET RADIO"));
  EXPECT_TRUE(allowed("Get Af"));
}

TEST(ExactEntries, ExactMatchingUsesTheGivenLengthNotATerminator) {
  // Same trap as the boundary rule: the command is a byte range in the payload,
  // not a C string, so a short command must not match by reading past its end.
  const char payload[] = "get radio.rxgain";
  EXPECT_FALSE(mqttCtrlExactCommand(payload, 5, "get radio"));   // "get r"
  EXPECT_TRUE(mqttCtrlExactCommand(payload, 9, "get radio"));    // "get radio"
  EXPECT_FALSE(mqttCtrlExactCommand(payload, 16, "get radio"));  // the whole thing
}

// ---- reads that describe how a node floods -----------------------------------
//
// Added after a bench node was set `repeat off` and there was no way to confirm
// it remotely. Whether a node forwards is not a detail: the topology model infers
// it from traffic, and that inference once counted every phone and companion as a
// relay.

TEST(FloodReads, TheFloodBehaviourGetsAreAdmitted) {
  EXPECT_TRUE(allowed("get repeat"));
  EXPECT_TRUE(allowed("get flood.max"));
  EXPECT_TRUE(allowed("get flood.max.unscoped"));
}

TEST(FloodReads, TheFloodWritesTravelAndRepeatStaysLocal) {
  // The flood limits are tuning, which is what the control plane is for.
  // `set repeat off` silences a node's forwarding: doing that remotely to someone
  // else's repeater takes it out of the mesh, and it is how a leaked key would
  // silence a region, so it stays denied (operator, 2026-10-08).
  EXPECT_TRUE(allowed("set flood.max 3"));
  EXPECT_TRUE(allowed("set flood.max.unscoped 2"));
  EXPECT_FALSE(allowed("set repeat off"));
  EXPECT_FALSE(allowed("set repeat on"));
  EXPECT_TRUE(allowed("get repeat"));
}

TEST(Denylist, TheNodesCountersAreReadableAndTheDumpsAreNot) {
  // `get stats` (2026-10-08) is the status block's values in one line; it travels
  // as any read does. The serial-only dumps it replaces do not.
  EXPECT_TRUE(allowed("get stats"));
  EXPECT_FALSE(allowed("stats-core"));
  EXPECT_FALSE(allowed("stats-radio"));
}

// ---- the topics name the node by its whole key (2026-10-08) -----------------------

static const char* KEY64 = "4AC61A7FF4800A079A7311CA606A4C7037FE6943D40E53932230142829A4F786";

TEST(Topics, TheLeafIsTheWholeKeyAndTheBroadcastIsTheWordAll) {
  char out[MQTTCTRL_MAX_TOPIC + 1];
  ASSERT_TRUE(mqttCtrlBuildTopic("JKG", KEY64, "cmd", out, sizeof(out)));
  EXPECT_STREQ("meshcore/JKG/4AC61A7FF4800A079A7311CA606A4C7037FE6943D40E53932230142829A4F786/cmd", out);
  ASSERT_TRUE(mqttCtrlBuildTopic("JKG", KEY64, "res", out, sizeof(out)));
  EXPECT_EQ(81u, strlen(out));                      // 9 + 3 + 1 + 64 + 1 + 3
  ASSERT_TRUE(mqttCtrlBuildTopic("JKG", "all", "cmd", out, sizeof(out)));
  EXPECT_STREQ("meshcore/JKG/all/cmd", out);
}

TEST(Topics, TheWholeKeyFormFitsTheSignedMessageAndIsRefusedWhenItCannot) {
  char out[MQTTCTRL_MAX_TOPIC + 1];
  ASSERT_TRUE(mqttCtrlBuildTopic("JKG", KEY64, "cmd", out, sizeof(out)));
  EXPECT_LE(strlen(out), (size_t)MQTTCTRL_MAX_TOPIC);
  char tiny[40];
  EXPECT_FALSE(mqttCtrlBuildTopic("JKG", KEY64, "cmd", tiny, sizeof(tiny)));
  EXPECT_FALSE(mqttCtrlBuildTopic("", KEY64, "cmd", out, sizeof(out)));
  EXPECT_FALSE(mqttCtrlBuildTopic("JKG", "", "cmd", out, sizeof(out)));
}

// ---- `set mqtt.cmd on` picks a slot (2026-10-08) -------------------------------------

// The last argument is "this board runs two slots at once", which is "no PSRAM".
static const bool PSRAM = false, NO_PSRAM = true;

TEST(AutoSlot, TheFirstFreeSlotFromThreeUp) {
  const char* presets[6] = { "analyzer-us", "analyzer-eu", "none", "none", "none", "none" };
  EXPECT_EQ(2, mqttCtrlPickSlot(presets, 6, PSRAM));    // slot 3
  const char* busy3[6] = { "analyzer-us", "analyzer-eu", "meshat.se", "", "none", "none" };
  EXPECT_EQ(3, mqttCtrlPickSlot(busy3, 6, PSRAM));      // an empty name is free too
  const char* upper[6] = { "none", "none", "NONE", "none", "none", "none" };
  EXPECT_EQ(2, mqttCtrlPickSlot(upper, 6, PSRAM));      // case does not matter
}

TEST(AutoSlot, WithPsramSlotsOneAndTwoAreNeverTaken) {
  const char* free2[6] = { "none", "none", "custom", "custom", "custom", "custom" };
  EXPECT_EQ(-1, mqttCtrlPickSlot(free2, 6, PSRAM));
  const char* eu[6] = { "analyzer-us", "analyzer-eu", "custom", "custom", "custom", "custom" };
  EXPECT_EQ(-1, mqttCtrlPickSlot(eu, 6, PSRAM));
  const char* eu_free3[6] = { "analyzer-us", "analyzer-eu", "none", "none", "none", "none" };
  EXPECT_EQ(2, mqttCtrlPickSlot(eu_free3, 6, PSRAM));
}

TEST(AutoSlot, WithoutPsramSlotTwoIsTakenFirstWhenEmpty) {
  const char* presets[6] = { "analyzer-us", "none", "none", "none", "none", "none" };
  EXPECT_EQ(1, mqttCtrlPickSlot(presets, 6, NO_PSRAM));
  const char* blank[6] = { "analyzer-us", "", "none", "none", "none", "none" };
  EXPECT_EQ(1, mqttCtrlPickSlot(blank, 6, NO_PSRAM));
}

TEST(AutoSlot, WithoutPsramTheObserversDefaultInSlotTwoGivesWay) {
  // Two slots run at once there: the observer's and the plane's.
  const char* presets[6] = { "analyzer-us", "analyzer-eu", "none", "none", "none", "none" };
  EXPECT_EQ(1, mqttCtrlPickSlot(presets, 6, NO_PSRAM));
  const char* upper[6] = { "analyzer-us", "ANALYZER-EU", "none", "none", "none", "none" };
  EXPECT_EQ(1, mqttCtrlPickSlot(upper, 6, NO_PSRAM));
}

TEST(AutoSlot, WithoutPsramACollectorTheOwnerChoseInSlotTwoIsLeftAlone) {
  const char* presets[6] = { "analyzer-us", "meshat.se", "none", "none", "none", "none" };
  EXPECT_EQ(2, mqttCtrlPickSlot(presets, 6, NO_PSRAM));
  const char* custom[6] = { "analyzer-us", "custom", "mcoar", "none", "none", "none" };
  EXPECT_EQ(3, mqttCtrlPickSlot(custom, 6, NO_PSRAM));
}

TEST(AutoSlot, SlotOneIsNeverTaken) {
  const char* presets[6] = { "none", "meshat.se", "custom", "custom", "custom", "custom" };
  EXPECT_EQ(-1, mqttCtrlPickSlot(presets, 6, NO_PSRAM));
  EXPECT_EQ(-1, mqttCtrlPickSlot(presets, 6, PSRAM));
}

TEST(AutoSlot, NoFreeSlotIsSaidNotGuessed) {
  const char* presets[6] = { "analyzer-us", "analyzer-eu", "meshat.se", "custom", "meshrank", "waev" };
  EXPECT_EQ(-1, mqttCtrlPickSlot(presets, 6, PSRAM));
  const char* three[3] = { "analyzer-us", "analyzer-eu", "custom" };
  EXPECT_EQ(-1, mqttCtrlPickSlot(three, 3, PSRAM));
  EXPECT_EQ(-1, mqttCtrlPickSlot(NULL, 6, NO_PSRAM));
}

TEST(PlaneSlot, NoCommandFormChangesTheSlotThePlaneRides) {
  // Slot 2, as on a board without PSRAM: analyzer.eu on or off, the slot's preset, its
  // server, anything under mqtt2.
  EXPECT_TRUE(mqttCtrlTouchesSlot("set mqtt.analyzer.eu on", 2));
  EXPECT_TRUE(mqttCtrlTouchesSlot("set mqtt.analyzer.eu off", 2));
  EXPECT_TRUE(mqttCtrlTouchesSlot("set mqtt.analyzer.eu", 2));
  EXPECT_TRUE(mqttCtrlTouchesSlot("set mqtt2.preset none", 2));
  EXPECT_TRUE(mqttCtrlTouchesSlot("set mqtt2.server mqtt.example", 2));
  EXPECT_TRUE(mqttCtrlTouchesSlot("set mqtt2.audience x", 2));
  // Slot 1 is analyzer.us's.
  EXPECT_TRUE(mqttCtrlTouchesSlot("set mqtt.analyzer.us off", 1));
  EXPECT_TRUE(mqttCtrlTouchesSlot("set mqtt1.preset none", 1));
  // Slot 3-6: only its own mqttN.
  EXPECT_TRUE(mqttCtrlTouchesSlot("set mqtt3.preset none", 3));
  EXPECT_TRUE(mqttCtrlTouchesSlot("set mqtt6.packets on", 6));
}

TEST(PlaneSlot, SpacingDoesNotGetPastIt) {
  EXPECT_TRUE(mqttCtrlTouchesSlot("set mqtt.analyzer.eu  off", 2));
  EXPECT_TRUE(mqttCtrlTouchesSlot("  set  mqtt.analyzer.eu off", 2));
  EXPECT_TRUE(mqttCtrlTouchesSlot("set   mqtt2.preset none", 2));
}

TEST(PlaneSlot, EverythingElseIsLeftAlone) {
  EXPECT_FALSE(mqttCtrlTouchesSlot("set mqtt.analyzer.eu off", 3));     // the plane is elsewhere
  EXPECT_FALSE(mqttCtrlTouchesSlot("set mqtt.analyzer.eu off", 0));     // no plane
  EXPECT_FALSE(mqttCtrlTouchesSlot("set mqtt.analyzer.us off", 2));
  EXPECT_FALSE(mqttCtrlTouchesSlot("set mqtt1.preset meshat.se", 2));
  EXPECT_FALSE(mqttCtrlTouchesSlot("get mqtt2.preset", 2));             // a read
  EXPECT_FALSE(mqttCtrlTouchesSlot("set mqtt.analyzer.euro on", 2));
  EXPECT_FALSE(mqttCtrlTouchesSlot("set mqtt.iata JKG", 2));
  EXPECT_FALSE(mqttCtrlTouchesSlot("set mqtt.cmd.slot 0", 2));          // the way out
  EXPECT_FALSE(mqttCtrlTouchesSlot(nullptr, 2));
}

// ---- `mqtt.cmd ping` (TODO 15, ar-12) -------------------------------------------------

static const uint8_t* bytes(const char* s) { return (const uint8_t *) s; }

TEST(Ping, ArmsWithAnEightHexNonce) {
  MqttCtrlPing p = {};
  char out[32];
  ASSERT_TRUE(mqttCtrlArmPing(&p, "a1b2c3d4", out, sizeof(out), 0));
  EXPECT_STREQ("ping|a1b2c3d4", out);
  EXPECT_TRUE(p.in_flight);
  MqttCtrlPing q = {};
  EXPECT_FALSE(mqttCtrlArmPing(&q, "a1b2c3", out, sizeof(out), 0));
  EXPECT_FALSE(mqttCtrlArmPing(&q, "a1b2c3zz", out, sizeof(out), 0));
  EXPECT_FALSE(mqttCtrlArmPing(&q, "a1b2c3d4", out, 8, 0));
  EXPECT_FALSE(q.in_flight);
}

TEST(Ping, OnlyThePongWithTheNonceInFlightIsTaken) {
  MqttCtrlPing p = {};
  char out[32];
  mqttCtrlArmPing(&p, "a1b2c3d4", out, sizeof(out), 0);
  EXPECT_FALSE(mqttCtrlTakePong(&p, bytes("pong|deadbeef"), 13, 50));    // foreign
  EXPECT_FALSE(mqttCtrlTakePong(&p, bytes("pong|a1b2c3d4x"), 14, 50));   // trailing byte
  EXPECT_FALSE(mqttCtrlTakePong(&p, bytes("pong|a1b2c3"), 11, 50));      // short
  EXPECT_FALSE(mqttCtrlTakePong(&p, bytes("ping|a1b2c3d4"), 13, 50));    // our own ping
  EXPECT_TRUE(p.in_flight);
  EXPECT_TRUE(mqttCtrlTakePong(&p, bytes("pong|A1B2C3D4"), 13, 230));    // either case
  EXPECT_FALSE(p.in_flight);
  EXPECT_EQ(230u, p.answered_ms);
}

TEST(Ping, ASecondPongIsIgnoredTheNonceIsConsumed) {
  // Abuse rule 1: a bridged broker's echo, or a replay, finds nothing in flight.
  MqttCtrlPing p = {};
  char out[32];
  mqttCtrlArmPing(&p, "a1b2c3d4", out, sizeof(out), 0);
  ASSERT_TRUE(mqttCtrlTakePong(&p, bytes("pong|a1b2c3d4"), 13, 100));
  EXPECT_FALSE(mqttCtrlTakePong(&p, bytes("pong|a1b2c3d4"), 13, 900));
  EXPECT_EQ(100u, p.answered_ms);
}

TEST(Ping, AStalePongWithNoPingInFlightChangesNothing) {
  MqttCtrlPing p = {};
  EXPECT_FALSE(mqttCtrlTakePong(&p, bytes("pong|00000000"), 13, 5));
  char out[32];
  mqttCtrlArmPing(&p, "11111111", out, sizeof(out), 0);
  p.in_flight = false;                          // the ping timed out
  EXPECT_FALSE(mqttCtrlTakePong(&p, bytes("pong|11111111"), 13, 20000));
  EXPECT_EQ(0u, p.answered_ms);
}

TEST(Ping, APongIsRecognisedBeforeAndNeverParsedAsACommand) {
  // Abuse rule 5: the check is a prefix compare, and a pong is no envelope.
  EXPECT_TRUE(mqttCtrlIsPong(bytes("pong|a1b2c3d4"), 13));
  EXPECT_TRUE(mqttCtrlIsPong(bytes("pong|"), 5));
  EXPECT_FALSE(mqttCtrlIsPong(bytes("pong"), 4));
  EXPECT_FALSE(mqttCtrlIsPong(bytes("{\"c\":1}"), 7));
  EXPECT_FALSE(mqttCtrlIsPong(nullptr, 0));
  MqttCtrlEnvelope env;
  EXPECT_NE(MQTTCTRL_OK, mqttCtrlParseEnvelope("pong|a1b2c3d4", 13, &env));
}

TEST(Ping, BeforeAnyPingTheStateSaysNone) {
  // QA: a zeroed state read as "pong in 0 ms" before the first ping.
  MqttCtrlPing p = {};
  EXPECT_EQ(MQTTCTRL_PING_NONE, p.last);
  EXPECT_FALSE(p.waiting);
  EXPECT_FALSE(mqttCtrlPingPoll(&p, 123));
  EXPECT_EQ(MQTTCTRL_PING_NONE, p.last);
}

TEST(Ping, SettlesOnThePongWithTheRoundTrip) {
  MqttCtrlPing p = {};
  char out[32];
  ASSERT_TRUE(mqttCtrlArmPing(&p, "a1b2c3d4", out, sizeof(out), 1000));
  EXPECT_FALSE(mqttCtrlPingPoll(&p, 1100));             // still waiting; nothing blocks
  EXPECT_TRUE(p.waiting);
  ASSERT_TRUE(mqttCtrlTakePong(&p, bytes("pong|a1b2c3d4"), 13, 1230));
  EXPECT_TRUE(mqttCtrlPingPoll(&p, 1240));              // settles once
  EXPECT_EQ(MQTTCTRL_PING_OK, p.last);
  EXPECT_EQ(230u, p.last_ms);
  EXPECT_FALSE(p.waiting);
  EXPECT_FALSE(mqttCtrlPingPoll(&p, 1300));             // and only once
}

TEST(Ping, SettlesAsNoPongAfterTenSecondsAndALatePongChangesNothing) {
  MqttCtrlPing p = {};
  char out[32];
  ASSERT_TRUE(mqttCtrlArmPing(&p, "a1b2c3d4", out, sizeof(out), 5000));
  EXPECT_FALSE(mqttCtrlPingPoll(&p, 5000 + MQTTCTRL_PING_TIMEOUT_MS - 1));
  EXPECT_TRUE(mqttCtrlPingPoll(&p, 5000 + MQTTCTRL_PING_TIMEOUT_MS));
  EXPECT_EQ(MQTTCTRL_PING_NO_PONG, p.last);
  EXPECT_FALSE(mqttCtrlTakePong(&p, bytes("pong|a1b2c3d4"), 13, 16000));
  EXPECT_FALSE(mqttCtrlPingPoll(&p, 16001));
  EXPECT_EQ(MQTTCTRL_PING_NO_PONG, p.last);
}

TEST(Ping, OneAtATimeAndARefusedPublishSettlesAtOnce) {
  MqttCtrlPing p = {};
  char out[32];
  ASSERT_TRUE(mqttCtrlArmPing(&p, "a1b2c3d4", out, sizeof(out), 0));
  EXPECT_FALSE(mqttCtrlArmPing(&p, "11111111", out, sizeof(out), 10));   // one waiting
  EXPECT_STREQ("a1b2c3d4", p.nonce);
  mqttCtrlPingRefused(&p);
  EXPECT_EQ(MQTTCTRL_PING_PUBLISH_REFUSED, p.last);
  EXPECT_FALSE(mqttCtrlPingPoll(&p, 20));
  EXPECT_TRUE(mqttCtrlArmPing(&p, "11111111", out, sizeof(out), 30));    // free again
}

TEST(Ping, AcrossTheMillisWrap) {
  MqttCtrlPing p = {};
  char out[32];
  ASSERT_TRUE(mqttCtrlArmPing(&p, "a1b2c3d4", out, sizeof(out), 0xFFFFFF00u));
  EXPECT_FALSE(mqttCtrlPingPoll(&p, 0xFFFFFFF0u));      // 240 ms in, before the wrap
  EXPECT_FALSE(mqttCtrlPingPoll(&p, 0x00000010u));
  ASSERT_TRUE(mqttCtrlTakePong(&p, bytes("pong|a1b2c3d4"), 13, 0x00000020u));
  ASSERT_TRUE(mqttCtrlPingPoll(&p, 0x00000030u));
  EXPECT_EQ(0x120u, p.last_ms);
}

TEST(Ping, TheAnswerNamesTheStepThatFailed) {
  char out[MQTTCTRL_MAX_REPLY];
  mqttCtrlPingAnswer(MQTTCTRL_PING_OK, 3, 230, "mqtts, jwt", out, sizeof(out));
  EXPECT_STREQ("OK - pong in 230 ms on slot 3 (mqtts, jwt)", out);
  mqttCtrlPingAnswer(MQTTCTRL_PING_NOT_CONNECTED, 3, 0, NULL, out, sizeof(out));
  EXPECT_STREQ("Err - slot 3 not connected", out);
  mqttCtrlPingAnswer(MQTTCTRL_PING_PUBLISH_REFUSED, 3, 0, NULL, out, sizeof(out));
  EXPECT_STREQ("Err - publish refused", out);
  mqttCtrlPingAnswer(MQTTCTRL_PING_NO_PONG, 3, 0, NULL, out, sizeof(out));
  EXPECT_STREQ("Err - no pong in 10 s: /cmd is not subscribed or the broker is not answering", out);
  mqttCtrlPingAnswer(MQTTCTRL_PING_OFF, 0, 0, NULL, out, sizeof(out));
  EXPECT_STREQ("Err - the command plane is off: set mqtt.cmd on", out);
}

TEST(Ping, IsAdmittedOverThePlaneExactlyAndIsNoTransmit) {
  // Abuse rule 6: an owner-signed read inside the command budget; nothing on the air.
  EXPECT_TRUE(allowed("mqtt.cmd ping"));
  EXPECT_FALSE(allowed("mqtt.cmd ping all"));
  EXPECT_FALSE(allowed("mqtt.cmd"));
  EXPECT_FALSE(mqttCtrlIsTransmitCommand("mqtt.cmd ping", 13));
}

// ---- signed results: r2 (2026-10-08, ar-11) ------------------------------------------

static uint8_t T_PUB[32], T_PRV[64];
static void testSigner(void* ctx, uint8_t sig[64], const uint8_t* msg, size_t len) {
  (void)ctx;
  ed25519_sign(sig, msg, len, T_PUB, T_PRV);
}
static void makeTestKey() {
  uint8_t seed[32];
  for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(0x11 + i);
  ed25519_create_keypair(T_PUB, T_PRV, seed);
}

TEST(SignedResult, TheLineIsR2WithTheNodesSignatureOverTopicAndLine) {
  makeTestKey();
  const char* topic = "meshcore/JKG/4AC61A7FF4800A079A7311CA606A4C7037FE6943D40E53932230142829A4F786/res";
  char out[MQTTCTRL_MAX_RESULT];
  size_t n = mqttCtrlFormatSignedResult(out, sizeof(out), topic, 42, 0, "get txdelay", "> 0.5", testSigner, NULL);
  ASSERT_GT(n, 0u);
  std::string s(out, n);
  EXPECT_EQ(0u, s.find("r2|42|0|get txdelay|> 0.5|"));
  size_t line_len = 0;
  const char* sig_hex = mqttCtrlSignedResultSplit(out, n, &line_len);
  ASSERT_NE(nullptr, sig_hex);
  EXPECT_EQ(std::string("r2|42|0|get txdelay|> 0.5"), std::string(out, line_len));
  // a verifier rebuilds "<topic>\n<line>" and checks with the node's key
  std::string msg = std::string(topic) + "\n" + std::string(out, line_len);
  uint8_t sig[64];
  hexToBytes(std::string(sig_hex, 128).c_str(), sig, sizeof(sig));
  EXPECT_EQ(1, ed25519_verify(sig, (const uint8_t*)msg.data(), msg.size(), T_PUB));
  // ... and not with another topic, nor with a changed reply
  std::string other = std::string("meshcore/JKG/all/cmd") + "\n" + std::string(out, line_len);
  EXPECT_EQ(0, ed25519_verify(sig, (const uint8_t*)other.data(), other.size(), T_PUB));
  std::string changed = std::string(topic) + "\n" + "r2|42|0|get txdelay|> 0.6";
  EXPECT_EQ(0, ed25519_verify(sig, (const uint8_t*)changed.data(), changed.size(), T_PUB));
}

TEST(SignedResult, TheReplyShortensSoTheSignatureAlwaysFits) {
  makeTestKey();
  std::string huge(400, 'x');
  char out[MQTTCTRL_MAX_RESULT];
  size_t n = mqttCtrlFormatSignedResult(out, sizeof(out), "meshcore/JKG/4AC61A7F/res", 7, 0, "get radio", huge.c_str(), testSigner, NULL);
  ASSERT_GT(n, 0u);
  EXPECT_EQ(sizeof(out) - 1, n);                          // full, not over
  size_t line_len = 0;
  ASSERT_NE(nullptr, mqttCtrlSignedResultSplit(out, n, &line_len));
  EXPECT_EQ(sizeof(out) - 1 - 129, line_len);             // the line gave way, the signature did not
  EXPECT_EQ(std::string("r2|7|0|get radio|"), std::string(out, 17));
}

TEST(SignedResult, AnR1OrAShortLineIsNotSplitAsSigned) {
  size_t line_len = 0;
  EXPECT_EQ(nullptr, mqttCtrlSignedResultSplit("r1|42|0|get txdelay|> 0.5", 25, &line_len));
  EXPECT_EQ(nullptr, mqttCtrlSignedResultSplit("r2|42|0|x|y|abc", 15, &line_len));
  char out[MQTTCTRL_MAX_RESULT];
  EXPECT_EQ(0u, mqttCtrlFormatSignedResult(out, 100, "meshcore/JKG/x/res", 1, 0, "ver", "v", testSigner, NULL));   // no room for a signature
}

TEST(Denylist, TheAutomaticUpdateSettingsTravelAndTheManualFlashStillDoesNot) {
  EXPECT_TRUE(allowed("set ota.auto on"));
  EXPECT_TRUE(allowed("set ota.check.hours 12"));
  EXPECT_TRUE(allowed("get ota"));
  EXPECT_TRUE(allowed("get ota.auto"));
  EXPECT_TRUE(allowed("ota check"));
  EXPECT_FALSE(allowed("ota update"));
}

// ---- the cross-check fixture for mccontrol (ar-11) ------------------------------------
//
// Writes every command mccontrol's tables know, with this firmware's verdict, to
// test/data/command-verdicts.txt (one "allowed|<command>" or "denied|<command>" per
// line). mccontrol's test reads the same file and asserts its denylist.py and the
// ar-11 row of firmware.py agree with every line, so the two cannot drift apart
// without a red test on one side. Runs on the host, writes beside the tests.

static const char* const known_commands[] = {
  "ver", "get name", "get autoreply", "region", "neighbors", "get radio", "get repeat",
  "get flood.max", "get flood.max.unscoped", "get txdelay", "get direct.txdelay", "get rxdelay",
  "get af", "get cad", "get int.thresh", "get mqtt.status", "get mqtt.cmd", "get mqtt.iata",
  "get mqtt.interval", "board", "memory", "clock", "ota check", "get stats", "get ota",
  "set autoreply on", "set autoreply.mode flood", "set autoreply.hops 3", "set autoreply.delay 60",
  "set autoreply.direct.flood on", "set autoreply.private on", "set autoreply.region se-jkp",
  "set autoreply.slot 1", "set autoreply.slots 16", "set autoreply.window 10 120",
  "trigger test", "trigger test F", "region put se-jkp *", "region allowf se-jkp", "region denyf se-jkp",
  "region remove se06", "region default se-jkp", "region home se-jkp", "region save",
  "set txdelay 0.5", "set direct.txdelay 0.3", "set rxdelay 0", "set af 9.0", "set cad on",
  "set int.thresh 1", "set flood.max 8", "set flood.max.unscoped 2", "set path.hash.mode 0",
  "set loop.detect 0", "set multi.acks on", "set mqtt.iata JKG", "set mqtt.interval 5",
  "set mqtt.status on", "set mqtt.packets on", "set mqtt.raw on", "set mqtt.neighbors on",
  "set mqtt.presets 2", "set mqtt1.preset meshat.se", "set mqtt1.server mqtt.louie.se",
  "set mqtt2.username mcoar", "set mqtt2.password x", "set mqtt3.preset custom",
  "set name Foo", "reboot", "clkreboot", "clear stats", "neighbor.remove 4AC61A7F",
  "powersaving on", "gps on", "set ota.auto on", "set ota.check.hours 12",
  "mqtt.cmd ping", "set autoreply.legacy off",
  // the denied groups
  "set prv.key 00", "set public.key 00", "set mqtt.cmd off", "set mqtt.cmd.slot 2", "get mqtt.cmd.pubkey",
  "set wifi.pwd x", "get wifi.ssid", "password x", "get guest.password", "set alert.psk 00",
  "get bridge.secret", "get snmp.community", "get mqtt.owner", "set owner.info x", "get tls.x",
  "get prv.key", "get mqtt1.password", "get mqtt6.token", "erase", "start webconfig", "ota update",
  "poweroff", "shutdown", "set bootloader.ver 2", "set lat 57.78", "get lon", "set role repeater",
  "set repeat off", "set freq 869.6", "set radio.rxgain 1", "set tx 20", "set extra.sf 1",
  "set dutycycle 10", "tempradio 869 62.5 8 8", "advert", "alert test", "set advert.interval 1",
  "time 1900000000", "log", "stats-core", "floodscan", "set", "get",
};

// test/data/command-verdicts.txt is the arrc image's (with auto-reply, as every release
// up to ar-13); command-verdicts-rc.txt is the same list for an image without it.
static void writeVerdicts(const char* path, bool auto_reply) {
  FILE* f = fopen(path, "w");
  ASSERT_NE(nullptr, f) << "run from the repository root";
  for (const char* c : known_commands) {
    bool ok = mqttCtrlCommandAllowed(c, strlen(c), auto_reply);
    fprintf(f, "%s|%s\n", ok ? "allowed" : "denied", c);
  }
  fclose(f);
}

TEST(CrossCheck, EveryKnownCommandsVerdictIsWritten) {
  writeVerdicts("test/data/command-verdicts.txt", true);
  writeVerdicts("test/data/command-verdicts-rc.txt", false);
}
