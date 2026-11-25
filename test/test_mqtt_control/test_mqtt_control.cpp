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
#include "helpers/SensorReadout.h"
#include "helpers/AutoReplyLogic.h"   // a trigger is checked one layer down
#include "MeshCore.h"                 // the packet bounds the mesh road is sized by
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

// A command as the checks after the envelope see it: counter, expiry and text, whatever
// road and seal brought it. The text is held here because the envelope points into it.
struct Cmd {
  std::string text;
  MqttCtrlEnvelope env;
  Cmd(uint32_t counter, uint32_t expiry, const std::string& command) : text(command) {
    memset(&env, 0, sizeof(env));
    env.counter = counter;
    env.expiry = expiry;
    env.command = text.data();
    env.command_len = text.size();
  }
  Cmd(const Cmd&) = delete;   // a copy's envelope would point into the original
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

TEST(CommandChars, AdmitsWellFormedUtf8SoANameCanHoldSwedishLetters) {
  const char* name = "set name SE-JKP-V\xC3\xA4ster-6F8C";   // "Väster"
  EXPECT_TRUE(mqttCtrlCommandCharsOk(name, strlen(name)));
  const char* aao = "set name \xC3\xA5\xC3\xA4\xC3\xB6\xC3\x85\xC3\x84\xC3\x96";   // åäöÅÄÖ
  EXPECT_TRUE(mqttCtrlCommandCharsOk(aao, strlen(aao)));
  const char* emoji = "set name \xF0\x9F\x93\xA1";          // U+1F4E1, four bytes
  EXPECT_TRUE(mqttCtrlCommandCharsOk(emoji, strlen(emoji)));
}

TEST(CommandChars, RefusesBytesThatAreNotWellFormedUtf8) {
  EXPECT_FALSE(mqttCtrlCommandCharsOk("set name \x80", 10));            // stray continuation
  EXPECT_FALSE(mqttCtrlCommandCharsOk("set name \xC3", 10));            // truncated at the end
  EXPECT_FALSE(mqttCtrlCommandCharsOk("set name \xC3x", 11));           // truncated mid-command
  EXPECT_FALSE(mqttCtrlCommandCharsOk("set name \xC0\xBC", 11));       // overlong '<'
  EXPECT_FALSE(mqttCtrlCommandCharsOk("set name \xE0\x80\xBC", 12));  // overlong, three bytes
  EXPECT_FALSE(mqttCtrlCommandCharsOk("set name \xED\xA0\x80", 12));  // UTF-16 surrogate
  EXPECT_FALSE(mqttCtrlCommandCharsOk("set name \xF4\x90\x80\x80", 13));  // above U+10FFFF
  EXPECT_FALSE(mqttCtrlCommandCharsOk("set name \xF5\x80\x80\x80", 13));
  EXPECT_FALSE(mqttCtrlCommandCharsOk("set name \xFF", 10));
  EXPECT_FALSE(mqttCtrlCommandCharsOk("get radio\x7F", 10));            // DEL
  // An overlong encoding of the separator must not slip one past the split.
  EXPECT_FALSE(mqttCtrlCommandCharsOk("get a\xC1\xBC", 7));
}

TEST(ParseEnvelope, AdmitsAUtf8Command) {
  MqttCtrlEnvelope e;
  EXPECT_EQ(MQTTCTRL_OK, parse(envelope("v1|1|1788200000|set name V\xC3\xA4ster"), &e));
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
    "ver", "get name", "region", "neighbors", "get cmd", "get stats", "get ota",
    "set ota.auto on", "cmd ping", "region put se-jkp *", "set mqtt.iata JKG", "reboot",
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
  // A signed `set cmd.slot 0`, or a slot with no broker behind it, would
  // leave the node listening nowhere, and only someone at its serial port could
  // undo that. The commands that decide where the node listens stay local.
  EXPECT_FALSE(allowed("set cmd off"));
  EXPECT_FALSE(allowed("set cmd.slot 0"));
  EXPECT_FALSE(allowed("set cmd.slot 2"));
}

TEST(Allowlist, TheCommandKeyIsNeitherWritableNorReadable) {
  // Rotating the key that authorises signed commands must not itself be a signed
  // command. MqttControl also refuses both to any non-zero sender_timestamp, which
  // mqttCtrlSenderStamp guarantees every MQTT command carries.
  EXPECT_FALSE(allowed("set cmd.pubkey "
                       "AA04792D7804529FABF230B32DC8F7FA494D1B3280F153B2215C305E4FD654DC"));
  EXPECT_FALSE(allowed("set cmd.pubkey"));
  EXPECT_FALSE(allowed("get cmd.pubkey"));
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
  EXPECT_FALSE(allowed("get cmd.pubkeyx"));
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
  Cmd h(9, 1788200060, "trigger test");
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthorise(&h.env, 8, 1788200000, true));
}

TEST(Authorise, StopsAtTheFirstRefusalInOrder) {
  // Replay is checked before expiry, and expiry before the allowlist: a replayed
  // command reports replay even when it is also expired and also forbidden, so a
  // caller publishing the reason cannot be used to probe the later checks.
  Cmd replayed(5, 1, "erase");
  EXPECT_EQ(MQTTCTRL_ERR_REPLAY, mqttCtrlAuthorise(&replayed.env, 5, 1788200000, true));

  Cmd expired(9, 1, "erase");
  EXPECT_EQ(MQTTCTRL_ERR_EXPIRED, mqttCtrlAuthorise(&expired.env, 8, 1788200000, true));

  Cmd forbidden(9, 1788200060, "erase");
  EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthorise(&forbidden.env, 8, 1788200000, true));
}

TEST(Authorise, RefusesEverythingWithoutAClock) {
  Cmd h(9, 1788200060, "trigger test");
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
  EXPECT_EQ(MQTTCTRL_CMD_MAX, 50);                    // operator, 2026-11-23
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
  EXPECT_EQ(MQTTCTRL_CMD_MAX, allowed);                // what it can remember
  SlidingBudget ten(200, 600);
  allowed = 0;
  for (int i = 0; i < 250; i++) allowed += ten.allow(1000);
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

  Cmd key(7, 1788200000, "set prv.key deadbeef");
  EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthorise(&key.env, 6, 1788199000, true));
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

// `get sensors` (operator 2026-11-23): battery, MCU temperature and the board's sensors on
// one line that a sealed answer over the mesh carries whole.
TEST(SensorReadout, BatteryMcuTemperatureAndTheBoardsSensors) {
  char out[SENSOR_READOUT_MAX + 1];
  // Channel 1: 23.5 C, 40.5 %, 1013.2 hPa. Channel 2: -4.5 C and 3.72 V, 0.125 A.
  const uint8_t lpp[] = { 1, 103, 0x00, 0xEB,   1, 104, 81,   1, 115, 0x27, 0x94,
                          2, 103, 0xFF, 0xD3,   2, 116, 0x01, 0x74,   2, 117, 0x00, 0x7D };
  sensorReadoutFormat(out, sizeof(out), 3881, 215, lpp, sizeof(lpp));
  EXPECT_STREQ("> batt=3881mV mcu=21.5C temp=23.5C hum=40.5% press=1013.2hPa temp/2=-4.5C "
               "volt/2=3.72V curr/2=0.125A", out);
  EXPECT_LE(strlen(out), (size_t)SENSOR_READOUT_MAX);
}

TEST(SensorReadout, ABoardWithNothingToSaySaysSo) {
  char out[SENSOR_READOUT_MAX + 1];
  sensorReadoutFormat(out, sizeof(out), -1, SENSOR_READOUT_NO_TEMP, NULL, 0);
  EXPECT_STREQ("> (no sensors)", out);
  sensorReadoutFormat(out, sizeof(out), 4100, SENSOR_READOUT_NO_TEMP, NULL, 0);
  EXPECT_STREQ("> batt=4100mV", out);
  sensorReadoutFormat(out, sizeof(out), -1, -73, NULL, 0);
  EXPECT_STREQ("> mcu=-7.3C", out);
}

TEST(SensorReadout, APositionIsLeftOutAndAnUnknownTypeEndsTheLine) {
  char out[SENSOR_READOUT_MAX + 1];
  // A GPS record (9 bytes) between two temperatures, then a type the table does not know.
  const uint8_t lpp[] = { 1, 103, 0x00, 0x64,   1, 136, 1, 2, 3, 4, 5, 6, 7, 8, 9,   3, 103, 0x00, 0xC8,
                          1, 250, 0xAA, 0xBB,   1, 103, 0x01, 0x2C };
  sensorReadoutFormat(out, sizeof(out), -1, SENSOR_READOUT_NO_TEMP, lpp, sizeof(lpp));
  EXPECT_STREQ("> temp=10.0C temp/3=20.0C", out);
  // A record cut short by the buffer's end is not read.
  sensorReadoutFormat(out, sizeof(out), -1, SENSOR_READOUT_NO_TEMP, lpp, 3);
  EXPECT_STREQ("> (no sensors)", out);
}

TEST(SensorReadout, TheLineNeverEndsInHalfAPairAndNeverLeavesItsBuffer) {
  uint8_t lpp[40 * 4];
  for (int i = 0; i < 40; i++) {
    lpp[i * 4] = (uint8_t)(10 + i);
    lpp[i * 4 + 1] = 103;
    lpp[i * 4 + 2] = 0x7F;
    lpp[i * 4 + 3] = 0xFF;
  }
  char guard[SENSOR_READOUT_MAX + 1 + 4];
  memset(guard, 'x', sizeof(guard));
  size_t n = sensorReadoutFormat(guard, SENSOR_READOUT_MAX + 1, 4200, 250, lpp, sizeof(lpp));
  EXPECT_EQ(strlen(guard), n);
  EXPECT_LE(n, (size_t)SENSOR_READOUT_MAX);
  EXPECT_EQ('x', guard[SENSOR_READOUT_MAX + 1]);
  EXPECT_EQ('C', guard[n - 1]);                      // whole pairs only
  EXPECT_NE(nullptr, strstr(guard, " temp/10=3276.7C"));
  char tiny[1];
  EXPECT_EQ(0u, sensorReadoutFormat(tiny, sizeof(tiny), 4200, 250, NULL, 0));
  EXPECT_EQ(0u, sensorReadoutFormat(NULL, 100, 4200, 250, NULL, 0));
}

TEST(SensorReadout, TheReadsTravelOnBothRoadsAndTheDebugSwitchOnNeither) {
  for (const char* c : { "get sensors", "get stats" }) {
    EXPECT_TRUE(mqttCtrlCommandAllowed(c, strlen(c), true)) << c;
    EXPECT_TRUE(mqttCtrlCommandAllowed(c, strlen(c), false)) << c;
    EXPECT_TRUE(mqttCtrlMeshCommandAllowed(c, strlen(c), false, true)) << c;
    EXPECT_TRUE(mqttCtrlMeshCommandAllowed(c, strlen(c), false, false)) << c;   // an image without an uplink
    EXPECT_FALSE(mqttCtrlIsTransmitCommand(c, strlen(c))) << c;
  }
  for (const char* c : { "set cmd.debug on", "set cmd.debug off" }) {
    EXPECT_TRUE(mqttCtrlCommandDenied(c, strlen(c))) << c;
    EXPECT_FALSE(mqttCtrlMeshCommandAllowed(c, strlen(c), true, false)) << c;
  }
}

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

// ---- the command key over the mesh admin login (OTM-6a) -------------------------

static const char* const kStrong = "correct horse";

TEST(CommandKeyCaller, NamedByTheCallerNeverByTheClock) {
  EXPECT_EQ(MQTTCTRL_KEY_LOCAL, mqttCtrlKeyCallerOf(0, false));
  EXPECT_EQ(MQTTCTRL_KEY_LOCAL, mqttCtrlKeyCallerOf(0, true));
  EXPECT_EQ(MQTTCTRL_KEY_MESH_ADMIN, mqttCtrlKeyCallerOf(1795000000, true));
  EXPECT_EQ(MQTTCTRL_KEY_REMOTE, mqttCtrlKeyCallerOf(1795000000, false));
}

// The pin: the plane runs every command with mqttCtrlSenderStamp(now) and no admin flag
// (its runner has no way to pass one), and that caller may never set the key -- not on a
// keyless node, not with the strongest password. Nothing here asks the deny list, so this
// holds with the list's entries removed; the next test pins the list on its own.
TEST(CommandKeyCaller, ThePlaneNeverSetsTheKeyWhateverTheDenyListSays) {
  const uint32_t clocks[] = { 0, 1, 1715770351, 1795000000, 0xFFFFFFFFu };
  for (uint32_t now : clocks) {
    const MqttCtrlKeyCaller plane = mqttCtrlKeyCallerOf(mqttCtrlSenderStamp(now), false);
    EXPECT_EQ(MQTTCTRL_KEY_REMOTE, plane) << now;
    EXPECT_STREQ("Err - serial only", mqttCtrlKeySetRefusal(plane, false, kStrong, "guest")) << now;
    EXPECT_STREQ("Err - serial only", mqttCtrlKeySetRefusal(plane, true, kStrong, "guest")) << now;
  }
}

TEST(CommandKeyCaller, TheDenyListRefusesTheKeyOnItsOwn) {
  const char* key_cmds[] = { "set cmd.pubkey 0123", "get cmd.pubkey" };
  for (const char* c : key_cmds) {
    EXPECT_TRUE(mqttCtrlCommandDenied(c, strlen(c))) << c;
    EXPECT_FALSE(mqttCtrlMeshCommandAllowed(c, strlen(c), true, true)) << c;
  }
}

TEST(CommandKeyCaller, ALocalCallerAlwaysMay) {
  EXPECT_EQ(nullptr, mqttCtrlKeySetRefusal(MQTTCTRL_KEY_LOCAL, false, "password", "password"));
  EXPECT_EQ(nullptr, mqttCtrlKeySetRefusal(MQTTCTRL_KEY_LOCAL, true, "", NULL));
}

TEST(CommandKeyCaller, ARemoteAdminOnlyGivesAKeylessNodeItsFirstKey) {
  EXPECT_EQ(nullptr, mqttCtrlKeySetRefusal(MQTTCTRL_KEY_MESH_ADMIN, false, kStrong, "guest"));
  EXPECT_STREQ("Err - a key is set: replace or clear it over USB",
               mqttCtrlKeySetRefusal(MQTTCTRL_KEY_MESH_ADMIN, true, kStrong, "guest"));
}

TEST(CommandKeyCaller, TheAdminPasswordRuleSaysWhichPartFailed) {
  const char* r = mqttCtrlKeySetRefusal(MQTTCTRL_KEY_MESH_ADMIN, false, "password", "guest");
  ASSERT_NE(nullptr, r);
  EXPECT_NE(nullptr, strstr(r, "default"));
  r = mqttCtrlKeySetRefusal(MQTTCTRL_KEY_MESH_ADMIN, false, "hunter2", "guest");
  ASSERT_NE(nullptr, r);
  EXPECT_NE(nullptr, strstr(r, "under 8"));
  r = mqttCtrlKeySetRefusal(MQTTCTRL_KEY_MESH_ADMIN, false, kStrong, kStrong);
  ASSERT_NE(nullptr, r);
  EXPECT_NE(nullptr, strstr(r, "guest"));
  EXPECT_NE(nullptr, mqttCtrlAdminPasswordRefusal(NULL, "guest"));
  EXPECT_NE(nullptr, mqttCtrlAdminPasswordRefusal("", "guest"));
  // Exactly 8 passes; 7 does not; an empty guest password is no match for a real one.
  EXPECT_EQ(nullptr, mqttCtrlAdminPasswordRefusal("12345678", ""));
  EXPECT_NE(nullptr, mqttCtrlAdminPasswordRefusal("1234567", ""));
  EXPECT_EQ(nullptr, mqttCtrlAdminPasswordRefusal("12345678", NULL));
  // Only the compiled default, not every word that contains it.
  EXPECT_EQ(nullptr, mqttCtrlAdminPasswordRefusal("password1", "guest"));
}

TEST(CommandKeyCaller, TheFingerprintIsTheFirstEightHex) {
  char fp[MQTTCTRL_KEY_FINGERPRINT_LEN + 1];
  mqttCtrlKeyFingerprint("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", fp);
  EXPECT_STREQ("01234567", fp);
  mqttCtrlKeyFingerprint("", fp);
  EXPECT_STREQ("", fp);
  mqttCtrlKeyFingerprint(NULL, fp);
  EXPECT_STREQ("", fp);
  EXPECT_STREQ("admin", mqttCtrlKeyViaName(MQTTCTRL_KEY_VIA_ADMIN));
  EXPECT_STREQ("usb", mqttCtrlKeyViaName(MQTTCTRL_KEY_VIA_USB));
  EXPECT_STREQ("usb", mqttCtrlKeyViaName(7));
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

TEST(BroadcastGuard, AnUpdateMayNotBeAddressedToEveryNode) {
  // `ota update` restarts the node: one publish to all/cmd would take the region off the
  // air together, all of it on an image no node had yet shown to work. Per node it goes.
  const char* cmd = "ota update";
  EXPECT_TRUE(allowed(cmd));
  EXPECT_FALSE(mqttCtrlIsTransmitCommand(cmd, strlen(cmd)));      // not an airtime cost...
  EXPECT_TRUE(mqttCtrlBroadcastRefused(cmd, strlen(cmd)));        // ...refused all the same
  EXPECT_EQ(MQTTCTRL_ERR_BROADCAST_TRANSMIT,
            mqttCtrlTransmitTopicResult(mqttCtrlBroadcastRefused(cmd, strlen(cmd)), "meshcore/JKG/all/cmd"));
  EXPECT_EQ(MQTTCTRL_OK,
            mqttCtrlTransmitTopicResult(mqttCtrlBroadcastRefused(cmd, strlen(cmd)), "meshcore/JKG/a1b2c3d4/cmd"));
  EXPECT_TRUE(mqttCtrlBroadcastRefused("trigger test", 12));
  EXPECT_FALSE(mqttCtrlBroadcastRefused("ota check", 9));
  EXPECT_FALSE(mqttCtrlBroadcastRefused("region put se-jkp *", 19));
}

TEST(BroadcastGuard, ARebootGoesToOneNodeNeverToEveryNode) {
  // One publish to all/cmd would restart the whole region together (operator, 2026-11-17).
  const char* cmd = "reboot";
  EXPECT_TRUE(allowed(cmd));
  EXPECT_FALSE(mqttCtrlIsTransmitCommand(cmd, strlen(cmd)));
  EXPECT_TRUE(mqttCtrlBroadcastRefused(cmd, strlen(cmd)));
  EXPECT_EQ(MQTTCTRL_ERR_BROADCAST_TRANSMIT,
            mqttCtrlTransmitTopicResult(mqttCtrlBroadcastRefused(cmd, strlen(cmd)), "meshcore/JKG/all/cmd"));
  EXPECT_EQ(MQTTCTRL_OK,
            mqttCtrlTransmitTopicResult(mqttCtrlBroadcastRefused(cmd, strlen(cmd)), "meshcore/JKG/a1b2c3d4/cmd"));
  EXPECT_TRUE(mqttCtrlMeshCommandAllowed(cmd, strlen(cmd), true));   // the mesh road reaches one node
}

TEST(RateLimit, AnUpdateSpendsTheCommandBudget) {
  // Not a transmit, so it costs one of the ten commands an hour like any setting, and
  // the eleventh in the hour is refused however validly it is signed.
  const char* cmd = "ota update";
  bool transmit = mqttCtrlIsTransmitCommand(cmd, strlen(cmd));
  EXPECT_TRUE(mqttCtrlSpendsCommandBudget(transmit));
  EXPECT_FALSE(mqttCtrlSpendsTransmitBudget(transmit));
  MqttCtrlBudget commands(MQTTCTRL_CMD_MAX, MQTTCTRL_CMD_WINDOW_SECS);
  const uint32_t now = 1795000000;
  for (int i = 0; i < MQTTCTRL_CMD_MAX; i++) EXPECT_TRUE(commands.allow(now + i));
  EXPECT_EQ(MQTTCTRL_ERR_RATE_LIMITED, mqttCtrlRateResult(transmit, commands.allow(now + 60), true));
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
  EXPECT_FALSE(allowed("set cmd.slot 2"));
  EXPECT_TRUE(allowed("set radio.watchdog on") == false);   // under the radio family, denied
  EXPECT_TRUE(allowed("set mqtt.interval 5"));              // not cmd
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
    "get mqtt.owner", "get cmd.pubkey", "get owner.info", "get tls.x",
    "get mqtt1.password", "get mqtt1.username", "get mqtt1.token",
    "get mqtt2.password", "get mqtt6.token", "get mqtt3.username x",
    "get lat", "get lon",
  };
  for (const char* command : never) EXPECT_FALSE(allowed(command)) << command;
  // The public key is what names the node to the whole mesh, so it is readable;
  // a broker's host name is settable over this plane now, so reading it back is
  // part of the same job. `get cmd` is state and counter, not the key.
  EXPECT_TRUE(allowed("get public.key"));
  EXPECT_TRUE(allowed("get mqtt1.server"));
  EXPECT_TRUE(allowed("get mqtt1.preset"));
  EXPECT_TRUE(allowed("get cmd"));
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
  EXPECT_FALSE(allowed("set cmd off"));
  EXPECT_FALSE(allowed("set cmd.slot 0"));
  EXPECT_FALSE(allowed("set cmd.pubkey 00"));
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

TEST(Denylist, OtaCheckAndOtaUpdateAreAdmittedBareOnly) {
  // `ota update` since the image is signed and the old one comes back when the new one
  // never proves itself (operator, 2026-11-17). Exact, as the CLI's memcmp is not:
  // `ota updatex` would reach the update's handler.
  EXPECT_TRUE(allowed("ota check"));
  EXPECT_FALSE(allowed("ota check x"));
  EXPECT_TRUE(allowed("ota update"));
  EXPECT_FALSE(allowed("ota update now"));
  EXPECT_FALSE(allowed("ota updatex"));
  EXPECT_FALSE(allowed("ota"));
  EXPECT_FALSE(allowed("ota branch dev"));
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
  // present". It gates get/set prv.key, get/set cmd.pubkey and erase.
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
  Cmd get(9, 1788200000, "get prv.key");
  EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthorise(&get.env, 8, 1788199000, true));

  Cmd set(9, 1788200000, "set prv.key deadbeef");
  EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthorise(&set.env, 8, 1788199000, true));
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

// ---- `set cmd on` picks a slot (2026-10-08) -------------------------------------

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

// ---- `get cmd` says what was refused unverified (bench, LOUTEST 2026-11-16) ----------

TEST(Unverified, ResultNamesAreMccontrolsAndFollowTheEnum) {
  EXPECT_STREQ("ok", mqttCtrlResultName(MQTTCTRL_OK));
  EXPECT_STREQ("bad-version", mqttCtrlResultName(MQTTCTRL_ERR_BAD_VERSION));
  EXPECT_STREQ("not-allowed", mqttCtrlResultName(MQTTCTRL_ERR_NOT_ALLOWED));
  EXPECT_STREQ("no-owner-key", mqttCtrlResultName(MQTTCTRL_ERR_NO_OWNER_KEY));
  EXPECT_STREQ("sig-invalid", mqttCtrlResultName(MQTTCTRL_ERR_SIG_INVALID));
  EXPECT_STREQ("broadcast-transmit", mqttCtrlResultName(MQTTCTRL_ERR_BROADCAST_TRANSMIT));
  EXPECT_STREQ("mesh-closed", mqttCtrlResultName(MQTTCTRL_ERR_MESH_CLOSED));
  EXPECT_STREQ("unknown", mqttCtrlResultName(MQTTCTRL_ERR_MESH_CLOSED + 1));
  EXPECT_STREQ("unknown", mqttCtrlResultName(-1));
}

TEST(Unverified, TheNoteNamesTheCountAndTheLastReason) {
  char out[64];
  mqttCtrlRefusalNote(0, MQTTCTRL_ERR_SIG_INVALID, out, sizeof(out));
  EXPECT_STREQ("", out);                                     // nothing refused, nothing said
  mqttCtrlRefusalNote(3, MQTTCTRL_ERR_SIG_INVALID, out, sizeof(out));
  EXPECT_STREQ(", unverified 3 (last sig-invalid)", out);
  // fits beside a day-old `get cmd` line in the 160-byte reply; the caller passes what
  // is left of it, so a longer one is cut, never overrun
  mqttCtrlRefusalNote(65535, MQTTCTRL_ERR_BROADCAST_TRANSMIT, out, sizeof(out));
  EXPECT_LE(strlen(out) + strlen("> on, counter 1794734056, slot 3 connected, jwt, /cmd subscribed, "
                                 "last command 86400 s ago, ping pong in 1234 ms"),
            (size_t)MQTTCTRL_MAX_REPLY - 1);
  char tiny[12];
  mqttCtrlRefusalNote(3, MQTTCTRL_ERR_SIG_INVALID, tiny, sizeof(tiny));
  EXPECT_STREQ(", unverifie", tiny);
}

// ---- `set cmd on [<host>]`: the shared broker or a region's own (RB-2) ----------

TEST(SlotPlan, TheBareFormIsTheMccontrolPresetAsBefore) {
  MqttCtrlSlotPlan plan;
  ASSERT_EQ(MQTTCTRL_SETUP_PRESET, mqttCtrlPlanSlot("set cmd on", &plan));
  EXPECT_STREQ("mccontrol", plan.preset);
  EXPECT_STREQ("", plan.server);       // the preset names the server and the audience
  EXPECT_STREQ("", plan.audience);
  EXPECT_EQ(MQTTPacketFilter::kAllPacketTypes, plan.filter);
  ASSERT_EQ(MQTTCTRL_SETUP_PRESET, mqttCtrlPlanSlot("set cmd on  ", &plan));
  EXPECT_STREQ("mccontrol", plan.preset);
}

TEST(SlotPlan, AHostIsACustomSlotOnThatBroker) {
  MqttCtrlSlotPlan plan;
  ASSERT_EQ(MQTTCTRL_SETUP_HOST, mqttCtrlPlanSlot("set cmd on mqtt.meshcore-vgr.se", &plan));
  EXPECT_STREQ("custom", plan.preset);
  EXPECT_STREQ("mqtts://mqtt.meshcore-vgr.se:8883", plan.server);
  EXPECT_STREQ("mqtt.meshcore-vgr.se", plan.audience);
  EXPECT_EQ(MQTTPacketFilter::kAllPacketTypes, plan.filter);
  // the longest host that fits the slot's server field, exactly
  std::string longest(MQTTCTRL_HOST_MAX - 3, 'a');
  longest += ".se";
  ASSERT_EQ(MQTTCTRL_SETUP_HOST, mqttCtrlPlanSlot(("set cmd on " + longest).c_str(), &plan));
  EXPECT_EQ("mqtts://" + longest + ":8883", std::string(plan.server));
  EXPECT_EQ(sizeof(plan.server) - 1, strlen(plan.server));
}

TEST(SlotPlan, ABadHostIsRefused) {
  MqttCtrlSlotPlan plan;
  const char* bad[] = {
    "set cmd on mqtts://mqtt.meshcore-vgr.se:8883",   // a URL, not a name
    "set cmd on mqtt.meshcore-vgr.se:8883",
    "set cmd on mqtt.meshcore-vgr.se/x",
    "set cmd on mqtt meshcore-vgr.se",
    "set cmd on .meshcore-vgr.se",
    "set cmd on meshcore-vgr.se.",
    "set cmd on mqtt_meshcore.se",
    "set cmd on m\xc3\xa4sh.se",
  };
  for (const char* c : bad) {
    EXPECT_EQ(MQTTCTRL_SETUP_BAD_HOST, mqttCtrlPlanSlot(c, &plan)) << c;
  }
  std::string too_long(MQTTCTRL_HOST_MAX - 2, 'a');
  too_long += ".se";
  EXPECT_EQ(MQTTCTRL_SETUP_BAD_HOST, mqttCtrlPlanSlot(("set cmd on " + too_long).c_str(), &plan));
}

TEST(SlotPlan, OtherCommandsAreNotThisOne) {
  MqttCtrlSlotPlan plan;
  EXPECT_EQ(MQTTCTRL_SETUP_NOT_ON, mqttCtrlPlanSlot("set cmd off", &plan));
  EXPECT_EQ(MQTTCTRL_SETUP_NOT_ON, mqttCtrlPlanSlot("set cmd only", &plan));
  EXPECT_EQ(MQTTCTRL_SETUP_NOT_ON, mqttCtrlPlanSlot("set cmd.slot 3", &plan));
  EXPECT_EQ(MQTTCTRL_SETUP_NOT_ON, mqttCtrlPlanSlot("get cmd", &plan));
  EXPECT_EQ(MQTTCTRL_SETUP_NOT_ON, mqttCtrlPlanSlot(NULL, &plan));
}

TEST(SlotPlan, NeverOverThePlane) {
  // Pointing the plane at another broker cuts the line it would arrive on, and hands the
  // node to whoever runs that broker: serial only, like every `set cmd`.
  const char* c = "set cmd on mqtt.meshcore-vgr.se";
  EXPECT_FALSE(mqttCtrlCommandAllowed(c, strlen(c), true));
  EXPECT_FALSE(mqttCtrlCommandAllowed(c, strlen(c), false));
}

// OTM-7: with a command slot already set, both forms rewrite that slot -- the bare one puts
// it back on the preset -- and only a node without one picks a free slot.
TEST(SlotPlan, TheSlotWrittenIsThePlanesOwnWhenItHasOne) {
  const char* presets[6] = { "analyzer-us", "analyzer-eu", "custom", "none", "", "none" };
  EXPECT_EQ(2, mqttCtrlSetupSlot(3, presets, 6, PSRAM));      // its own, though not free
  EXPECT_EQ(5, mqttCtrlSetupSlot(6, presets, 6, PSRAM));
  EXPECT_EQ(1, mqttCtrlSetupSlot(2, presets, 6, NO_PSRAM));
  EXPECT_EQ(3, mqttCtrlSetupSlot(0, presets, 6, PSRAM));      // none yet: the first free
  EXPECT_EQ(1, mqttCtrlSetupSlot(0, presets, 6, NO_PSRAM));
  const char* busy[6] = { "a", "b", "c", "d", "e", "f" };
  EXPECT_EQ(-1, mqttCtrlSetupSlot(0, busy, 6, PSRAM));
  EXPECT_EQ(3, mqttCtrlSetupSlot(4, busy, 6, PSRAM));
  EXPECT_EQ(-1, mqttCtrlSetupSlot(7, busy, 6, PSRAM));        // out of range is no slot
}

TEST(SlotPlan, TheBareFormPutsACustomSlotBackOnThePreset) {
  char preset[24] = "custom", server[64] = "mqtts://mqtt.meshcore-vgr.se:8883";
  char audience[64] = "mqtt.meshcore-vgr.se";
  uint16_t filter = 0x0001;
  MqttCtrlSlotPlan plan;
  ASSERT_EQ(MQTTCTRL_SETUP_PRESET, mqttCtrlPlanSlot("set cmd on", &plan));
  mqttCtrlApplySlotPlan(&plan, preset, sizeof(preset), server, sizeof(server), audience,
                        sizeof(audience), &filter);
  EXPECT_STREQ("mccontrol", preset);
  EXPECT_STREQ("", server);
  EXPECT_STREQ("", audience);
  EXPECT_EQ(MQTTPacketFilter::kAllPacketTypes, filter);
}

TEST(SlotPlan, TheHostFormRewritesTheSlotAsBefore) {
  char preset[24] = "mccontrol", server[64] = "", audience[64] = "";
  uint16_t filter = 0;
  MqttCtrlSlotPlan plan;
  ASSERT_EQ(MQTTCTRL_SETUP_HOST, mqttCtrlPlanSlot("set cmd on mqtt.meshcore-vgr.se", &plan));
  mqttCtrlApplySlotPlan(&plan, preset, sizeof(preset), server, sizeof(server), audience,
                        sizeof(audience), &filter);
  EXPECT_STREQ("custom", preset);
  EXPECT_STREQ("mqtts://mqtt.meshcore-vgr.se:8883", server);
  EXPECT_STREQ("mqtt.meshcore-vgr.se", audience);
  EXPECT_EQ(MQTTPacketFilter::kAllPacketTypes, filter);
}

TEST(SlotRepair, TheOldPasswordSlotIsFoundInEveryFormItWasStoredIn) {
  EXPECT_TRUE(mqttCtrlSlotNeedsRepair("custom", "mqtt.louie.se", "mcoar", ""));
  EXPECT_TRUE(mqttCtrlSlotNeedsRepair("custom", "mqtt://mqtt.louie.se:1883", "mcoar", ""));
  EXPECT_TRUE(mqttCtrlSlotNeedsRepair("custom", "mqtts://mqtt.louie.se:8883", "mcoar", ""));
  EXPECT_TRUE(mqttCtrlSlotNeedsRepair("custom", "wss://mqtt.louie.se:443/mqtt", "mcoar", ""));
  EXPECT_TRUE(mqttCtrlSlotNeedsRepair("custom", "MQTT.Louie.SE", "mcoar", ""));
  EXPECT_TRUE(mqttCtrlSlotNeedsRepair("custom", "mqtt-meshcore.louie.se", "mcoar", ""));
  EXPECT_TRUE(mqttCtrlSlotNeedsRepair("custom", "mqtt://mqtt.meshcore-jkp.se", "someone", ""));
  EXPECT_TRUE(mqttCtrlSlotNeedsRepair("custom", "mqtt.louie.se/mqtt", "mcoar", ""));
}

TEST(SlotRepair, ASlotSetOnPurposeIsLeftAlone) {
  // `set cmd on <host>` leaves an audience, and that slot signs in with a token
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("custom", "mqtts://mqtt.meshcore-vgr.se:8883", "",
                                       "mqtt.meshcore-vgr.se"));
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("custom", "mqtts://mqtt.louie.se:8883", "mcoar",
                                       "mqtt.louie.se"));
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("mccontrol", "", "", ""));
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("mccontrol", "mqtt.louie.se", "mcoar", ""));   // stale fields
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("none", "mqtt.louie.se", "mcoar", ""));
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("", "mqtt.louie.se", "mcoar", ""));
  // somebody else's broker, with a password
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("custom", "mqtt.example.org", "user", ""));
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("custom", "mqtt://mqtt.example.org:1883", "user", ""));
  // no username is no password login
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("custom", "mqtt.louie.se", "", ""));
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair(nullptr, "mqtt.louie.se", "mcoar", ""));
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("custom", nullptr, "mcoar", ""));
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("custom", "mqtt.louie.se", nullptr, ""));
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("custom", "mqtt.louie.se", "mcoar", nullptr));
}

TEST(SlotRepair, AHostThatOnlyContainsOneOfTheNamesIsNotOurs) {
  EXPECT_FALSE(mqttCtrlPlaneHost("evilmqtt.louie.se.example.org"));
  EXPECT_FALSE(mqttCtrlPlaneHost("mqtt.louie.se.example.org"));
  EXPECT_FALSE(mqttCtrlPlaneHost("evilmqtt.louie.se"));
  EXPECT_FALSE(mqttCtrlPlaneHost("mqtt.louie.s"));
  EXPECT_FALSE(mqttCtrlPlaneHost("mqtt://mqtt.louie.se@example.org:1883"));
  EXPECT_FALSE(mqttCtrlPlaneHost("mqtt://example.org/mqtt.louie.se"));
  EXPECT_FALSE(mqttCtrlPlaneHost("mqtt://"));
  EXPECT_FALSE(mqttCtrlPlaneHost(""));
  EXPECT_FALSE(mqttCtrlPlaneHost(nullptr));
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("custom", "mqtt.louie.se.example.org", "mcoar", ""));
  EXPECT_FALSE(mqttCtrlSlotNeedsRepair("custom", "mqtt://evilmqtt.louie.se.example.org:1883", "mcoar", ""));
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
  EXPECT_FALSE(mqttCtrlTouchesSlot("set cmd.slot 0", 2));          // the way out
  EXPECT_FALSE(mqttCtrlTouchesSlot(nullptr, 2));
}

// ---- `cmd ping` (TODO 15, ar-12) -------------------------------------------------

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
  EXPECT_STREQ("Err - the command plane is off: set cmd on", out);
}

TEST(Ping, IsAdmittedOverThePlaneExactlyAndIsNoTransmit) {
  // Abuse rule 6: an owner-signed read inside the command budget; nothing on the air.
  EXPECT_TRUE(allowed("cmd ping"));
  EXPECT_FALSE(allowed("cmd ping all"));
  EXPECT_FALSE(allowed("cmd"));
  EXPECT_FALSE(mqttCtrlIsTransmitCommand("cmd ping", 13));
}

TEST(Denylist, TheAutomaticUpdateSettingsTravelAndSoDoesTheUpdateItself) {
  EXPECT_TRUE(allowed("set ota.auto on"));
  EXPECT_TRUE(allowed("set ota.check.hours 12"));
  EXPECT_TRUE(allowed("get ota"));
  EXPECT_TRUE(allowed("get ota.auto"));
  EXPECT_TRUE(allowed("ota check"));
  EXPECT_TRUE(allowed("ota update"));
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
  "get af", "get cad", "get int.thresh", "get mqtt.status", "get cmd", "get mqtt.iata",
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
  "cmd ping", "set autoreply.legacy off", "ota update",
  // the denied groups
  "set prv.key 00", "set public.key 00", "set cmd off", "set cmd.slot 2", "get cmd.pubkey",
  "set wifi.pwd x", "get wifi.ssid", "password x", "get guest.password", "set alert.psk 00",
  "get bridge.secret", "get snmp.community", "get mqtt.owner", "set owner.info x", "get tls.x",
  "get prv.key", "get mqtt1.password", "get mqtt6.token", "erase", "start webconfig",
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

// ---- the mesh road (operator 2026-11-16) ---------------------------------------------
//
// One signed command, carried as an anonymous request instead of on /cmd. The request itself
// is mcc3's (test_mqtt_v3); what is here is what the road decides after it has been opened.

TEST(MeshRoad, TheOldSubtypeIsStillKnownSoItIsNeverReadAsALogin) {
  uint8_t v[20] = {0};
  v[4] = 0xC1;
  EXPECT_TRUE(mqttCtrlMeshIsOldRequest(v, sizeof(v)));
  EXPECT_TRUE(mqttCtrlMeshIsOldRequest(v, 5));
  EXPECT_FALSE(mqttCtrlMeshIsOldRequest(v, 4));
  EXPECT_FALSE(mqttCtrlMeshIsOldRequest(NULL, sizeof(v)));
  for (uint8_t t : { (uint8_t)0x00, (uint8_t)0x01, (uint8_t)0x02, (uint8_t)0x03, (uint8_t)' ', (uint8_t)'p',
                     (uint8_t)0xC0, (uint8_t)0xC2 }) {
    v[4] = t;
    EXPECT_FALSE(mqttCtrlMeshIsOldRequest(v, sizeof(v))) << (int)t;
  }
  // Upstream reads a first byte from ' ' up as a password, so an old request nobody claims
  // is a failed login. 0xC1 starts no UTF-8 sequence, so no real password begins with it.
  EXPECT_GE(MQTTCTRL_MESH_OLD_SUBTYPE, ' ');
  const unsigned char c1[] = { 0xC1, 0x81 };
  EXPECT_EQ(0u, mqttCtrlUtf8SeqLen(c1, sizeof(c1)));
  EXPECT_FALSE(mqttCtrlCommandCharsOk((const char *)c1, sizeof(c1)));
}

TEST(MeshRoad, TheCounterIsSharedAcrossTheRoads) {
  // A command run over MQTT is a replay over the mesh, and the other way round.
  const uint32_t now = 1795000000 - 60;
  Cmd mqtt(7, 1795000000, "get name");
  uint32_t last = 0;
  ASSERT_EQ(MQTTCTRL_OK, mqttCtrlAuthorise(&mqtt.env, last, now, true));
  last = mqtt.env.counter;
  Cmd same(7, 1795000000, "get name");
  EXPECT_EQ(MQTTCTRL_ERR_REPLAY, mqttCtrlAuthoriseMesh(&same.env, last, now, true));

  Cmd next(8, 1795000000, "get name");
  ASSERT_EQ(MQTTCTRL_OK, mqttCtrlAuthoriseMesh(&next.env, last, now, true));
  last = next.env.counter;
  Cmd again(8, 1795000000, "get name");
  EXPECT_EQ(MQTTCTRL_ERR_REPLAY, mqttCtrlAuthorise(&again.env, last, now, true));
}

TEST(MeshRoad, TheRepairAllowanceIsTheMeshRoadsAlone) {
  const char* repair[] = {
    "set wifi.ssid HomeNet", "set wifi.ssid My Net 5G", "set wifi.pwd hunter2",
    "set cmd on", "set cmd on mqtt-meshcore.louie.se", "reboot",
  };
  for (const char* c : repair) {
    EXPECT_TRUE(mqttCtrlMeshCommandAllowed(c, strlen(c), true)) << c;
    if (strcmp(c, "reboot") != 0) EXPECT_FALSE(allowed(c)) << c;   // never over MQTT
  }
  // Everything else the deny list holds stays denied on the mesh road too.
  const char* still[] = {
    "set wifi.ssid", "set wifi.pwd", "set wifi.pwdx", "set wifi.ssid.x y", "get wifi.pwd",
    "get wifi.ssid", "set cmd off", "set cmd.slot 2", "set cmd.pubkey 00",
    "set cmd.mesh on", "set cmd onx", "get cmd.pubkey", "set prv.key 00",
    "get prv.key", "erase", "set password x", "set freq 869.6", "set radio 1", "set lat 1",
    "set role x", "set repeat off", "advert", "time 1900000000", "log",
    "SET WIFI.PWD x", "Set wifi.ssid x", "start ota", "get mqtt1.password",
  };
  for (const char* c : still) EXPECT_FALSE(mqttCtrlMeshCommandAllowed(c, strlen(c), true)) << c;
  // What MQTT admits, the mesh road admits.
  for (const char* c : known_commands) {
    if (allowed(c)) EXPECT_TRUE(mqttCtrlMeshCommandAllowed(c, strlen(c), true)) << c;
  }
  // ... and in an image without auto-reply, its triggers stay out on both.
  EXPECT_FALSE(mqttCtrlMeshCommandAllowed("trigger test", 12, false));
}

TEST(MeshRoad, AnUpdateTravelsAsOnTheBrokerAndTheNodeChecksItsOwnLink) {
  // No allowance of its own: the plane's rules admit it, so the mesh road does, and the
  // road reaches one node only, so the broadcast refusal has nothing to add. The download
  // is over Wi-Fi, and the CLI answers "ERR: wifi not connected" without one, so a node
  // whose Wi-Fi is the reason the road opened says so and stays as it is.
  EXPECT_TRUE(mqttCtrlMeshCommandAllowed("ota update", 10, true));
  EXPECT_TRUE(mqttCtrlMeshCommandAllowed("ota update", 10, false));
  EXPECT_FALSE(mqttCtrlMeshCommandAllowed("ota updatex", 11, true));
}

TEST(MeshRoad, ARepairArrivingOverMqttIsRefused) {
  const uint32_t now = 1795000000 - 60;
  Cmd h(9, 1795000000, "set wifi.pwd hunter2");
  EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthorise(&h.env, 0, now, true));
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthoriseMesh(&h.env, 0, now, true));
}

// The owner's tool signs "time <now>" with an expiry minutes later. A node weeks behind would
// refuse anything else as expiry-too-far; this one command is judged by its own word. (A clock
// still at the firmware default, before 2025, skips the expiry check already.)
TEST(MeshRoad, AClockStepMendsANodeThatIsWeeksBehind) {
  const uint32_t owner_now = 1795000000;
  const uint32_t behind = owner_now - 21u * 86400u;   // set once, then weeks behind
  Cmd other(9, 1795000150, "get name");
  EXPECT_EQ(MQTTCTRL_ERR_FUTURE, mqttCtrlAuthoriseMesh(&other.env, 0, behind, true));
  Cmd step(9, 1795000150, "time 1795000000");
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthoriseMesh(&step.env, 0, behind, true));
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthoriseMesh(&step.env, 0, behind, true, false)) << "a mesh-only image too";
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthoriseMesh(&step.env, 0, owner_now, true)) << "and on a node whose clock is right";
}

TEST(MeshRoad, AClockStepIsStillACommandWithACounter) {
  Cmd step(9, 1795000150, "time 1795000000");
  EXPECT_EQ(MQTTCTRL_ERR_REPLAY, mqttCtrlAuthoriseMesh(&step.env, 9, 1700000000, true));
  EXPECT_EQ(MQTTCTRL_ERR_REPLAY, mqttCtrlAuthoriseMesh(&step.env, 10, 1700000000, true));
}

// The time must agree with the command's own signed expiry: at or before it, by an hour at most.
TEST(MeshRoad, AClockStepMustAgreeWithItsOwnExpiry) {
  Cmd late(9, 1795000150, "time 1795000151");
  EXPECT_EQ(MQTTCTRL_ERR_EXPIRED, mqttCtrlAuthoriseMesh(&late.env, 0, 1700000000, true));
  Cmd edge(9, 1795003600, "time 1795000000");
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthoriseMesh(&edge.env, 0, 1700000000, true));
  Cmd far(9, 1795003601, "time 1795000000");
  EXPECT_EQ(MQTTCTRL_ERR_FUTURE, mqttCtrlAuthoriseMesh(&far.env, 0, 1700000000, true));
}

// Only the whole form: digits, a time that looks synced. Anything else is the deny list's.
TEST(MeshRoad, OnlyAWholeClockStepIsOne) {
  uint32_t e = 0;
  EXPECT_TRUE(mqttCtrlMeshClockStep("time 1795000000", 15, &e));
  EXPECT_EQ(1795000000u, e);
  for (const char* c : { "time", "time ", "time 12", "time 1795000000 x", "time -1", "time 99999999999", "time 0x6AFD", "Time 1795000000", "timex 1795000000", "clock sync" }) {
    EXPECT_FALSE(mqttCtrlMeshClockStep(c, strlen(c), &e)) << c;
  }
  const uint32_t now = 1795000000 - 60;
  for (const char* body : { "time", "time 12", "time 1795000000 x" }) {
    Cmd h(9, 1795000000, body);
    EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthoriseMesh(&h.env, 0, now, true)) << body;
  }
}

// Over MQTT the clock stays out of reach: an Observer node has NTP, and a broker could hold a command.
TEST(MeshRoad, AClockStepOverMqttIsRefused) {
  Cmd step(9, 1795000150, "time 1795000000");
  EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthorise(&step.env, 0, 1795000000, true));
}

// `rekey <43 base64url characters>`: 32 bytes, the whole form, nothing else.
TEST(Rekey, OnlyTheWholeFormNamesAKey) {
  char hex[65];
  // 32 bytes 00..1F, base64url without padding
  const char* ok = "rekey AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
  ASSERT_EQ(49u, strlen(ok));
  ASSERT_TRUE(mqttCtrlRekeyParse(ok, strlen(ok), hex));
  EXPECT_STREQ("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", hex);
  EXPECT_LE(strlen(ok), (size_t)57) << "it must fit the mesh road";
  for (const char* c : { "rekey", "rekey ", "rekey AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh",
                         "rekey AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8A", "rekeyAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8x",
                         "Rekey AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "rekey AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd*h8" }) {
    EXPECT_FALSE(mqttCtrlRekeyParse(c, strlen(c), hex)) << c;
  }
  EXPECT_TRUE(mqttCtrlIsRekey("rekey", 5));
  EXPECT_TRUE(mqttCtrlIsRekey("rekey x", 7));
  EXPECT_FALSE(mqttCtrlIsRekey("rekeyx", 6));
  EXPECT_FALSE(mqttCtrlIsRekey("get rekey", 9));
}

// The deny list admits it on both roads, with or without an uplink: it is how a key is replaced
// without a visit. `set cmd.pubkey` stays out of the plane's reach.
TEST(Rekey, ThePlaneAdmitsItAndStillRefusesTheSerialWay) {
  const char* c = "rekey AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
  EXPECT_TRUE(mqttCtrlCommandAllowed(c, strlen(c), true));
  EXPECT_TRUE(mqttCtrlMeshCommandAllowed(c, strlen(c), true, true));
  EXPECT_TRUE(mqttCtrlMeshCommandAllowed(c, strlen(c), false, false));
  const char* serial = "set cmd.pubkey 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
  EXPECT_FALSE(mqttCtrlCommandAllowed(serial, strlen(serial), true));
  EXPECT_FALSE(mqttCtrlMeshCommandAllowed(serial, strlen(serial), true, true));
}

// A waiting key waits an hour, across millis() wrapping, and not at all when none was offered.
TEST(Rekey, AWaitingKeyWaitsAnHour) {
  EXPECT_FALSE(mqttCtrlRekeyWaiting(false, 0, 10));
  EXPECT_TRUE(mqttCtrlRekeyWaiting(true, 1000, 1000));
  EXPECT_TRUE(mqttCtrlRekeyWaiting(true, 1000, 1000 + MQTTCTRL_REKEY_WAIT_MS - 1));
  EXPECT_FALSE(mqttCtrlRekeyWaiting(true, 1000, 1000 + MQTTCTRL_REKEY_WAIT_MS));
  EXPECT_TRUE(mqttCtrlRekeyWaiting(true, 0xFFFFFF00UL, 0x00000100UL));
  EXPECT_STREQ("rekey", mqttCtrlKeyViaName(MQTTCTRL_KEY_VIA_REKEY));
  EXPECT_STREQ("usb", mqttCtrlKeyViaName(9));
}

TEST(MeshRoad, AnUnsetClockLeavesTheCounterAsTheOnlyGuard) {
  const uint32_t unset = 1715770351 + 3600;           // the firmware's 2024 default, an hour up
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlMeshCheckExpiry(unset, 1795000000));
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlMeshCheckExpiry(0, 1));
  // MQTT still refuses: its expiry window does not move.
  EXPECT_EQ(MQTTCTRL_ERR_FUTURE, mqttCtrlCheckExpiry(unset, 1795000000));
  // A set clock is held to the same window as MQTT.
  EXPECT_EQ(MQTTCTRL_ERR_EXPIRED, mqttCtrlMeshCheckExpiry(1795000001, 1795000000));
  EXPECT_EQ(MQTTCTRL_ERR_FUTURE, mqttCtrlMeshCheckExpiry(1795000000, 1795000000 + MQTTCTRL_MAX_FUTURE_SECS + 1));
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlMeshCheckExpiry(1795000000, 1795000000 + MQTTCTRL_MAX_FUTURE_SECS));
  // ... and the replay still stops an unset clock.
  Cmd h(5, 1795000000, "get name");
  EXPECT_EQ(MQTTCTRL_ERR_REPLAY, mqttCtrlAuthoriseMesh(&h.env, 5, unset, true));
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthoriseMesh(&h.env, 4, unset, true));
}

TEST(MeshRoad, AutoOpensFifteenMinutesAfterTheSlotWentDown) {
  uint32_t down = 0;
  down = mqttCtrlMeshDownSince(true, down, 1000);
  EXPECT_EQ(0u, down);
  EXPECT_FALSE(mqttCtrlMeshOpen(MQTTCTRL_MESH_AUTO, down, 1000));   // MQTT up: closed
  down = mqttCtrlMeshDownSince(false, down, 5000);
  EXPECT_EQ(5000u, down);
  down = mqttCtrlMeshDownSince(false, down, 9000);
  EXPECT_EQ(5000u, down);                                            // kept, not restarted
  EXPECT_FALSE(mqttCtrlMeshOpen(MQTTCTRL_MESH_AUTO, down, 5000 + MQTTCTRL_MESH_AUTO_AFTER_MS - 1));
  EXPECT_TRUE(mqttCtrlMeshOpen(MQTTCTRL_MESH_AUTO, down, 5000 + MQTTCTRL_MESH_AUTO_AFTER_MS));
  EXPECT_EQ(15UL * 60UL * 1000UL, MQTTCTRL_MESH_AUTO_AFTER_MS);
  EXPECT_FALSE(mqttCtrlMeshOpen(MQTTCTRL_MESH_OFF, down, 5000 + 10 * MQTTCTRL_MESH_AUTO_AFTER_MS));
  EXPECT_TRUE(mqttCtrlMeshOpen(MQTTCTRL_MESH_ON, 0, 0));
  // Back up: closed again at once.
  down = mqttCtrlMeshDownSince(true, down, 5000 + MQTTCTRL_MESH_AUTO_AFTER_MS);
  EXPECT_FALSE(mqttCtrlMeshOpen(MQTTCTRL_MESH_AUTO, down, 5000 + MQTTCTRL_MESH_AUTO_AFTER_MS));
  // Down at millis() 0 still counts as down; and across the 49-day wrap.
  EXPECT_NE(0u, mqttCtrlMeshDownSince(false, 0, 0));
  EXPECT_TRUE(mqttCtrlMeshOpen(MQTTCTRL_MESH_AUTO, 0xFFFFF000u, 0xFFFFF000u + MQTTCTRL_MESH_AUTO_AFTER_MS));
  // The refusal has its own name, appended.
  EXPECT_STREQ("mesh-closed", mqttCtrlResultName(MQTTCTRL_ERR_MESH_CLOSED));
  EXPECT_EQ(19, (int)MQTTCTRL_ERR_MESH_CLOSED);
}

TEST(GetCmd, TheLineNamesTheLogin) {
  char out[MQTTCTRL_MAX_REPLY];
  mqttCtrlDescribeSlot(true, 41, 2, true, true, "mqtts://mqtt-meshcore.louie.se:8883",
                       MQTT_SUB_GRANTED, "312 s ago", "pong in 230 ms", out, sizeof(out));
  EXPECT_STREQ("> on, counter 41, slot 2 connected, jwt, /cmd subscribed, last command 312 s ago, "
               "ping pong in 230 ms", out);
  // a password login somewhere else is somebody's own broker, and theirs to judge
  mqttCtrlDescribeSlot(false, 7, 3, false, false, "mqtt://mqtt.example.org:1883",
                       MQTT_SUB_PENDING, "none yet", "-", out, sizeof(out));
  EXPECT_STREQ("> off, counter 7, slot 3 not connected, password, /cmd not subscribed, "
               "last command none yet, ping -", out);
  mqttCtrlDescribeSlot(true, 7, 3, true, false, nullptr, MQTT_SUB_GRANTED, nullptr, nullptr,
                       out, sizeof(out));
  EXPECT_STREQ("> on, counter 7, slot 3 connected, password, /cmd subscribed, last command -, ping -",
               out);
}

TEST(GetCmd, APasswordLoginOnThePlanesOwnBrokerNamesTheCure) {
  char out[MQTTCTRL_MAX_REPLY];
  for (const char* url : { "mqtt://mqtt.louie.se:1883", "mqtts://mqtt.louie.se:8883",
                           "mqtt://mqtt-meshcore.louie.se:1883", "mqtt.meshcore-jkp.se" }) {
    mqttCtrlDescribeSlot(true, 41, 3, true, false, url, MQTT_SUB_REFUSED, "none yet",
                         "no pong in 10 s", out, sizeof(out));
    EXPECT_STREQ("> on, counter 41, slot 3 connected, password (run set cmd on), /cmd refused, "
                 "last command none yet, ping no pong in 10 s", out) << url;
  }
  // a token login there is the plane as it should be
  mqttCtrlDescribeSlot(true, 41, 3, true, true, "mqtts://mqtt.louie.se:8883", MQTT_SUB_GRANTED,
                       "none yet", "-", out, sizeof(out));
  EXPECT_EQ(nullptr, strstr(out, "set cmd on"));
  mqttCtrlDescribeSlot(true, 41, 3, true, false, "mqtt://mqtt.louie.se.example.org:1883",
                       MQTT_SUB_GRANTED, "none yet", "-", out, sizeof(out));
  EXPECT_EQ(nullptr, strstr(out, "set cmd on"));
}

TEST(GetCmd, TheLineStaysInsideTheReply) {
  // a day-old line on a ten-digit counter leaves room for the mesh note, with either login
  char out[MQTTCTRL_MAX_REPLY], note[40];
  mqttCtrlMeshNote(MQTTCTRL_MESH_AUTO, 0, 0, note, sizeof(note));
  mqttCtrlDescribeSlot(true, 1794734056UL, 3, true, true, "mqtts://mqtt-meshcore.louie.se:8883",
                       MQTT_SUB_GRANTED, "86400 s ago", "pong in 1234 ms", out, sizeof(out));
  EXPECT_LE(strlen(out) + strlen(note), (size_t)MQTTCTRL_MAX_REPLY - 1);
  mqttCtrlDescribeSlot(true, 1794734056UL, 3, true, false, "mqtt://mqtt.louie.se:1883",
                       MQTT_SUB_REFUSED, "none yet", "no pong in 10 s", out, sizeof(out));
  EXPECT_LE(strlen(out) + strlen(note), (size_t)MQTTCTRL_MAX_REPLY - 1);
  // and whatever it is given, it is cut and never overrun
  char tiny[24];
  memset(tiny, 'x', sizeof(tiny));
  mqttCtrlDescribeSlot(false, 4294967295UL, 6, false, false, "mqtt.louie.se", MQTT_SUB_PENDING,
                       "4294967 s ago", "no pong in 10 s", tiny, sizeof(tiny) - 4);
  EXPECT_STREQ("> off, counter 4294", tiny);
  EXPECT_EQ('x', tiny[20]);
  mqttCtrlDescribeSlot(true, 1, 1, true, true, "", MQTT_SUB_GRANTED, "", "", nullptr, 10);
  mqttCtrlDescribeSlot(true, 1, 1, true, true, "", MQTT_SUB_GRANTED, "", "", tiny, 0);
}

TEST(MeshRoad, ASlotTheServerRefusesIsDown) {
  EXPECT_TRUE(mqttCtrlSlotUp(true, MQTT_SUB_GRANTED));
  EXPECT_TRUE(mqttCtrlSlotUp(true, MQTT_SUB_PENDING));       // just connected, no SUBACK yet
  EXPECT_FALSE(mqttCtrlSlotUp(true, MQTT_SUB_REFUSED));
  EXPECT_FALSE(mqttCtrlSlotUp(false, MQTT_SUB_PENDING));
  EXPECT_FALSE(mqttCtrlSlotUp(false, MQTT_SUB_GRANTED));
  EXPECT_FALSE(mqttCtrlSlotUp(false, MQTT_SUB_REFUSED));
}

TEST(MeshRoad, ARefusedSlotOpensTheRoadAfterTheUsualWait) {
  // connected the whole time: pending for a moment, then mcc/cmd refused, and it stays so
  uint32_t since = 0, now = 5000;
  since = mqttCtrlMeshDownSince(mqttCtrlSlotUp(true, MQTT_SUB_PENDING), since, now);
  EXPECT_EQ(0u, since);
  now += 200;
  since = mqttCtrlMeshDownSince(mqttCtrlSlotUp(true, MQTT_SUB_REFUSED), since, now);
  EXPECT_EQ(5200u, since);
  EXPECT_FALSE(mqttCtrlMeshOpen(MQTTCTRL_MESH_AUTO, since, now + MQTTCTRL_MESH_AUTO_AFTER_MS - 1));
  EXPECT_TRUE(mqttCtrlMeshOpen(MQTTCTRL_MESH_AUTO, since, now + MQTTCTRL_MESH_AUTO_AFTER_MS));
  EXPECT_FALSE(mqttCtrlMeshOpen(MQTTCTRL_MESH_OFF, since, now + MQTTCTRL_MESH_AUTO_AFTER_MS));
  char out[MQTTCTRL_MAX_REPLY];
  mqttCtrlMeshDescribe(MQTTCTRL_MESH_AUTO, since, since + 3 * 60000, true, out, sizeof(out));
  EXPECT_STREQ("> auto, closed: the server refuses /cmd 3 min", out);
  mqttCtrlMeshDescribe(MQTTCTRL_MESH_AUTO, since, since + 17 * 60000, true, out, sizeof(out));
  EXPECT_STREQ("> auto, open: the server refuses /cmd 17 min", out);
  // the slot granted again closes it
  since = mqttCtrlMeshDownSince(mqttCtrlSlotUp(true, MQTT_SUB_GRANTED), since, now);
  EXPECT_EQ(0u, since);
  mqttCtrlMeshDescribe(MQTTCTRL_MESH_AUTO, since, now, false, out, sizeof(out));
  EXPECT_STREQ("> auto, closed: MQTT up", out);
}

TEST(MeshRoad, ModesParseAndDescribe) {
  uint8_t m = 9;
  ASSERT_TRUE(mqttCtrlMeshParseMode("off", &m)); EXPECT_EQ(MQTTCTRL_MESH_OFF, m);
  ASSERT_TRUE(mqttCtrlMeshParseMode("on", &m)); EXPECT_EQ(MQTTCTRL_MESH_ON, m);
  ASSERT_TRUE(mqttCtrlMeshParseMode("auto", &m)); EXPECT_EQ(MQTTCTRL_MESH_AUTO, m);
  EXPECT_FALSE(mqttCtrlMeshParseMode("yes", &m));
  EXPECT_FALSE(mqttCtrlMeshParseMode("", &m));
  char out[MQTTCTRL_MAX_REPLY];
  mqttCtrlMeshDescribe(MQTTCTRL_MESH_AUTO, 0, 1000, false, out, sizeof(out));
  EXPECT_STREQ("> auto, closed: MQTT up", out);
  mqttCtrlMeshDescribe(MQTTCTRL_MESH_AUTO, 1000, 1000 + 3 * 60000, false, out, sizeof(out));
  EXPECT_STREQ("> auto, closed: MQTT down 3 min", out);
  mqttCtrlMeshDescribe(MQTTCTRL_MESH_AUTO, 1000, 1000 + 17 * 60000, false, out, sizeof(out));
  EXPECT_STREQ("> auto, open: MQTT down 17 min", out);
  mqttCtrlMeshDescribe(MQTTCTRL_MESH_OFF, 1000, 1000 + 17 * 60000, false, out, sizeof(out));
  EXPECT_STREQ("> off, closed", out);
  mqttCtrlMeshNote(MQTTCTRL_MESH_AUTO, 2, 5, out, sizeof(out));
  EXPECT_STREQ(", mesh auto ok 2 refused 5", out);
}

// ---- the relay (lou-20) ---------------------------------------------------------------

TEST(Relay, ModesParseAndDescribe) {
  uint8_t m = 9;
  ASSERT_TRUE(mqttCtrlRelayParseMode("off", &m)); EXPECT_EQ(MQTTCTRL_RELAY_OFF, m);
  ASSERT_TRUE(mqttCtrlRelayParseMode("own", &m)); EXPECT_EQ(MQTTCTRL_RELAY_OWN, m);
  for (const char* bad : { "on", "listed", "anyone", "OWN", "own ", "" }) {
    EXPECT_FALSE(mqttCtrlRelayParseMode(bad, &m)) << bad;
  }
  EXPECT_EQ(MQTTCTRL_RELAY_OWN, m);
  EXPECT_FALSE(mqttCtrlRelayParseMode(NULL, &m));
  EXPECT_EQ(0, (int)MQTTCTRL_RELAY_OWN);           // a file older than the setting reads as own

  char out[MQTTCTRL_MAX_REPLY];
  mqttCtrlRelayDescribe(MQTTCTRL_RELAY_OFF, 5, 4, 1, MQTTCTRL_AIR_BURST, 1000, 3, out, sizeof(out));
  EXPECT_STREQ("> off", out);
  mqttCtrlRelayDescribe(MQTTCTRL_RELAY_OWN, 0, 0, 0, MQTTCTRL_AIR_IDLE, MQTTCTRL_AIR_BURST_MS, 0, out, sizeof(out));
  EXPECT_STREQ("> own, forwarded 0, answered 0, refused 0, idle, 45.0 s airtime left, floods today 0 of 100", out);
  mqttCtrlRelayDescribe(MQTTCTRL_RELAY_OWN, 12, 9, 3, MQTTCTRL_AIR_BURST, 24650, 4, out, sizeof(out));
  EXPECT_STREQ("> own, forwarded 12, answered 9, refused 3, burst, 24.6 s airtime left, floods today 4 of 100", out);
  mqttCtrlRelayDescribe(MQTTCTRL_RELAY_OWN, 30, 30, 0, MQTTCTRL_AIR_COOL, 0, 100, out, sizeof(out));
  EXPECT_STREQ("> own, forwarded 30, answered 30, refused 0, cooldown, 0.0 s airtime left, floods today 100 of 100", out);
  mqttCtrlRelayDescribe(MQTTCTRL_RELAY_OWN, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, MQTTCTRL_AIR_COOL,
                        0xFFFFFFFFu, 100, out, sizeof(out));
  EXPECT_LT(strlen(out), (size_t)MQTTCTRL_MAX_REPLY - 1);
}

TEST(Relay, TheOwnerSwitchesItOverThePlaneAndNothingUnderMqttCmdOpens) {
  // `relay` is outside `cmd`, so the deny list admits it on both roads, with or
  // without auto-reply, and needs no exception.
  for (const char* c : { "set relay own", "set relay off", "get relay" }) {
    EXPECT_FALSE(mqttCtrlCommandDenied(c, strlen(c))) << c;
    EXPECT_TRUE(mqttCtrlCommandAllowed(c, strlen(c), true)) << c;
    EXPECT_TRUE(mqttCtrlCommandAllowed(c, strlen(c), false)) << c;
    EXPECT_TRUE(mqttCtrlMeshCommandAllowed(c, strlen(c), true)) << c;
    EXPECT_FALSE(mqttCtrlIsTransmitCommand(c, strlen(c))) << c;
  }
  // The plane's own settings stay where they were, the name the research first gave it too.
  for (const char* c : { "set cmd off", "set cmd.relay own", "set cmd.relay off",
                         "set cmd.mesh on", "set cmd.slot 2", "set cmd.pubkey 00",
                         "get cmd.pubkey" }) {
    EXPECT_TRUE(mqttCtrlCommandDenied(c, strlen(c))) << c;
    EXPECT_FALSE(mqttCtrlCommandAllowed(c, strlen(c), true)) << c;
  }
}

// The budgets are in RAM and a restart opens a burst: a cooldown after every boot was tried
// and withdrawn (operator 2026-11-23). Pinned, so that it does not come back unnoticed.
TEST(AirBudget, ANodeJustStartedHasItsBurst) {
  const uint32_t t = 1795000000;
  MqttCtrlAirBudget b;
  EXPECT_FALSE(b.cooling(t));
  EXPECT_EQ(MQTTCTRL_AIR_BURST_MS, b.leftMs(t));
  MqttCtrlRelayBudget r;
  EXPECT_TRUE(r.allows(t, true, false));
  EXPECT_TRUE(r.allows(t, true, true));
}

TEST(AirBudget, ABurstOfFivePerCentThenACooldownOfOneThenABurstAgain) {
  EXPECT_EQ(MQTTCTRL_AIR_QUARTER_SECS * 1000UL * 5 / 100, MQTTCTRL_AIR_BURST_MS);
  EXPECT_EQ(MQTTCTRL_AIR_QUARTER_SECS * 1000UL * 1 / 100, MQTTCTRL_AIR_COOL_MS);
  MqttCtrlAirBudget b;
  const uint32_t t = 1795000000;
  // Asking spends nothing and opens nothing.
  for (int i = 0; i < 100; i++) EXPECT_TRUE(b.allows(t));
  EXPECT_EQ(MQTTCTRL_AIR_IDLE, b.phase(t));
  EXPECT_EQ(MQTTCTRL_AIR_BURST_MS, b.leftMs(t));

  // The first packet opens the burst; 1 700 ms each, the 27th is the one that crosses 45 s.
  int sent = 0;
  while (b.allows(t + 10 + sent)) {
    b.spend(t + 10 + sent, 1700);
    sent++;
  }
  EXPECT_EQ(27, sent);
  EXPECT_EQ(MQTTCTRL_AIR_BURST, b.phase(t + 100));
  EXPECT_EQ(0u, b.leftMs(t + 100));
  EXPECT_FALSE(b.allows(t + 10 + MQTTCTRL_AIR_QUARTER_SECS - 1));

  // The cooldown starts a quarter after the burst opened, used up or not, with 9 s.
  const uint32_t cool = t + 10 + MQTTCTRL_AIR_QUARTER_SECS;
  EXPECT_EQ(MQTTCTRL_AIR_COOL, b.phase(cool));
  EXPECT_EQ(MQTTCTRL_AIR_COOL_MS, b.leftMs(cool));
  sent = 0;
  while (b.allows(cool + sent)) {
    b.spend(cool + sent, 1700);
    sent++;
  }
  EXPECT_EQ(6, sent);
  EXPECT_FALSE(b.allows(cool + MQTTCTRL_AIR_QUARTER_SECS - 1));

  // After it the next packet opens a new burst, whenever it comes.
  const uint32_t again = cool + MQTTCTRL_AIR_QUARTER_SECS + 5000;
  EXPECT_EQ(MQTTCTRL_AIR_IDLE, b.phase(again));
  EXPECT_TRUE(b.allows(again));
  b.spend(again, 1700);
  EXPECT_EQ(MQTTCTRL_AIR_BURST, b.phase(again));
  EXPECT_EQ(MQTTCTRL_AIR_BURST_MS - 1700, b.leftMs(again + MQTTCTRL_AIR_QUARTER_SECS - 1));
  EXPECT_EQ(MQTTCTRL_AIR_COOL, b.phase(again + MQTTCTRL_AIR_QUARTER_SECS));
}

TEST(AirBudget, AClockSteppedBackwardsMintsNoBurst) {
  const uint32_t t = 1795000000;
  MqttCtrlAirBudget b;
  b.spend(t, MQTTCTRL_AIR_BURST_MS);
  EXPECT_FALSE(b.allows(t - 86400));                               // the burst restarts, still spent
  EXPECT_FALSE(b.allows(t - 86400 + MQTTCTRL_AIR_QUARTER_SECS - 1));
  EXPECT_EQ(MQTTCTRL_AIR_COOL, b.phase(t - 86400 + MQTTCTRL_AIR_QUARTER_SECS));

  MqttCtrlAirBudget c;                                             // in a cooldown it stays one
  c.spend(t, 100);
  c.spend(t + MQTTCTRL_AIR_QUARTER_SECS, MQTTCTRL_AIR_COOL_MS);
  EXPECT_FALSE(c.allows(t + MQTTCTRL_AIR_QUARTER_SECS + 1));
  EXPECT_EQ(MQTTCTRL_AIR_COOL, c.phase(t + 100));                  // a small step back, into the burst's time
  EXPECT_FALSE(c.allows(t + 100));
  EXPECT_FALSE(c.allows(t + 100 + MQTTCTRL_AIR_QUARTER_SECS - 1));
  EXPECT_EQ(MQTTCTRL_AIR_COOL, c.phase(t - 5000));
  EXPECT_FALSE(c.allows(t - 5000));
  EXPECT_FALSE(c.allows(t - 5000 + MQTTCTRL_AIR_QUARTER_SECS - 1));
  EXPECT_TRUE(c.allows(t - 5000 + MQTTCTRL_AIR_QUARTER_SECS));
  // A huge packet length cannot wrap the count round to nothing spent.
  MqttCtrlAirBudget d;
  d.spend(t, 0xFFFFFFF0u);
  d.spend(t, 0x100);
  EXPECT_FALSE(d.allows(t));
}

TEST(Relay, FloodsKeepAGapADayAndAnHourOfTheirOwn) {
  const uint32_t t = 1795000000, air = 1700;
  MqttCtrlRelayBudget b;
  for (int i = 0; i < 100; i++) EXPECT_TRUE(b.allows(t, true, true));   // asking spends nothing
  EXPECT_EQ(0, b.floodsToday(t));

  // In a burst one flood a minute; a direct forward waits for no gap.
  b.spend(t, true, false, air);
  EXPECT_FALSE(b.allows(t + MQTTCTRL_RELAY_FLOOD_GAP_SECS - 1, true, false));
  EXPECT_TRUE(b.allows(t + 1, false, false));
  EXPECT_TRUE(b.allows(t + MQTTCTRL_RELAY_FLOOD_GAP_SECS, true, false));
  int floods = 1;
  for (uint32_t at = t + 60; at < t + MQTTCTRL_AIR_QUARTER_SECS; at += 20) {
    if (!b.allows(at, true, false)) continue;
    b.spend(at, true, false, air);
    floods++;
  }
  EXPECT_EQ(15, floods);

  // In the cooldown one in five minutes.
  const uint32_t cool = t + MQTTCTRL_AIR_QUARTER_SECS;
  floods = 0;
  for (uint32_t at = cool; at < cool + MQTTCTRL_AIR_QUARTER_SECS; at += 20) {
    if (!b.allows(at, true, false)) continue;
    b.spend(at, true, false, air);
    floods++;
  }
  EXPECT_EQ(3, floods);
  EXPECT_EQ(18, b.floodsToday(cool + 899));
}

TEST(Relay, AHundredFloodsADayAndTwoWideOnesAnHour) {
  const uint32_t t = 1795000000;
  MqttCtrlRelayBudget b;
  // No airtime, so only the flood limits speak. A flood every five minutes.
  int given = 0;
  uint32_t at = t;
  for (; given < MQTTCTRL_RELAY_FLOODS_A_DAY; at += 300) {
    ASSERT_TRUE(b.allows(at, true, false)) << given;
    b.spend(at, true, false, 0);
    given++;
  }
  EXPECT_FALSE(b.allows(at, true, false));
  EXPECT_TRUE(b.allows(at, false, false));                       // a direct forward is not a flood
  EXPECT_FALSE(b.allows(t + MQTTCTRL_RELAY_DAY_SECS - 1, true, false));
  EXPECT_TRUE(b.allows(t + MQTTCTRL_RELAY_DAY_SECS, true, false));
  b.spend(t + MQTTCTRL_RELAY_DAY_SECS, true, false, 0);
  EXPECT_EQ(1, b.floodsToday(t + MQTTCTRL_RELAY_DAY_SECS));

  MqttCtrlRelayBudget w;
  w.spend(t, true, true, 0);
  w.spend(t + 600, true, true, 0);
  EXPECT_FALSE(w.allows(t + 1200, true, true));
  EXPECT_TRUE(w.allows(t + 1200, true, false));                  // a flood in the region home may go
  EXPECT_FALSE(w.allows(t + 3599, true, true));
  EXPECT_TRUE(w.allows(t + 3600, true, true));
  w.spend(t + 3600, true, true, 0);
  EXPECT_FALSE(w.allows(t + 4199, true, true));
  EXPECT_TRUE(w.allows(t + 4200, true, true));

  // A clock stepped backwards mints nothing: what is remembered is pulled back to now.
  MqttCtrlRelayBudget c;
  c.spend(t, true, true, 0);
  c.spend(t + 600, true, true, 0);
  EXPECT_FALSE(c.allows(t - 86400, true, false));                 // the gap counts from now
  EXPECT_TRUE(c.allows(t - 86400 + 60, true, false));
  EXPECT_FALSE(c.allows(t - 86400 + 60, true, true));             // and so does the wide hour
  EXPECT_FALSE(c.allows(t - 86400 + 3659, true, true));
  EXPECT_TRUE(c.allows(t - 86400 + 3660, true, true));
}

TEST(Relay, AnEmptyAirBudgetStopsEveryForward) {
  const uint32_t t = 1795000000;
  MqttCtrlRelayBudget b;
  b.spend(t, false, false, MQTTCTRL_AIR_BURST_MS);
  EXPECT_FALSE(b.allows(t + 100, false, false));
  EXPECT_FALSE(b.allows(t + 100, true, false));
  EXPECT_TRUE(b.allows(t + MQTTCTRL_AIR_QUARTER_SECS, false, false));
}

// The way back to a sender (bench at Gisebo, 2026-11-23): kept for the three last answered.
static void requesterKey(uint8_t* key, uint8_t first, uint8_t fill) {
  memset(key, fill, MQTTCTRL_REQUESTER_KEY_LEN);
  key[0] = first;
}

TEST(Requesters, ASenderAnsweredIsListenedToForFiveMinutesAndKeepsThePathItBrings) {
  MqttCtrlRequesters r;
  uint8_t a[32], secret[32], other[32];
  requesterKey(a, 0xF4, 1);
  requesterKey(other, 0xF4, 2);
  memset(secret, 7, sizeof(secret));
  EXPECT_EQ(-1, r.find(a));
  EXPECT_EQ(nullptr, r.pathTo(a));
  EXPECT_FALSE(r.listening(0, 1000));

  const int i = r.note(a, secret, 1000);
  ASSERT_GE(i, 0);
  EXPECT_EQ(i, r.find(a));
  EXPECT_EQ(-1, r.find(other));                       // the same first byte is not the same sender
  EXPECT_TRUE(r.listening(i, 1000));
  EXPECT_TRUE(r.listening(i, 1000 + MQTTCTRL_REQUESTER_LISTEN_MS - 1));
  EXPECT_FALSE(r.listening(i, 1000 + MQTTCTRL_REQUESTER_LISTEN_MS));
  EXPECT_EQ(0, memcmp(secret, r.entry[i].secret, 32));
  EXPECT_EQ(nullptr, r.pathTo(a));                    // answered, but it has brought no path yet

  // Two hops of three-byte hashes: path length 0x82.
  const uint8_t path[6] = { 0x4A, 0xC6, 0x1A, 0x70, 0x16, 0x53 };
  ASSERT_TRUE(r.learn(i, path, 0x82));
  const MqttCtrlRequester* way = r.pathTo(a);
  ASSERT_NE(nullptr, way);
  EXPECT_EQ(0x82, way->path_len);
  EXPECT_EQ(0, memcmp(path, way->path, 6));

  // Answered again: the path stays, the five minutes start anew, across the millis wrap too.
  EXPECT_EQ(i, r.note(a, secret, 0xFFFFFF00u));
  EXPECT_NE(nullptr, r.pathTo(a));
  EXPECT_TRUE(r.listening(i, 100));
  EXPECT_FALSE(r.listening(i, 0xFFFFFF00u + MQTTCTRL_REQUESTER_LISTEN_MS));

  // A neighbour's way back has no hops, and is a path all the same.
  ASSERT_TRUE(r.learn(i, NULL, 0));
  ASSERT_NE(nullptr, r.pathTo(a));
  EXPECT_EQ(0, r.pathTo(a)->path_len);
}

TEST(Requesters, AFourthSenderTakesThePlaceOfTheOneHeardLongestAgo) {
  MqttCtrlRequesters r;
  uint8_t key[5][32], secret[32] = {0};
  for (int k = 0; k < 5; k++) requesterKey(key[k], (uint8_t)(0x10 + k), (uint8_t)k);
  const uint8_t hop[1] = { 0xAA };
  EXPECT_EQ(0, r.note(key[0], secret, 1000));
  EXPECT_EQ(1, r.note(key[1], secret, 2000));
  EXPECT_EQ(2, r.note(key[2], secret, 3000));
  ASSERT_TRUE(r.learn(0, hop, 1));
  ASSERT_TRUE(r.learn(1, hop, 1));
  EXPECT_EQ(0, r.note(key[0], secret, 4000));         // the first is heard again
  EXPECT_EQ(1, r.note(key[3], secret, 5000));         // so the second goes, and its path with it
  EXPECT_EQ(-1, r.find(key[1]));
  EXPECT_EQ(nullptr, r.pathTo(key[3]));
  EXPECT_NE(nullptr, r.pathTo(key[0]));
  EXPECT_EQ(2, r.note(key[4], secret, 6000));
  EXPECT_EQ(-1, r.find(key[2]));
}

TEST(Requesters, APathThatDoesNotFitOrIsMalformedIsNotKept) {
  MqttCtrlRequesters r;
  uint8_t a[32], secret[32] = {0}, path[64] = {0};
  requesterKey(a, 0xF4, 1);
  const int i = r.note(a, secret, 1);
  EXPECT_EQ(63, mqttCtrlPathBytes(0x3F, 64));
  EXPECT_EQ(64, mqttCtrlPathBytes(0x60, 64));          // 32 two-byte hashes
  EXPECT_EQ(-1, mqttCtrlPathBytes(0x61, 64));          // 33 of them
  EXPECT_EQ(-1, mqttCtrlPathBytes(0x96, 64));          // 22 three-byte hashes: 66 bytes
  EXPECT_EQ(-1, mqttCtrlPathBytes(0xC1, 64));          // the reserved hash size
  EXPECT_TRUE(r.learn(i, path, 0x60));
  EXPECT_FALSE(r.learn(i, path, 0x61));
  EXPECT_FALSE(r.learn(i, path, 0xC1));
  EXPECT_FALSE(r.learn(i, NULL, 0x01));
  EXPECT_FALSE(r.learn(-1, path, 0x01));
  EXPECT_FALSE(r.learn(MQTTCTRL_REQUESTERS, path, 0x01));
  EXPECT_FALSE(r.learn(2, path, 0x01));                // nobody is there
  EXPECT_EQ(0x60, r.pathTo(a)->path_len);              // the refusals changed nothing
  EXPECT_EQ(-1, r.note(NULL, secret, 1));
  EXPECT_EQ(-1, r.note(a, NULL, 1));
  EXPECT_EQ(-1, r.find(NULL));
}

TEST(MeshRoad, AFloodedRequestIsAnsweredOnceItsCopiesHaveDiedDown) {
  EXPECT_EQ(300u, mqttCtrlMeshAnswerDelay(false, 0));
  EXPECT_EQ(300u, mqttCtrlMeshAnswerDelay(false, 0xFFFFFFFFu));
  EXPECT_EQ(15000u, mqttCtrlMeshAnswerDelay(true, 0));
  EXPECT_EQ(30000u, mqttCtrlMeshAnswerDelay(true, 15000));
  EXPECT_EQ(15000u, mqttCtrlMeshAnswerDelay(true, 15001));
  bool low = false, high = false;
  for (uint32_t r = 0; r < 100000; r += 7) {
    const uint32_t d = mqttCtrlMeshAnswerDelay(true, r * 2654435761u);
    ASSERT_GE(d, 15000u);
    ASSERT_LE(d, 30000u);
    low = low || d < 17000;
    high = high || d > 28000;
  }
  EXPECT_TRUE(low && high);
  // Well inside the two minutes a relay waits, with the flood's own travel either way.
  EXPECT_LT(MQTTCTRL_MESH_FLOOD_ANSWER_MIN_MS + MQTTCTRL_MESH_FLOOD_ANSWER_SPAN_MS + 2 * 30000UL, 120000UL);
}

TEST(MeshRoad, TheResponseRoomIsTheDatagramsAndThePathReturns) {
  // Mesh::createDatagram and Mesh::createPathReturn's own bounds.
  EXPECT_EQ(167u, mqttCtrlMeshResponseRoom(false, 0));
  EXPECT_EQ((size_t)(MAX_PACKET_PAYLOAD - CIPHER_MAC_SIZE - (CIPHER_BLOCK_SIZE - 1)),
            mqttCtrlMeshResponseRoom(false, 0));
  EXPECT_EQ((size_t)(MAX_PACKET_PAYLOAD - 2 - CIPHER_BLOCK_SIZE - 5 - 30), mqttCtrlMeshResponseRoom(true, 30));
  EXPECT_EQ(0u, mqttCtrlMeshResponseRoom(true, 200));
}

// ---- mesh only (operator 2026-11-16, plan phase 5) -----------------------------------
//
// An image without Wi-Fi and MQTT (an nRF52 board, a non-Observer ESP32 build) has the mesh
// road as the plane's only road: the same counter, expiry and deny list, always open, the
// uplink's repairs refused.

// ---- alive (mcc3, lou-20) -------------------------------------------------------------

TEST(Alive, TheIntervalIsFiveMinutesToADayAndHasNoOff) {
  uint16_t m = 0;
  EXPECT_TRUE(mqttCtrlAliveParseMinutes("5", &m));
  EXPECT_EQ(5, m);
  EXPECT_TRUE(mqttCtrlAliveParseMinutes("1440", &m));
  EXPECT_EQ(1440, m);
  for (const char* bad : { "4", "1441", "0", "off", "", "15 ", "-5", "99999999999" }) {
    EXPECT_FALSE(mqttCtrlAliveParseMinutes(bad, &m)) << bad;
  }
  EXPECT_EQ(15, mqttCtrlAliveMinutes(0));
  EXPECT_EQ(60, mqttCtrlAliveMinutes(60));
  // Admitted over the plane, so the owner tunes it remotely; the plane's own settings are not.
  const char* set = "set alive.interval 30";
  EXPECT_TRUE(mqttCtrlCommandAllowed(set, strlen(set), false));
  EXPECT_TRUE(mqttCtrlMeshCommandAllowed(set, strlen(set), false));
}

TEST(Alive, AFirstConnectWaitsUpToTwoMinutesAReconnectFiveToSixtySeconds) {
  MqttCtrlAliveClock c = {};
  const uint32_t t0 = 1000;
  mqttCtrlAliveLink(&c, false, t0, 0);
  EXPECT_FALSE(mqttCtrlAliveDue(&c, t0 + 10000000));            // never while down
  mqttCtrlAliveLink(&c, true, t0, 120000);                      // the top of 0..120 s
  EXPECT_FALSE(mqttCtrlAliveDue(&c, t0 + 119999));
  EXPECT_TRUE(mqttCtrlAliveDue(&c, t0 + 120000));
  mqttCtrlAliveLink(&c, true, t0 + 200000, 0);                  // still up: nothing moves
  EXPECT_TRUE(mqttCtrlAliveDue(&c, t0 + 120000));

  MqttCtrlAliveClock d = {};
  mqttCtrlAliveLink(&d, true, t0, 0);
  EXPECT_TRUE(mqttCtrlAliveDue(&d, t0));                        // the bottom: at once
  mqttCtrlAliveSent(&d, t0, 900, 0);
  mqttCtrlAliveLink(&d, false, t0 + 1000, 0);
  EXPECT_FALSE(mqttCtrlAliveDue(&d, t0 + 10000000));
  mqttCtrlAliveLink(&d, true, t0 + 2000, 0);                    // reconnect: 5 s at least
  EXPECT_FALSE(mqttCtrlAliveDue(&d, t0 + 2000 + 4999));
  EXPECT_TRUE(mqttCtrlAliveDue(&d, t0 + 2000 + 5000));
  mqttCtrlAliveLink(&d, false, t0 + 3000, 0);
  mqttCtrlAliveLink(&d, true, t0 + 4000, 55000);                // ... and 60 s at most
  EXPECT_FALSE(mqttCtrlAliveDue(&d, t0 + 4000 + 59999));
  EXPECT_TRUE(mqttCtrlAliveDue(&d, t0 + 4000 + 60000));
}

TEST(Alive, TheNextIsHalfToOneAndAHalfIntervalsAwayAcrossTheWrap) {
  MqttCtrlAliveClock c = {};
  const uint32_t t0 = 0xFFFFFFFFu - 100000;                    // millis() about to wrap
  mqttCtrlAliveLink(&c, true, t0, 0);
  mqttCtrlAliveSent(&c, t0, 900, 0);                            // U(0.5, 1.5) at its bottom
  EXPECT_FALSE(mqttCtrlAliveDue(&c, t0 + 449999));
  EXPECT_TRUE(mqttCtrlAliveDue(&c, t0 + 450000));
  mqttCtrlAliveSent(&c, t0, 900, 900000);                       // ... and its top
  EXPECT_FALSE(mqttCtrlAliveDue(&c, t0 + 1349999));
  EXPECT_TRUE(mqttCtrlAliveDue(&c, t0 + 1350000));
  mqttCtrlAliveSent(&c, t0, 1440 * 60, 0xFFFFFFFFu);            // a day fits in 32 bits of ms
  EXPECT_FALSE(mqttCtrlAliveDue(&c, t0 + 1440UL * 30000UL - 1));
}

TEST(Alive, AChangeBringsTheNextOneCloserButNeverPutsItOff) {
  MqttCtrlAliveClock c = {};
  mqttCtrlAliveLink(&c, true, 0, 0);
  mqttCtrlAliveSent(&c, 0, 900, 0);                             // due at 450 s
  mqttCtrlAliveNudge(&c, 1000, 0);                              // a key change: 5 s from now
  EXPECT_FALSE(mqttCtrlAliveDue(&c, 5999));
  EXPECT_TRUE(mqttCtrlAliveDue(&c, 6000));
  mqttCtrlAliveNudge(&c, 2000, 55000);                          // 60 s from now is later: kept
  EXPECT_TRUE(mqttCtrlAliveDue(&c, 6000));
  MqttCtrlAliveClock down = {};
  mqttCtrlAliveNudge(&down, 0, 0);                              // down: the reconnect sends one
  EXPECT_FALSE(mqttCtrlAliveDue(&down, 100000));
}

TEST(MeshOnly, TheRoadListensWhileThePlaneIsOnAndIsAlwaysOpen) {
  for (uint8_t mode : { MQTTCTRL_MESH_AUTO, MQTTCTRL_MESH_ON, MQTTCTRL_MESH_OFF }) {
    EXPECT_TRUE(mqttCtrlMeshListening(true, false, mode)) << (int)mode;
    EXPECT_FALSE(mqttCtrlMeshListening(false, false, mode)) << (int)mode;
    EXPECT_TRUE(mqttCtrlMeshRoadOpen(false, mode, 0, 1000)) << (int)mode;
  }
  // With an uplink, as before: off is silent, auto waits for the slot to be down 15 min.
  EXPECT_FALSE(mqttCtrlMeshListening(true, true, MQTTCTRL_MESH_OFF));
  EXPECT_TRUE(mqttCtrlMeshListening(true, true, MQTTCTRL_MESH_AUTO));
  EXPECT_FALSE(mqttCtrlMeshRoadOpen(true, MQTTCTRL_MESH_AUTO, 0, 1000));
  EXPECT_TRUE(mqttCtrlMeshRoadOpen(true, MQTTCTRL_MESH_AUTO, 1000, 1000 + MQTTCTRL_MESH_AUTO_AFTER_MS));
}

TEST(MeshOnly, ACommandIsAcceptedWithNoUplink) {
  const uint32_t now = 1795000000 - 60;
  Cmd h(9, 1795000000, "get name");
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthoriseMesh(&h.env, 0, now, true, false));
  Cmd r(9, 1795000000, "reboot");
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthoriseMesh(&r.env, 0, now, false, false));
  Cmd t(9, 1795000000, "trigger test");
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthoriseMesh(&t.env, 0, now, true, false));
  EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthoriseMesh(&t.env, 0, now, false, false));
}

TEST(MeshOnly, TheUplinksRepairsAndItsUpdateAreRefused) {
  const char* refused[] = {
    "set wifi.ssid HomeNet", "set wifi.pwd hunter2", "set cmd on",
    "set cmd on mqtt-meshcore.louie.se", "ota update", "ota check", "cmd ping",
    "OTA UPDATE", "set mqtt1.preset meshat.se", "set mqtt2.server mqtt.example.org", "SET MQTT6.PORT 1883",
  };
  const uint32_t now = 1795000000 - 60;
  for (const char* c : refused) {
    EXPECT_FALSE(mqttCtrlMeshCommandAllowed(c, strlen(c), true, false)) << c;
    Cmd h(9, 1795000000, c);
    EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthoriseMesh(&h.env, 0, now, true, false)) << c;
  }
  // With an uplink the same commands travel as before.
  for (const char* c : refused) EXPECT_TRUE(mqttCtrlMeshCommandAllowed(c, strlen(c), true)) << c;
  EXPECT_FALSE(mqttCtrlMeshCommandAllowed("ota updatex", 11, true, false));
  // Only a slot: the plane's own settings and a name that merely starts so are not the slot's.
  EXPECT_FALSE(mqttCtrlNeedsUplink("set mqtt.iata GOT", 17));
  EXPECT_FALSE(mqttCtrlNeedsUplink("set mqtt1", 9));
  EXPECT_FALSE(mqttCtrlNeedsUplink("set mqttx.preset a", 18));
}

TEST(MeshOnly, CounterExpiryAndDenyListAreUnchanged) {
  // Every known command: what the plane admits, less what needs an uplink.
  for (const char* c : known_commands) {
    const size_t n = strlen(c);
    EXPECT_EQ(allowed(c) && !mqttCtrlNeedsUplink(c, n), mqttCtrlMeshCommandAllowed(c, n, true, false)) << c;
    EXPECT_EQ(allowedWithoutAutoReply(c) && !mqttCtrlNeedsUplink(c, n),
              mqttCtrlMeshCommandAllowed(c, n, false, false)) << c;
  }
  const uint32_t unset = 1715770351 + 3600;
  Cmd h(5, 1795000000, "get name");
  EXPECT_EQ(MQTTCTRL_ERR_REPLAY, mqttCtrlAuthoriseMesh(&h.env, 5, unset, true, false));
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthoriseMesh(&h.env, 4, unset, true, false));
  EXPECT_EQ(MQTTCTRL_ERR_EXPIRED, mqttCtrlAuthoriseMesh(&h.env, 4, 1795000001, true, false));
  EXPECT_EQ(MQTTCTRL_ERR_FUTURE, mqttCtrlAuthoriseMesh(&h.env, 4, 1795000000 - MQTTCTRL_MAX_FUTURE_SECS - 1,
                                                       true, false));
}

// ---- The arrivals queue ----

static bool push(MqttCtrlQueue* q, const std::string& topic, const std::string& payload) {
  return mqttCtrlQueuePush(q, topic.c_str(), (const uint8_t*)payload.data(), payload.size());
}

TEST(ArrivalsQueue, TwoBackToBackAreBothTakenInOrder) {
  static MqttCtrlQueue q;
  mqttCtrlQueueReset(&q);
  EXPECT_EQ(nullptr, mqttCtrlQueueFront(&q));
  EXPECT_TRUE(push(&q, "mcc/cmd/a", "first"));
  EXPECT_TRUE(push(&q, "mcc/cmd/b", "second!"));

  const MqttCtrlStaged* s = mqttCtrlQueueFront(&q);
  ASSERT_NE(nullptr, s);
  EXPECT_STREQ("mcc/cmd/a", s->topic);
  EXPECT_STREQ("first", s->payload);
  EXPECT_EQ(5u, s->payload_len);
  EXPECT_EQ(s, mqttCtrlQueueFront(&q));       // it stays the oldest until it is popped
  mqttCtrlQueuePop(&q);

  s = mqttCtrlQueueFront(&q);
  ASSERT_NE(nullptr, s);
  EXPECT_STREQ("mcc/cmd/b", s->topic);
  EXPECT_STREQ("second!", s->payload);
  EXPECT_EQ(7u, s->payload_len);
  mqttCtrlQueuePop(&q);
  EXPECT_EQ(nullptr, mqttCtrlQueueFront(&q));
  mqttCtrlQueuePop(&q);                       // an empty queue stays empty
  EXPECT_EQ(nullptr, mqttCtrlQueueFront(&q));
  EXPECT_TRUE(push(&q, "t", "third"));
  ASSERT_NE(nullptr, mqttCtrlQueueFront(&q));
  EXPECT_STREQ("third", mqttCtrlQueueFront(&q)->payload);
  EXPECT_EQ(0u, mqttCtrlQueueDropped(&q));
}

TEST(ArrivalsQueue, AFullQueueDropsTheNewestAndCountsIt) {
  static MqttCtrlQueue q;
  mqttCtrlQueueReset(&q);
  for (int i = 0; i < MQTTCTRL_QUEUE_LEN; i++) EXPECT_TRUE(push(&q, "t", std::string(1, (char)('a' + i)))) << i;
  EXPECT_EQ(0u, mqttCtrlQueueDropped(&q));
  EXPECT_FALSE(push(&q, "t", "late"));
  EXPECT_FALSE(push(&q, "t", "later"));
  EXPECT_EQ(2u, mqttCtrlQueueDropped(&q));

  // What waited is untouched, and one taken out makes room for exactly one.
  for (int i = 0; i < MQTTCTRL_QUEUE_LEN; i++) {
    const MqttCtrlStaged* s = mqttCtrlQueueFront(&q);
    ASSERT_NE(nullptr, s) << i;
    EXPECT_EQ(std::string(1, (char)('a' + i)), s->payload) << i;
    mqttCtrlQueuePop(&q);
    if (i == 0) {
      EXPECT_TRUE(push(&q, "t", "room"));
      EXPECT_FALSE(push(&q, "t", "none"));
    }
  }
  ASSERT_NE(nullptr, mqttCtrlQueueFront(&q));
  EXPECT_STREQ("room", mqttCtrlQueueFront(&q)->payload);
  mqttCtrlQueuePop(&q);
  EXPECT_EQ(nullptr, mqttCtrlQueueFront(&q));
  EXPECT_EQ(3u, mqttCtrlQueueDropped(&q));
  mqttCtrlQueueReset(&q);
  EXPECT_EQ(0u, mqttCtrlQueueDropped(&q));
}

TEST(ArrivalsQueue, TheCountsWrap) {
  static MqttCtrlQueue q;
  mqttCtrlQueueReset(&q);
  // Around the slots several times...
  for (int i = 0; i < 3 * MQTTCTRL_QUEUE_LEN + 1; i++) {
    const std::string a = "a" + std::to_string(i), b = "b" + std::to_string(i);
    EXPECT_TRUE(push(&q, "t", a)) << i;
    EXPECT_TRUE(push(&q, "t", b)) << i;
    ASSERT_NE(nullptr, mqttCtrlQueueFront(&q)) << i;
    EXPECT_EQ(a, mqttCtrlQueueFront(&q)->payload) << i;
    mqttCtrlQueuePop(&q);
    ASSERT_NE(nullptr, mqttCtrlQueueFront(&q)) << i;
    EXPECT_EQ(b, mqttCtrlQueueFront(&q)->payload) << i;
    mqttCtrlQueuePop(&q);
    EXPECT_EQ(nullptr, mqttCtrlQueueFront(&q)) << i;
  }
  // ... and across 2^32 messages, full on the far side of the wrap.
  q.head = q.tail = 0xFFFFFFFEu;
  for (int i = 0; i < MQTTCTRL_QUEUE_LEN; i++) EXPECT_TRUE(push(&q, "t", std::string(1, (char)('a' + i)))) << i;
  EXPECT_EQ(2u, q.head);
  EXPECT_FALSE(push(&q, "t", "late"));
  EXPECT_EQ(1u, mqttCtrlQueueDropped(&q));
  for (int i = 0; i < MQTTCTRL_QUEUE_LEN; i++) {
    ASSERT_NE(nullptr, mqttCtrlQueueFront(&q)) << i;
    EXPECT_EQ(std::string(1, (char)('a' + i)), mqttCtrlQueueFront(&q)->payload) << i;
    mqttCtrlQueuePop(&q);
  }
  EXPECT_EQ(nullptr, mqttCtrlQueueFront(&q));
}

TEST(ArrivalsQueue, WhatCannotFitTakesNoSlot) {
  static MqttCtrlQueue q;
  mqttCtrlQueueReset(&q);
  const std::string topic(MQTTCTRL_MAX_TOPIC, 't'), payload(MQTTCTRL_MAX_PAYLOAD, 'p');
  EXPECT_FALSE(push(&q, topic + "t", "x"));
  EXPECT_FALSE(push(&q, "t", payload + "p"));
  EXPECT_FALSE(push(&q, "t", ""));
  EXPECT_FALSE(mqttCtrlQueuePush(&q, NULL, (const uint8_t*)"x", 1));
  EXPECT_FALSE(mqttCtrlQueuePush(&q, "t", NULL, 1));
  EXPECT_FALSE(mqttCtrlQueuePush(NULL, "t", (const uint8_t*)"x", 1));
  EXPECT_EQ(nullptr, mqttCtrlQueueFront(&q));
  EXPECT_EQ(nullptr, mqttCtrlQueueFront(NULL));
  mqttCtrlQueuePop(NULL);
  EXPECT_EQ(0u, mqttCtrlQueueDropped(NULL));
  EXPECT_EQ(0u, mqttCtrlQueueDropped(&q));    // refused for its size, not for want of room

  // The longest that fits is kept whole, and the queue still holds its full number after.
  EXPECT_TRUE(push(&q, topic, payload));
  const MqttCtrlStaged* s = mqttCtrlQueueFront(&q);
  ASSERT_NE(nullptr, s);
  EXPECT_EQ(topic, s->topic);
  EXPECT_EQ(payload, std::string(s->payload, s->payload_len));
  EXPECT_EQ(0, s->payload[MQTTCTRL_MAX_PAYLOAD]);
  for (int i = 1; i < MQTTCTRL_QUEUE_LEN; i++) EXPECT_TRUE(push(&q, "t", "x")) << i;
  EXPECT_FALSE(push(&q, topic + "t", "x"));
  EXPECT_EQ(0u, mqttCtrlQueueDropped(&q));    // too long is never counted as a full queue
}
