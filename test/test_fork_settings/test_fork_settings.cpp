// A node's settings across combinations (TODO 22.3): each feature keeps its settings in a
// file of its own -- /autoreply (auto-reply), /mqttcontrol (the command plane), /ota (OTA,
// every Observer image) -- and a build without the feature neither reads nor writes that
// file (Fork::begin opens each only under its feature's switch). Here a node's flash is a
// map of file names to bytes, each "image" decodes and encodes only the files it owns,
// through the same codecs the firmware uses, and the node is flashed arrc -> ar -> rc ->
// arrc with settings changed on the way.
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <vector>

#include "helpers/AutoReplyLogic.h"
#include "helpers/MqttControlLogic.h"
#include "helpers/OtaAutoLogic.h"

typedef std::map<std::string, std::vector<uint8_t>> Flash;

struct Image {
  bool ar, rc;                 // every image here is an Observer one, so OTA is always in
  AutoReplyStoredConfig autoreply;
  MqttCtrlStoredConfig control;
  bool ota_auto = false;
  uint8_t ota_hours = OTA_AUTO_CHECK_HOURS_DEFAULT;

  // What Fork::begin does: each feature present reads its own file, and nothing else.
  Image(const Flash& flash, bool ar_, bool rc_) : ar(ar_), rc(rc_) {
    autoReplyConfigDefaults(&autoreply);
    mqttCtrlConfigDefaults(&control);
    auto f = flash.find("/autoreply");
    if (ar && f != flash.end()) autoReplyConfigDecode(f->second.data(), f->second.size(), &autoreply);
    f = flash.find("/mqttcontrol");
    if (rc && f != flash.end()) mqttCtrlConfigDecode(f->second.data(), f->second.size(), 6, &control);
    f = flash.find("/ota");
    if (f != flash.end()) {
      otaAutoDecode(f->second.data(), f->second.size(), &ota_auto, &ota_hours);
    } else if ((f = flash.find("/mqttcontrol")) != flash.end()) {
      otaAutoDecodeLegacy(f->second.data(), f->second.size(), &ota_auto, &ota_hours);
    }
  }
  // A setting changed: only the file that setting lives in is written.
  void saveAutoReply(Flash& flash) {
    ASSERT_TRUE(ar);
    uint8_t buf[AUTOREPLY_CONFIG_MAX_BYTES];
    size_t n = autoReplyConfigEncode(&autoreply, buf, sizeof(buf));
    flash["/autoreply"].assign(buf, buf + n);
  }
  void saveControl(Flash& flash) {
    ASSERT_TRUE(rc);
    uint8_t buf[MQTTCTRL_CONFIG_LEN];
    size_t n = mqttCtrlConfigEncode(&control, buf, sizeof(buf));
    flash["/mqttcontrol"].assign(buf, buf + n);
  }
  void saveOta(Flash& flash) {
    uint8_t buf[OTA_AUTO_FILE_LEN];
    otaAutoEncode(buf, ota_auto, ota_hours);
    flash["/ota"].assign(buf, buf + sizeof(buf));
  }
};

static const char* KEY = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

TEST(SettingsAcrossCombinations, ArrcToArToRcToArrcLosesNothing) {
  Flash flash;
  {  // arrc, first boot: everything set
    Image arrc(flash, true, true);
    arrc.autoreply.enabled = true;
    strcpy(arrc.autoreply.region, "se-jkp");
    arrc.saveAutoReply(flash);
    arrc.control.enabled = true;
    arrc.control.slot = 3;
    arrc.control.counter = 100;
    strcpy(arrc.control.pubkey, KEY);
    arrc.saveControl(flash);
    arrc.ota_auto = true;
    arrc.ota_hours = 12;
    arrc.saveOta(flash);
  }
  const std::vector<uint8_t> control_before = flash["/mqttcontrol"];
  {  // ar: auto-reply's settings are there and change; the plane's file is not touched
    Image ar(flash, true, false);
    EXPECT_TRUE(ar.autoreply.enabled);
    EXPECT_STREQ("se-jkp", ar.autoreply.region);
    EXPECT_TRUE(ar.ota_auto);
    EXPECT_EQ(12, ar.ota_hours);
    ar.autoreply.hops = 3;
    ar.saveAutoReply(flash);
  }
  EXPECT_EQ(control_before, flash["/mqttcontrol"]);
  const std::vector<uint8_t> autoreply_after_ar = flash["/autoreply"];
  {  // rc: the plane's settings are there, and its counter moves on
    Image rc(flash, false, true);
    EXPECT_TRUE(rc.control.enabled);
    EXPECT_EQ(3, rc.control.slot);
    EXPECT_EQ(100u, rc.control.counter);
    EXPECT_STREQ(KEY, rc.control.pubkey);
    rc.control.counter = 101;
    rc.saveControl(flash);
  }
  EXPECT_EQ(autoreply_after_ar, flash["/autoreply"]);
  {  // arrc again: both lines of change are kept
    Image arrc(flash, true, true);
    EXPECT_TRUE(arrc.autoreply.enabled);
    EXPECT_EQ(3, arrc.autoreply.hops);
    EXPECT_STREQ("se-jkp", arrc.autoreply.region);
    EXPECT_EQ(101u, arrc.control.counter);       // no replay window from the detour
    EXPECT_STREQ(KEY, arrc.control.pubkey);
    EXPECT_TRUE(arrc.ota_auto);
    EXPECT_EQ(12, arrc.ota_hours);
  }
}

TEST(SettingsAcrossCombinations, AnAr13NodeKeepsItsOtaSettingsAndRollsBackToThem) {
  // ar-13 wrote /mqttcontrol v3 with ota.auto on, every 6 h, and had no /ota.
  Flash flash;
  MqttCtrlStoredConfig ar13;
  mqttCtrlConfigDefaults(&ar13);
  ar13.enabled = true;
  ar13.slot = 2;
  ar13.counter = 7;
  strcpy(ar13.pubkey, KEY);
  ar13.ota_legacy[0] = 1;
  ar13.ota_legacy[1] = 6;
  uint8_t buf[MQTTCTRL_CONFIG_LEN];
  flash["/mqttcontrol"].assign(buf, buf + mqttCtrlConfigEncode(&ar13, buf, sizeof(buf)));
  {  // lou-14 ar: no plane, so it reads the two bytes and never writes the file
    Image ar(flash, true, false);
    EXPECT_TRUE(ar.ota_auto);
    EXPECT_EQ(6, ar.ota_hours);
  }
  {  // lou-14 rc: a command moves the counter; the ar-13 bytes ride along unchanged
    Image rc(flash, false, true);
    rc.control.counter = 8;
    rc.saveControl(flash);
    rc.ota_auto = false;               // set ota.auto off: /ota from now on
    rc.saveOta(flash);
  }
  const std::vector<uint8_t>& mc = flash["/mqttcontrol"];
  ASSERT_EQ((size_t)MQTTCTRL_CONFIG_LEN, mc.size());
  bool on = false;
  uint8_t hours = 0;
  ASSERT_TRUE(otaAutoDecodeLegacy(mc.data(), mc.size(), &on, &hours));
  EXPECT_TRUE(on);                     // what ar-13 finds if the new image rolls back
  EXPECT_EQ(6, hours);
  Image again(flash, false, true);
  EXPECT_FALSE(again.ota_auto);        // /ota, once written, is what lou-14 reads
  EXPECT_EQ(8u, again.control.counter);
}

TEST(ControlConfig, EveryVersionReads) {
  uint8_t v1[] = { 1, 1, 0x2A, 0, 0, 0 };
  MqttCtrlStoredConfig c;
  mqttCtrlConfigDefaults(&c);
  ASSERT_TRUE(mqttCtrlConfigDecode(v1, sizeof(v1), 6, &c));
  EXPECT_TRUE(c.enabled);
  EXPECT_EQ(42u, c.counter);
  EXPECT_EQ(0, c.slot);                // v1: deaf and keyless
  EXPECT_STREQ("", c.pubkey);
  EXPECT_EQ(OTA_AUTO_CHECK_HOURS_DEFAULT, c.ota_legacy[1]);

  uint8_t v2[1 + 1 + 4 + 1 + MQTTCTRL_CONFIG_KEY_LEN] = { 2, 0, 5, 0, 0, 0, 9 };
  memcpy(&v2[7], KEY, 64);
  mqttCtrlConfigDefaults(&c);
  ASSERT_TRUE(mqttCtrlConfigDecode(v2, sizeof(v2), 6, &c));
  EXPECT_EQ(0, c.slot);                // 9 is no slot of a 6-slot node
  EXPECT_STREQ(KEY, c.pubkey);

  EXPECT_FALSE(mqttCtrlConfigDecode(v1, 1, 6, &c));
  uint8_t v0[] = { 0, 1 };
  EXPECT_FALSE(mqttCtrlConfigDecode(v0, sizeof(v0), 6, &c));
  EXPECT_EQ(0u, mqttCtrlConfigEncode(&c, v2, sizeof(v2)));   // too small for v3
}

TEST(ControlConfig, TheMeshModeIsVersion4AndDefaultsToAuto) {
  MqttCtrlStoredConfig c;
  mqttCtrlConfigDefaults(&c);
  EXPECT_EQ(MQTTCTRL_MESH_AUTO, c.mesh_mode);
  c.mesh_mode = MQTTCTRL_MESH_OFF;
  c.counter = 12;
  uint8_t buf[MQTTCTRL_CONFIG_LEN];
  ASSERT_EQ((size_t)MQTTCTRL_CONFIG_LEN, mqttCtrlConfigEncode(&c, buf, sizeof(buf)));
  EXPECT_LE(4, buf[0]);
  MqttCtrlStoredConfig back;
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
  EXPECT_EQ(MQTTCTRL_MESH_OFF, back.mesh_mode);
  EXPECT_EQ(12u, back.counter);

  // A v3 file, as lou-18 writes it, reads as auto and keeps its OTA bytes.
  buf[0] = 3;
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, MQTTCTRL_CONFIG_LEN_3, 6, &back));
  EXPECT_EQ(MQTTCTRL_MESH_AUTO, back.mesh_mode);
  EXPECT_EQ(c.ota_legacy[1], back.ota_legacy[1]);

  // A mode this build does not know reads as the default.
  buf[0] = 4;
  buf[MQTTCTRL_CONFIG_LEN_3] = 7;
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
  EXPECT_EQ(MQTTCTRL_MESH_AUTO, back.mesh_mode);
}

TEST(ControlConfig, HowTheKeyWasSetIsVersion5AndAnOlderKeyWasUsbs) {
  MqttCtrlStoredConfig c;
  mqttCtrlConfigDefaults(&c);
  EXPECT_EQ(MQTTCTRL_KEY_VIA_USB, c.key_via);
  strcpy(c.pubkey, KEY);
  c.key_via = MQTTCTRL_KEY_VIA_ADMIN;
  c.mesh_mode = MQTTCTRL_MESH_OFF;
  uint8_t buf[MQTTCTRL_CONFIG_LEN];
  ASSERT_EQ((size_t)MQTTCTRL_CONFIG_LEN, mqttCtrlConfigEncode(&c, buf, sizeof(buf)));
  EXPECT_LE(5, buf[0]);
  MqttCtrlStoredConfig back;
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
  EXPECT_EQ(MQTTCTRL_KEY_VIA_ADMIN, back.key_via);
  EXPECT_EQ(MQTTCTRL_MESH_OFF, back.mesh_mode);
  EXPECT_STREQ(KEY, back.pubkey);

  // A v4 file, as lou-19-rc writes it: the key it holds was set over USB, the only way then.
  buf[0] = 4;
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, MQTTCTRL_CONFIG_LEN_4, 6, &back));
  EXPECT_EQ(MQTTCTRL_KEY_VIA_USB, back.key_via);
  EXPECT_EQ(MQTTCTRL_MESH_OFF, back.mesh_mode);
  EXPECT_STREQ(KEY, back.pubkey);

  // A value this build does not know reads as USB.
  buf[0] = 5;
  buf[MQTTCTRL_CONFIG_LEN_4] = 9;
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
  EXPECT_EQ(MQTTCTRL_KEY_VIA_USB, back.key_via);
}

TEST(ControlConfig, TheAliveIntervalAndTheBootCounterAreVersion6) {
  MqttCtrlStoredConfig c;
  mqttCtrlConfigDefaults(&c);
  EXPECT_EQ(0, c.alive_minutes);
  EXPECT_EQ(MQTTCTRL_ALIVE_DEFAULT_MINUTES, mqttCtrlAliveMinutes(c.alive_minutes));
  strcpy(c.pubkey, KEY);
  c.key_via = MQTTCTRL_KEY_VIA_ADMIN;
  c.counter = 77;
  c.alive_minutes = 60;
  c.boot = 0x01020304;
  uint8_t buf[MQTTCTRL_CONFIG_LEN];
  ASSERT_EQ((size_t)MQTTCTRL_CONFIG_LEN, mqttCtrlConfigEncode(&c, buf, sizeof(buf)));
  EXPECT_LE(6, buf[0]);
  EXPECT_EQ((size_t)MQTTCTRL_CONFIG_LEN_5 + 6, (size_t)MQTTCTRL_CONFIG_LEN_6);
  MqttCtrlStoredConfig back;
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
  EXPECT_EQ(60, back.alive_minutes);
  EXPECT_EQ(0x01020304u, back.boot);
  EXPECT_EQ(MQTTCTRL_KEY_VIA_ADMIN, back.key_via);
  EXPECT_EQ(77u, back.counter);

  // What lou-19 reads of it: the first 76 bytes, every field it knows.
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, MQTTCTRL_CONFIG_LEN_5, 6, &back));
  EXPECT_EQ(MQTTCTRL_KEY_VIA_ADMIN, back.key_via);
  EXPECT_EQ(77u, back.counter);
  EXPECT_EQ(0, back.alive_minutes);

  // A v5 file, as lou-19 writes it: the default interval, boot counter 0.
  buf[0] = 5;
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, MQTTCTRL_CONFIG_LEN_5, 6, &back));
  EXPECT_EQ(0, back.alive_minutes);
  EXPECT_EQ(0u, back.boot);
  EXPECT_EQ(MQTTCTRL_KEY_VIA_ADMIN, back.key_via);

  // An interval outside 5..1440 reads as the default.
  buf[0] = 6;
  for (uint16_t bad : { 4, 1441, 65535 }) {
    memcpy(&buf[MQTTCTRL_CONFIG_LEN_5], &bad, 2);
    ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
    EXPECT_EQ(0, back.alive_minutes) << bad;
  }
  for (uint16_t good : { 5, 15, 1440 }) {
    memcpy(&buf[MQTTCTRL_CONFIG_LEN_5], &good, 2);
    ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
    EXPECT_EQ(good, back.alive_minutes);
  }
}

TEST(ControlConfig, TheRelayModeIsVersion7AndAnOlderFileReadsAsOwn) {
  MqttCtrlStoredConfig c;
  mqttCtrlConfigDefaults(&c);
  strcpy(c.pubkey, KEY);
  c.counter = 77;
  c.alive_minutes = 60;
  c.boot = 9;
  c.mesh_mode = MQTTCTRL_MESH_ON;
  c.relay_mode = MQTTCTRL_RELAY_OFF;
  uint8_t buf[MQTTCTRL_CONFIG_LEN];
  ASSERT_EQ((size_t)MQTTCTRL_CONFIG_LEN, mqttCtrlConfigEncode(&c, buf, sizeof(buf)));
  buf[0] = 7;
  MqttCtrlStoredConfig back;
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, MQTTCTRL_CONFIG_LEN_7, 6, &back));
  EXPECT_EQ(MQTTCTRL_RELAY_OFF, back.relay_mode);
  EXPECT_EQ(60, back.alive_minutes);
  EXPECT_EQ(9u, back.boot);
  EXPECT_EQ(MQTTCTRL_MESH_ON, back.mesh_mode);
  EXPECT_EQ(77u, back.counter);
  EXPECT_STREQ(KEY, back.pubkey);

  // What an image before the relay reads of it: the 82 bytes it knows, every field.
  mqttCtrlConfigDefaults(&back);
  back.relay_mode = MQTTCTRL_RELAY_OWN;
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, MQTTCTRL_CONFIG_LEN_6, 6, &back));
  EXPECT_EQ(60, back.alive_minutes);
  EXPECT_EQ(9u, back.boot);
  EXPECT_EQ(MQTTCTRL_RELAY_OWN, back.relay_mode);

  // A v6 file, as that image writes it, leaves the mode as it was, whatever byte follows.
  buf[0] = 6;
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
  EXPECT_EQ(MQTTCTRL_RELAY_ANY, back.relay_mode);
  EXPECT_EQ(60, back.alive_minutes);
}

// Version 8 (lou-21): any is the default, a version 7 file's own was that default and reads as
// any, and the guests' cap follows the mode.
TEST(ControlConfig, Version8MovesTheDefaultOwnToAnyAndKeepsTheGuestCap) {
  MqttCtrlStoredConfig c;
  mqttCtrlConfigDefaults(&c);
  EXPECT_EQ(MQTTCTRL_RELAY_ANY, c.relay_mode);
  EXPECT_EQ(MQTTCTRL_RELAY_GUEST_DEFAULT, c.relay_guest);
  c.relay_mode = MQTTCTRL_RELAY_OWN;
  c.relay_guest = 3;
  c.boot = 9;
  uint8_t buf[MQTTCTRL_CONFIG_LEN];
  ASSERT_EQ((size_t)MQTTCTRL_CONFIG_LEN, mqttCtrlConfigEncode(&c, buf, sizeof(buf)));
  EXPECT_EQ(9, buf[0]);
  EXPECT_EQ((size_t)MQTTCTRL_CONFIG_LEN_7 + 1, (size_t)MQTTCTRL_CONFIG_LEN_8);
  EXPECT_EQ(84u, (size_t)MQTTCTRL_CONFIG_LEN_8);
  EXPECT_EQ(0u, mqttCtrlConfigEncode(&c, buf, sizeof(buf) - 1));
  EXPECT_EQ(MQTTCTRL_RELAY_OWN, buf[MQTTCTRL_CONFIG_LEN_6]);
  EXPECT_EQ(3, buf[MQTTCTRL_CONFIG_LEN_7]);

  // An own set in version 8 was chosen, and stays.
  MqttCtrlStoredConfig back;
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
  EXPECT_EQ(MQTTCTRL_RELAY_OWN, back.relay_mode);
  EXPECT_EQ(3, back.relay_guest);
  EXPECT_EQ(9u, back.boot);

  // The same byte in version 7 was the default, and moves to any; off stays off.
  buf[0] = 7;
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, MQTTCTRL_CONFIG_LEN_7, 6, &back));
  EXPECT_EQ(MQTTCTRL_RELAY_ANY, back.relay_mode);
  EXPECT_EQ(MQTTCTRL_RELAY_GUEST_DEFAULT, back.relay_guest);
  buf[MQTTCTRL_CONFIG_LEN_6] = MQTTCTRL_RELAY_OFF;
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, MQTTCTRL_CONFIG_LEN_7, 6, &back));
  EXPECT_EQ(MQTTCTRL_RELAY_OFF, back.relay_mode);

  // Any in version 8 is any; lou-20 reads it as a mode it does not know, which is own there.
  buf[0] = 8;
  buf[MQTTCTRL_CONFIG_LEN_6] = MQTTCTRL_RELAY_ANY;
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
  EXPECT_EQ(MQTTCTRL_RELAY_ANY, back.relay_mode);

  // A mode or a cap this build does not know reads as the default; a short file keeps it.
  buf[MQTTCTRL_CONFIG_LEN_6] = 3;
  buf[MQTTCTRL_CONFIG_LEN_7] = 101;
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
  EXPECT_EQ(MQTTCTRL_RELAY_ANY, back.relay_mode);
  EXPECT_EQ(MQTTCTRL_RELAY_GUEST_DEFAULT, back.relay_guest);
  buf[MQTTCTRL_CONFIG_LEN_7] = 0;
  back.relay_guest = 42;
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, MQTTCTRL_CONFIG_LEN_7, 6, &back));
  EXPECT_EQ(42, back.relay_guest);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
  EXPECT_EQ(0, back.relay_guest);
}

// Version 9 (lou-21): the report's two battery thresholds, 3600 and 3400 mV by default; an
// older file keeps the defaults, and a value past 10000 reads as the default.
TEST(ControlConfig, Version9KeepsTheBatteryThresholds) {
  MqttCtrlStoredConfig c;
  mqttCtrlConfigDefaults(&c);
  EXPECT_EQ(MQTTCTRL_ANNOUNCE_LOW_DEFAULT, c.announce_low);
  EXPECT_EQ(MQTTCTRL_ANNOUNCE_CRITICAL_DEFAULT, c.announce_critical);
  EXPECT_EQ(3600, MQTTCTRL_ANNOUNCE_LOW_DEFAULT);
  EXPECT_EQ(3400, MQTTCTRL_ANNOUNCE_CRITICAL_DEFAULT);
  c.announce_low = 3300;
  c.announce_critical = 0;
  c.relay_guest = 7;
  uint8_t buf[MQTTCTRL_CONFIG_LEN];
  ASSERT_EQ((size_t)MQTTCTRL_CONFIG_LEN, mqttCtrlConfigEncode(&c, buf, sizeof(buf)));
  EXPECT_EQ(88u, (size_t)MQTTCTRL_CONFIG_LEN);
  EXPECT_EQ(9, buf[0]);
  MqttCtrlStoredConfig back;
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
  EXPECT_EQ(3300, back.announce_low);
  EXPECT_EQ(0, back.announce_critical);
  EXPECT_EQ(7, back.relay_guest);

  // What lou-21 before version 9 and a short file leave: the defaults, the rest read.
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, MQTTCTRL_CONFIG_LEN_8, 6, &back));
  EXPECT_EQ(MQTTCTRL_ANNOUNCE_LOW_DEFAULT, back.announce_low);
  EXPECT_EQ(7, back.relay_guest);
  buf[0] = 8;
  mqttCtrlConfigDefaults(&back);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
  EXPECT_EQ(MQTTCTRL_ANNOUNCE_LOW_DEFAULT, back.announce_low);
  EXPECT_EQ(MQTTCTRL_ANNOUNCE_CRITICAL_DEFAULT, back.announce_critical);

  buf[0] = 9;
  const uint16_t big = 10001, max = 10000;
  memcpy(&buf[MQTTCTRL_CONFIG_LEN_8], &big, 2);
  memcpy(&buf[MQTTCTRL_CONFIG_LEN_8 + 2], &max, 2);
  ASSERT_TRUE(mqttCtrlConfigDecode(buf, sizeof(buf), 6, &back));
  EXPECT_EQ(MQTTCTRL_ANNOUNCE_LOW_DEFAULT, back.announce_low);
  EXPECT_EQ(10000, back.announce_critical);
}

TEST(ControlConfig, TheBatteryThresholdsParse) {
  uint16_t mv = 1;
  EXPECT_TRUE(mqttCtrlAnnounceParseMv("0", &mv));
  EXPECT_EQ(0, mv);
  EXPECT_TRUE(mqttCtrlAnnounceParseMv("3450", &mv));
  EXPECT_EQ(3450, mv);
  EXPECT_TRUE(mqttCtrlAnnounceParseMv("10000", &mv));
  EXPECT_FALSE(mqttCtrlAnnounceParseMv("10001", &mv));
  EXPECT_FALSE(mqttCtrlAnnounceParseMv("70000", &mv));
  EXPECT_FALSE(mqttCtrlAnnounceParseMv("", &mv));
  EXPECT_FALSE(mqttCtrlAnnounceParseMv("3.6", &mv));
  EXPECT_FALSE(mqttCtrlAnnounceParseMv("-1", &mv));
  EXPECT_FALSE(mqttCtrlAnnounceParseMv(NULL, &mv));
  EXPECT_EQ(10000, mv);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
