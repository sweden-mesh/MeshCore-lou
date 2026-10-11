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
  ASSERT_EQ((size_t)OTA_AUTO_LEGACY_LEN, mc.size());
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

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
