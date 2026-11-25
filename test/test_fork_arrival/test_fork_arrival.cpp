// A feature the old image did not have starts switched off, once (ForkArrival.h): what the
// old image leaves behind, what the new one makes of it, and how the old image's name is
// read out of the image itself. The node here is the two files and two switches the real
// one has, run through the same decisions in the order Fork::settleArrival takes them.
#include <gtest/gtest.h>
#include <string.h>
#include <map>
#include <string>
#include <vector>

#include "helpers/ForkArrival.h"

static const char* ENV = "Heltec_v3_repeater_observer_mqtt";

// A node's storage and the two switches, as an image of 'token' sees them.
struct Node {
  std::map<std::string, std::string> files;   // the marker among them
  bool auto_reply = false;                     // /autoreply's "on"
  bool plane = false;                          // /mqttcontrol's "on"
  std::string command_key;                     // ... and its key
  std::string other_slot;                      // the image this node ran before, as bytes
  bool pending = false;                        // first start after an update
  int saves = 0;

  // The old image has written and verified an update of 'version' and is about to restart.
  void updateTaken(const char* own_token, const char* version) {
    if (forkArrivalMarkerWanted(own_token, version)) files[FORK_ARRIVAL_FILE] = own_token;
    other_slot = image(own_token);
    pending = true;
  }

  static std::string image(const char* token) {
    std::string bytes(700, '\xff');
    bytes += std::string("ota-base-native:https://example/latest") + '\0';
    bytes += std::string(ENV) + "-" + token + '\0';
    bytes += std::string("%s/%s.json") + '\0' + std::string(900, 'x');
    return bytes;
  }

  // An image of 'token' starts: Fork::settleArrival.
  ForkArrival start(const char* token) {
    char from[FORK_ARRIVAL_TOKEN_MAX] = {0};
    size_t n = 0;
    const bool marked = files.count(FORK_ARRIVAL_FILE) != 0;
    if (marked) {
      const std::string& m = files[FORK_ARRIVAL_FILE];
      n = forkArrivalTokenLen((const uint8_t *)m.data(), m.size() < sizeof(from) ? m.size() : sizeof(from) - 1);
      memcpy(from, m.data(), n);
    } else if (pending) {
      ForkVariantScan scan;
      const std::string own = std::string(ENV) + "-" + token;
      if (forkVariantScanBegin(&scan, own.c_str(), token)) {
        for (size_t off = 0; off < other_slot.size(); off += 512) {
          size_t len = other_slot.size() - off < 512 ? other_slot.size() - off : 512;
          if (forkVariantScanFeed(&scan, (const uint8_t *)other_slot.data() + off, len, from, sizeof(from))) {
            n = strlen(from);
            break;
          }
        }
      }
    }
    ForkArrival a = forkArrivalFrom(token, from, n);
    if (a.auto_reply_off && auto_reply) { auto_reply = false; saves++; }
    if (a.mqtt_command_off && plane) { plane = false; saves++; }
    if (marked) files.erase(FORK_ARRIVAL_FILE);
    pending = false;
    return a;
  }
};

static const char* V21 = "esp32s3-v1.18.0-lou-21-arrc-1a2b3c4d";

// ---- the marker: written by the old image, from lou-21 --------------------------------

TEST(ForkArrivalMarker, IsLeftOnlyForAnUpdateWithAFeatureTheRunningImageLacks) {
  EXPECT_TRUE(forkArrivalMarkerWanted("ar", V21));
  EXPECT_TRUE(forkArrivalMarkerWanted("rc", V21));
  EXPECT_FALSE(forkArrivalMarkerWanted("arrc", V21));
  EXPECT_FALSE(forkArrivalMarkerWanted("ar", "esp32s3-v1.18.0-lou-21-ar-1a2b3c4d"));
  EXPECT_FALSE(forkArrivalMarkerWanted("arrc", "esp32s3-v1.18.0-lou-21-ar-1a2b3c4d"));
  // rc for ar is a feature it lacks, though it is not more of them
  EXPECT_TRUE(forkArrivalMarkerWanted("ar", "esp32s3-v1.18.0-lou-21-rc-1a2b3c4d"));
  // a version that names no features, an image without any, nothing at all
  EXPECT_FALSE(forkArrivalMarkerWanted("ar", "esp32s3-v1.17.1-ar-13-16a05810"));
  EXPECT_FALSE(forkArrivalMarkerWanted("", V21));
  EXPECT_FALSE(forkArrivalMarkerWanted("ar", NULL));
  EXPECT_FALSE(forkArrivalMarkerWanted(NULL, V21));
  EXPECT_FALSE(forkArrivalMarkerWanted("nope", V21));
}

TEST(ForkArrival, FromArRemoteCommandStartsOffAndTheKeyIsKept) {
  Node n;
  n.auto_reply = true; n.plane = true; n.command_key = "A1B2";
  n.updateTaken("ar", V21);
  ASSERT_EQ("ar", n.files[FORK_ARRIVAL_FILE]);
  ForkArrival a = n.start("arrc");
  EXPECT_TRUE(a.known);
  EXPECT_TRUE(a.mqtt_command_off);
  EXPECT_FALSE(a.auto_reply_off);
  EXPECT_FALSE(n.plane);
  EXPECT_TRUE(n.auto_reply);
  EXPECT_EQ("A1B2", n.command_key);
  EXPECT_EQ(0u, n.files.count(FORK_ARRIVAL_FILE));
}

TEST(ForkArrival, FromRcAutoReplyStartsOffAndThePlaneIsLeftAlone) {
  Node n;
  n.auto_reply = true; n.plane = true; n.command_key = "A1B2";
  n.updateTaken("rc", V21);
  ForkArrival a = n.start("arrc");
  EXPECT_TRUE(a.auto_reply_off);
  EXPECT_FALSE(a.mqtt_command_off);
  EXPECT_FALSE(n.auto_reply);
  EXPECT_TRUE(n.plane);
  EXPECT_EQ("A1B2", n.command_key);
  EXPECT_EQ(1, n.saves);
}

TEST(ForkArrival, FromArrcOrWithNothingToGoByNothingChanges) {
  Node n;
  n.auto_reply = true; n.plane = true;
  n.updateTaken("arrc", V21);
  EXPECT_EQ(0u, n.files.count(FORK_ARRIVAL_FILE));
  ForkArrival a = n.start("arrc");
  EXPECT_TRUE(a.known);
  EXPECT_FALSE(a.auto_reply_off || a.mqtt_command_off);
  EXPECT_TRUE(n.auto_reply && n.plane);
  EXPECT_EQ(0, n.saves);

  // A cable flash, a new node: no marker and no update behind this start.
  Node fresh;
  fresh.auto_reply = true; fresh.plane = true;
  a = fresh.start("arrc");
  EXPECT_FALSE(a.known);
  EXPECT_TRUE(fresh.auto_reply && fresh.plane);
}

TEST(ForkArrival, TheSecondStartChangesNothing) {
  Node n;
  n.plane = true;
  n.updateTaken("ar", V21);
  n.start("arrc");
  ASSERT_FALSE(n.plane);
  n.plane = true;   // the owner switches it on
  ForkArrival a = n.start("arrc");
  EXPECT_FALSE(a.known);
  EXPECT_TRUE(n.plane);
  // ... and the old image in the other slot says nothing once the first start is over
  EXPECT_FALSE(n.other_slot.empty());
}

TEST(ForkArrival, AfterARollbackTheOldImageRemovesItsOwnMarker) {
  Node n;
  n.auto_reply = true; n.plane = true;
  n.updateTaken("ar", V21);
  ASSERT_EQ(1u, n.files.count(FORK_ARRIVAL_FILE));
  // The new image never started this far; the ar image is back. It has no plane to switch.
  n.pending = false;
  ForkArrival a = n.start("ar");
  EXPECT_TRUE(a.known);
  EXPECT_FALSE(a.auto_reply_off || a.mqtt_command_off);
  EXPECT_TRUE(n.auto_reply);
  EXPECT_TRUE(n.plane);
  EXPECT_EQ(0u, n.files.count(FORK_ARRIVAL_FILE));
  // A cable flash to arrc later finds no marker, and the plane as the owner left it.
  a = n.start("arrc");
  EXPECT_FALSE(a.known);
  EXPECT_TRUE(n.plane);
}

TEST(ForkArrival, AMarkerThatIsNoTokenSwitchesNothingAndIsRemoved) {
  for (const char* junk : { "", "arr", "banana", "\n", "ARRC" }) {
    Node n;
    n.auto_reply = true; n.plane = true;
    n.files[FORK_ARRIVAL_FILE] = junk;
    ForkArrival a = n.start("arrc");
    EXPECT_FALSE(a.known) << junk;
    EXPECT_TRUE(n.auto_reply && n.plane) << junk;
    EXPECT_EQ(0u, n.files.count(FORK_ARRIVAL_FILE));
  }
  Node n;
  n.plane = true;
  n.files[FORK_ARRIVAL_FILE] = "ar\r\n";
  EXPECT_TRUE(n.start("arrc").mqtt_command_off);
}

TEST(ForkArrival, TheDecisionForEveryPair) {
  struct { const char* own; const char* from; bool ar_off; bool rc_off; } rows[] = {
    { "arrc", "ar", false, true }, { "arrc", "rc", true, false }, { "arrc", "arrc", false, false },
    { "ar", "ar", false, false },  { "ar", "rc", true, false },   { "ar", "arrc", false, false },
    { "rc", "ar", false, true },   { "rc", "rc", false, false },  { "rc", "arrc", false, false },
    { "", "ar", false, false },    { "", "arrc", false, false },
  };
  for (const auto& r : rows) {
    ForkArrival a = forkArrivalFrom(r.own, r.from, strlen(r.from));
    EXPECT_TRUE(a.known) << r.own << " from " << r.from;
    EXPECT_EQ(r.ar_off, a.auto_reply_off) << r.own << " from " << r.from;
    EXPECT_EQ(r.rc_off, a.mqtt_command_off) << r.own << " from " << r.from;
  }
  EXPECT_FALSE(forkArrivalFrom("arrc", NULL, 0).known);
  EXPECT_FALSE(forkArrivalFrom(NULL, "ar", 2).known);
  EXPECT_FALSE(forkArrivalFrom("arrc", "arx", 3).known);
}

TEST(ForkArrival, ATokenIsItsBits) {
  EXPECT_EQ(0, forkFeatureBits("", 0));
  EXPECT_EQ(FORK_BIT_MQTT_COMMAND, forkFeatureBits("rc", 2));
  EXPECT_EQ(FORK_BIT_AUTO_REPLY, forkFeatureBits("ar", 2));
  EXPECT_EQ(FORK_BIT_AUTO_REPLY | FORK_BIT_MQTT_COMMAND, forkFeatureBits("arrc", 4));
  EXPECT_EQ(FORK_BIT_AUTO_REPLY, forkFeatureBits("arrc", 2));   // the length is the caller's
  EXPECT_EQ(-1, forkFeatureBits("rcar", 4));
  EXPECT_EQ(-1, forkFeatureBits(NULL, 0));
}

// ---- no marker: a node from lou-20, whose image knew nothing of this -------------------

TEST(ForkArrivalFromLou20, TheOldImageInTheOtherSlotSaysWhatItWas) {
  for (const char* old : { "ar", "rc", "arrc" }) {
    Node n;
    n.auto_reply = true; n.plane = true; n.command_key = "A1B2";
    n.other_slot = Node::image(old);   // a lou-20 image: it left no marker
    n.pending = true;
    ForkArrival a = n.start("arrc");
    EXPECT_TRUE(a.known) << old;
    EXPECT_EQ(strcmp(old, "ar") != 0, n.plane) << old;
    EXPECT_EQ(strcmp(old, "rc") != 0, n.auto_reply) << old;
    EXPECT_EQ("A1B2", n.command_key);
    // The next start is not the first after an update: the owner's "on" stands.
    n.auto_reply = true; n.plane = true;
    EXPECT_FALSE(n.start("arrc").known);
    EXPECT_TRUE(n.auto_reply && n.plane);
  }
}

TEST(ForkArrivalFromLou20, AnImageThatNamesNoCombinationSwitchesNothing) {
  Node n;
  n.auto_reply = true; n.plane = true;
  // ar-13 and before asked for <env>.json; another board's name is not this one's either.
  n.other_slot = std::string(300, '\0') + ENV + '\0' + "heltec_v4_repeater_observer_mqtt-ar" + '\0';
  n.pending = true;
  EXPECT_FALSE(n.start("arrc").known);
  EXPECT_TRUE(n.auto_reply && n.plane);
  n.other_slot.clear();
  n.pending = true;
  EXPECT_FALSE(n.start("arrc").known);
}

static bool scanAll(const std::string& bytes, size_t chunk, std::string* token) {
  ForkVariantScan scan;
  const std::string own = std::string(ENV) + "-arrc";
  if (!forkVariantScanBegin(&scan, own.c_str(), "arrc")) return false;
  char out[FORK_ARRIVAL_TOKEN_MAX];
  for (size_t off = 0; off < bytes.size(); off += chunk) {
    size_t len = bytes.size() - off < chunk ? bytes.size() - off : chunk;
    if (forkVariantScanFeed(&scan, (const uint8_t *)bytes.data() + off, len, out, sizeof(out))) {
      *token = out;
      return true;
    }
  }
  return false;
}

TEST(ForkVariantScan, ANameIsFoundWhereverTheChunksCutIt) {
  const std::string name = std::string(ENV) + "-rc" + '\0';
  for (size_t lead = 0; lead < 2 * name.size(); lead++) {
    const std::string bytes = std::string(lead, 'q') + name + std::string(40, 'z');
    for (size_t chunk : { (size_t)1, (size_t)7, (size_t)32, name.size(), (size_t)512 }) {
      std::string token;
      ASSERT_TRUE(scanAll(bytes, chunk, &token)) << "lead " << lead << " chunk " << chunk;
      ASSERT_EQ("rc", token);
    }
  }
}

TEST(ForkVariantScan, OnlyAWholeNameWithATokenAndItsNulCounts) {
  std::string token;
  const std::string env = ENV;
  EXPECT_FALSE(scanAll(env + "-ar", 512, &token));                       // cut off: no NUL
  EXPECT_FALSE(scanAll(env + "-ar.json" + '\0', 512, &token));           // a file name
  EXPECT_FALSE(scanAll(env + "-" + '\0', 512, &token));                  // the env alone
  EXPECT_FALSE(scanAll(env + "-arr" + '\0', 512, &token));
  EXPECT_FALSE(scanAll(env + "-esp32s3-v1.18.0-lou-20-ar-9c6c0a0.bin" + '\0', 512, &token));
  EXPECT_FALSE(scanAll(std::string("x_repeater_observer_mqtt-ar") + '\0', 512, &token));
  EXPECT_TRUE(scanAll(env + "-ar.json" + '\0' + env + "-arrc" + '\0', 512, &token));
  EXPECT_EQ("arrc", token);
  // the prefix twice over, the second the name
  EXPECT_TRUE(scanAll(env + "-" + env + "-ar" + '\0', 16, &token));
  EXPECT_EQ("ar", token);
}

TEST(ForkVariantScan, TheEnvIsThisImagesOwnNameWithoutItsToken) {
  ForkVariantScan scan;
  ASSERT_TRUE(forkVariantScanBegin(&scan, "Heltec_v3_repeater_observer_mqtt-arrc", "arrc"));
  EXPECT_STREQ("Heltec_v3_repeater_observer_mqtt-", scan.prefix);
  ASSERT_TRUE(forkVariantScanBegin(&scan, "Heltec_v3_repeater_observer_mqtt-ar", "ar"));
  EXPECT_STREQ("Heltec_v3_repeater_observer_mqtt-", scan.prefix);
  // build.sh's default name has no token, and an image without features has none to strip
  EXPECT_FALSE(forkVariantScanBegin(&scan, "Heltec_v3_repeater_observer_mqtt", "arrc"));
  EXPECT_FALSE(forkVariantScanBegin(&scan, "Heltec_v3_repeater_observer_mqtt-arrc", ""));
  EXPECT_FALSE(forkVariantScanBegin(&scan, "arrc", "arrc"));
  EXPECT_FALSE(forkVariantScanBegin(&scan, std::string(120, 'e').append("-ar").c_str(), "ar"));
  EXPECT_FALSE(forkVariantScanBegin(&scan, NULL, "ar"));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
