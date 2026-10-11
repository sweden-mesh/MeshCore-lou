// Host tests for OtaVerifyLogic.h: a manifest's signature by the release key, and
// the image hash compared as bytes. A signed image is what makes pull OTA safe to
// hand to a signed command (ships with ar-11, operator decision 2026-10-08).
#include <gtest/gtest.h>
#include <string>
#include "helpers/OtaVerifyLogic.h"

static uint8_t R_PUB[32], R_PRV[64];
static std::string R_PUB_HEX;

static void makeReleaseKey() {
  uint8_t seed[32];
  for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(0x40 + i);
  ed25519_create_keypair(R_PUB, R_PRV, seed);
  static const char* H = "0123456789ABCDEF";
  R_PUB_HEX.clear();
  for (int i = 0; i < 32; i++) { R_PUB_HEX += H[R_PUB[i] >> 4]; R_PUB_HEX += H[R_PUB[i] & 15]; }
}

static std::string signManifest(const std::string& sha, const std::string& ver, const std::string& file) {
  std::string msg = sha + "|" + ver + "|" + file;
  uint8_t sig[64];
  ed25519_sign(sig, (const uint8_t*)msg.data(), msg.size(), R_PUB, R_PRV);
  static const char* H = "0123456789abcdef";
  std::string hex;
  for (int i = 0; i < 64; i++) { hex += H[sig[i] >> 4]; hex += H[sig[i] & 15]; }
  return hex;
}

static const std::string SHA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

TEST(OtaVerify, AManifestSignedByTheReleaseKeyPasses) {
  makeReleaseKey();
  std::string sig = signManifest(SHA, "v1.17.1.3-ar-11-abc1234", "Heltec_v3_repeater_observer_mqtt-v1.17.1.3-ar-11-abc1234.bin");
  EXPECT_TRUE(otaManifestSignatureOk(R_PUB_HEX.c_str(), SHA.c_str(), "v1.17.1.3-ar-11-abc1234",
                                     "Heltec_v3_repeater_observer_mqtt-v1.17.1.3-ar-11-abc1234.bin", sig.c_str()));
}

TEST(OtaVerify, AnyChangedFieldOrAnotherKeyFails) {
  makeReleaseKey();
  std::string sig = signManifest(SHA, "v1", "a.bin");
  EXPECT_TRUE(otaManifestSignatureOk(R_PUB_HEX.c_str(), SHA.c_str(), "v1", "a.bin", sig.c_str()));
  std::string other = SHA; other[0] = other[0] == 'a' ? 'b' : 'a';
  EXPECT_FALSE(otaManifestSignatureOk(R_PUB_HEX.c_str(), other.c_str(), "v1", "a.bin", sig.c_str()));
  EXPECT_FALSE(otaManifestSignatureOk(R_PUB_HEX.c_str(), SHA.c_str(), "v2", "a.bin", sig.c_str()));
  EXPECT_FALSE(otaManifestSignatureOk(R_PUB_HEX.c_str(), SHA.c_str(), "v1", "b.bin", sig.c_str()));
  std::string flipped = sig; flipped[5] = flipped[5] == '0' ? '1' : '0';
  EXPECT_FALSE(otaManifestSignatureOk(R_PUB_HEX.c_str(), SHA.c_str(), "v1", "a.bin", flipped.c_str()));
  std::string other_key = R_PUB_HEX; other_key[10] = other_key[10] == '0' ? '1' : '0';
  EXPECT_FALSE(otaManifestSignatureOk(other_key.c_str(), SHA.c_str(), "v1", "a.bin", sig.c_str()));
}

TEST(OtaVerify, ADevBuildWithNoReleaseKeyFailsClosed) {
  makeReleaseKey();
  std::string sig = signManifest(SHA, "v1", "a.bin");
  EXPECT_FALSE(otaManifestSignatureOk("", SHA.c_str(), "v1", "a.bin", sig.c_str()));
  EXPECT_FALSE(otaManifestSignatureOk(NULL, SHA.c_str(), "v1", "a.bin", sig.c_str()));
  EXPECT_FALSE(otaManifestSignatureOk(R_PUB_HEX.c_str(), SHA.c_str(), "v1", "a.bin", ""));
  EXPECT_FALSE(otaManifestSignatureOk(R_PUB_HEX.c_str(), "deadbeef", "v1", "a.bin", sig.c_str()));
}

TEST(OtaVerify, TheHashIsComparedAsBytesWhateverTheCase) {
  uint8_t digest[32];
  otaHexToBytes(SHA.c_str(), 64, digest, 32);
  EXPECT_TRUE(otaImageHashOk(digest, SHA.c_str()));
  std::string upper = SHA; for (auto& c : upper) c = (char)toupper(c);
  EXPECT_TRUE(otaImageHashOk(digest, upper.c_str()));
  digest[31] ^= 1;
  EXPECT_FALSE(otaImageHashOk(digest, SHA.c_str()));
  EXPECT_FALSE(otaImageHashOk(digest, "9f86"));
  EXPECT_FALSE(otaImageHashOk(digest, NULL));
}
TEST(OtaVerify, AManifestFromThePythonSignerVerifiesHere) {
  // scripts/sign_manifest.py with seed 55x32 over sha256("a firmware image"), this
  // version and file: the release tooling and the node must agree on the bytes.
  const char* pub = "C6822637C7D310EC57627BE00BA259D253749F4AAF644470CFFBE53A35F73242";
  const char* sha = "8354d20f1a8ac4e9dd7b7a9dcba2a2be34a5ffbef65eeeb688885e00cc403810";
  const char* sig = "ff3580f74b01f2b041a2edb73beb3679d51125eef38797bdd0acb77a908522e8"
                    "f0a52b7936942430f5bdf22fe12f30545e1cdc685b4b4b74c77b3b936e1d1c08";
  EXPECT_TRUE(otaManifestSignatureOk(pub, sha, "esp32s3-v1.17.1-ar-11-abc1234",
      "https://github.com/the-louie/MeshCore-observer/releases/download/v1.17.1-ar-11/x.bin", sig));
  EXPECT_FALSE(otaManifestSignatureOk(pub, sha, "esp32s3-v1.17.1-ar-11-abc1235",
      "https://github.com/the-louie/MeshCore-observer/releases/download/v1.17.1-ar-11/x.bin", sig));
}


// ---- newer-than: the ar-N revision decides -------------------------------------------

TEST(OtaNewer, TheRevisionDecidesAndNeverRollsBack) {
  EXPECT_EQ(11, otaRevisionOf("esp32s3-v1.17.1-ar-11-5d863f47"));
  EXPECT_EQ(10, otaRevisionOf("esp32s3-v1.17.1.3-ar-10-42f48ce9"));
  EXPECT_EQ(-1, otaRevisionOf("v1.16.0.37-observer-9670035"));
  EXPECT_EQ(OTA_NEWER, otaUpdateVerdict("esp32s3-v1.17.1-ar-10-42f48ce9", "esp32s3-v1.17.1-ar-11-5d863f47", -1, -1, false));
  EXPECT_EQ(OTA_OLDER, otaUpdateVerdict("esp32s3-v1.17.1-ar-11-5d863f47", "esp32s3-v1.17.1-ar-10-42f48ce9", -1, -1, false));
  // a lower revision with a higher build number or a different base is still older
  EXPECT_EQ(OTA_OLDER, otaUpdateVerdict("esp32s3-v1.17.1-ar-11-aaaa", "esp32s3-v1.18.0.9-ar-10-bbbb", 0, 9, false));
}

TEST(OtaNewer, WithinARevisionTheBuildNumberThenTheHash) {
  EXPECT_EQ(OTA_NEWER, otaUpdateVerdict("x-v1.17.1.2-ar-11-aaaa", "x-v1.17.1.3-ar-11-bbbb", 2, 3, false));
  EXPECT_EQ(OTA_OLDER, otaUpdateVerdict("x-v1.17.1.3-ar-11-aaaa", "x-v1.17.1.2-ar-11-bbbb", 3, 2, false));
  EXPECT_EQ(OTA_UP_TO_DATE, otaUpdateVerdict("x-v1.17.1.3-ar-11-aaaa", "x-v1.17.1.3-ar-11-aaaa", 3, 3, true));
  // no build numbers: the hash, as upstream does
  EXPECT_EQ(OTA_UP_TO_DATE, otaUpdateVerdict("x-v1.17.1-ar-11-aaaa", "x-v1.17.1-ar-11-aaaa", -1, -1, true));
  EXPECT_EQ(OTA_NEWER, otaUpdateVerdict("x-v1.17.1-ar-11-aaaa", "x-v1.17.1-ar-11-bbbb", -1, -1, false));
  // one side without a revision (an upstream image): falls to the build number / hash
  EXPECT_EQ(OTA_NEWER, otaUpdateVerdict("v1.16.0.37-observer-9670035", "x-v1.17.1-ar-11-bbbb", 37, -1, false));
}

TEST(OtaNewer, LouIsReadBeforeAr) {
  // An ar-only image carries `-ar-` after the revision; the revision is lou's number.
  EXPECT_EQ(14, otaRevisionOf("esp32s3-v1.17.1-lou-14-ar-1a2b3c4d"));
  EXPECT_EQ(14, otaRevisionOf("esp32s3-v1.17.1-lou-14-ar-9f04c21b"));
  EXPECT_EQ(14, otaRevisionOf("esp32s3-v1.17.1-lou-14-arrc-1a2b3c4d"));
  EXPECT_EQ(15, otaRevisionOf("nrf52-v1.17.1-lou-15-asarrc-1a2b3c4d"));
  EXPECT_EQ(13, otaRevisionOf("esp32s3-v1.17.1-ar-13-16a05810"));
  EXPECT_EQ(13, otaRevisionOf("esp32s3-v1.17.1-ar-13-observer-16a05810"));   // as ar-13 embedded it
  EXPECT_EQ(14, otaRevisionOf("esp32s3-v1.17.1-lou-14-ar-observer-1a2b3c4d"));
  EXPECT_EQ(-1, otaRevisionOf("esp32s3-v1.17.1-lou-x-ar-13-aaaa"));
}

TEST(OtaNewer, LouContinuesTheArCounter) {
  EXPECT_EQ(OTA_NEWER, otaUpdateVerdict("esp32s3-v1.17.1-ar-13-16a05810",
                                        "esp32s3-v1.17.1-lou-14-arrc-1a2b3c4d", -1, -1, false));
  EXPECT_EQ(OTA_OLDER, otaUpdateVerdict("esp32s3-v1.17.1-lou-14-ar-1a2b3c4d",
                                        "esp32s3-v1.17.1-ar-13-16a05810", -1, -1, false));
  // The hazard: read `-ar-` first and an ar image on lou-14 is "revision 1" (from the
  // hash), so ar-13 would look newer and the node would roll itself back.
  EXPECT_EQ(OTA_UP_TO_DATE, otaUpdateVerdict("esp32s3-v1.17.1-lou-14-ar-1a2b3c4d",
                                             "esp32s3-v1.17.1-lou-14-ar-1a2b3c4d", -1, -1, true));
}

// ---- the combination: sig2 over the variant and the features (lou-14) ---------------

static std::string sign2(const std::string& sha, const std::string& ver, const std::string& file,
                         const std::string& variant, const std::string& features) {
  return signManifest(sha, ver, file + "|" + variant + "|" + features);
}

static const char* V = "esp32s3-v1.17.1-lou-14-ar-1a2b3c4d";
static const char* F = "https://github.com/the-louie/MeshCore-observer/releases/download/v1.17.1-lou-14/"
                       "Heltec_v3_repeater_observer_mqtt-esp32s3-v1.17.1-lou-14-ar-1a2b3c4d.bin";

TEST(OtaCombination, OnlyItsOwnCombinationIsAccepted) {
  makeReleaseKey();
  std::string s2 = sign2(SHA, V, F, "Heltec_v3_repeater_observer_mqtt-ar", "ar");
  EXPECT_EQ(OTA_COMBO_OK, otaManifestCombination(R_PUB_HEX.c_str(), SHA.c_str(), V, F,
            "Heltec_v3_repeater_observer_mqtt-ar", "ar", s2.c_str(),
            "Heltec_v3_repeater_observer_mqtt-ar", "ar"));
}

TEST(OtaCombination, AnArNodeRefusesAnArrcManifest) {
  // Properly signed, for the same board -- but not this node's features.
  makeReleaseKey();
  std::string s2 = sign2(SHA, V, F, "Heltec_v3_repeater_observer_mqtt-arrc", "arrc");
  EXPECT_EQ(OTA_COMBO_OTHER_VARIANT, otaManifestCombination(R_PUB_HEX.c_str(), SHA.c_str(), V, F,
            "Heltec_v3_repeater_observer_mqtt-arrc", "arrc", s2.c_str(),
            "Heltec_v3_repeater_observer_mqtt-ar", "ar"));
  // Even under this node's own variant name, the features are checked on their own.
  s2 = sign2(SHA, V, F, "Heltec_v3_repeater_observer_mqtt-ar", "arrc");
  EXPECT_EQ(OTA_COMBO_OTHER_FEATURES, otaManifestCombination(R_PUB_HEX.c_str(), SHA.c_str(), V, F,
            "Heltec_v3_repeater_observer_mqtt-ar", "arrc", s2.c_str(),
            "Heltec_v3_repeater_observer_mqtt-ar", "ar"));
}

TEST(OtaCombination, AnotherBoardIsRefused) {
  makeReleaseKey();
  std::string s2 = sign2(SHA, V, F, "heltec_v4_repeater_observer_mqtt-ar", "ar");
  EXPECT_EQ(OTA_COMBO_OTHER_VARIANT, otaManifestCombination(R_PUB_HEX.c_str(), SHA.c_str(), V, F,
            "heltec_v4_repeater_observer_mqtt-ar", "ar", s2.c_str(),
            "Heltec_v3_repeater_observer_mqtt-ar", "ar"));
}

TEST(OtaCombination, ANameEditedAfterSigningOrNoSig2IsUnsigned) {
  makeReleaseKey();
  std::string s2 = sign2(SHA, V, F, "Heltec_v3_repeater_observer_mqtt-arrc", "arrc");
  // The channel relabels an arrc manifest as this node's: sig2 no longer verifies.
  EXPECT_EQ(OTA_COMBO_UNSIGNED, otaManifestCombination(R_PUB_HEX.c_str(), SHA.c_str(), V, F,
            "Heltec_v3_repeater_observer_mqtt-ar", "ar", s2.c_str(),
            "Heltec_v3_repeater_observer_mqtt-ar", "ar"));
  // sig (the pre-lou-14 signature) in sig2's place does not verify either.
  std::string s1 = signManifest(SHA, V, F);
  EXPECT_EQ(OTA_COMBO_UNSIGNED, otaManifestCombination(R_PUB_HEX.c_str(), SHA.c_str(), V, F,
            "Heltec_v3_repeater_observer_mqtt-ar", "ar", s1.c_str(),
            "Heltec_v3_repeater_observer_mqtt-ar", "ar"));
  EXPECT_EQ(OTA_COMBO_UNSIGNED, otaManifestCombination(R_PUB_HEX.c_str(), SHA.c_str(), V, F,
            "Heltec_v3_repeater_observer_mqtt-ar", "ar", "",
            "Heltec_v3_repeater_observer_mqtt-ar", "ar"));
  EXPECT_EQ(OTA_COMBO_UNSIGNED, otaManifestCombination(R_PUB_HEX.c_str(), SHA.c_str(), V, F,
            NULL, "ar", s2.c_str(), "Heltec_v3_repeater_observer_mqtt-ar", "ar"));
}

TEST(OtaNewer, TheRunningVersionIsComparedWhole) {
  // Up to lou-14 the firmware compared only the token before the first '-' -- "esp32s3"
  // since ar-11's MCU prefix, "v1.17.1" before it -- which carries no revision, so every
  // other build on offer read as newer, an older one included. The verdict takes the
  // whole string; the token is for the build number and for display.
  const char* running = "esp32s3-v1.17.1-lou-14-arrc-observer-1a2b3c4d";
  EXPECT_EQ(OTA_OLDER, otaUpdateVerdict(running, "esp32s3-v1.17.1-ar-13-16a05810", -1, 0, false));
  EXPECT_EQ(OTA_NEWER, otaUpdateVerdict(running, "esp32s3-v1.17.1-lou-15-arrc-9f04c21b", -1, 0, false));
  char tok[16];
  otaVersionToken(running, tok, sizeof(tok));
  EXPECT_STREQ("v1.17.1", tok);
  otaVersionToken("v1.16.0.37-observer-9670035", tok, sizeof(tok));
  EXPECT_STREQ("v1.16.0.37", tok);
  otaVersionToken("nrf52840-v1.17.1.3-lou-14-ar-1a2b3c4d", tok, sizeof(tok));
  EXPECT_STREQ("v1.17.1.3", tok);
  otaVersionToken("dev-build", tok, sizeof(tok));
  EXPECT_STREQ("dev", tok);
  otaVersionToken(NULL, tok, sizeof(tok));
  EXPECT_STREQ("", tok);
}

// The manifest scripts/manifest.py signs, read back here: the release tooling and the
// node agree on both signed strings byte for byte. Signed with this suite's test key
// (seed 40..5f), never the release key.
static std::string jsonField(const std::string& doc, const std::string& key) {
  size_t at = doc.find("\"" + key + "\": \"");
  if (at == std::string::npos) return "";
  at += key.size() + 5;
  return doc.substr(at, doc.find('"', at) - at);
}

TEST(OtaCombination, TheReleaseToolsManifestVerifiesOnTheNode) {
  makeReleaseKey();
  EXPECT_EQ("2543B92FF1095511476ADC8369DB6DDC933665A11978DDA1404EE1066CA9559D", R_PUB_HEX);
  FILE* f = fopen("test/data/manifest-lou-14-example.json", "r");
  ASSERT_NE(nullptr, f) << "run from the repository root";
  std::string doc;
  char buf[512];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) doc.append(buf, n);
  fclose(f);
  const std::string sha = jsonField(doc, "sha256"), ver = jsonField(doc, "version"),
                    file = jsonField(doc, "file"), variant = jsonField(doc, "variant"),
                    features = jsonField(doc, "features");
  EXPECT_TRUE(otaManifestSignatureOk(R_PUB_HEX.c_str(), sha.c_str(), ver.c_str(), file.c_str(),
                                     jsonField(doc, "sig").c_str()));
  const std::string sig2 = jsonField(doc, "sig2");
  EXPECT_EQ(OTA_COMBO_OK, otaManifestCombination(R_PUB_HEX.c_str(), sha.c_str(), ver.c_str(), file.c_str(),
            variant.c_str(), features.c_str(), sig2.c_str(), "Heltec_v3_repeater_observer_mqtt-ar", "ar"));
  EXPECT_EQ(OTA_COMBO_OTHER_VARIANT, otaManifestCombination(R_PUB_HEX.c_str(), sha.c_str(), ver.c_str(),
            file.c_str(), variant.c_str(), features.c_str(), sig2.c_str(),
            "Heltec_v3_repeater_observer_mqtt-arrc", "arrc"));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
