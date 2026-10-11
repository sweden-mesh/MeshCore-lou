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

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
