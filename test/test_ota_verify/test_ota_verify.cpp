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
int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
