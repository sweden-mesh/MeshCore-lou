// Host tests for the v2 command envelope (src/helpers/MqttControlV2.h, firmware TODO 17a)
// against the real ChaCha20-Poly1305, HKDF and SHA-256 of rweather/Crypto and MeshCore's
// own ed25519. Runs in env:native_v2. The fixture test writes the known-answer vectors
// mccontrol checks byte for byte: tests/data/v2-vectors-ar-13.txt in the mccontrol tree.
#include <gtest/gtest.h>
#include <stdarg.h>
#include <string>
#include <vector>
#include <ed_25519.h>
#include "helpers/MqttControlV2.h"

static std::string hex(const uint8_t* b, size_t n) {
  static const char d[] = "0123456789ABCDEF";
  std::string s;
  for (size_t i = 0; i < n; i++) { s += d[b[i] >> 4]; s += d[b[i] & 15]; }
  return s;
}

static std::vector<uint8_t> unhex(const char* h) {
  std::vector<uint8_t> v;
  for (size_t i = 0; h[i] && h[i + 1]; i += 2) {
    unsigned x;
    sscanf(h + i, "%2x", &x);
    v.push_back((uint8_t)x);
  }
  return v;
}

// A MeshCore identity from a 32-byte seed, as LocalIdentity does: the 64-byte expanded key.
struct Ident {
  uint8_t pub[32], prv[64];
  explicit Ident(uint8_t fill) {
    uint8_t seed[32];
    memset(seed, fill, sizeof(seed));
    ed25519_create_keypair(pub, prv, seed);
  }
};

static void signWith(void* ctx, uint8_t sig[64], const uint8_t* msg, size_t len) {
  Ident* id = (Ident*)ctx;
  ed25519_sign(sig, msg, len, id->pub, id->prv);
}

static const Ident OP(0x11), NODE(0x22);
static const uint32_t EXPIRY = 1760000000;

static std::string topicFor(const Ident& node) {
  return "meshcore/JKG/" + hex(node.pub, 32) + "/cmd";
}

// The node's key: its own identity with the operator's public key.
static void nodeKey(uint8_t key[32]) {
  uint8_t shared[32];
  ed25519_key_exchange(shared, OP.pub, NODE.prv);
  mqttV2DeriveKey(shared, topicFor(NODE).c_str(), key);
}

// The tool's key: the operator's own seed with the node's public key.
static void toolKey(uint8_t key[32]) {
  uint8_t shared[32];
  ed25519_key_exchange(shared, NODE.pub, OP.prv);
  mqttV2DeriveKey(shared, topicFor(NODE).c_str(), key);
}

static std::string command(uint32_t counter, const char* text, uint32_t expiry = EXPIRY) {
  uint8_t key[32];
  toolKey(key);
  char out[MQTTCTRL_MAX_PAYLOAD + 1];
  size_t n = mqttV2BuildCommand(key, topicFor(NODE).c_str(), counter, expiry, text, signWith,
                                (void*)&OP, out, sizeof(out));
  return std::string(out, n);
}

static std::string region100() {
  std::string s = "region put ";
  while (s.size() < 100) s += "se-jkp-mul-";
  return s.substr(0, 100);
}

// ---- the primitives against their RFCs -----------------------------------------------

TEST(Primitives, ChaChaPolyIsRfc8439) {
  // RFC 8439 2.8.2
  std::vector<uint8_t> key = unhex("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");
  std::vector<uint8_t> iv = unhex("070000004041424344454647");
  std::vector<uint8_t> aad = unhex("50515253C0C1C2C3C4C5C6C7");
  const char* pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
  ChaChaPoly c;
  c.setKey(key.data(), 32);
  c.setIV(iv.data(), 12);
  c.addAuthData(aad.data(), aad.size());
  std::vector<uint8_t> ct(strlen(pt));
  c.encrypt(ct.data(), (const uint8_t*)pt, ct.size());
  uint8_t tag[16];
  c.computeTag(tag, 16);
  EXPECT_EQ("D31A8D34648E60DB7B86AFBC53EF7EC2", hex(ct.data(), 16));
  EXPECT_EQ("1AE10B594F09E26A7E902ECBD0600691", hex(tag, 16));
}

TEST(Primitives, HkdfSha256WithAnEmptySaltIsRfc5869) {
  // RFC 5869 A.3
  std::vector<uint8_t> ikm(22, 0x0b);
  uint8_t okm[42];
  hkdf<SHA256>(okm, sizeof(okm), ikm.data(), ikm.size(), NULL, 0, NULL, 0);
  EXPECT_EQ("8DA4E775A563C18F715F802A063C5A31B8A11F5C5EE1879EC3454E5F3C738D2D"
            "9D201395FAA4B61A96C8", hex(okm, sizeof(okm)));
}

TEST(Primitives, BothSidesAgreeOnTheKey) {
  uint8_t a[32], b[32];
  nodeKey(a);
  toolKey(b);
  EXPECT_EQ(hex(a, 32), hex(b, 32));
}

TEST(Primitives, TheKeyIsPerTopic) {
  uint8_t shared[32], a[32], b[32];
  ed25519_key_exchange(shared, OP.pub, NODE.prv);
  mqttV2DeriveKey(shared, "meshcore/JKG/AA/cmd", a);
  mqttV2DeriveKey(shared, "meshcore/JKG/AB/cmd", b);
  EXPECT_NE(hex(a, 32), hex(b, 32));
}

TEST(Primitives, NonceIsDirectionZerosAndTheCounterBigEndian) {
  uint8_t n[12];
  mqttV2Nonce(MQTTV2_DIR_COMMAND, 7, n);
  EXPECT_EQ("000000000000000000000007", hex(n, 12));
  mqttV2Nonce(MQTTV2_DIR_RESULT, 0x01020304, n);
  EXPECT_EQ("010000000000000001020304", hex(n, 12));
}

TEST(Primitives, Base64UrlRoundTripsWithoutPadding) {
  uint8_t in[5] = {0xFB, 0xFF, 0x00, 0x10, 0x83};
  char out[16];
  for (size_t n = 0; n <= 5; n++) {
    size_t len = mqttV2B64Encode(in, n, out, sizeof(out));
    EXPECT_EQ(MQTTV2_B64_LEN(n), len);
    EXPECT_EQ(nullptr, strchr(out, '='));
    uint8_t back[8];
    EXPECT_EQ(n, mqttV2B64Decode(out, len, back, sizeof(back)));
    EXPECT_EQ(0, memcmp(in, back, n));
  }
  mqttV2B64Encode(in, 3, out, sizeof(out));
  EXPECT_STREQ("-_8A", out);
  uint8_t back[8];
  EXPECT_EQ(0u, mqttV2B64Decode("-_8=", 4, back, sizeof(back)));   // padding is not ours
  EXPECT_EQ(0u, mqttV2B64Decode("A", 1, back, sizeof(back)));
}

// ---- the command ---------------------------------------------------------------------

TEST(Command, OpensToTheTextItCarried) {
  uint8_t key[32];
  nodeKey(key);
  std::string p = command(1, "get name");
  MqttCtrlEnvelope env;
  char text[MQTTV2_CMD_PAD_LARGE + 1];
  ASSERT_EQ(MQTTCTRL_OK, mqttV2OpenCommand(key, p.data(), p.size(), &env, text));
  EXPECT_EQ(1u, env.counter);
  EXPECT_EQ(EXPIRY, env.expiry);
  EXPECT_EQ("get name", std::string(env.command, env.command_len));
}

TEST(Command, PaddingBoundaries64And160) {
  // The b64 field's length names only the padded size, never the command.
  auto sealedLen = [](const std::string& p) {
    size_t a = p.find('|', p.find('|', 3) + 1) + 1;
    return p.find('|', a) - a;
  };
  std::string c64(64, 'x'), c65(65, 'x'), c160(160, 'x'), c161(161, 'x');
  EXPECT_EQ(MQTTV2_B64_LEN(64 + 16), sealedLen(command(1, "get name")));
  EXPECT_EQ(MQTTV2_B64_LEN(64 + 16), sealedLen(command(1, c64.c_str())));
  EXPECT_EQ(MQTTV2_B64_LEN(160 + 16), sealedLen(command(1, c65.c_str())));
  EXPECT_EQ(MQTTV2_B64_LEN(160 + 16), sealedLen(command(1, c160.c_str())));
  EXPECT_EQ("", command(1, c161.c_str()));                 // over 160 refused
  uint8_t key[32];
  nodeKey(key);
  for (const std::string& c : {c64, c65, c160}) {
    std::string p = command(3, c.c_str());
    MqttCtrlEnvelope env;
    char text[MQTTV2_CMD_PAD_LARGE + 1];
    ASSERT_EQ(MQTTCTRL_OK, mqttV2OpenCommand(key, p.data(), p.size(), &env, text));
    EXPECT_EQ(c, std::string(env.command, env.command_len));
  }
}

TEST(Command, TheTagIsCheckedFirstAndAForgeryYieldsNothing) {
  uint8_t key[32];
  nodeKey(key);
  std::string p = command(5, "set autoreply off");
  size_t b = p.find('|', p.find('|', 3) + 1) + 1;
  for (size_t at : {b, b + 40, b + 100}) {                // ciphertext and tag bytes
    std::string bad = p;
    bad[at] = bad[at] == 'A' ? 'B' : 'A';
    MqttCtrlEnvelope env;
    char text[MQTTV2_CMD_PAD_LARGE + 1];
    memset(text, 0x55, sizeof(text));
    EXPECT_EQ(MQTTCTRL_ERR_SIG_INVALID, mqttV2OpenCommand(key, bad.data(), bad.size(), &env, text));
    EXPECT_EQ(0, text[0]);                                 // nothing of the plaintext kept
  }
}

TEST(Command, TheCounterAndExpiryAreBoundByTheTag) {
  // Replaying the sealed bytes under another counter or expiry fails the tag.
  uint8_t key[32];
  nodeKey(key);
  std::string p = command(5, "get name");
  std::string later = "v2|6" + p.substr(4);
  std::string longer = p;
  longer.replace(p.find(std::to_string(EXPIRY)), 10, std::to_string(EXPIRY + 600));
  MqttCtrlEnvelope env;
  char text[MQTTV2_CMD_PAD_LARGE + 1];
  EXPECT_EQ(MQTTCTRL_ERR_SIG_INVALID, mqttV2OpenCommand(key, later.data(), later.size(), &env, text));
  EXPECT_EQ(MQTTCTRL_ERR_SIG_INVALID, mqttV2OpenCommand(key, longer.data(), longer.size(), &env, text));
}

TEST(Command, AnotherNodesKeyCannotOpenIt) {
  Ident other(0x33);
  uint8_t shared[32], key[32];
  ed25519_key_exchange(shared, OP.pub, other.prv);
  mqttV2DeriveKey(shared, topicFor(other).c_str(), key);
  std::string p = command(1, "get name");
  MqttCtrlEnvelope env;
  char text[MQTTV2_CMD_PAD_LARGE + 1];
  EXPECT_EQ(MQTTCTRL_ERR_SIG_INVALID, mqttV2OpenCommand(key, p.data(), p.size(), &env, text));
}

TEST(Command, ShapesThatAreNotV2AreRefusedBeforeAnyCrypto) {
  uint8_t key[32];
  nodeKey(key);
  MqttCtrlEnvelope env;
  char text[MQTTV2_CMD_PAD_LARGE + 1];
  std::string p = command(1, "get name");
  std::string v1 = "v1" + p.substr(2);
  EXPECT_EQ(MQTTCTRL_ERR_BAD_VERSION, mqttV2OpenCommand(key, v1.data(), v1.size(), &env, text));
  std::string nosig = p.substr(0, p.rfind('|'));
  EXPECT_NE(MQTTCTRL_OK, mqttV2OpenCommand(key, nosig.data(), nosig.size(), &env, text));
  std::string zero = "v2|01" + p.substr(4);                // "01" is not the "1" sealed
  EXPECT_NE(MQTTCTRL_OK, mqttV2OpenCommand(key, zero.data(), zero.size(), &env, text));
}

TEST(Command, TheOuterSignatureIsTheOperatorsOverTopicAndBody) {
  // What the broker checks: "<topic>\n" + everything before the last '|'.
  std::string p = command(7, "get name");
  std::string body = p.substr(0, p.rfind('|'));
  std::string msg = topicFor(NODE) + "\n" + body;
  std::vector<uint8_t> sig = unhex(p.substr(p.rfind('|') + 1).c_str());
  ASSERT_EQ(64u, sig.size());
  EXPECT_EQ(1, ed25519_verify(sig.data(), (const uint8_t*)msg.data(), msg.size(), OP.pub));
}

TEST(Command, AfterOpeningTheV1RulesDecide) {
  // Counter, expiry and the deny list run on the decrypted text, as for v1.
  uint8_t key[32];
  nodeKey(key);
  MqttCtrlEnvelope env;
  char text[MQTTV2_CMD_PAD_LARGE + 1];
  std::string ok = command(9, "get name");
  ASSERT_EQ(MQTTCTRL_OK, mqttV2OpenCommand(key, ok.data(), ok.size(), &env, text));
  EXPECT_EQ(MQTTCTRL_OK, mqttCtrlAuthorise(&env, 8, EXPIRY - 60));
  std::string denied = command(10, "set prv.key 00");
  ASSERT_EQ(MQTTCTRL_OK, mqttV2OpenCommand(key, denied.data(), denied.size(), &env, text));
  EXPECT_EQ(MQTTCTRL_ERR_NOT_ALLOWED, mqttCtrlAuthorise(&env, 9, EXPIRY - 60));
}

TEST(Command, NoNonceIsReusedAcrossAReboot) {
  // The counter is the nonce, and it is persisted before a command runs. After a reboot
  // the node loads the last one and refuses any command at or below it, so the sealed
  // bytes of a counter already used -- the same nonce -- are never accepted twice.
  uint8_t key[32];
  nodeKey(key);
  MqttCtrlEnvelope env;
  char text[MQTTV2_CMD_PAD_LARGE + 1];
  std::string p = command(12, "get name");
  ASSERT_EQ(MQTTCTRL_OK, mqttV2OpenCommand(key, p.data(), p.size(), &env, text));
  uint32_t persisted = 11;
  ASSERT_EQ(MQTTCTRL_OK, mqttCtrlAuthorise(&env, persisted, EXPIRY - 60));
  persisted = env.counter;                                  // saved, then the node reboots
  ASSERT_EQ(MQTTCTRL_OK, mqttV2OpenCommand(key, p.data(), p.size(), &env, text));
  EXPECT_EQ(MQTTCTRL_ERR_REPLAY, mqttCtrlAuthorise(&env, persisted, EXPIRY - 60));
}

TEST(Command, AV1PayloadIsNeverTakenForV2) {
  // A v1 node's path is untouched: the v2 branch claims only "v2|".
  EXPECT_FALSE(mqttV2IsEnvelope("v1|1|2|get name|00", 18));
  EXPECT_FALSE(mqttV2IsEnvelope("v2", 2));
  EXPECT_FALSE(mqttV2IsEnvelope("pong|a1b2c3d4", 13));
  EXPECT_TRUE(mqttV2IsEnvelope("v2|1", 4));
}

// ---- the result ----------------------------------------------------------------------

static std::string result(uint32_t counter, int code, const char* cmd, const char* reply) {
  uint8_t key[32];
  nodeKey(key);
  char out[MQTTV2_MAX_RESULT];
  size_t n = mqttV2BuildResult(key, counter, code, cmd, reply, out, sizeof(out));
  return std::string(out, n);
}

TEST(Result, RoundTripsToTheTool) {
  std::string r = result(1, 0, "get name", "> Gisebo");
  EXPECT_EQ(0u, r.find("r3|1|"));
  uint8_t key[32];
  toolKey(key);
  uint32_t counter = 0;
  char text[MQTTV2_RES_PAD_LARGE + 1];
  ASSERT_TRUE(mqttV2OpenResult(key, r.c_str(), &counter, text));
  EXPECT_EQ(1u, counter);
  EXPECT_STREQ("0|get name|> Gisebo", text);
}

TEST(Result, PaddingBoundaries256And512AndALongReplyIsCut) {
  auto sealedLen = [](const std::string& r) { return r.size() - (r.find('|', 3) + 1); };
  // "0|c|" is 4 bytes, so a reply of 252 fills 256 exactly
  std::string r252(252, 'y'), r253(253, 'y'), r508(508, 'y'), r600(600, 'y');
  EXPECT_EQ(MQTTV2_B64_LEN(256 + 16), sealedLen(result(2, 0, "c", r252.c_str())));
  EXPECT_EQ(MQTTV2_B64_LEN(512 + 16), sealedLen(result(2, 0, "c", r253.c_str())));
  EXPECT_EQ(MQTTV2_B64_LEN(512 + 16), sealedLen(result(2, 0, "c", r508.c_str())));
  std::string cut = result(2, 0, "c", r600.c_str());
  EXPECT_EQ(MQTTV2_B64_LEN(512 + 16), sealedLen(cut));
  uint8_t key[32];
  toolKey(key);
  uint32_t counter;
  char text[MQTTV2_RES_PAD_LARGE + 1];
  ASSERT_TRUE(mqttV2OpenResult(key, cut.c_str(), &counter, text));
  EXPECT_EQ(512u, strlen(text));
  EXPECT_EQ("0|c|" + std::string(508, 'y'), std::string(text));
}

TEST(Result, UsesTheOtherDirectionSoNoNonceRepeats) {
  // A command and its result share a counter; their keystreams must still differ.
  uint8_t key[32];
  nodeKey(key);
  uint8_t zeros[64] = {0}, a[80], b[80];
  mqttV2Seal(key, MQTTV2_DIR_COMMAND, 9, "x", zeros, 64, a);
  mqttV2Seal(key, MQTTV2_DIR_RESULT, 9, "x", zeros, 64, b);
  EXPECT_NE(hex(a, 64), hex(b, 64));
}

TEST(Result, AForgedOrTamperedResultDoesNotOpen) {
  std::string r = result(4, 0, "get name", "> Gisebo");
  r[r.size() - 3] = r[r.size() - 3] == 'A' ? 'B' : 'A';
  uint8_t key[32];
  toolKey(key);
  uint32_t counter;
  char text[MQTTV2_RES_PAD_LARGE + 1];
  EXPECT_FALSE(mqttV2OpenResult(key, r.c_str(), &counter, text));
  std::string moved = "r3|5" + result(4, 0, "get name", "> Gisebo").substr(4);
  EXPECT_FALSE(mqttV2OpenResult(key, moved.c_str(), &counter, text));
}

// ---- the shared fixture --------------------------------------------------------------

static void add(std::string& out, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
static void add(std::string& out, const char* fmt, ...) {
  char line[2048];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(line, sizeof(line), fmt, ap);
  va_end(ap);
  out += line;
}

static void writeFile(const char* path, const std::string& text) {
  FILE* f = fopen(path, "w");
  ASSERT_NE(nullptr, f) << path;
  fwrite(text.data(), 1, text.size(), f);
  fclose(f);
}

// One record per line: the kind, then tab-separated "name=value" fields. Values never
// hold a tab; hex is upper case; the payload is always the last field. Written beside the
// tests, and into the mccontrol tree when it sits where the workspace keeps it.
TEST(Fixture, WritesTheKnownAnswerVectorsForMccontrol) {
  uint8_t shared[32], key[32];
  ed25519_key_exchange(shared, OP.pub, NODE.prv);
  nodeKey(key);
  std::string topic = topicFor(NODE), out;
  add(out, "# v2 envelope known-answer vectors, firmware ar-13 (planning/firmware/TODO.md 17a).\n");
  add(out, "# Written by MeshCore-observer test/test_mqtt_v2; do not edit. One record per line:\n");
  add(out, "# the kind, then tab-separated name=value fields; hex upper case; payload last.\n");
  add(out, "keys\toperator_seed=%s\toperator_pub=%s\tnode_seed=%s\tnode_pub=%s\tshared=%s\ttopic=%s\tkey=%s\n",
      std::string(64, '1').c_str(), hex(OP.pub, 32).c_str(), std::string(64, '2').c_str(),
      hex(NODE.pub, 32).c_str(), hex(shared, 32).c_str(), topic.c_str(), hex(key, 32).c_str());
  struct { uint32_t counter; std::string text; } cmds[] = { {1, "get name"}, {7, region100()} };
  for (auto& c : cmds) {
    uint8_t nonce[12];
    mqttV2Nonce(MQTTV2_DIR_COMMAND, c.counter, nonce);
    add(out, "command\tcounter=%u\texpiry=%u\tcommand=%s\tpadded=%u\tnonce=%s\taad=v2|%u|%u\tpayload=%s\n",
        (unsigned)c.counter, (unsigned)EXPIRY, c.text.c_str(),
        (unsigned)mqttV2PadTo(c.text.size(), MQTTV2_CMD_PAD_SMALL, MQTTV2_CMD_PAD_LARGE),
        hex(nonce, 12).c_str(), (unsigned)c.counter, (unsigned)EXPIRY,
        command(c.counter, c.text.c_str()).c_str());
  }
  uint8_t nonce[12];
  mqttV2Nonce(MQTTV2_DIR_RESULT, 1, nonce);
  add(out, "result\tcounter=1\tcode=0\tcommand=get name\treply=> Gisebo\tplaintext=0|get name|> Gisebo"
           "\tpadded=256\tnonce=%s\taad=r3|1\tpayload=%s\n",
      hex(nonce, 12).c_str(), result(1, 0, "get name", "> Gisebo").c_str());

  writeFile("test/data/v2-vectors-ar-13.txt", out);
  FILE* probe = fopen("../../mccontrol/tests/data/command-verdicts-ar-11.txt", "r");
  if (probe != NULL) {
    fclose(probe);
    writeFile("../../mccontrol/tests/data/v2-vectors-ar-13.txt", out);
  }
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
