// Host tests for mcc3 (src/helpers/MqttControlV3.h, lou-20): the control plane keyed by the
// node and sealed to its owner, against the real rweather/Crypto and MeshCore's ed25519.
// Runs in env:native_v2. The contract is mccontrol-spec's vectors, copied to
// test/data/mcc3-vectors.json and turned into mcc3_vectors.h by scripts/mcc3-vectors.py:
// every vector is rebuilt byte for byte from its inputs, every refusal gives its outcome.
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <ed_25519.h>
#include "helpers/MqttControlV3.h"
#include "mcc3_vectors.h"

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

// A MeshCore identity from a 32-byte seed, as LocalIdentity holds it.
struct Ident {
  uint8_t pub[32], prv[64];
  explicit Ident(const char* seed_hex) {
    std::vector<uint8_t> seed = unhex(seed_hex);
    ed25519_create_keypair(pub, prv, seed.data());
  }
};

static void signWith(void* ctx, uint8_t sig[64], const uint8_t* msg, size_t len) {
  Ident* id = (Ident*)ctx;
  ed25519_sign(sig, msg, len, id->pub, id->prv);
}

// The node's verifier: the command key it holds, as mesh::Identity::verify checks it.
static bool verifyWith(void* ctx, const uint8_t sig[64], const uint8_t* msg, size_t len) {
  return ed25519_verify(sig, msg, len, (const uint8_t*)ctx) == 1;
}

static const Ident OWNER(MCC3_SEED_COMMAND), NODE(MCC3_SEED_NODE);

// The node's side: its identity and the command key it holds, as Fork::refreshMcc3Keys.
static Mcc3Keys nodeKeys(const Ident& node, const uint8_t* command_key) {
  uint8_t shared[32];
  ed25519_key_exchange(shared, command_key, node.prv);
  Mcc3Keys k;
  mcc3DeriveKeys(shared, hex(node.pub, 32).c_str(), &k);
  return k;
}

// The owner's side: its seed and the node's key.
static Mcc3Keys ownerKeys(const Ident& owner, const uint8_t* node_key) {
  uint8_t shared[32];
  ed25519_key_exchange(shared, node_key, owner.prv);
  Mcc3Keys k;
  mcc3DeriveKeys(shared, hex(node_key, 32).c_str(), &k);
  return k;
}

static Mcc3Keys keysOf(const char* cmd, const char* mesh, const char* alive) {
  Mcc3Keys k;
  memcpy(k.cmd, unhex(cmd).data(), 32);
  memcpy(k.mesh, unhex(mesh).data(), 32);
  memcpy(k.alive, unhex(alive).data(), 32);
  return k;
}

static std::vector<uint8_t> unb64(const char* s) {
  std::vector<uint8_t> v(strlen(s));
  size_t n = mqttV2B64Decode(s, strlen(s), v.data(), v.size());
  v.resize(n);
  return v;
}

static MqttCtrlResult openOnNode(const Mcc3Keys& k, const uint8_t* node_key, const std::string& payload,
                                 const uint8_t* command_key, Mcc3Command* out) {
  return mcc3OpenCommand(&k, node_key, payload.data(), payload.size(), verifyWith, (void*)command_key, out);
}

// ---- the owner's side, as mccontrol opens what the node sends ---------------------------

struct Opened {
  std::string outcome;
  uint32_t counter = 0, clock = 0;
  int code = -1;
  std::string command, reply;
};

static Opened openResult(const Mcc3Keys& k, const char* payload) {
  Opened o;
  std::vector<uint8_t> raw = unb64(payload);
  if ((raw.size() != MCC3_RES_SIZE(MCC3_RES_PAD_SMALL) && raw.size() != MCC3_RES_SIZE(MCC3_RES_PAD_LARGE))
      || raw[0] != MCC3_KIND_RESULT) { o.outcome = "bad-fields"; return o; }
  size_t n = raw.size() - MCC3_RES_HEAD - MCC3_TAG_LEN;
  uint8_t* p = raw.data() + MCC3_RES_HEAD;
  if (!mcc3Open(k.cmd, raw.data() + 1, raw.data(), MCC3_RES_HEAD, p, n, p)) { o.outcome = "sig-invalid"; return o; }
  o.outcome = "ok";
  o.counter = mqttCtrlMeshU32(p);
  o.code = p[4];
  o.clock = mqttCtrlMeshU32(p + 5);
  o.command.assign((const char*)p + 10, p[9]);
  size_t r = n - 10 - p[9];
  while (r > 0 && p[10 + p[9] + r - 1] == 0) r--;
  o.reply.assign((const char*)p + 10 + p[9], r);
  return o;
}

static Opened openMeshResponse(const Mcc3Keys& k, const std::vector<uint8_t>& resp) {
  Opened o;
  if (resp.size() < MCC3_MESH_RESP_OVERHEAD || resp[4] != MCC3_KIND_RESULT) { o.outcome = "bad-fields"; return o; }
  std::vector<uint8_t> r = resp;
  size_t n = r.size() - 17 - MCC3_TAG_LEN;
  uint8_t* p = r.data() + 17;
  if (!mcc3Open(k.cmd, r.data() + 5, r.data() + 4, 13, p, n, p)) { o.outcome = "sig-invalid"; return o; }
  o.outcome = "ok";
  o.counter = mqttCtrlMeshU32(p);
  o.code = p[4];
  o.clock = mqttCtrlMeshU32(p + 5);
  o.reply.assign((const char*)p + 9, n - 9);
  return o;
}

struct OpenedAlive {
  std::string outcome;
  uint32_t w[6] = {0};
  uint8_t flags = 0, mesh = 0, via = 0;
  std::string fingerprint, version, region, name;
};

static OpenedAlive openAlive(const Mcc3Keys& k, const char* payload) {
  OpenedAlive a;
  std::vector<uint8_t> raw = unb64(payload);
  if (raw.size() != MCC3_ALIVE_SIZE || raw[0] != MCC3_KIND_ALIVE) { a.outcome = "bad-fields"; return a; }
  uint8_t* p = raw.data() + 13;
  if (!mcc3Open(k.alive, raw.data() + 1, raw.data(), 13, p, MCC3_ALIVE_PLAIN, p)) { a.outcome = "sig-invalid"; return a; }
  a.outcome = "ok";
  for (int i = 0; i < 6; i++) a.w[i] = mqttCtrlMeshU32(p + 4 * i);
  a.flags = p[24];
  a.mesh = p[25];
  a.fingerprint = hex(p + 26, 4);
  a.via = p[30];
  size_t at = 32;
  std::string* s[3] = { &a.version, &a.region, &a.name };
  for (int i = 0; i < 3; i++) {
    s[i]->assign((const char*)p + at + 1, p[at]);
    at += 1 + p[at];
  }
  return a;
}

// ---- keys -------------------------------------------------------------------------------

TEST(Mcc3Keys, BothSidesAgreeOnSAndTheThreeKeys) {
  EXPECT_EQ(MCC3_PUB_COMMAND, hex(OWNER.pub, 32));
  EXPECT_EQ(MCC3_PUB_NODE, hex(NODE.pub, 32));
  uint8_t a[32], b[32];
  ed25519_key_exchange(a, OWNER.pub, NODE.prv);
  ed25519_key_exchange(b, NODE.pub, OWNER.prv);
  EXPECT_EQ(MCC3_SHARED_NODE_SIDE, hex(a, 32));
  EXPECT_EQ(MCC3_SHARED, hex(b, 32));
  Mcc3Keys n = nodeKeys(NODE, OWNER.pub), o = ownerKeys(OWNER, NODE.pub);
  EXPECT_EQ(MCC3_K_NODE_SIDE_CMD, hex(n.cmd, 32));
  EXPECT_EQ(MCC3_K_NODE_SIDE_MESH, hex(n.mesh, 32));
  EXPECT_EQ(MCC3_K_NODE_SIDE_ALIVE, hex(n.alive, 32));
  EXPECT_EQ(MCC3_K_OWNER_CMD, hex(o.cmd, 32));
  EXPECT_EQ(MCC3_K_OWNER_MESH, hex(o.mesh, 32));
  EXPECT_EQ(MCC3_K_OWNER_ALIVE, hex(o.alive, 32));
}

TEST(Mcc3Keys, AnotherNodeAndAnotherOwnerGetOtherKeys) {
  Ident other_node(MCC3_SEED_OTHER_NODE), other_owner(MCC3_SEED_OTHER_OWNER);
  EXPECT_EQ(MCC3_PUB_OTHER_NODE, hex(other_node.pub, 32));
  EXPECT_EQ(MCC3_PUB_OTHER_OWNER, hex(other_owner.pub, 32));
  Mcc3Keys a = nodeKeys(other_node, OWNER.pub);
  EXPECT_EQ(MCC3_K_OTHER_NODE_CMD, hex(a.cmd, 32));
  EXPECT_EQ(MCC3_K_OTHER_NODE_MESH, hex(a.mesh, 32));
  EXPECT_EQ(MCC3_K_OTHER_NODE_ALIVE, hex(a.alive, 32));
  Mcc3Keys b = nodeKeys(NODE, other_owner.pub);
  EXPECT_EQ(MCC3_K_OTHER_OWNER_CMD, hex(b.cmd, 32));
  EXPECT_EQ(MCC3_K_OTHER_OWNER_MESH, hex(b.mesh, 32));
  EXPECT_EQ(MCC3_K_OTHER_OWNER_ALIVE, hex(b.alive, 32));
}

TEST(Mcc3Keys, TheTopicsCarryTheWholeKeyAndNoRegion) {
  char t[MQTTCTRL_MAX_TOPIC + 1];
  ASSERT_TRUE(mcc3Topic("cmd", MCC3_PUB_NODE, t, sizeof(t)));
  EXPECT_STREQ(MCC3_COMMANDS[0].topic, t);
  ASSERT_TRUE(mcc3Topic("alive", MCC3_PUB_NODE, t, sizeof(t)));
  EXPECT_STREQ(MCC3_ALIVE[0].topic, t);
  EXPECT_TRUE(mcc3IsCommandTopic(MCC3_COMMANDS[0].topic));
  EXPECT_FALSE(mcc3IsCommandTopic("meshcore/JKG/4FD0/cmd"));
  EXPECT_FALSE(mcc3IsCommandTopic("mcc/alive/4FD0"));
  std::vector<uint8_t> rid = unhex(MCC3_COMMANDS[0].rid);
  ASSERT_TRUE(mcc3ResultTopic(rid.data(), t, sizeof(t)));
  EXPECT_STREQ(MCC3_COMMANDS[0].reply_topic, t);
  EXPECT_FALSE(mcc3ResultTopic(rid.data(), t, 38));
}

// ---- the vectors, byte for byte ---------------------------------------------------------

TEST(Mcc3Vectors, EveryMqttCommandIsRebuiltAndOpens) {
  const Mcc3Keys owner = ownerKeys(OWNER, NODE.pub), node = nodeKeys(NODE, OWNER.pub);
  for (const Mcc3VecCommand& v : MCC3_COMMANDS) {
    SCOPED_TRACE(v.name);
    std::vector<uint8_t> rid = unhex(v.rid), nonce = unhex(v.nonce);
    uint8_t msg[MCC3_MAX_SIGNED];
    size_t m = mcc3SignedBytes(NODE.pub, MCC3_ROAD_MQTT, 0, v.counter, v.expiry, rid.data(), v.command,
                               strlen(v.command), msg);
    EXPECT_EQ(v.signed_hex, hex(msg, m));
    uint8_t sig[64];
    signWith((void*)&OWNER, sig, msg, m);
    EXPECT_EQ(v.signature, hex(sig, 64));

    char out[512];
    size_t n = mcc3BuildCommand(&owner, NODE.pub, nonce.data(), v.counter, v.expiry, rid.data(), v.command,
                                signWith, (void*)&OWNER, out, sizeof(out));
    EXPECT_EQ(std::string(v.payload), std::string(out, n));
    EXPECT_EQ(v.bytes, unb64(v.payload).size());

    Mcc3Command c;
    ASSERT_EQ(MQTTCTRL_OK, openOnNode(node, NODE.pub, v.payload, OWNER.pub, &c));
    EXPECT_EQ(v.counter, c.counter);
    EXPECT_EQ(v.expiry, c.expiry);
    EXPECT_EQ(v.rid, hex(c.rid, 16));
    EXPECT_STREQ(v.command, c.command);
    EXPECT_EQ(strlen(v.command), c.command_len);
  }
}

TEST(Mcc3Vectors, EveryResultIsRebuiltAndOpens) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub), owner = ownerKeys(OWNER, NODE.pub);
  for (const Mcc3VecResult& v : MCC3_RESULTS) {
    SCOPED_TRACE(v.name);
    char out[MCC3_MAX_RESULT];
    size_t n = mcc3BuildResult(node.cmd, unhex(v.nonce).data(), v.counter, v.code, v.clock, v.command,
                               v.reply, out, sizeof(out));
    EXPECT_EQ(std::string(v.payload), std::string(out, n));
    EXPECT_EQ(v.bytes, unb64(out).size());
    Opened o = openResult(owner, out);
    ASSERT_EQ("ok", o.outcome);
    EXPECT_EQ(v.counter, o.counter);
    EXPECT_EQ(v.code, o.code);
    EXPECT_EQ(v.clock, o.clock);
    EXPECT_EQ(v.command, o.command);
    EXPECT_EQ(v.reply_opened, o.reply);
  }
}

TEST(Mcc3Vectors, EveryMeshRequestIsRebuiltAndOpens) {
  const Mcc3Keys owner = ownerKeys(OWNER, NODE.pub), node = nodeKeys(NODE, OWNER.pub);
  for (const Mcc3VecMeshRequest& v : MCC3_MESH_REQUESTS) {
    SCOPED_TRACE(v.name);
    uint8_t msg[MCC3_MAX_SIGNED];
    size_t m = mcc3SignedBytes(NODE.pub, MCC3_ROAD_MESH, 0, v.counter, v.expiry, NULL, v.command,
                               strlen(v.command), msg);
    EXPECT_EQ(v.signed_hex, hex(msg, m));
    uint8_t req[MCC3_MESH_REQUEST];
    ASSERT_TRUE(mcc3MeshBuildRequest(&owner, NODE.pub, v.companion_tag, v.counter, v.expiry, v.command,
                                     signWith, (void*)&OWNER, req));
    EXPECT_EQ(v.request, hex(req, sizeof(req)));
    EXPECT_EQ(v.app_sends, hex(req + 4, sizeof(req) - 4));
    uint8_t nonce[12] = {0};
    mqttCtrlMeshPutU32(&nonce[8], v.counter);
    EXPECT_EQ(v.nonce, hex(nonce, 12));
    uint8_t plain[MCC3_MESH_REQUEST - MCC3_MESH_HEAD];
    mcc3MeshStream(node.mesh, v.counter, req + MCC3_MESH_HEAD, sizeof(plain), plain);
    EXPECT_EQ(v.plaintext, hex(plain, sizeof(plain)));
    EXPECT_EQ(v.signature, hex(plain + 4, 64));

    // The node reads the first 136 bytes; the cipher's block padding after them is ignored.
    std::vector<uint8_t> datagram(req, req + sizeof(req));
    datagram.resize(144, 0xA5);
    Mcc3Command c;
    ASSERT_EQ(MQTTCTRL_OK, mcc3MeshOpen(&node, NODE.pub, v.counter - 1, datagram.data(), datagram.size(),
                                        verifyWith, (void*)OWNER.pub, &c));
    EXPECT_EQ(v.companion_tag, c.tag);
    EXPECT_EQ(v.counter, c.counter);
    EXPECT_EQ(v.expiry, c.expiry);
    EXPECT_STREQ(v.command, c.command);
  }
}

TEST(Mcc3Vectors, TheMeshResponseIsRebuiltAndOpens) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub), owner = ownerKeys(OWNER, NODE.pub);
  for (const Mcc3VecMeshResponse& v : MCC3_MESH_RESPONSES) {
    SCOPED_TRACE(v.name);
    uint8_t out[167];
    size_t n = mcc3MeshBuildResponse(node.cmd, unhex(v.nonce).data(), v.companion_tag, v.counter, v.code,
                                     v.clock, v.reply, sizeof(out), out);
    EXPECT_EQ(v.response, hex(out, n));
    Opened o = openMeshResponse(owner, std::vector<uint8_t>(out, out + n));
    ASSERT_EQ("ok", o.outcome);
    EXPECT_EQ(v.counter, o.counter);
    EXPECT_EQ(v.code, o.code);
    EXPECT_EQ(v.clock, o.clock);
    EXPECT_EQ(v.reply, o.reply);
  }
}

TEST(Mcc3Vectors, EveryAliveIsRebuiltAndOpens) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub), owner = ownerKeys(OWNER, NODE.pub);
  for (const Mcc3VecAlive& v : MCC3_ALIVE) {
    SCOPED_TRACE(v.name);
    Mcc3Alive a = { v.boot, v.sequence, v.uptime, v.clock, v.last_counter, v.interval, v.flags, v.mesh,
                    {0}, v.via, v.version, v.region, v.name_field };
    memcpy(a.fingerprint, unhex(v.fingerprint).data(), 4);
    char out[MCC3_ALIVE_B64 + 1];
    size_t n = mcc3BuildAlive(node.alive, unhex(v.nonce).data(), &a, out, sizeof(out));
    EXPECT_EQ(std::string(v.payload), std::string(out, n));
    EXPECT_EQ((size_t)MCC3_ALIVE_B64, n);
    OpenedAlive o = openAlive(owner, out);
    ASSERT_EQ("ok", o.outcome);
    const uint32_t w[6] = { v.boot, v.sequence, v.uptime, v.clock, v.last_counter, v.interval };
    for (int i = 0; i < 6; i++) EXPECT_EQ(w[i], o.w[i]) << i;
    EXPECT_EQ(v.flags, o.flags);
    EXPECT_EQ(v.mesh, o.mesh);
    EXPECT_EQ(v.fingerprint, o.fingerprint);
    EXPECT_EQ(v.via, o.via);
    EXPECT_EQ(v.opened_version, o.version);
    EXPECT_EQ(v.opened_region, o.region);
    EXPECT_EQ(v.opened_name, o.name);
  }
}

TEST(Mcc3Vectors, EveryRefusalGivesItsOutcome) {
  int by_node = 0, by_owner = 0;
  for (const Mcc3VecRefusal& v : MCC3_REFUSALS) {
    SCOPED_TRACE(v.name);
    std::string outcome;
    if (v.by_node) {
      by_node++;
      Ident node(v.node_seed);
      std::vector<uint8_t> command_key = unhex(v.command_key);
      Mcc3Keys k = nodeKeys(node, command_key.data());
      Mcc3Command c;
      MqttCtrlResult r;
      if (strcmp(v.kind, "command") == 0) {
        r = openOnNode(k, node.pub, v.input, command_key.data(), &c);
      } else {
        ASSERT_STREQ("mesh_request", v.kind);
        std::vector<uint8_t> req = unhex(v.input);
        r = mcc3MeshOpen(&k, node.pub, v.last_counter < 0 ? 0 : (uint32_t)v.last_counter, req.data(),
                         req.size(), verifyWith, command_key.data(), &c);
      }
      outcome = mqttCtrlResultName(r);
    } else {
      by_owner++;
      Mcc3Keys k = keysOf(v.key_cmd, v.key_mesh, v.key_alive);
      if (strcmp(v.kind, "result") == 0) outcome = openResult(k, v.input).outcome;
      else if (strcmp(v.kind, "alive") == 0) outcome = openAlive(k, v.input).outcome;
      else outcome = openMeshResponse(k, unhex(v.input)).outcome;
    }
    EXPECT_EQ(v.outcome, outcome);
  }
  EXPECT_EQ(25, by_node);
  EXPECT_EQ(12, by_owner);
}

TEST(Mcc3Vectors, WhatNoSenderBuildsIsNotBuilt) {
  const Mcc3Keys owner = ownerKeys(OWNER, NODE.pub);
  const uint8_t nonce[12] = {0}, rid[16] = {0};
  for (const Mcc3VecNotBuilt& v : MCC3_NOT_BUILT) {
    SCOPED_TRACE(v.command);
    if (v.mesh) {
      uint8_t req[MCC3_MESH_REQUEST];
      EXPECT_FALSE(mcc3MeshBuildRequest(&owner, NODE.pub, 0, 1, 1, v.command, signWith, (void*)&OWNER, req));
    } else {
      char out[512];
      EXPECT_EQ(0u, mcc3BuildCommand(&owner, NODE.pub, nonce, 1, 1, rid, v.command, signWith, (void*)&OWNER,
                                     out, sizeof(out)));
    }
  }
}

// ---- beyond the vectors -----------------------------------------------------------------

static std::string v1Payload() { return MCC3_COMMANDS[0].payload; }

TEST(Mcc3Command, EveryBitOfEveryByteMattersAndFlagsAreCheckedBeforeTheCipher) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub);
  std::vector<uint8_t> raw = unb64(v1Payload().c_str());
  for (size_t i = 0; i < raw.size(); i++) {
    for (int bit : { 0, 7 }) {
      std::vector<uint8_t> r = raw;
      r[i] ^= (uint8_t)(1 << bit);
      char b64[400];
      size_t n = mqttV2B64Encode(r.data(), r.size(), b64, sizeof(b64));
      Mcc3Command c;
      MqttCtrlResult res = openOnNode(node, NODE.pub, std::string(b64, n), OWNER.pub, &c);
      if (i == 0) EXPECT_EQ(MQTTCTRL_ERR_BAD_FIELDS, res) << i;
      else if (i == 1) EXPECT_EQ(MQTTCTRL_ERR_BAD_VERSION, res) << i;
      else EXPECT_EQ(MQTTCTRL_ERR_SIG_INVALID, res) << i << "/" << bit;
    }
  }
}

TEST(Mcc3Command, OnlyTheTwoSizesAreACommand) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub);
  std::vector<uint8_t> raw = unb64(v1Payload().c_str());
  for (size_t len : { (size_t)0, (size_t)181, (size_t)183, (size_t)277, (size_t)279, (size_t)400 }) {
    std::vector<uint8_t> r = raw;
    r.resize(len, 0);
    char b64[600];
    size_t n = mqttV2B64Encode(r.data(), r.size(), b64, sizeof(b64));
    Mcc3Command c;
    EXPECT_EQ(MQTTCTRL_ERR_BAD_FIELDS, openOnNode(node, NODE.pub, std::string(b64, n), OWNER.pub, &c)) << len;
  }
  Mcc3Command c;
  EXPECT_EQ(MQTTCTRL_ERR_BAD_FIELDS, openOnNode(node, NODE.pub, v1Payload() + "=", OWNER.pub, &c));
  // A v1 or v2 payload on the mcc3 topic is not an mcc3 command.
  EXPECT_EQ(MQTTCTRL_ERR_BAD_FIELDS, openOnNode(node, NODE.pub, "v1|7|1795000000|get name|" + std::string(128, 'A'),
                                                OWNER.pub, &c));
}

TEST(Mcc3Command, AFlagSetIsRefusedWhateverElseIsRight) {
  // Sealed and signed correctly by the owner with flags 1: still bad-version, never opened.
  const Mcc3Keys owner = ownerKeys(OWNER, NODE.pub), node = nodeKeys(NODE, OWNER.pub);
  std::vector<uint8_t> raw = unb64(v1Payload().c_str());
  raw[1] = 0x01;
  mcc3Seal(owner.cmd, raw.data() + 2, raw.data(), MCC3_CMD_HEAD, raw.data() + MCC3_CMD_HEAD,
           raw.size() - MCC3_CMD_HEAD - 16, raw.data() + MCC3_CMD_HEAD);
  char b64[400];
  size_t n = mqttV2B64Encode(raw.data(), raw.size(), b64, sizeof(b64));
  Mcc3Command c;
  EXPECT_EQ(MQTTCTRL_ERR_BAD_VERSION, openOnNode(node, NODE.pub, std::string(b64, n), OWNER.pub, &c));
}

TEST(Mcc3Command, TheSignedBytesNameTheNodeTheRoadAndTheReplyId) {
  uint8_t a[MCC3_MAX_SIGNED], b[MCC3_MAX_SIGNED];
  const uint8_t rid[16] = {1};
  size_t n = mcc3SignedBytes(NODE.pub, MCC3_ROAD_MQTT, 0, 7, 9, rid, "get name", 8, a);
  EXPECT_EQ(9u + 32 + 2 + 8 + 16 + 8, n);
  EXPECT_EQ(n - 16, mcc3SignedBytes(NODE.pub, MCC3_ROAD_MESH, 0, 7, 9, NULL, "get name", 8, b));
  EXPECT_EQ(0, memcmp(a, "mcc3/sig|", 9));
  EXPECT_EQ(0, memcmp(a + 9, NODE.pub, 32));
  EXPECT_EQ(MCC3_ROAD_MQTT, a[41]);
  EXPECT_EQ(MCC3_ROAD_MESH, b[41]);
  EXPECT_EQ(7, a[43]);                       // little-endian
  EXPECT_EQ(9, a[47]);
  EXPECT_EQ(1, a[51]);
  EXPECT_EQ((size_t)MCC3_MAX_SIGNED, mcc3SignedBytes(NODE.pub, 0, 0, 0, 0, rid, std::string(160, 'x').c_str(), 160, a));
}

TEST(Mcc3Mesh, EveryBitFromTheCounterOnIsRefused) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub);
  std::vector<uint8_t> req = unhex(MCC3_MESH_REQUESTS[0].request);
  for (size_t i = 6; i < req.size(); i++) {
    for (int bit : { 0, 7 }) {
      std::vector<uint8_t> r = req;
      r[i] ^= (uint8_t)(1 << bit);
      Mcc3Command c;
      MqttCtrlResult res = mcc3MeshOpen(&node, NODE.pub, 0, r.data(), r.size(), verifyWith, (void*)OWNER.pub, &c);
      EXPECT_TRUE(res == MQTTCTRL_ERR_SIG_INVALID || res == MQTTCTRL_ERR_COMMAND_CHARS)
          << i << "/" << bit << " " << mqttCtrlResultName(res);
    }
  }
}

TEST(Mcc3Mesh, TheHeadIsCheckedBeforeAnythingIsDecrypted) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub);
  std::vector<uint8_t> req = unhex(MCC3_MESH_REQUESTS[0].request);
  Mcc3Command c;
  EXPECT_EQ(MQTTCTRL_ERR_BAD_FIELDS, mcc3MeshOpen(&node, NODE.pub, 0, req.data(), 135, verifyWith, (void*)OWNER.pub, &c));
  EXPECT_EQ(MQTTCTRL_ERR_NO_OWNER_KEY, mcc3MeshOpen(NULL, NODE.pub, 0, req.data(), req.size(), verifyWith, (void*)OWNER.pub, &c));
  EXPECT_EQ(MQTTCTRL_ERR_REPLAY, mcc3MeshOpen(&node, NODE.pub, 7, req.data(), req.size(), verifyWith, (void*)OWNER.pub, &c));
  EXPECT_EQ(MQTTCTRL_OK, mcc3MeshOpen(&node, NODE.pub, 6, req.data(), req.size(), verifyWith, (void*)OWNER.pub, &c));
  req[5] = 0x80;
  EXPECT_EQ(MQTTCTRL_ERR_BAD_VERSION, mcc3MeshOpen(NULL, NODE.pub, 99, req.data(), req.size(), verifyWith, (void*)OWNER.pub, &c));
  EXPECT_TRUE(mcc3MeshIsRequest(req.data(), req.size()));
  req[4] = 0xC1;
  EXPECT_FALSE(mcc3MeshIsRequest(req.data(), req.size()));
}

TEST(Mcc3Mesh, TheStreamIsTheAeadCiphertextWithoutItsTag) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub);
  uint8_t plain[126], a[126], b[126 + 16], nonce[12] = {0};
  for (int i = 0; i < 126; i++) plain[i] = (uint8_t)(i * 7);
  mqttCtrlMeshPutU32(&nonce[8], 0x01020304);
  mcc3MeshStream(node.mesh, 0x01020304, plain, sizeof(plain), a);
  mcc3Seal(node.mesh, nonce, NULL, 0, plain, sizeof(plain), b);
  EXPECT_EQ(hex(b, 126), hex(a, 126));
}

TEST(Mcc3Mesh, TheResponseIsCutToTheRoomOnACharacterBoundary) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub), owner = ownerKeys(OWNER, NODE.pub);
  const uint8_t nonce[12] = {9};
  std::string reply = std::string(124, 'a') + "\xC3\xB6" + "tail";   // 'ö' straddles byte 125
  uint8_t out[167];
  size_t n = mcc3MeshBuildResponse(node.cmd, nonce, 1, 7, 0, 0, reply.c_str(), sizeof(out), out);
  EXPECT_EQ((size_t)MCC3_MESH_RESP_OVERHEAD + 124, n);
  Opened o = openMeshResponse(owner, std::vector<uint8_t>(out, out + n));
  EXPECT_EQ(std::string(124, 'a'), o.reply);
  // A path return of 100 path bytes leaves 61, 19 of them for the reply.
  n = mcc3MeshBuildResponse(node.cmd, nonce, 1, 7, 0, 0, reply.c_str(), mqttCtrlMeshResponseRoom(true, 100), out);
  EXPECT_EQ(61u, n);
  EXPECT_EQ(0u, mcc3MeshBuildResponse(node.cmd, nonce, 1, 7, 0, 0, "x", MCC3_MESH_RESP_OVERHEAD - 1, out));
  EXPECT_EQ((size_t)MCC3_MESH_RESP_OVERHEAD, mcc3MeshBuildResponse(node.cmd, nonce, 1, 7, 0, 0, NULL, 167, out));
  EXPECT_EQ(125, 167 - MCC3_MESH_RESP_OVERHEAD);
}

TEST(Mcc3Result, TheReplyIsCutOnACharacterBoundaryAndPadsToTwoSizes) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub), owner = ownerKeys(OWNER, NODE.pub);
  const uint8_t nonce[12] = {1};
  char out[MCC3_MAX_RESULT];
  // 10 + 8 + 238 = 256: the small pad exactly; one more byte takes the large.
  EXPECT_EQ(380u, mcc3BuildResult(node.cmd, nonce, 1, 0, 0, "get name", std::string(238, 'r').c_str(), out, sizeof(out)));
  EXPECT_EQ(722u, mcc3BuildResult(node.cmd, nonce, 1, 0, 0, "get name", std::string(239, 'r').c_str(), out, sizeof(out)));
  std::string reply = std::string(493, 'r') + "\xC3\xB6";      // 10 + 8 + 493 = 511: 'ö' does not fit
  mcc3BuildResult(node.cmd, nonce, 1, 0, 0, "get name", reply.c_str(), out, sizeof(out));
  EXPECT_EQ(std::string(493, 'r'), openResult(owner, out).reply);
  // A refusal names the command and has no reply; the code is the plane's own.
  mcc3BuildResult(node.cmd, nonce, 1, MQTTCTRL_ERR_RATE_LIMITED, 5, "reboot", "", out, sizeof(out));
  Opened o = openResult(owner, out);
  EXPECT_EQ(MQTTCTRL_ERR_RATE_LIMITED, o.code);
  EXPECT_EQ("reboot", o.command);
  EXPECT_EQ("", o.reply);
  EXPECT_EQ(0u, mcc3BuildResult(node.cmd, nonce, 1, 0, 0, "x", "y", out, 380));    // no room for the NUL
}

TEST(Mcc3Result, TheNonceIsTheCallersSoTheSameAnswerTwiceDiffers) {
  // The node draws a fresh nonce per result; a counter-derived one would repeat when a replay
  // and the original are both answered (v2's r3 had that flaw).
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub);
  const uint8_t n1[12] = {1}, n2[12] = {2};
  char a[MCC3_MAX_RESULT], b[MCC3_MAX_RESULT];
  mcc3BuildResult(node.cmd, n1, 7, MQTTCTRL_ERR_REPLAY, 0, "get name", "", a, sizeof(a));
  mcc3BuildResult(node.cmd, n2, 7, MQTTCTRL_ERR_REPLAY, 0, "get name", "", b, sizeof(b));
  EXPECT_STRNE(a, b);
}

TEST(Mcc3Alive, OneLengthWhateverItSaysAndTheMeshModeIsRenumbered) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub), owner = ownerKeys(OWNER, NODE.pub);
  const uint8_t nonce[12] = {0};
  Mcc3Alive empty = {};
  Mcc3Alive full = { 1, 2, 3, 4, 5, 6, 0x0F, 2, {1, 2, 3, 4}, 1, "lou-20-arrc-0123456789abcdef0123456789",
                     "SE-JKP-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN" };
  char a[MCC3_ALIVE_B64 + 1], b[MCC3_ALIVE_B64 + 1];
  EXPECT_EQ((size_t)MCC3_ALIVE_B64, mcc3BuildAlive(node.alive, nonce, &empty, a, sizeof(a)));
  EXPECT_EQ((size_t)MCC3_ALIVE_B64, mcc3BuildAlive(node.alive, nonce, &full, b, sizeof(b)));
  EXPECT_EQ(252, MCC3_ALIVE_B64);
  OpenedAlive o = openAlive(owner, b);
  EXPECT_EQ(31u, o.version.size());
  EXPECT_EQ("se-jkp-" + std::string(22, 'a'), o.region);
  EXPECT_EQ(32u, o.name.size());
  EXPECT_EQ(0, mcc3AliveMeshMode(MQTTCTRL_MESH_OFF));
  EXPECT_EQ(1, mcc3AliveMeshMode(MQTTCTRL_MESH_ON));
  EXPECT_EQ(2, mcc3AliveMeshMode(MQTTCTRL_MESH_AUTO));
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
