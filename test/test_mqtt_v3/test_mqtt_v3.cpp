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

static Mcc3Keys keysOf(const char* cmd, const char* mesh, const char* alive, const char* fwd) {
  Mcc3Keys k;
  memcpy(k.cmd, unhex(cmd).data(), 32);
  memcpy(k.mesh, unhex(mesh).data(), 32);
  memcpy(k.alive, unhex(alive).data(), 32);
  memcpy(k.fwd, unhex(fwd).data(), 32);
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

TEST(Mcc3Keys, BothSidesAgreeOnSAndTheFourKeys) {
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
  EXPECT_EQ(MCC3_K_NODE_SIDE_FWD, hex(n.fwd, 32));
  EXPECT_EQ(MCC3_K_OWNER_CMD, hex(o.cmd, 32));
  EXPECT_EQ(MCC3_K_OWNER_MESH, hex(o.mesh, 32));
  EXPECT_EQ(MCC3_K_OWNER_ALIVE, hex(o.alive, 32));
  EXPECT_EQ(MCC3_K_OWNER_FWD, hex(o.fwd, 32));
}

TEST(Mcc3Keys, AnotherNodeAndAnotherOwnerGetOtherKeys) {
  Ident other_node(MCC3_SEED_OTHER_NODE), other_owner(MCC3_SEED_OTHER_OWNER);
  EXPECT_EQ(MCC3_PUB_OTHER_NODE, hex(other_node.pub, 32));
  EXPECT_EQ(MCC3_PUB_OTHER_OWNER, hex(other_owner.pub, 32));
  Mcc3Keys a = nodeKeys(other_node, OWNER.pub);
  EXPECT_EQ(MCC3_K_OTHER_NODE_CMD, hex(a.cmd, 32));
  EXPECT_EQ(MCC3_K_OTHER_NODE_MESH, hex(a.mesh, 32));
  EXPECT_EQ(MCC3_K_OTHER_NODE_ALIVE, hex(a.alive, 32));
  EXPECT_EQ(MCC3_K_OTHER_NODE_FWD, hex(a.fwd, 32));
  Mcc3Keys b = nodeKeys(NODE, other_owner.pub);
  EXPECT_EQ(MCC3_K_OTHER_OWNER_CMD, hex(b.cmd, 32));
  EXPECT_EQ(MCC3_K_OTHER_OWNER_MESH, hex(b.mesh, 32));
  EXPECT_EQ(MCC3_K_OTHER_OWNER_ALIVE, hex(b.alive, 32));
  EXPECT_EQ(MCC3_K_OTHER_OWNER_FWD, hex(b.fwd, 32));
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
    size_t m = mcc3SignedBytes(NODE.pub, MCC3_ROAD_MESH, v.flags, v.counter, v.expiry, NULL, v.command,
                               strlen(v.command), msg);
    EXPECT_EQ(v.signed_hex, hex(msg, m));
    uint8_t req[MCC3_MESH_REQUEST];
    ASSERT_TRUE(mcc3MeshBuildRequest(&owner, NODE.pub, v.companion_tag, v.counter, v.expiry, v.command,
                                     signWith, (void*)&OWNER, req, v.flags));
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
    EXPECT_EQ(v.flags, c.flags);
    EXPECT_EQ(v.counter, c.counter);
    EXPECT_EQ(v.expiry, c.expiry);
    EXPECT_STREQ(v.command, c.command);
  }
  // V3z is V3 with the zero-hop flag, and nothing else differs before the signature.
  EXPECT_EQ(0, MCC3_MESH_REQUESTS[0].flags);
  EXPECT_EQ(MCC3_MESH_FLAG_ZERO_HOP, MCC3_MESH_REQUESTS[2].flags);
  EXPECT_STREQ(MCC3_MESH_REQUESTS[0].command, MCC3_MESH_REQUESTS[2].command);
  EXPECT_STRNE(MCC3_MESH_REQUESTS[0].signature, MCC3_MESH_REQUESTS[2].signature);
}

static Mcc3Forward forwardOf(const Mcc3VecForward& v) {
  Mcc3Forward f;
  memset(&f, 0, sizeof(f));
  f.counter = v.counter;
  f.expiry = v.expiry;
  memcpy(f.rid, unhex(v.rid).data(), MCC3_RID_LEN);
  memcpy(f.target, unhex(v.target).data(), 32);
  f.route = v.route;
  f.path_len = v.path_len;
  std::vector<uint8_t> path = unhex(v.path_field), body = unhex(v.body);
  memcpy(f.path, path.data(), path.size());
  f.body_len = v.body_len;
  memcpy(f.body, body.data(), body.size());
  return f;
}

TEST(Mcc3Vectors, EveryForwardIsRebuiltAndOpens) {
  const Mcc3Keys owner = ownerKeys(OWNER, NODE.pub), node = nodeKeys(NODE, OWNER.pub);
  for (const Mcc3VecForward& v : MCC3_FORWARDS) {
    SCOPED_TRACE(v.name);
    ASSERT_EQ(0, v.flags);
    const Mcc3Forward f = forwardOf(v);
    EXPECT_EQ(v.body_len, unhex(v.body).size());
    char out[MCC3_FWD_B64 + 1];
    if (f.body[0] == 0xC1) {
      // The spec's vectors still hold lou-20's forward of an old request. It opens, since
      // the owner sealed it, and is then a bad body: not built here, not sent on.
      EXPECT_EQ(0u, mcc3BuildForward(&owner, NODE.pub, unhex(v.nonce).data(), &f, out, sizeof(out)));
      Mcc3Forward old;
      ASSERT_EQ(MQTTCTRL_OK, mcc3OpenForward(&node, v.payload, strlen(v.payload), &old));
      EXPECT_FALSE(mcc3ForwardBodyOk(&old, NODE.pub));
      continue;
    }
    size_t n = mcc3BuildForward(&owner, NODE.pub, unhex(v.nonce).data(), &f, out, sizeof(out));
    EXPECT_EQ(std::string(v.payload), std::string(out, n));
    EXPECT_EQ(v.bytes, unb64(v.payload).size());
    char t[MQTTCTRL_MAX_TOPIC + 1];
    ASSERT_TRUE(mcc3Topic("cmd", MCC3_PUB_NODE, t, sizeof(t)));
    EXPECT_STREQ(v.topic, t);
    ASSERT_TRUE(mcc3ResultTopic(f.rid, t, sizeof(t)));
    EXPECT_STREQ(v.reply_topic, t);
    EXPECT_EQ(MCC3_KIND_FORWARD, mcc3PayloadKind(v.payload, strlen(v.payload)));

    Mcc3Forward back;
    ASSERT_EQ(MQTTCTRL_OK, mcc3OpenForward(&node, v.payload, strlen(v.payload), &back));
    EXPECT_TRUE(mcc3ForwardBodyOk(&back, NODE.pub));
    EXPECT_EQ(v.counter, back.counter);
    EXPECT_EQ(v.expiry, back.expiry);
    EXPECT_EQ(v.rid, hex(back.rid, MCC3_RID_LEN));
    EXPECT_EQ(v.target, hex(back.target, 32));
    EXPECT_EQ(v.route, back.route);
    EXPECT_EQ(v.path_len, back.path_len);
    EXPECT_EQ(v.path, hex(back.path, mcc3PathBytes(back.path_len)));
    EXPECT_EQ(v.body_len, back.body_len);
    EXPECT_EQ(v.body, hex(back.body, back.body_len));
  }
  // F1 carries V3z as the app hands it over; F2's path field is not a path.
  EXPECT_STREQ(MCC3_MESH_REQUESTS[2].app_sends, MCC3_FORWARDS[0].body);
  EXPECT_EQ(MCC3_PUB_OTHER_NODE, std::string(MCC3_FORWARDS[0].target));
  EXPECT_STREQ("A1B2C3", MCC3_FORWARDS[1].path_field);
  EXPECT_STREQ("", MCC3_FORWARDS[1].path);
}

TEST(Mcc3Vectors, EveryForwardResultIsRebuiltAndOpens) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub), owner = ownerKeys(OWNER, NODE.pub);
  for (const Mcc3VecForwardResult& v : MCC3_FORWARD_RESULTS) {
    SCOPED_TRACE(v.name);
    Mcc3ForwardResult r;
    mcc3ForwardResultInit(&r, v.counter, v.status);
    r.clock = v.clock;
    r.sent = v.sent;
    r.snr = (int8_t)v.snr;
    std::vector<uint8_t> path = unhex(v.path), response = unhex(v.response);
    mcc3ForwardResultPath(&r, v.path_len, path.data());
    r.response_len = (uint8_t)response.size();
    memcpy(r.response, response.data(), response.size());
    char out[MCC3_FWD_RES_B64 + 1];
    size_t n = mcc3BuildForwardResult(node.fwd, unhex(v.nonce).data(), &r, out, sizeof(out));
    EXPECT_EQ(std::string(v.payload), std::string(out, n));
    EXPECT_EQ(v.bytes, unb64(v.payload).size());
    EXPECT_STREQ(v.topic, MCC3_FORWARDS[0].reply_topic);

    Mcc3ForwardResult back;
    ASSERT_EQ(MQTTCTRL_OK, mcc3OpenForwardResult(owner.fwd, v.payload, strlen(v.payload), &back));
    EXPECT_EQ(v.counter, back.counter);
    EXPECT_EQ(v.status, back.status);
    EXPECT_EQ(v.clock, back.clock);
    EXPECT_EQ(v.sent, back.sent);
    EXPECT_EQ(v.snr, back.snr);
    EXPECT_EQ(v.path_len, back.path_len);
    EXPECT_EQ(v.path, hex(back.path, path.size()));
    EXPECT_EQ(v.response, hex(back.response, back.response_len));
  }
  // F3 answers F1 with V4 from its fifth byte on, which the owner opens as a companion's.
  const Mcc3VecForwardResult& f3 = MCC3_FORWARD_RESULTS[0];
  EXPECT_EQ(std::string(MCC3_MESH_RESPONSES[0].response).substr(8), std::string(f3.response));
  EXPECT_EQ(MCC3_FWD_ANSWERED, f3.status);
  EXPECT_EQ(MCC3_SNR_NONE, MCC3_FORWARD_RESULTS[1].snr);
  EXPECT_EQ(MCC3_FWD_NO_ANSWER, MCC3_FORWARD_RESULTS[1].status);
  std::vector<uint8_t> companion = unhex(MCC3_MESH_RESPONSES[0].response), relayed = unhex(f3.response);
  std::vector<uint8_t> rebuilt(companion.begin(), companion.begin() + 4);
  rebuilt.insert(rebuilt.end(), relayed.begin(), relayed.end());
  Opened o = openMeshResponse(owner, rebuilt);
  ASSERT_EQ("ok", o.outcome);
  EXPECT_EQ(MCC3_MESH_RESPONSES[0].reply, o.reply);
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
  // Bit 4 says the node relays; only the third vector's node does.
  EXPECT_EQ(0, MCC3_ALIVE[0].flags & MCC3_ALIVE_RELAY);
  EXPECT_EQ(MCC3_ALIVE_RELAY, MCC3_ALIVE[2].flags & MCC3_ALIVE_RELAY);
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
      } else if (strcmp(v.kind, "forward") == 0) {
        // The vectors name the body rule, the first check with an answer, with the silent ones.
        Mcc3Forward f;
        r = mcc3OpenForward(&k, v.input, strlen(v.input), &f);
        if (r == MQTTCTRL_OK) {
          outcome = mcc3ForwardBodyOk(&f, node.pub) ? "ok" : "bad-body";
          EXPECT_EQ(v.outcome, outcome);
          continue;
        }
      } else {
        ASSERT_STREQ("mesh_request", v.kind);
        std::vector<uint8_t> req = unhex(v.input);
        r = mcc3MeshOpen(&k, node.pub, v.last_counter < 0 ? 0 : (uint32_t)v.last_counter, req.data(),
                         req.size(), verifyWith, command_key.data(), &c);
      }
      outcome = mqttCtrlResultName(r);
    } else {
      by_owner++;
      Mcc3Keys k = keysOf(v.key_cmd, v.key_mesh, v.key_alive, v.key_fwd);
      Mcc3ForwardResult fr;
      if (strcmp(v.kind, "result") == 0) outcome = openResult(k, v.input).outcome;
      else if (strcmp(v.kind, "alive") == 0) outcome = openAlive(k, v.input).outcome;
      else if (strcmp(v.kind, "forward_result") == 0) {
        outcome = mqttCtrlResultName(mcc3OpenForwardResult(k.fwd, v.input, strlen(v.input), &fr));
      } else {
        ASSERT_STREQ("mesh_response", v.kind);
        outcome = openMeshResponse(k, unhex(v.input)).outcome;
      }
    }
    EXPECT_EQ(v.outcome, outcome);
  }
  EXPECT_EQ(48, by_node);
  EXPECT_EQ(18, by_owner);
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

TEST(Mcc3Mesh, AFieldWithNoZeroLeftIsRefusedEvenWhenSigned) {
  // 58 command bytes, properly signed by the owner: the field must end in a zero.
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub);
  const std::string cmd(58, 'z');
  uint8_t req[MCC3_MESH_REQUEST] = {0};
  req[4] = MCC3_MESH_SUBTYPE;
  mqttCtrlMeshPutU32(&req[6], 9);
  uint8_t* plain = req + MCC3_MESH_HEAD;
  mqttCtrlMeshPutU32(plain, 1795000000);
  uint8_t msg[MCC3_MAX_SIGNED];
  size_t m = mcc3SignedBytes(NODE.pub, MCC3_ROAD_MESH, 0, 9, 1795000000, NULL, cmd.c_str(), cmd.size(), msg);
  signWith((void*)&OWNER, plain + 4, msg, m);
  memcpy(plain + 4 + MCC3_SIG_LEN, cmd.data(), cmd.size());
  mcc3MeshStream(node.mesh, 9, plain, MCC3_MESH_REQUEST - MCC3_MESH_HEAD, plain);
  Mcc3Command c;
  EXPECT_EQ(MQTTCTRL_ERR_COMMAND_CHARS,
            mcc3MeshOpen(&node, NODE.pub, 0, req, sizeof(req), verifyWith, (void*)OWNER.pub, &c));
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

// ---- the zero-hop flag on the mesh road -------------------------------------------------

TEST(Mcc3Mesh, TheZeroHopFlagIsSignedAndNoOtherFlagIsTaken) {
  const Mcc3Keys owner = ownerKeys(OWNER, NODE.pub), node = nodeKeys(NODE, OWNER.pub);
  const Mcc3VecMeshRequest& v = MCC3_MESH_REQUESTS[0];
  uint8_t req[MCC3_MESH_REQUEST];
  ASSERT_TRUE(mcc3MeshBuildRequest(&owner, NODE.pub, v.companion_tag, v.counter, v.expiry, v.command,
                                   signWith, (void*)&OWNER, req, MCC3_MESH_FLAG_ZERO_HOP));
  EXPECT_EQ(MCC3_MESH_FLAG_ZERO_HOP, req[5]);
  Mcc3Command c;
  ASSERT_EQ(MQTTCTRL_OK, mcc3MeshOpen(&node, NODE.pub, 0, req, sizeof(req), verifyWith, (void*)OWNER.pub, &c));
  EXPECT_EQ(MCC3_MESH_FLAG_ZERO_HOP, c.flags);
  EXPECT_STREQ(v.command, c.command);

  // Without the flag the request is the vector's, and opens with none.
  std::vector<uint8_t> plain = unhex(v.request);
  ASSERT_EQ(MQTTCTRL_OK, mcc3MeshOpen(&node, NODE.pub, 0, plain.data(), plain.size(), verifyWith,
                                      (void*)OWNER.pub, &c));
  EXPECT_EQ(0, c.flags);

  // The flag is inside the signature: set on a request signed without it, or cleared on one
  // signed with it, the signature fails.
  plain[5] = MCC3_MESH_FLAG_ZERO_HOP;
  EXPECT_EQ(MQTTCTRL_ERR_SIG_INVALID, mcc3MeshOpen(&node, NODE.pub, 0, plain.data(), plain.size(), verifyWith,
                                                   (void*)OWNER.pub, &c));
  req[5] = 0;
  EXPECT_EQ(MQTTCTRL_ERR_SIG_INVALID, mcc3MeshOpen(&node, NODE.pub, 0, req, sizeof(req), verifyWith,
                                                   (void*)OWNER.pub, &c));

  // Every other bit is refused before any key is used, signed or not, with the flag or without.
  for (int flags = 0; flags < 256; flags++) {
    if (flags == 0 || flags == MCC3_MESH_FLAG_ZERO_HOP) continue;
    ASSERT_TRUE(mcc3MeshBuildRequest(&owner, NODE.pub, 1, 9, 1795000000, "get name", signWith, (void*)&OWNER,
                                     req, (uint8_t)flags));
    EXPECT_EQ(MQTTCTRL_ERR_BAD_VERSION, mcc3MeshOpen(NULL, NODE.pub, 0, req, sizeof(req), verifyWith,
                                                     (void*)OWNER.pub, &c)) << flags;
  }
}

TEST(Mcc3Command, OnMqttTheZeroHopBitIsStillRefused) {
  const Mcc3Keys owner = ownerKeys(OWNER, NODE.pub), node = nodeKeys(NODE, OWNER.pub);
  std::vector<uint8_t> raw = unb64(v1Payload().c_str());
  raw[1] = MCC3_MESH_FLAG_ZERO_HOP;
  mcc3Seal(owner.cmd, raw.data() + 2, raw.data(), MCC3_CMD_HEAD, raw.data() + MCC3_CMD_HEAD,
           raw.size() - MCC3_CMD_HEAD - 16, raw.data() + MCC3_CMD_HEAD);
  char b64[400];
  size_t n = mqttV2B64Encode(raw.data(), raw.size(), b64, sizeof(b64));
  Mcc3Command c;
  EXPECT_EQ(MQTTCTRL_ERR_BAD_VERSION, openOnNode(node, NODE.pub, std::string(b64, n), OWNER.pub, &c));
}

// ---- the relay --------------------------------------------------------------------------
//
// NODE is the relay; the target is the vectors' other node, of the same owner. The forward
// carries the 132 bytes a companion would be handed for the target.

static const Ident TARGET(MCC3_SEED_OTHER_NODE);
static const uint32_t RELAY_NOW = 1795000000;

static Mcc3Forward forwardTo(const Ident& target, uint32_t counter, uint8_t route, uint8_t flags = 0) {
  const Mcc3Keys target_keys = ownerKeys(OWNER, target.pub);
  uint8_t req[MCC3_MESH_REQUEST];
  EXPECT_TRUE(mcc3MeshBuildRequest(&target_keys, target.pub, 0, 7, RELAY_NOW + 600, "get name", signWith,
                                   (void*)&OWNER, req, flags));
  Mcc3Forward f;
  memset(&f, 0, sizeof(f));
  f.counter = counter;
  f.expiry = RELAY_NOW + 60;
  for (int i = 0; i < MCC3_RID_LEN; i++) f.rid[i] = (uint8_t)i;
  memcpy(f.target, target.pub, 32);
  f.route = route;
  f.body_len = MCC3_FWD_BODY;
  memcpy(f.body, req + 4, MCC3_FWD_BODY);
  return f;
}

static const uint8_t FWD_NONCE[12] = { 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B };

static std::string sealForward(const Mcc3Keys& k, const Mcc3Forward& f) {
  char out[MCC3_FWD_B64 + 1];
  size_t n = mcc3BuildForward(&k, NODE.pub, FWD_NONCE, &f, out, sizeof(out));
  return std::string(out, n);
}

// A forward no sender builds, sealed all the same: the relay must refuse it itself.
static std::string sealForwardRaw(const Mcc3Keys& k, const Mcc3Forward& f, uint8_t flags = 0) {
  Mcc3Forward good = forwardTo(TARGET, f.counter, 0);
  std::vector<uint8_t> raw = unb64(sealForward(k, good).c_str());
  raw[1] = flags;
  uint8_t* p = raw.data() + MCC3_FWD_HEAD;
  mqttCtrlMeshPutU32(p, f.counter);
  mqttCtrlMeshPutU32(p + 4, f.expiry);
  memcpy(p + 8, f.rid, 16);
  memcpy(p + 24, f.target, 32);
  p[56] = f.route;
  p[57] = f.path_len;
  memcpy(p + 58, f.path, MCC3_FWD_PATH);
  p[115] = f.body_len;
  memcpy(p + 116, f.body, MCC3_FWD_BODY);
  mcc3Seal(k.fwd, raw.data() + 2, raw.data(), MCC3_FWD_HEAD, p, MCC3_FWD_PLAIN, p);
  char out[MCC3_FWD_B64 + 1];
  size_t n = mqttV2B64Encode(raw.data(), raw.size(), out, sizeof(out));
  return std::string(out, n);
}

TEST(Mcc3Relay, KFwdIsAFourthKeyBothSidesAgreeOn) {
  const Mcc3Keys n = nodeKeys(NODE, OWNER.pub), o = ownerKeys(OWNER, NODE.pub);
  EXPECT_EQ(hex(n.fwd, 32), hex(o.fwd, 32));
  EXPECT_NE(hex(n.fwd, 32), hex(n.cmd, 32));
  EXPECT_NE(hex(n.fwd, 32), hex(n.mesh, 32));
  EXPECT_NE(hex(n.fwd, 32), hex(n.alive, 32));
  EXPECT_NE(hex(n.fwd, 32), hex(nodeKeys(TARGET, OWNER.pub).fwd, 32));
  // The label, straight from the design note: HKDF-SHA256(S, salt empty, "mcc3/fwd/" + KEY).
  uint8_t shared[32], want[32];
  ed25519_key_exchange(shared, OWNER.pub, NODE.prv);
  const std::string info = "mcc3/fwd/" + hex(NODE.pub, 32);
  hkdf<SHA256>(want, 32, shared, 32, NULL, 0, info.data(), info.size());
  EXPECT_EQ(hex(want, 32), hex(n.fwd, 32));
}

TEST(Mcc3Relay, AForwardIs278BytesAndOpensToWhatWasSealed) {
  const Mcc3Keys owner = ownerKeys(OWNER, NODE.pub), node = nodeKeys(NODE, OWNER.pub);
  Mcc3Forward f = forwardTo(TARGET, 9, MCC3_ROUTE_DIRECT, MCC3_MESH_FLAG_ZERO_HOP);
  f.path_len = 2;
  f.path[0] = 0xAB;
  f.path[1] = 0xCD;
  const std::string payload = sealForward(owner, f);
  ASSERT_EQ(371u, payload.size());
  std::vector<uint8_t> raw = unb64(payload.c_str());
  ASSERT_EQ(278u, raw.size());
  EXPECT_EQ((size_t)MCC3_CMD_SIZE(MCC3_CMD_PAD_LARGE), raw.size());   // the larger command's length
  EXPECT_EQ(0x46, raw[0]);
  EXPECT_EQ(0, raw[1]);
  EXPECT_EQ(hex(FWD_NONCE, 12), hex(raw.data() + 2, 12));
  EXPECT_EQ(MCC3_KIND_FORWARD, mcc3PayloadKind(payload.data(), payload.size()));
  EXPECT_EQ(MCC3_KIND_COMMAND, mcc3PayloadKind(v1Payload().data(), v1Payload().size()));
  EXPECT_EQ(0, mcc3PayloadKind("Rg", 2));
  EXPECT_EQ(0, mcc3PayloadKind("v1|7", 4));
  EXPECT_EQ(0, mcc3PayloadKind(NULL, 0));

  Mcc3Forward back;
  ASSERT_EQ(MQTTCTRL_OK, mcc3OpenForward(&node, payload.data(), payload.size(), &back));
  EXPECT_EQ(9u, back.counter);
  EXPECT_EQ(RELAY_NOW + 60, back.expiry);
  EXPECT_EQ(hex(f.rid, 16), hex(back.rid, 16));
  EXPECT_EQ(hex(TARGET.pub, 32), hex(back.target, 32));
  EXPECT_EQ(MCC3_ROUTE_DIRECT, back.route);
  EXPECT_EQ(2, back.path_len);
  EXPECT_EQ(hex(f.path, MCC3_FWD_PATH), hex(back.path, MCC3_FWD_PATH));
  EXPECT_EQ(132, back.body_len);
  EXPECT_EQ(hex(f.body, 132), hex(back.body, 132));

  // The layout, field by field, from the plaintext.
  uint8_t* p = raw.data() + 14;
  ASSERT_TRUE(mcc3Open(node.fwd, raw.data() + 2, raw.data(), 14, p, 248, p));
  EXPECT_EQ(9u, mqttCtrlMeshU32(p));
  EXPECT_EQ(RELAY_NOW + 60, mqttCtrlMeshU32(p + 4));
  EXPECT_EQ(hex(f.rid, 16), hex(p + 8, 16));
  EXPECT_EQ(hex(TARGET.pub, 32), hex(p + 24, 32));
  EXPECT_EQ(0, p[56]);
  EXPECT_EQ(2, p[57]);
  EXPECT_EQ(0xAB, p[58]);
  EXPECT_EQ(132, p[115]);
  EXPECT_EQ(0xC2, p[116]);
  EXPECT_EQ(MCC3_MESH_FLAG_ZERO_HOP, p[117]);

  // The target takes the body behind any tag the relay writes, flag and all.
  uint8_t req[MCC3_MESH_REQUEST];
  mqttCtrlMeshPutU32(req, 0xDEADBEEF);
  memcpy(req + 4, back.body, back.body_len);
  const Mcc3Keys target = nodeKeys(TARGET, OWNER.pub);
  Mcc3Command c;
  ASSERT_EQ(MQTTCTRL_OK, mcc3MeshOpen(&target, TARGET.pub, 0, req, sizeof(req), verifyWith, (void*)OWNER.pub, &c));
  EXPECT_EQ(0xDEADBEEFu, c.tag);
  EXPECT_EQ(MCC3_MESH_FLAG_ZERO_HOP, c.flags);
  EXPECT_STREQ("get name", c.command);
}

TEST(Mcc3Relay, EveryBitOfAForwardMattersAndFlagsAreCheckedBeforeTheCipher) {
  const Mcc3Keys owner = ownerKeys(OWNER, NODE.pub), node = nodeKeys(NODE, OWNER.pub);
  std::vector<uint8_t> raw = unb64(sealForward(owner, forwardTo(TARGET, 9, 0)).c_str());
  for (size_t i = 0; i < raw.size(); i++) {
    for (int bit : { 0, 7 }) {
      std::vector<uint8_t> r = raw;
      r[i] ^= (uint8_t)(1 << bit);
      char b64[MCC3_FWD_B64 + 1];
      size_t n = mqttV2B64Encode(r.data(), r.size(), b64, sizeof(b64));
      Mcc3Forward f;
      MqttCtrlResult res = mcc3OpenForward(&node, b64, n, &f);
      if (i == 0) EXPECT_EQ(MQTTCTRL_ERR_BAD_FIELDS, res) << i;
      else if (i == 1) EXPECT_EQ(MQTTCTRL_ERR_BAD_VERSION, res) << i;
      else EXPECT_EQ(MQTTCTRL_ERR_SIG_INVALID, res) << i << "/" << bit;
    }
  }
}

TEST(Mcc3Relay, OnlyAForwardOfTheOwnersOpens) {
  const Mcc3Keys owner = ownerKeys(OWNER, NODE.pub), node = nodeKeys(NODE, OWNER.pub);
  const Mcc3Forward f = forwardTo(TARGET, 9, 0);
  const std::string payload = sealForward(owner, f);
  Mcc3Forward back;
  // No command key on the relay; another node's K_fwd; another owner's.
  EXPECT_EQ(MQTTCTRL_ERR_NO_OWNER_KEY, mcc3OpenForward(NULL, payload.data(), payload.size(), &back));
  const Mcc3Keys other_node = nodeKeys(Ident(MCC3_SEED_OTHER_NODE), OWNER.pub);
  EXPECT_EQ(MQTTCTRL_ERR_SIG_INVALID, mcc3OpenForward(&other_node, payload.data(), payload.size(), &back));
  const Ident other_owner(MCC3_SEED_OTHER_OWNER);
  const std::string stranger = sealForward(ownerKeys(other_owner, NODE.pub), f);
  EXPECT_EQ(MQTTCTRL_ERR_SIG_INVALID, mcc3OpenForward(&node, stranger.data(), stranger.size(), &back));
  // Sealed under K_cmd, the command's key, it is not a forward either.
  Mcc3Keys wrong = owner;
  memcpy(wrong.fwd, owner.cmd, 32);
  const std::string under_cmd = sealForward(wrong, f);
  EXPECT_EQ(MQTTCTRL_ERR_SIG_INVALID, mcc3OpenForward(&node, under_cmd.data(), under_cmd.size(), &back));

  // Flags set and properly sealed: bad-version, before the key is asked for.
  const std::string flagged = sealForwardRaw(owner, f, 1);
  EXPECT_EQ(MQTTCTRL_ERR_BAD_VERSION, mcc3OpenForward(&node, flagged.data(), flagged.size(), &back));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_VERSION, mcc3OpenForward(NULL, flagged.data(), flagged.size(), &back));

  // Not 278 bytes, or not kind 'F': not a forward. A command is not one, nor a forward a command.
  std::vector<uint8_t> raw = unb64(payload.c_str());
  for (size_t len : { (size_t)0, (size_t)182, (size_t)277, (size_t)279, (size_t)285 }) {
    std::vector<uint8_t> r = raw;
    r.resize(len, 0);
    char b64[600];
    size_t n = mqttV2B64Encode(r.data(), r.size(), b64, sizeof(b64));
    EXPECT_EQ(MQTTCTRL_ERR_BAD_FIELDS, mcc3OpenForward(&node, b64, n, &back)) << len;
  }
  const std::string longest = MCC3_COMMANDS[4].payload;
  ASSERT_EQ(278u, unb64(longest.c_str()).size());
  EXPECT_EQ(MQTTCTRL_ERR_BAD_FIELDS, mcc3OpenForward(&node, longest.data(), longest.size(), &back));
  Mcc3Command c;
  EXPECT_EQ(MQTTCTRL_ERR_BAD_FIELDS, openOnNode(node, NODE.pub, payload, OWNER.pub, &c));
}

// What Fork::onMeshCommand does with an anonymous request before upstream sees it. An old
// request left unclaimed is a failed login to upstream, and five of them throttle the
// sender's key for ten minutes.
TEST(Mcc3Mesh, AnOldRequestIsClaimedANewOneRunAndALoginLeftAlone) {
  uint8_t req[MCC3_MESH_REQUEST] = {0};
  req[4] = 0xC1;
  EXPECT_EQ(MCC3_CLAIM_OLD, mcc3MeshClaim(req, sizeof(req)));
  EXPECT_EQ(MCC3_CLAIM_OLD, mcc3MeshClaim(req, 5));              // whatever follows, or nothing
  req[4] = 0xC2;
  EXPECT_EQ(MCC3_CLAIM_REQUEST, mcc3MeshClaim(req, sizeof(req)));
  // A login: a password's first byte, printable or the start of a UTF-8 sequence.
  for (int first = ' '; first < 256; first++) {
    if (first == 0xC1 || first == 0xC2) continue;
    req[4] = (uint8_t)first;
    EXPECT_EQ(MCC3_CLAIM_NONE, mcc3MeshClaim(req, sizeof(req))) << first;
  }
  // Upstream's typed requests, and a request too short to have a type.
  for (uint8_t typed : { (uint8_t)0x00, (uint8_t)0x01, (uint8_t)0x02, (uint8_t)0x03 }) {
    req[4] = typed;
    EXPECT_EQ(MCC3_CLAIM_NONE, mcc3MeshClaim(req, sizeof(req))) << (int)typed;
  }
  req[4] = 0xC1;
  EXPECT_EQ(MCC3_CLAIM_NONE, mcc3MeshClaim(req, 4));
  EXPECT_EQ(MCC3_CLAIM_NONE, mcc3MeshClaim(NULL, sizeof(req)));
}

TEST(Mcc3Relay, TheBodyRuleTheRouteThePathAndTheTarget) {
  Mcc3Forward f = forwardTo(TARGET, 9, 0);
  EXPECT_TRUE(mcc3ForwardBodyOk(&f, NODE.pub));

  // 0xC2: the whole 132 bytes and nothing shorter.
  f.body_len = 131;
  EXPECT_FALSE(mcc3ForwardBodyOk(&f, NODE.pub));
  f.body_len = 133;
  EXPECT_FALSE(mcc3ForwardBodyOk(&f, NODE.pub));
  // 0xC1, the request of lou-20 and older, is no longer carried, at any length.
  f.body[0] = 0xC1;
  for (int len = 0; len < 256; len++) {
    f.body_len = (uint8_t)len;
    EXPECT_FALSE(mcc3ForwardBodyOk(&f, NODE.pub)) << len;
  }
  // Nothing else: a login's first byte, upstream's typed requests, a sub-type not defined yet.
  f.body_len = 132;
  for (int first = 0; first < 256; first++) {
    f.body[0] = (uint8_t)first;
    EXPECT_EQ(first == 0xC2, mcc3ForwardBodyOk(&f, NODE.pub)) << first;
  }

  f = forwardTo(TARGET, 9, 0);
  for (int route = 0; route < 256; route++) {
    f.route = (uint8_t)route;
    EXPECT_EQ(route <= 2, mcc3ForwardBodyOk(&f, NODE.pub)) << route;
  }
  f.route = 0;
  // The path: MeshCore's encoding, the reserved hash size refused, and at most the field's 57 bytes.
  for (int path_len = 0; path_len < 256; path_len++) {
    f.path_len = (uint8_t)path_len;
    const int size = (path_len >> 6) + 1, count = path_len & 63;
    EXPECT_EQ(size != 4 && size * count <= 57, mcc3ForwardBodyOk(&f, NODE.pub)) << path_len;
  }
  EXPECT_EQ(57, mcc3PathBytes(57));
  EXPECT_EQ(56, mcc3PathBytes(0x40 | 28));
  EXPECT_EQ(57, mcc3PathBytes(0x80 | 19));
  EXPECT_EQ(-1, mcc3PathBytes(0xC0));
  f.path_len = 0;
  // Never to itself.
  memcpy(f.target, NODE.pub, 32);
  EXPECT_FALSE(mcc3ForwardBodyOk(&f, NODE.pub));
  f.target[31] ^= 1;
  EXPECT_TRUE(mcc3ForwardBodyOk(&f, NODE.pub));
}

TEST(Mcc3Relay, NoSenderBuildsWhatARelayRefuses) {
  const Mcc3Keys owner = ownerKeys(OWNER, NODE.pub);
  char out[MCC3_FWD_B64 + 1];
  Mcc3Forward f = forwardTo(TARGET, 9, 0);
  EXPECT_EQ(371u, mcc3BuildForward(&owner, NODE.pub, FWD_NONCE, &f, out, sizeof(out)));
  EXPECT_EQ(0u, mcc3BuildForward(&owner, NODE.pub, FWD_NONCE, &f, out, 371));   // no room for the NUL
  f.route = 3;
  EXPECT_EQ(0u, mcc3BuildForward(&owner, NODE.pub, FWD_NONCE, &f, out, sizeof(out)));
  f = forwardTo(TARGET, 9, 0);
  f.body[0] = 0xC3;
  EXPECT_EQ(0u, mcc3BuildForward(&owner, NODE.pub, FWD_NONCE, &f, out, sizeof(out)));
  f = forwardTo(TARGET, 9, 0);
  f.path_len = 58;
  EXPECT_EQ(0u, mcc3BuildForward(&owner, NODE.pub, FWD_NONCE, &f, out, sizeof(out)));
  f = forwardTo(NODE, 9, 0);
  EXPECT_EQ(0u, mcc3BuildForward(&owner, NODE.pub, FWD_NONCE, &f, out, sizeof(out)));
}

// What the relay does with a forward that opened (design §3), one refusal at a time.
struct RelayBench {
  Mcc3Keys owner = ownerKeys(OWNER, NODE.pub), node = nodeKeys(NODE, OWNER.pub);
  Mcc3Relay relay;
  uint8_t mode = MQTTCTRL_RELAY_OWN;
  bool has_home = true;
  uint32_t air_ms = 1700;

  // As Fork::relayForward: open, admit, and count a send that went out.
  int take(const std::string& payload, uint32_t now, bool pool_empty = false,
           bool clock_never_set = false) {
    Mcc3Forward f;
    if (mcc3OpenForward(&node, payload.data(), payload.size(), &f) != MQTTCTRL_OK) return -2;
    int status = mcc3RelayAdmit(&relay, mode, now, &f, NODE.pub, has_home, clock_never_set);
    if (status != MCC3_FWD_SEND) return status;
    if (pool_empty) return MCC3_FWD_SEND_FAILED;
    mcc3RelaySent(&relay, now, f.route, has_home, air_ms);
    return MCC3_FWD_SEND;
  }
  int take(const Mcc3Forward& f, uint32_t now, bool pool_empty = false, bool clock_never_set = false) {
    return take(sealForwardRaw(owner, f), now, pool_empty, clock_never_set);
  }
};

TEST(Mcc3Relay, TheStatusesAreTheDesignNotesNumbers) {
  EXPECT_EQ(0, MCC3_FWD_ANSWERED);
  EXPECT_EQ(1, MCC3_FWD_NO_ANSWER);
  EXPECT_EQ(2, MCC3_FWD_OFF);
  EXPECT_EQ(3, MCC3_FWD_EXPIRED);
  EXPECT_EQ(4, MCC3_FWD_REPLAY);
  EXPECT_EQ(5, MCC3_FWD_BAD_BODY);
  EXPECT_EQ(6, MCC3_FWD_BUSY);
  EXPECT_EQ(7, MCC3_FWD_RATE_LIMITED);
  EXPECT_EQ(8, MCC3_FWD_CLOCK_UNSET);
  EXPECT_EQ(9, MCC3_FWD_SEND_FAILED);
  EXPECT_EQ(0x46, MCC3_KIND_FORWARD);
  EXPECT_EQ(0x66, MCC3_KIND_FWD_RESULT);
  EXPECT_EQ(0x10, MCC3_ALIVE_RELAY);
  EXPECT_EQ(0x02, MCC3_MESH_FLAG_ZERO_HOP);
  EXPECT_EQ(278, MCC3_FWD_SIZE);
  EXPECT_EQ(371, MCC3_FWD_B64);
  EXPECT_EQ(285, MCC3_FWD_RES_SIZE);
  EXPECT_EQ(380, MCC3_FWD_RES_B64);
  EXPECT_EQ(132, MCC3_FWD_MIN_BODY);
  EXPECT_LE(MCC3_FWD_B64, MQTTCTRL_MAX_PAYLOAD);          // the plane's staging buffer takes it
}

TEST(Mcc3Relay, AForwardIsSentOnceAndThenWaitsForItsAnswer) {
  RelayBench b;
  EXPECT_EQ(MCC3_FWD_SEND, b.take(forwardTo(TARGET, 9, 0), RELAY_NOW));
  EXPECT_TRUE(b.relay.waiting);
  EXPECT_EQ(9u, b.relay.last_counter);
  EXPECT_EQ(1u, b.relay.forwarded);
  // The next one finds it waiting; its counter is taken all the same.
  EXPECT_EQ(MCC3_FWD_BUSY, b.take(forwardTo(TARGET, 10, 0), RELAY_NOW + 1));
  EXPECT_EQ(10u, b.relay.last_counter);
  EXPECT_EQ(1u, b.relay.forwarded);
  b.relay.waiting = false;
  EXPECT_EQ(MCC3_FWD_SEND, b.take(forwardTo(TARGET, 11, 0), RELAY_NOW + 2));
}

TEST(Mcc3Relay, OffAndAnUnsetClockRefuseBeforeTheCounterIsTaken) {
  RelayBench b;
  b.mode = MQTTCTRL_RELAY_OFF;
  EXPECT_EQ(MCC3_FWD_OFF, b.take(forwardTo(TARGET, 9, 0), RELAY_NOW));
  b.mode = MQTTCTRL_RELAY_OWN;
  // 0 and the firmware's 2024 default are both no clock; a forward whose expiry would pass
  // against that default is refused for the clock, not let through.
  Mcc3Forward f = forwardTo(TARGET, 9, 0);
  EXPECT_EQ(MCC3_FWD_CLOCK_UNSET, b.take(f, 0));
  f.expiry = MQTTConnectionPolicy::kSyncedClockEpoch - 1 + 60;
  EXPECT_EQ(MCC3_FWD_CLOCK_UNSET, b.take(f, MQTTConnectionPolicy::kSyncedClockEpoch - 1));
  // An ESP32 after a power cycle reads 1 March 2026 and up: no clock either, when the
  // caller says it was never set, though the forward's expiry would pass against it.
  const uint32_t power_on = MQTTConnectionPolicy::kPowerOnClockEpoch + 60;
  f.expiry = power_on + 60;
  EXPECT_EQ(MCC3_FWD_CLOCK_UNSET, b.take(f, power_on, false, true));
  EXPECT_EQ(0u, b.relay.last_counter);
  EXPECT_FALSE(b.relay.waiting);
  EXPECT_EQ(MCC3_FWD_SEND, b.take(forwardTo(TARGET, 9, 0), RELAY_NOW));
}

TEST(Mcc3Relay, TheExpiryMustNotHavePassedNorLieMoreThan300SecondsAhead) {
  struct { int32_t expiry_from_now; int want; } cases[] = {
    { -1, MCC3_FWD_EXPIRED }, { 0, MCC3_FWD_SEND }, { 1, MCC3_FWD_SEND }, { 300, MCC3_FWD_SEND },
    { 301, MCC3_FWD_EXPIRED }, { 3600, MCC3_FWD_EXPIRED }, { -86400, MCC3_FWD_EXPIRED },
  };
  for (const auto& c : cases) {
    RelayBench b;
    Mcc3Forward f = forwardTo(TARGET, 9, 0);
    f.expiry = RELAY_NOW + c.expiry_from_now;
    EXPECT_EQ(c.want, b.take(f, RELAY_NOW)) << c.expiry_from_now;
    // An expired forward leaves the counter alone: the owner's next one, in time, still passes.
    EXPECT_EQ(c.want == MCC3_FWD_SEND ? 9u : 0u, b.relay.last_counter) << c.expiry_from_now;
  }
  RelayBench b;
  Mcc3Forward f = forwardTo(TARGET, 9, 0);
  f.expiry = 0xFFFFFFFF;
  EXPECT_EQ(MCC3_FWD_EXPIRED, b.take(f, RELAY_NOW));
  f.expiry = 0;
  EXPECT_EQ(MCC3_FWD_EXPIRED, b.take(f, RELAY_NOW));
}

TEST(Mcc3Relay, AForwardCounterIsTakenOnceEvenWhenItsBodyIsRefused) {
  RelayBench b;
  const std::string first = sealForward(b.owner, forwardTo(TARGET, 9, 0));
  EXPECT_EQ(MCC3_FWD_SEND, b.take(first, RELAY_NOW));
  b.relay.waiting = false;
  // The same bytes again, as anyone on the broker can publish them, and an older counter.
  EXPECT_EQ(MCC3_FWD_REPLAY, b.take(first, RELAY_NOW + 1));
  EXPECT_EQ(MCC3_FWD_REPLAY, b.take(forwardTo(TARGET, 8, 0), RELAY_NOW + 1));
  EXPECT_EQ(1u, b.relay.forwarded);

  // A bad body is refused, and its counter is spent: sent again it is a replay, not bad-body.
  Mcc3Forward bad = forwardTo(TARGET, 20, 3);
  EXPECT_EQ(MCC3_FWD_BAD_BODY, b.take(bad, RELAY_NOW + 2));
  EXPECT_EQ(20u, b.relay.last_counter);
  EXPECT_EQ(MCC3_FWD_REPLAY, b.take(bad, RELAY_NOW + 3));
  bad = forwardTo(NODE, 21, 0);
  EXPECT_EQ(MCC3_FWD_BAD_BODY, b.take(bad, RELAY_NOW + 4));
  bad = forwardTo(TARGET, 22, 0);
  bad.body[0] = 0xC3;
  EXPECT_EQ(MCC3_FWD_BAD_BODY, b.take(bad, RELAY_NOW + 5));
  bad = forwardTo(TARGET, 23, 0);
  bad.body[0] = 0xC1;   // a whole request of the old scheme: refused, as a short one was
  EXPECT_EQ(MCC3_FWD_BAD_BODY, b.take(bad, RELAY_NOW + 6));
  bad = forwardTo(TARGET, 24, 0);
  bad.body_len = 131;
  EXPECT_EQ(MCC3_FWD_BAD_BODY, b.take(bad, RELAY_NOW + 7));
  bad = forwardTo(TARGET, 25, 0);
  bad.path_len = 58;
  EXPECT_EQ(MCC3_FWD_BAD_BODY, b.take(bad, RELAY_NOW + 8));
  EXPECT_EQ(1u, b.relay.forwarded);
  EXPECT_FALSE(b.relay.waiting);

  // A body length past the field never reads past it.
  bad = forwardTo(TARGET, 26, 0);
  bad.body_len = 255;
  EXPECT_EQ(MCC3_FWD_BAD_BODY, b.take(bad, RELAY_NOW + 9));
}

TEST(Mcc3Relay, TheAirtimeAndTheFloodLimitsRefuseAndAFailedSendSpendsNothing) {
  RelayBench b;
  uint32_t counter = 100, now = RELAY_NOW;
  auto send = [&](uint8_t route, uint32_t at, bool pool_empty = false) {
    Mcc3Forward f = forwardTo(TARGET, ++counter, route);
    f.expiry = at + 60;
    int status = b.take(f, at, pool_empty);
    b.relay.waiting = false;
    return status;
  };
  // A flood, and the next one a minute later; a direct forward waits for no gap.
  EXPECT_EQ(MCC3_FWD_SEND, send(MCC3_ROUTE_FLOOD_HOME, now));
  EXPECT_EQ(MCC3_FWD_RATE_LIMITED, send(MCC3_ROUTE_FLOOD_HOME, now + 59));
  EXPECT_EQ(MCC3_FWD_SEND, send(MCC3_ROUTE_DIRECT, now + 59));
  EXPECT_EQ(MCC3_FWD_SEND, send(MCC3_ROUTE_FLOOD_DEFAULT, now + 60));
  // Two floods to the default scope an hour; the region home is still open.
  EXPECT_EQ(MCC3_FWD_SEND, send(MCC3_ROUTE_FLOOD_DEFAULT, now + 120));
  EXPECT_EQ(MCC3_FWD_RATE_LIMITED, send(MCC3_ROUTE_FLOOD_DEFAULT, now + 180));
  EXPECT_EQ(MCC3_FWD_SEND, send(MCC3_ROUTE_FLOOD_HOME, now + 180));
  // A relay with no region home floods its default scope whatever was asked, and it counts so.
  b.has_home = false;
  EXPECT_EQ(MCC3_FWD_RATE_LIMITED, send(MCC3_ROUTE_FLOOD_HOME, now + 240));
  b.has_home = true;
  EXPECT_EQ(MCC3_FWD_SEND, send(MCC3_ROUTE_FLOOD_HOME, now + 240));
  EXPECT_EQ(6u, b.relay.forwarded);
  EXPECT_EQ(5, b.relay.budget.floodsToday(now + 240));

  // A send the packet pool refused spends nothing, however often.
  for (int i = 0; i < 40; i++) EXPECT_EQ(MCC3_FWD_SEND_FAILED, send(MCC3_ROUTE_DIRECT, now + 250, true));
  EXPECT_EQ(MQTTCTRL_AIR_BURST_MS - 6 * 1700, b.relay.budget.air.leftMs(now + 250));

  // The burst holds 45 s of requests: 21 more of 1.7 s, the last one crossing the line.
  int sent = 0;
  while (send(MCC3_ROUTE_DIRECT, now + 300 + sent) == MCC3_FWD_SEND) sent++;
  EXPECT_EQ(21, sent);
  EXPECT_EQ(MCC3_FWD_RATE_LIMITED, send(MCC3_ROUTE_DIRECT, now + 899));
  // The cooldown: 9 s, and a flood only every five minutes.
  EXPECT_EQ(MCC3_FWD_SEND, send(MCC3_ROUTE_FLOOD_HOME, now + 900));
  EXPECT_EQ(MCC3_FWD_RATE_LIMITED, send(MCC3_ROUTE_FLOOD_HOME, now + 1199));
  EXPECT_EQ(MCC3_FWD_SEND, send(MCC3_ROUTE_FLOOD_HOME, now + 1200));
  sent = 0;
  while (send(MCC3_ROUTE_DIRECT, now + 1300 + sent) == MCC3_FWD_SEND) sent++;
  EXPECT_EQ(4, sent);
  // And the quarter after it a burst again.
  EXPECT_EQ(MCC3_FWD_RATE_LIMITED, send(MCC3_ROUTE_DIRECT, now + 1799));
  EXPECT_EQ(MCC3_FWD_SEND, send(MCC3_ROUTE_DIRECT, now + 1800));
}

TEST(Mcc3Relay, AStatusHasTheNameMccontrolPrints) {
  EXPECT_STREQ("answered", mcc3ForwardStatusName(MCC3_FWD_ANSWERED));
  EXPECT_STREQ("off", mcc3ForwardStatusName(MCC3_FWD_OFF));
  EXPECT_STREQ("rate-limited", mcc3ForwardStatusName(MCC3_FWD_RATE_LIMITED));
  EXPECT_STREQ("send-failed", mcc3ForwardStatusName(MCC3_FWD_SEND_FAILED));
  EXPECT_STREQ("unknown", mcc3ForwardStatusName(MCC3_FWD_SEND_FAILED + 1));
  EXPECT_STREQ("unknown", mcc3ForwardStatusName(-1));
}

// The relay's refusal lines on the serial console print these, never the number
// (MqttRelayHooks.cpp): each status its own name, in the order of the numbers on the wire.
TEST(Mcc3Relay, EveryStatusHasItsOwnName) {
  static const struct { int status; const char* name; } rows[] = {
    { MCC3_FWD_ANSWERED, "answered" },         { MCC3_FWD_NO_ANSWER, "no-answer" },
    { MCC3_FWD_OFF, "off" },                   { MCC3_FWD_EXPIRED, "expired" },
    { MCC3_FWD_REPLAY, "replay" },             { MCC3_FWD_BAD_BODY, "bad-body" },
    { MCC3_FWD_BUSY, "busy" },                 { MCC3_FWD_RATE_LIMITED, "rate-limited" },
    { MCC3_FWD_CLOCK_UNSET, "clock-unset" },   { MCC3_FWD_SEND_FAILED, "send-failed" },
  };
  int n = 0;
  for (const auto& r : rows) {
    EXPECT_EQ(n++, r.status);
    EXPECT_STREQ(r.name, mcc3ForwardStatusName(r.status));
  }
  EXPECT_EQ(MCC3_FWD_SEND_FAILED + 1, n);
  // The longest line the relay prints for a refusal fits debugLine's 120 bytes.
  char line[120];
  int len = snprintf(line, sizeof(line), "relay: forward %u, request %u, refused, %s", 4294967295u, 4294967295u,
                     mcc3ForwardStatusName(MCC3_FWD_RATE_LIMITED));
  EXPECT_LT(len, (int)sizeof(line));
}

TEST(Mcc3Relay, TheWaitEndsAfter120SecondsAcrossAMillisWrap) {
  EXPECT_FALSE(mcc3RelayWaitOver(1000, 1000));
  EXPECT_FALSE(mcc3RelayWaitOver(1000, 1000 + 119999));
  EXPECT_TRUE(mcc3RelayWaitOver(1000, 1000 + 120000));
  EXPECT_FALSE(mcc3RelayWaitOver(0xFFFFFF00u, 100));
  EXPECT_TRUE(mcc3RelayWaitOver(0xFFFFFF00u, 120000 - 0x100));
}

TEST(Mcc3Relay, TheAnswerIsTakenOnlyWhenItStartsWithTheRelaysTag) {
  const Mcc3Keys target = nodeKeys(TARGET, OWNER.pub), owner_of_target = ownerKeys(OWNER, TARGET.pub);
  const uint8_t nonce[12] = {7};
  uint8_t resp[176] = {0};
  size_t n = mcc3MeshBuildResponse(target.cmd, nonce, 0x11223344, 7, 0, RELAY_NOW, "> SE-JKP-Target", 167, resp);
  const size_t padded = (n + 15) / 16 * 16;            // as the relay decrypts it

  Mcc3ForwardResult r;
  mcc3ForwardResultInit(&r, 9, MCC3_FWD_ANSWERED);
  EXPECT_FALSE(mcc3RelayTakeResponse(0x11223345, resp, padded, &r));      // another forward's answer
  EXPECT_FALSE(mcc3RelayTakeResponse(0x44332211, resp, padded, &r));      // little-endian, not big
  EXPECT_FALSE(mcc3RelayTakeResponse(0x11223344, resp, 3, &r));
  EXPECT_FALSE(mcc3RelayTakeResponse(0x11223344, NULL, 0, &r));
  EXPECT_EQ(0, r.response_len);
  ASSERT_TRUE(mcc3RelayTakeResponse(0x11223344, resp, padded, &r));
  EXPECT_EQ(padded - 4, r.response_len);
  EXPECT_EQ(hex(resp + 4, padded - 4), hex(r.response, r.response_len));

  // What the owner does with it: the tag back in front, the padding dropped, opened as a
  // companion's would be.
  std::vector<uint8_t> companion(4, 0);
  companion.insert(companion.end(), r.response, r.response + n - 4);
  Opened o = openMeshResponse(owner_of_target, companion);
  ASSERT_EQ("ok", o.outcome);
  EXPECT_EQ("> SE-JKP-Target", o.reply);

  // The longest response is 167 bytes and decrypts to 176: only padding is cut.
  n = mcc3MeshBuildResponse(target.cmd, nonce, 0x11223344, 7, 0, RELAY_NOW, std::string(200, 'r').c_str(), 167, resp);
  ASSERT_EQ(167u, n);
  ASSERT_TRUE(mcc3RelayTakeResponse(0x11223344, resp, 176, &r));
  EXPECT_EQ(167, r.response_len);
  EXPECT_EQ(hex(resp + 4, 163), hex(r.response, 163));
}

TEST(Mcc3Relay, AResultIs285BytesWhateverItSaysAndOpensToWhatWasSealed) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub), owner = ownerKeys(OWNER, NODE.pub);
  const uint8_t nonce[12] = { 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B };
  Mcc3ForwardResult r;
  mcc3ForwardResultInit(&r, 9, MCC3_FWD_ANSWERED);
  r.clock = RELAY_NOW + 5;
  r.sent = MCC3_SENT_FLOOD;
  r.snr = -23;
  const uint8_t path[3] = { 0xAA, 0xBB, 0xCC };
  mcc3ForwardResultPath(&r, 3, path);
  r.response_len = 60;
  for (int i = 0; i < 60; i++) r.response[i] = (uint8_t)(i + 1);

  char out[MCC3_FWD_RES_B64 + 1];
  ASSERT_EQ(380u, mcc3BuildForwardResult(node.fwd, nonce, &r, out, sizeof(out)));
  EXPECT_EQ(0u, mcc3BuildForwardResult(node.fwd, nonce, &r, out, 380));
  ASSERT_EQ(380u, mcc3BuildForwardResult(node.fwd, nonce, &r, out, sizeof(out)));
  std::vector<uint8_t> raw = unb64(out);
  ASSERT_EQ(285u, raw.size());
  EXPECT_EQ(0x66, raw[0]);
  EXPECT_EQ(hex(nonce, 12), hex(raw.data() + 1, 12));

  Mcc3ForwardResult back;
  ASSERT_EQ(MQTTCTRL_OK, mcc3OpenForwardResult(owner.fwd, out, 380, &back));
  EXPECT_EQ(9u, back.counter);
  EXPECT_EQ(MCC3_FWD_ANSWERED, back.status);
  EXPECT_EQ(RELAY_NOW + 5, back.clock);
  EXPECT_EQ(MCC3_SENT_FLOOD, back.sent);
  EXPECT_EQ(-23, back.snr);
  EXPECT_EQ(3, back.path_len);
  EXPECT_EQ("AABBCC", hex(back.path, 3));
  EXPECT_EQ(60, back.response_len);
  EXPECT_EQ(hex(r.response, 60), hex(back.response, 60));

  // The layout, field by field.
  uint8_t* p = raw.data() + 13;
  ASSERT_TRUE(mcc3Open(owner.fwd, raw.data() + 1, raw.data(), 13, p, 256, p));
  EXPECT_EQ(9u, mqttCtrlMeshU32(p));
  EXPECT_EQ(0, p[4]);
  EXPECT_EQ(RELAY_NOW + 5, mqttCtrlMeshU32(p + 5));
  EXPECT_EQ(2, p[9]);
  EXPECT_EQ(0xE9, p[10]);
  EXPECT_EQ(3, p[11]);
  EXPECT_EQ("AABBCC00", hex(p + 12, 4));
  EXPECT_EQ(60, p[76]);
  EXPECT_EQ(1, p[77]);
  EXPECT_EQ(60, p[136]);
  EXPECT_EQ(std::string(2 * (256 - 137), '0'), hex(p + 137, 256 - 137));

  // A refusal: nothing sent, no SNR, no path, no response, and the same length.
  mcc3ForwardResultInit(&r, 10, MCC3_FWD_RATE_LIMITED);
  ASSERT_EQ(380u, mcc3BuildForwardResult(node.fwd, nonce, &r, out, sizeof(out)));
  ASSERT_EQ(MQTTCTRL_OK, mcc3OpenForwardResult(owner.fwd, out, 380, &back));
  EXPECT_EQ(MCC3_FWD_RATE_LIMITED, back.status);
  EXPECT_EQ(0u, back.clock);
  EXPECT_EQ(MCC3_SENT_NOTHING, back.sent);
  EXPECT_EQ(MCC3_SNR_NONE, back.snr);
  EXPECT_EQ(MCC3_PATH_NONE, back.path_len);
  EXPECT_EQ(0, back.response_len);
  raw = unb64(out);
  p = raw.data() + 13;
  ASSERT_TRUE(mcc3Open(owner.fwd, raw.data() + 1, raw.data(), 13, p, 256, p));
  EXPECT_EQ(0x80, p[10]);
  EXPECT_EQ(0xFF, p[11]);

  // The longest of everything still fits the 256 bytes.
  mcc3ForwardResultInit(&r, 11, MCC3_FWD_ANSWERED);
  uint8_t long_path[64];
  memset(long_path, 0x5A, sizeof(long_path));
  mcc3ForwardResultPath(&r, 0x40 | 32, long_path);
  EXPECT_EQ(0x40 | 32, r.path_len);
  r.response_len = 167;
  memset(r.response, 0xA5, 167);
  ASSERT_EQ(380u, mcc3BuildForwardResult(node.fwd, nonce, &r, out, sizeof(out)));
  ASSERT_EQ(MQTTCTRL_OK, mcc3OpenForwardResult(owner.fwd, out, 380, &back));
  EXPECT_EQ(hex(long_path, 64), hex(back.path, 64));
  EXPECT_EQ(167, back.response_len);
  EXPECT_EQ(0xA5, back.response[166]);
  EXPECT_EQ(256, 77 + 167 + 12);

  // A path the field cannot hold, or the reserved hash size, is no path.
  mcc3ForwardResultPath(&r, 0x80 | 22, long_path);
  EXPECT_EQ(MCC3_PATH_NONE, r.path_len);
  mcc3ForwardResultPath(&r, 0xC1, long_path);
  EXPECT_EQ(MCC3_PATH_NONE, r.path_len);
  mcc3ForwardResultPath(&r, 0, NULL);
  EXPECT_EQ(0, r.path_len);
}

TEST(Mcc3Relay, EveryBitOfAResultMattersAndOnlyThisRelaysKeyOpensIt) {
  const Mcc3Keys node = nodeKeys(NODE, OWNER.pub), owner = ownerKeys(OWNER, NODE.pub);
  const uint8_t nonce[12] = {3};
  Mcc3ForwardResult r, back;
  mcc3ForwardResultInit(&r, 9, MCC3_FWD_NO_ANSWER);
  char out[MCC3_FWD_RES_B64 + 1];
  ASSERT_EQ(380u, mcc3BuildForwardResult(node.fwd, nonce, &r, out, sizeof(out)));
  std::vector<uint8_t> raw = unb64(out);
  for (size_t i = 0; i < raw.size(); i++) {
    std::vector<uint8_t> x = raw;
    x[i] ^= 0x01;
    char b64[MCC3_FWD_RES_B64 + 1];
    size_t n = mqttV2B64Encode(x.data(), x.size(), b64, sizeof(b64));
    EXPECT_EQ(i == 0 ? MQTTCTRL_ERR_BAD_FIELDS : MQTTCTRL_ERR_SIG_INVALID,
              mcc3OpenForwardResult(owner.fwd, b64, n, &back)) << i;
  }
  EXPECT_EQ(MQTTCTRL_ERR_SIG_INVALID, mcc3OpenForwardResult(ownerKeys(OWNER, TARGET.pub).fwd, out, 380, &back));
  EXPECT_EQ(MQTTCTRL_ERR_SIG_INVALID, mcc3OpenForwardResult(owner.cmd, out, 380, &back));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_FIELDS, mcc3OpenForwardResult(owner.fwd, out, 379, &back));
  // A command's result is the same length and is not a forward's; nor the other way round.
  char res[MCC3_MAX_RESULT];
  ASSERT_EQ(380u, mcc3BuildResult(node.cmd, nonce, 9, 0, 0, "get name", "> x", res, sizeof(res)));
  EXPECT_EQ(MQTTCTRL_ERR_BAD_FIELDS, mcc3OpenForwardResult(owner.fwd, res, 380, &back));
  EXPECT_EQ("bad-fields", openResult(owner, out).outcome);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
