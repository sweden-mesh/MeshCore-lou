// Host tests for the announce (src/helpers/MeshAliveLogic.h, lou-21): what a node without
// Wi-Fi floods to its owner, and what an Observer node that hears it hands the command server. Part of the test_mqtt_v3 suite (env:native_v2, the real rweather/Crypto and MeshCore's
// ed25519), whose main() runs these too. The vectors are test/data/malive-vectors.json, made
// by scripts/malive-vectors.py in Python and turned into malive_vectors.h: every one is
// rebuilt here byte for byte.
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <ed_25519.h>
#include "helpers/MeshAliveLogic.h"
#include "malive_vectors.h"

namespace {

std::string hex(const uint8_t* b, size_t n) {
  static const char d[] = "0123456789ABCDEF";
  std::string s;
  for (size_t i = 0; i < n; i++) { s += d[b[i] >> 4]; s += d[b[i] & 15]; }
  return s;
}

std::vector<uint8_t> unhex(const char* h) {
  std::vector<uint8_t> v;
  for (size_t i = 0; h[i] && h[i + 1]; i += 2) {
    unsigned x;
    sscanf(h + i, "%2x", &x);
    v.push_back((uint8_t)x);
  }
  return v;
}

struct Ident {
  uint8_t pub[32], prv[64];
  explicit Ident(const char* seed_hex) {
    std::vector<uint8_t> seed = unhex(seed_hex);
    ed25519_create_keypair(pub, prv, seed.data());
  }
};

const Ident OWNER(MALIVE_SEED_OWNER), NODE(MALIVE_SEED_NODE), CATCHER(MALIVE_SEED_CATCHER);

// The node's identity signs, as LocalIdentity::sign does; the key the announce names verifies.
void signAs(void* ctx, uint8_t sig[MCC3_SIG_LEN], const uint8_t* msg, size_t len) {
  const Ident* id = (const Ident*)ctx;
  ed25519_sign(sig, msg, len, id->pub, id->prv);
}
bool verifyNamed(void* ctx, const uint8_t sig[MCC3_SIG_LEN], const uint8_t* msg, size_t len) {
  return ed25519_verify(sig, msg, len, (const uint8_t*)ctx) == 1;
}
bool open(const uint8_t* key, const uint8_t* payload, size_t len, MeshAliveOpened* o) {
  return meshAliveOpen(key, OWNER.pub, payload, len, verifyNamed, (void*)(payload + 1), o);
}

// One side's key: its own identity, the other's public key, and the node the key is named by.
std::vector<uint8_t> derive(const Ident& self, const uint8_t* peer, const char* label, const uint8_t* node_key) {
  uint8_t shared[32];
  ed25519_key_exchange(shared, peer, self.prv);
  std::vector<uint8_t> k(32);
  meshAliveDeriveKey(shared, label, hex(node_key, 32).c_str(), k.data());
  return k;
}

const Ident& identOf(const MAliveVecAnnounce& v) { return strcmp(v.node, "node") == 0 ? NODE : CATCHER; }

MeshAlive fieldsOf(const MAliveVecAnnounce& v) {
  MeshAlive a;
  a.boot = v.boot;
  a.sequence = v.sequence;
  a.uptime = v.uptime;
  a.clock = v.clock;
  a.last_counter = v.last_counter;
  a.flags = v.flags;
  a.battery_mv = v.battery_mv;
  a.version = v.version;
  a.name = v.name_field;
  return a;
}

// An announce of a made-up node for OWNER, signed by an identity made from the same byte.
std::vector<uint8_t> announceOf(uint8_t node, uint32_t boot, uint32_t sequence, const uint8_t* owner = OWNER.pub) {
  uint8_t key[32], seed[32];
  memset(key, 0x5A, sizeof(key));
  memset(seed, node, sizeof(seed));
  Ident id(hex(seed, 32).c_str());
  MeshAlive a = {};
  a.boot = boot;
  a.sequence = sequence;
  a.version = "lou-21-rc";
  a.name = "n";
  std::vector<uint8_t> out(MALIVE_PAYLOAD);
  meshAliveBuild(key, owner, id.pub, &a, signAs, (void*)&id, out.data());
  return out;
}



}  // namespace

TEST(MeshAlive, KeysOfBothSidesAreTheVectors) {
  uint8_t shared[32];
  ed25519_key_exchange(shared, OWNER.pub, NODE.prv);
  EXPECT_EQ(hex(shared, 32), MALIVE_SHARED_NODE_OWNER);
  ed25519_key_exchange(shared, OWNER.pub, CATCHER.prv);
  EXPECT_EQ(hex(shared, 32), MALIVE_SHARED_CATCHER_OWNER);
  EXPECT_EQ(hex(NODE.pub, 32), MALIVE_PUB_NODE);
  EXPECT_EQ(hex(CATCHER.pub, 32), MALIVE_PUB_CATCHER);

  EXPECT_EQ(hex(derive(NODE, OWNER.pub, MALIVE_LABEL, NODE.pub).data(), 32), MALIVE_K_MALIVE_NODE);
  EXPECT_EQ(hex(derive(OWNER, NODE.pub, MALIVE_LABEL, NODE.pub).data(), 32), MALIVE_K_MALIVE_NODE);
  EXPECT_EQ(hex(derive(CATCHER, OWNER.pub, MALIVE_LABEL, CATCHER.pub).data(), 32), MALIVE_K_MALIVE_CATCHER);
}

// A key of its own: not one of the four mcc3 derives for the same node and owner.
TEST(MeshAlive, TheKeyIsNoneOfMcc3s) {
  uint8_t shared[32];
  ed25519_key_exchange(shared, OWNER.pub, NODE.prv);
  Mcc3Keys k;
  mcc3DeriveKeys(shared, MALIVE_PUB_NODE, &k);
  std::vector<uint8_t> malive = unhex(MALIVE_K_MALIVE_NODE);
  for (const uint8_t* other : { k.cmd, k.mesh, k.alive, k.fwd }) EXPECT_NE(0, memcmp(malive.data(), other, 32));
}

TEST(MeshAlive, EveryAnnounceIsRebuiltByteForByte) {
  ASSERT_GE(sizeof(MALIVE_ANNOUNCES) / sizeof(MALIVE_ANNOUNCES[0]), 4u);
  for (const MAliveVecAnnounce& v : MALIVE_ANNOUNCES) {
    SCOPED_TRACE(v.name);
    const Ident& node = identOf(v);
    std::vector<uint8_t> key = derive(node, OWNER.pub, MALIVE_LABEL, node.pub);
    MeshAlive a = fieldsOf(v);
    uint8_t out[MALIVE_PAYLOAD];
    meshAliveBuild(key.data(), OWNER.pub, node.pub, &a, signAs, (void*)&node, out);
    EXPECT_EQ(hex(out, sizeof(out)), v.payload);
    EXPECT_EQ(hex(out + MALIVE_AT_OWNER_TAG, 4), v.owner_tag);
    uint8_t msg[9 + MALIVE_SIGNED];
    EXPECT_EQ(meshAliveSignedBytes(out, msg), 109u);
    EXPECT_EQ(hex(msg, sizeof(msg)), v.signed_bytes);
    EXPECT_EQ(hex(out + MALIVE_AT_SIG, MCC3_SIG_LEN), v.signature);
    EXPECT_TRUE(meshAliveSignatureOk(out, verifyNamed, (void*)node.pub));
    EXPECT_EQ(out[0], node.pub[0]);
    EXPECT_EQ(0, memcmp(out + 1, node.pub, 32));
    EXPECT_EQ(out[MALIVE_AT_KIND], 0x4D);

    uint8_t nonce[MCC3_NONCE_LEN];
    meshAliveNonce(v.boot, v.sequence, nonce);
    EXPECT_EQ(hex(nonce, sizeof(nonce)), v.nonce);
  }
}

TEST(MeshAlive, TheOwnerOpensEveryAnnounce) {
  for (const MAliveVecAnnounce& v : MALIVE_ANNOUNCES) {
    SCOPED_TRACE(v.name);
    const Ident& node = identOf(v);
    std::vector<uint8_t> key = derive(OWNER, node.pub, MALIVE_LABEL, node.pub);
    std::vector<uint8_t> payload = unhex(v.payload);
    MeshAliveOpened o;
    ASSERT_TRUE(open(key.data(), payload.data(), payload.size(), &o));
    EXPECT_EQ(hex(o.node_key, 32), hex(node.pub, 32));
    EXPECT_EQ(o.boot, v.boot);
    EXPECT_EQ(o.sequence, v.sequence);
    EXPECT_EQ(o.uptime, v.uptime);
    EXPECT_EQ(o.clock, v.clock);
    EXPECT_EQ(o.last_counter, v.last_counter);
    EXPECT_EQ(o.flags, v.flags);
    EXPECT_EQ(o.battery_mv, v.battery_mv);
    EXPECT_STREQ(o.version, v.opened_version);
    EXPECT_STREQ(o.name, v.opened_name);
  }
}

// The sealed part as the note lays it out: the battery is two bytes after the flags, low
// byte first, and 0 says the board cannot read it.
TEST(MeshAlive, TheSealedPartHoldsTheBatteryAfterTheFlags) {
  const MAliveVecAnnounce& v = MALIVE_ANNOUNCES[0];
  std::vector<uint8_t> plain = unhex(v.plaintext);
  ASSERT_EQ(plain.size(), (size_t)MALIVE_SEALED);
  EXPECT_EQ(mqttCtrlMeshU32(plain.data()), v.uptime);
  EXPECT_EQ(mqttCtrlMeshU32(plain.data() + 4), v.clock);
  EXPECT_EQ(mqttCtrlMeshU32(plain.data() + 8), v.last_counter);
  EXPECT_EQ(plain[12], v.flags);
  ASSERT_EQ(v.battery_mv, 3987);
  EXPECT_EQ(plain[13], 0x93);
  EXPECT_EQ(plain[14], 0x0F);
  EXPECT_EQ(plain[15], strlen(v.version));
  EXPECT_EQ(MALIVE_PAYLOAD, 165);
  EXPECT_EQ(MALIVE_AT_SEALED + MALIVE_SEALED + MALIVE_TAG_LEN, 101);
  EXPECT_EQ(MALIVE_AT_SIG + MCC3_SIG_LEN, MALIVE_PAYLOAD);
  EXPECT_EQ(MALIVE_SIGNED, 100);
  EXPECT_EQ(MALIVE_AAD_LEN, 45);
  // It fits an ANON_REQ with the room the mesh gives a payload.
  EXPECT_LE(MALIVE_PAYLOAD, 184);   // MAX_PACKET_PAYLOAD
  // The longest version and name fill the sealed part exactly.
  EXPECT_EQ(15 + 1 + MALIVE_MAX_VERSION + 1 + MALIVE_MAX_NAME, MALIVE_SEALED);
  EXPECT_EQ(MALIVE_ANNOUNCES[1].battery_mv, 0);
}

TEST(MeshAlive, EveryRefusalGivesItsOutcome) {
  std::vector<uint8_t> key = derive(OWNER, NODE.pub, MALIVE_LABEL, NODE.pub);
  ASSERT_GE(sizeof(MALIVE_REFUSALS) / sizeof(MALIVE_REFUSALS[0]), 12u);
  for (const MAliveVecRefusal& v : MALIVE_REFUSALS) {
    SCOPED_TRACE(v.name);
    std::vector<uint8_t> p = unhex(v.input);
    std::string outcome = "opens";
    MeshAliveOpened o;
    if (!meshAliveIsAnnounce(p.data(), p.size())) outcome = "not-announce";
    else if (!meshAliveSignatureOk(p.data(), verifyNamed, (void*)(p.data() + 1))) outcome = "bad-signature";
    else if (!meshAliveForOwner(p.data(), OWNER.pub)) outcome = "other-owner";
    else if (!open(key.data(), p.data(), p.size(), &o)) outcome = "does-not-open";
    EXPECT_EQ(outcome, v.outcome);
    EXPECT_FALSE(open(key.data(), p.data(), p.size(), &o));
  }
}

TEST(MeshAlive, EveryBitOfAnAnnounceIsGuarded) {
  std::vector<uint8_t> key = derive(OWNER, NODE.pub, MALIVE_LABEL, NODE.pub);
  std::vector<uint8_t> good = unhex(MALIVE_ANNOUNCES[0].payload);
  MeshAliveOpened o;
  ASSERT_TRUE(open(key.data(), good.data(), good.size(), &o));
  for (size_t bit = 0; bit < good.size() * 8; bit++) {
    std::vector<uint8_t> p = good;
    p[bit / 8] ^= (uint8_t)(1 << (bit % 8));
    EXPECT_FALSE(open(key.data(), p.data(), p.size(), &o)) << "bit " << bit;
    // The signature alone guards every byte from the node's key on, the seal not needed.
    if (bit >= 8) EXPECT_FALSE(meshAliveSignatureOk(p.data(), verifyNamed, (void*)(p.data() + 1))) << "bit " << bit;
  }
  // Another node's key opens nothing, and nor does the owner's key for another node.
  std::vector<uint8_t> other = derive(OWNER, CATCHER.pub, MALIVE_LABEL, CATCHER.pub);
  EXPECT_FALSE(open(other.data(), good.data(), good.size(), &o));
  // Signed by another identity than the one it names.
  std::vector<uint8_t> forged = good;
  uint8_t msg[9 + MALIVE_SIGNED];
  signAs((void*)&CATCHER, forged.data() + MALIVE_AT_SIG, msg, meshAliveSignedBytes(forged.data(), msg));
  EXPECT_FALSE(meshAliveSignatureOk(forged.data(), verifyNamed, (void*)(forged.data() + 1)));
  EXPECT_TRUE(meshAliveSignatureOk(forged.data(), verifyNamed, (void*)CATCHER.pub));
  EXPECT_FALSE(meshAliveIsAnnounce(NULL, MALIVE_PAYLOAD));
}

// The tag changes with the node, the owner and each announce, so two announces say nothing
// about a shared owner to somebody who does not know the owner's key.
TEST(MeshAlive, TheOwnerTagFollowsEveryInput) {
  uint8_t base[4], t[4];
  meshAliveOwnerTag(OWNER.pub, NODE.pub, 7, 1, base);
  EXPECT_EQ(hex(base, 4), MALIVE_ANNOUNCES[0].owner_tag);
  meshAliveOwnerTag(OWNER.pub, NODE.pub, 7, 2, t);
  EXPECT_NE(0, memcmp(base, t, 4));
  meshAliveOwnerTag(OWNER.pub, NODE.pub, 8, 1, t);
  EXPECT_NE(0, memcmp(base, t, 4));
  meshAliveOwnerTag(OWNER.pub, CATCHER.pub, 7, 1, t);
  EXPECT_NE(0, memcmp(base, t, 4));
  meshAliveOwnerTag(CATCHER.pub, NODE.pub, 7, 1, t);
  EXPECT_NE(0, memcmp(base, t, 4));
}

// ---- when a node announces ---------------------------------------------------------------

TEST(MeshAlive, ANodeAnnouncesSoonAfterItIsReady) {
  MeshAliveClock c = {};
  EXPECT_FALSE(meshAliveDue(&c, 1000000));
  EXPECT_FALSE(meshAliveBecameReady(&c, false, false));
  EXPECT_TRUE(meshAliveBecameReady(&c, true, false));     // the start, or `set cmd on`
  EXPECT_FALSE(meshAliveBecameReady(&c, true, false));
  EXPECT_TRUE(meshAliveBecameReady(&c, true, true));      // `set cmd.pubkey`
  EXPECT_FALSE(meshAliveBecameReady(&c, false, true));
  EXPECT_TRUE(meshAliveBecameReady(&c, true, false));

  for (uint32_t rnd : { 0u, 1u, 54999u, 55000u, 55001u, 123456789u, 0x7FFFFFFFu }) {
    MeshAliveClock s = {};
    s.ready = true;
    meshAliveSoon(&s, 1000, rnd);
    EXPECT_GE(s.due_ms, 1000u + 5000u);
    EXPECT_LE(s.due_ms, 1000u + 60000u);
    EXPECT_FALSE(meshAliveDue(&s, s.due_ms - 1));
    EXPECT_TRUE(meshAliveDue(&s, s.due_ms));
  }
  MeshAliveClock lo = {}, hi = {};
  meshAliveSoon(&lo, 0, 0);
  meshAliveSoon(&hi, 0, 55000);
  EXPECT_EQ(lo.due_ms, 5000u);
  EXPECT_EQ(hi.due_ms, 60000u);
}

TEST(MeshAlive, ThenEvery23HoursATenthEitherWay) {
  EXPECT_EQ(MALIVE_INTERVAL_MS, 82800000UL);
  MeshAliveClock c = {};
  c.ready = true;
  meshAliveSent(&c, 0, 0);
  EXPECT_EQ(c.due_ms, 74520000u);                 // 20.7 h
  meshAliveSent(&c, 0, 2 * MALIVE_SPREAD_MS);
  EXPECT_EQ(c.due_ms, 91080000u);                 // 25.3 h
  meshAliveSent(&c, 0, 2 * MALIVE_SPREAD_MS + 1);
  EXPECT_EQ(c.due_ms, 74520000u);
  EXPECT_FALSE(meshAliveDue(&c, 74519999u));
  EXPECT_TRUE(meshAliveDue(&c, 74520000u));

  // Something that would bring it close never puts it off, and brings a far one closer.
  meshAliveSoon(&c, 74500000u, 55000);
  EXPECT_EQ(c.due_ms, 74520000u);
  meshAliveSoon(&c, 1000, 0);
  EXPECT_EQ(c.due_ms, 6000u);

  // Across the wrap of millis().
  meshAliveSent(&c, 0xFFFFF000u, 0);
  EXPECT_EQ(c.due_ms, 0xFFFFF000u + 74520000u);
  EXPECT_FALSE(meshAliveDue(&c, 0xFFFFFFFFu));
  EXPECT_FALSE(meshAliveDue(&c, c.due_ms - 1));
  EXPECT_TRUE(meshAliveDue(&c, c.due_ms));

  // One that could not go out when it was due is tried again a minute later.
  meshAliveLater(&c, 5000);
  EXPECT_FALSE(meshAliveDue(&c, 64999));
  EXPECT_TRUE(meshAliveDue(&c, 65000));

  // Not while the node is not ready to: no key, `cmd off` or no region.
  c.ready = false;
  EXPECT_FALSE(meshAliveDue(&c, c.due_ms + 1));
}

// ---- the Observer node that hears it ---------------------------------------------------

TEST(MeshAliveSeen, EveryForwardIsRebuiltByteForByteAndRead) {
  ASSERT_GE(sizeof(MALIVE_SEEN) / sizeof(MALIVE_SEEN[0]), 3u);
  for (const MAliveVecSeen& v : MALIVE_SEEN) {
    SCOPED_TRACE(v.name);
    const MAliveVecAnnounce* heard = NULL;
    for (const MAliveVecAnnounce& a : MALIVE_ANNOUNCES) if (strcmp(a.name, v.announce) == 0) heard = &a;
    ASSERT_NE(heard, nullptr);
    std::vector<uint8_t> on_air = unhex(heard->payload);

    uint8_t item[MALIVE_SEEN_SIZE];
    meshAliveBuildSeen(on_air.data(), (int8_t)v.snr, v.hops, v.via, item);
    char out[MALIVE_SEEN_B64 + 1];
    size_t n = mqttV2B64Encode(item, sizeof(item), out, sizeof(out));
    EXPECT_EQ(std::string(out, n), v.payload);
    EXPECT_EQ(v.bytes, (size_t)MALIVE_SEEN_SIZE);
    char topic[MQTTCTRL_MAX_TOPIC + 1];
    ASSERT_TRUE(meshAliveSeenTopic(hex(CATCHER.pub, 32).c_str(), topic, sizeof(topic)));
    EXPECT_STREQ(topic, v.topic);

    // As the server does: the announce as it was on the air, checked by the key it names.
    uint8_t announce[MALIVE_PAYLOAD];
    int8_t snr;
    uint8_t hops, via;
    ASSERT_TRUE(meshAliveOpenSeen(v.payload, strlen(v.payload), announce, &snr, &hops, &via));
    EXPECT_EQ(hex(announce, sizeof(announce)), heard->payload);
    EXPECT_EQ(snr, v.snr);
    EXPECT_EQ(hops, v.hops);
    EXPECT_EQ(via, v.via);
    EXPECT_TRUE(meshAliveSignatureOk(announce, verifyNamed, (void*)(announce + 1)));
  }
}

TEST(MeshAliveSeen, TheSizes) {
  EXPECT_EQ(MALIVE_SEEN_SIZE, 168);
  EXPECT_EQ((int)MALIVE_SEEN_B64, 224);
  uint8_t announce[MALIVE_PAYLOAD];
  int8_t snr;
  uint8_t hops, via;
  const char* good = MALIVE_SEEN[0].payload;
  EXPECT_FALSE(meshAliveOpenSeen(good, strlen(good) - 4, announce, &snr, &hops, &via));
  EXPECT_FALSE(meshAliveOpenSeen(NULL, 0, announce, &snr, &hops, &via));
  uint8_t raw[MALIVE_SEEN_SIZE];
  ASSERT_EQ(mqttV2B64Decode(good, strlen(good), raw, sizeof(raw)), (size_t)MALIVE_SEEN_SIZE);
  EXPECT_EQ(raw[0], 0x53);
  char text[MALIVE_SEEN_B64 + 1];
  raw[0] = 0x48;
  EXPECT_FALSE(meshAliveOpenSeen(text, mqttV2B64Encode(raw, sizeof(raw), text, sizeof(text)), announce, &snr, &hops, &via));
  raw[0] = 0x53;
  raw[MALIVE_SEEN_SIZE - 1] = 3;
  EXPECT_FALSE(meshAliveOpenSeen(text, mqttV2B64Encode(raw, sizeof(raw), text, sizeof(text)), announce, &snr, &hops, &via));
}

// A window, not a table of nodes: the same report is forwarded once in ten minutes, a newer
// one at once.
TEST(MeshAliveSeen, AnAnnounceGoesOnceInTenMinutes) {
  MeshAliveRecent r = {};
  std::vector<uint8_t> a = announceOf(1, 5, 1);
  EXPECT_TRUE(meshAliveRecentFresh(&r, a.data(), 100));
  EXPECT_FALSE(meshAliveRecentFresh(&r, a.data(), 100));
  EXPECT_FALSE(meshAliveRecentFresh(&r, a.data(), 100 + 599));
  EXPECT_TRUE(meshAliveRecentFresh(&r, announceOf(1, 5, 2).data(), 200));
  EXPECT_TRUE(meshAliveRecentFresh(&r, announceOf(1, 6, 1).data(), 200));
  EXPECT_TRUE(meshAliveRecentFresh(&r, announceOf(2, 5, 1).data(), 200));
  EXPECT_TRUE(meshAliveRecentFresh(&r, a.data(), 100 + 600));
  EXPECT_FALSE(meshAliveRecentFresh(&r, a.data(), 100 + 601));

  // Eight are remembered; a ninth pushes out the oldest.
  MeshAliveRecent w = {};
  for (uint8_t n = 1; n <= MALIVE_RECENT; n++) EXPECT_TRUE(meshAliveRecentFresh(&w, announceOf(n, 1, 1).data(), 0));
  for (uint8_t n = 1; n <= MALIVE_RECENT; n++) EXPECT_FALSE(meshAliveRecentFresh(&w, announceOf(n, 1, 1).data(), 1));
  EXPECT_TRUE(meshAliveRecentFresh(&w, announceOf(9, 1, 1).data(), 2));
  EXPECT_TRUE(meshAliveRecentFresh(&w, announceOf(1, 1, 1).data(), 3));
  EXPECT_FALSE(meshAliveRecentFresh(&w, announceOf(3, 1, 1).data(), 4));
}

TEST(MeshAliveSeen, EightWaitTheOldestGivesWay) {
  MeshAliveSeenQueue q = {};
  EXPECT_EQ(meshAliveSeenFront(&q), nullptr);
  meshAliveSeenPop(&q);
  uint8_t item[MALIVE_SEEN_SIZE];
  for (uint8_t n = 1; n <= MALIVE_SEEN_QUEUE + 2; n++) {
    memset(item, n, sizeof(item));
    meshAliveSeenPush(&q, item);
  }
  EXPECT_EQ(q.count, MALIVE_SEEN_QUEUE);
  EXPECT_EQ(q.dropped, 2u);
  for (uint8_t n = 3; n <= MALIVE_SEEN_QUEUE + 2; n++) {
    ASSERT_NE(meshAliveSeenFront(&q), nullptr);
    EXPECT_EQ(meshAliveSeenFront(&q)[0], n);
    EXPECT_EQ(meshAliveSeenFront(&q)[MALIVE_SEEN_SIZE - 1], n);
    meshAliveSeenPop(&q);
  }
  EXPECT_EQ(meshAliveSeenFront(&q), nullptr);
  // About 1.4 KB in RAM, the window beside it.
  EXPECT_LE(sizeof(MeshAliveSeenQueue) + sizeof(MeshAliveRecent), 1500u);
}

TEST(MeshAliveSeen, OnePublishInTwoSeconds) {
  EXPECT_TRUE(meshAliveSeenDue(false, 0, 0));
  EXPECT_FALSE(meshAliveSeenDue(true, 1000, 1000 + MALIVE_SEEN_GAP_MS - 1));
  EXPECT_TRUE(meshAliveSeenDue(true, 1000, 1000 + MALIVE_SEEN_GAP_MS));
  EXPECT_FALSE(meshAliveSeenDue(true, 0xFFFFFF00u, 0x100));
  EXPECT_TRUE(meshAliveSeenDue(true, 0xFFFFFF00u, MALIVE_SEEN_GAP_MS - 0x100));
  // At most 1800 an hour; the server takes 120 of one key, the queue holds the rest a while.
  EXPECT_EQ(MALIVE_SEEN_GAP_MS, 2000UL);
}

// ---- a guest's forward (lou-21), in these vectors for the tools of this release ---------

TEST(MeshAliveGuest, TheGuestForwardAndItsResultAreRebuiltByteForByte) {
  ASSERT_GE(sizeof(MALIVE_GUESTS) / sizeof(MALIVE_GUESTS[0]), 1u);
  const MAliveVecGuest& v = MALIVE_GUESTS[0];
  const Ident GUEST(MALIVE_SEED_OTHER_OWNER);
  uint8_t shared[32], key[32];
  ed25519_key_exchange(shared, GUEST.pub, CATCHER.prv);
  mcc3DeriveGuestKey(shared, MALIVE_PUB_CATCHER, key);
  EXPECT_EQ(hex(key, 32), v.k_gfwd);
  ed25519_key_exchange(shared, CATCHER.pub, GUEST.prv);
  mcc3DeriveGuestKey(shared, MALIVE_PUB_CATCHER, key);
  EXPECT_EQ(hex(key, 32), v.k_gfwd);

  Mcc3Forward f;
  memset(&f, 0, sizeof(f));
  f.counter = v.counter;
  f.expiry = v.expiry;
  for (int i = 0; i < MCC3_RID_LEN; i++) f.rid[i] = (uint8_t)i;
  memcpy(f.target, NODE.pub, 32);
  f.route = MCC3_ROUTE_FLOOD_HOME;
  std::vector<uint8_t> body = unhex(v.body);
  f.body_len = (uint8_t)body.size();
  memcpy(f.body, body.data(), body.size());
  std::vector<uint8_t> nonce = unhex(v.nonce);
  char out[MCC3_GFWD_B64 + 1];
  size_t n = mcc3BuildGuestForward(key, GUEST.pub, CATCHER.pub, nonce.data(), &f, out, sizeof(out));
  EXPECT_EQ(std::string(out, n), v.payload);
  EXPECT_EQ(v.bytes, (size_t)MCC3_GFWD_SIZE);
  Mcc3Forward back;
  ASSERT_EQ(MQTTCTRL_OK, mcc3OpenGuestForward(key, v.payload, strlen(v.payload), &back));
  EXPECT_EQ(back.counter, v.counter);

  Mcc3ForwardResult r;
  mcc3ForwardResultInit(&r, v.counter, MCC3_FWD_GUEST_CAP);
  r.clock = 1795000010;
  std::vector<uint8_t> rnonce = unhex(v.result_nonce);
  char res[MCC3_FWD_RES_B64 + 1];
  n = mcc3BuildForwardResult(key, rnonce.data(), &r, res, sizeof(res));
  EXPECT_EQ(std::string(res, n), v.result);
}
