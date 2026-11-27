// Host tests for the announce (src/helpers/MeshAliveLogic.h, lou-21): what a node without
// Wi-Fi floods to its owner, and the table and the publish of the Observer node that catches
// it. Part of the test_mqtt_v3 suite (env:native_v2, the real rweather/Crypto and MeshCore's
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

// The made-up node's key, as the table keeps it.
uint8_t keyByteOf(uint8_t node) { return announceOf(node, 1, 1)[1]; }

MeshAliveVerdict take(MeshAliveTable* t, const std::vector<uint8_t>& p, uint32_t now_secs, int* slot = NULL,
                      uint32_t heard_at = 1795000000, int8_t snr = 0, uint8_t hops = 0) {
  return meshAliveTake(t, OWNER.pub, p.data(), p.size(), heard_at, snr, hops, now_secs, slot);
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
  EXPECT_EQ(hex(derive(CATCHER, OWNER.pub, MALIVE_HEARD_LABEL, CATCHER.pub).data(), 32), MALIVE_K_HEARD_CATCHER);
  EXPECT_EQ(hex(derive(OWNER, CATCHER.pub, MALIVE_HEARD_LABEL, CATCHER.pub).data(), 32), MALIVE_K_HEARD_CATCHER);
}

// A key of its own: not one of the four mcc3 derives for the same node and owner.
TEST(MeshAlive, TheKeyIsNoneOfMcc3s) {
  uint8_t shared[32];
  ed25519_key_exchange(shared, OWNER.pub, NODE.prv);
  Mcc3Keys k;
  mcc3DeriveKeys(shared, MALIVE_PUB_NODE, &k);
  std::vector<uint8_t> malive = unhex(MALIVE_K_MALIVE_NODE);
  for (const uint8_t* other : { k.cmd, k.mesh, k.alive, k.fwd }) EXPECT_NE(0, memcmp(malive.data(), other, 32));
  EXPECT_NE(std::string(MALIVE_K_MALIVE_CATCHER), MALIVE_K_HEARD_CATCHER);
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

// ---- the catching node -------------------------------------------------------------------

TEST(MeshAliveTable, KeepsTheNewestOfANode) {
  MeshAliveTable t;
  int slot = -1;
  EXPECT_EQ(take(&t, announceOf(1, 5, 1), 0, &slot, 111, -8, 3), MALIVE_ADDED);
  EXPECT_EQ(slot, 0);
  EXPECT_TRUE(t.entry[0].used);
  EXPECT_EQ(t.entry[0].heard_at, 111u);
  EXPECT_EQ(t.entry[0].snr, -8);
  EXPECT_EQ(t.entry[0].hops, 3);
  EXPECT_EQ(t.entry[0].advert_heard_at, 0u);
  EXPECT_EQ(hex(t.entry[0].kept, MALIVE_KEPT), hex(announceOf(1, 5, 1).data() + 33, MALIVE_KEPT));

  // The same again, by another path or replayed, and anything older: dropped, nothing moves.
  slot = -1;
  EXPECT_EQ(take(&t, announceOf(1, 5, 1), 0, &slot, 222, 4, 1), MALIVE_OLD);
  EXPECT_EQ(slot, -1);
  EXPECT_EQ(t.entry[0].heard_at, 111u);
  EXPECT_EQ(take(&t, announceOf(1, 4, 99), 0), MALIVE_OLD);
  EXPECT_EQ(meshAliveEntryBoot(&t.entry[0]), 5u);
  EXPECT_EQ(meshAliveEntrySequence(&t.entry[0]), 1u);

  // A later sequence, then a later boot whose sequence starts again.
  EXPECT_EQ(take(&t, announceOf(1, 5, 2), 0, &slot, 333, 4, 1), MALIVE_NEWER);
  EXPECT_EQ(slot, 0);
  EXPECT_EQ(t.entry[0].heard_at, 333u);
  EXPECT_EQ(t.entry[0].snr, 4);
  EXPECT_EQ(t.entry[0].hops, 1);
  EXPECT_EQ(take(&t, announceOf(1, 6, 1), 0, &slot), MALIVE_NEWER);
  EXPECT_EQ(meshAliveEntryBoot(&t.entry[0]), 6u);
  EXPECT_EQ(take(&t, announceOf(1, 5, 3), 0), MALIVE_OLD);
  EXPECT_FALSE(t.entry[1].used);
  EXPECT_TRUE(meshAliveKept(MALIVE_NEWER));
  EXPECT_TRUE(meshAliveKept(MALIVE_ADDED));
  EXPECT_FALSE(meshAliveKept(MALIVE_OLD));
  EXPECT_FALSE(meshAliveKept(MALIVE_LIMITED));
}

TEST(MeshAliveTable, KeepsOnlyItsOwnOwners) {
  MeshAliveTable t;
  int slot = -1;
  EXPECT_EQ(take(&t, announceOf(1, 5, 1, CATCHER.pub), 0, &slot), MALIVE_OTHER_OWNER);
  std::vector<uint8_t> p = announceOf(1, 5, 1);
  p[MALIVE_AT_KIND] = 0x4E;
  EXPECT_EQ(take(&t, p, 0, &slot), MALIVE_NOT_ANNOUNCE);
  p = announceOf(1, 5, 1);
  p.push_back(0);
  EXPECT_EQ(take(&t, p, 0, &slot), MALIVE_NOT_ANNOUNCE);
  p.resize(100);
  EXPECT_EQ(take(&t, p, 0, &slot), MALIVE_NOT_ANNOUNCE);
  EXPECT_EQ(slot, -1);
  for (const MeshAliveEntry& e : t.entry) EXPECT_FALSE(e.used);
  // None of them counted against the hour's four.
  for (uint8_t n = 1; n <= 4; n++) EXPECT_EQ(take(&t, announceOf(n, 1, 1), 0), MALIVE_ADDED);
}

TEST(MeshAliveTable, AdmitsFourNewNodesAnHour) {
  MeshAliveTable t;
  for (uint8_t n = 1; n <= 4; n++) EXPECT_EQ(take(&t, announceOf(n, 1, 1), 100 + n), MALIVE_ADDED);
  int slot = -1;
  EXPECT_EQ(take(&t, announceOf(5, 1, 1), 200, &slot), MALIVE_LIMITED);
  EXPECT_EQ(slot, -1);
  EXPECT_FALSE(t.entry[4].used);
  // A node already in the table is not new: its next announce is kept whatever the hour holds.
  EXPECT_EQ(take(&t, announceOf(2, 1, 2), 200), MALIVE_NEWER);
  // An hour after the first was admitted there is room for one, and for no more.
  EXPECT_EQ(take(&t, announceOf(5, 1, 1), 100 + 1 + 3599), MALIVE_LIMITED);
  EXPECT_EQ(take(&t, announceOf(5, 1, 1), 100 + 1 + 3600, &slot), MALIVE_ADDED);
  EXPECT_EQ(slot, 4);
  EXPECT_EQ(take(&t, announceOf(6, 1, 1), 100 + 1 + 3600), MALIVE_LIMITED);
}

TEST(MeshAliveTable, AFullTableDropsTheNodeHeardLongestAgo) {
  MeshAliveTable t;
  uint32_t now = 0;
  for (uint8_t n = 1; n <= MALIVE_TABLE; n++) {
    int slot = -1;
    EXPECT_EQ(take(&t, announceOf(n, 1, 1), now, &slot), MALIVE_ADDED);
    EXPECT_EQ(slot, n - 1);
    now += 900;
  }
  // Node 1 is heard again, so node 2 is now the one heard longest ago.
  EXPECT_EQ(take(&t, announceOf(1, 1, 2), now), MALIVE_NEWER);
  t.entry[1].advert_heard_at = 1795000000;
  int slot = -1;
  EXPECT_EQ(take(&t, announceOf(100, 1, 1), now, &slot), MALIVE_ADDED);
  EXPECT_EQ(slot, 1);
  EXPECT_EQ(t.entry[1].node_key[0], keyByteOf(100));
  EXPECT_EQ(t.entry[0].node_key[0], keyByteOf(1));
  // Nothing of the entry that left stays behind in its slot.
  EXPECT_EQ(meshAliveEntrySequence(&t.entry[1]), 1u);
  EXPECT_EQ(t.entry[1].advert_heard_at, 0u);
  now += 900;
  EXPECT_EQ(take(&t, announceOf(101, 1, 1), now, &slot), MALIVE_ADDED);
  EXPECT_EQ(slot, 2);
  // The node that left is new again when it comes back.
  now += 900;
  EXPECT_EQ(take(&t, announceOf(2, 1, 1), now, &slot), MALIVE_ADDED);
  EXPECT_EQ(slot, 3);
  int used = 0;
  for (const MeshAliveEntry& e : t.entry) used += e.used;
  EXPECT_EQ(used, MALIVE_TABLE);
}

TEST(MeshAliveHeard, EveryPublishIsRebuiltByteForByteAndOpened) {
  std::vector<uint8_t> key = derive(CATCHER, OWNER.pub, MALIVE_HEARD_LABEL, CATCHER.pub);
  ASSERT_GE(sizeof(MALIVE_HEARD) / sizeof(MALIVE_HEARD[0]), 2u);
  for (const MAliveVecHeard& v : MALIVE_HEARD) {
    SCOPED_TRACE(v.name);
    const MAliveVecAnnounce* heard = NULL;
    for (const MAliveVecAnnounce& a : MALIVE_ANNOUNCES) if (strcmp(a.name, v.announce) == 0) heard = &a;
    ASSERT_NE(heard, nullptr);
    std::vector<uint8_t> on_air = unhex(heard->payload);

    // As the catching node does: the announce into its table, the entry onto its slot.
    MeshAliveTable t;
    int slot = -1;
    ASSERT_EQ(take(&t, on_air, 0, &slot, v.heard_at, (int8_t)v.snr, v.hops), MALIVE_ADDED);
    MeshAliveEntry* e = &t.entry[slot];
    e->advert_heard_at = v.advert_heard_at;
    e->advert_snr = (int8_t)v.advert_snr;
    e->advert_hops = v.advert_hops;
    char out[MALIVE_HEARD_B64 + 1];
    std::vector<uint8_t> nonce = unhex(v.nonce);
    size_t n = meshAliveBuildHeard(key.data(), nonce.data(), e, out, sizeof(out));
    EXPECT_EQ(std::string(out, n), v.payload);
    EXPECT_EQ(n, (size_t)MALIVE_HEARD_B64);
    EXPECT_EQ(v.bytes, (size_t)MALIVE_HEARD_SIZE);

    char topic[MQTTCTRL_MAX_TOPIC + 1];
    ASSERT_TRUE(meshAliveHeardTopic(hex(CATCHER.pub, 32).c_str(), v.slot, topic, sizeof(topic)));
    EXPECT_STREQ(topic, v.topic);

    // As the owner does: the entry with K_heard, then the announce inside with K_malive.
    std::vector<uint8_t> owner_key = derive(OWNER, CATCHER.pub, MALIVE_HEARD_LABEL, CATCHER.pub);
    MeshAliveEntry got;
    uint8_t announce[MALIVE_PAYLOAD];
    ASSERT_TRUE(meshAliveOpenHeard(owner_key.data(), v.payload, strlen(v.payload), &got, announce));
    EXPECT_EQ(hex(got.node_key, 32), v.node_key);
    EXPECT_EQ(got.heard_at, v.heard_at);
    EXPECT_EQ(got.snr, v.snr);
    EXPECT_EQ(got.hops, v.hops);
    EXPECT_EQ(got.advert_heard_at, v.advert_heard_at);
    EXPECT_EQ(got.advert_snr, v.advert_snr);
    EXPECT_EQ(got.advert_hops, v.advert_hops);
    EXPECT_EQ(hex(announce, sizeof(announce)), heard->payload);
    const Ident& node = identOf(*heard);
    std::vector<uint8_t> malive = derive(OWNER, node.pub, MALIVE_LABEL, node.pub);
    MeshAliveOpened o;
    ASSERT_TRUE(open(malive.data(), announce, sizeof(announce), &o));
    EXPECT_STREQ(o.name, heard->opened_name);
    EXPECT_EQ(o.battery_mv, heard->battery_mv);
  }
}

TEST(MeshAliveHeard, OnlyTheOwnerOpensIt) {
  const MAliveVecHeard& v = MALIVE_HEARD[0];
  std::vector<uint8_t> key = unhex(MALIVE_K_HEARD_CATCHER);
  MeshAliveEntry got;
  uint8_t announce[MALIVE_PAYLOAD];
  ASSERT_TRUE(meshAliveOpenHeard(key.data(), v.payload, strlen(v.payload), &got, announce));

  // Not the key the catching node's own announce would be sealed under, nor its alive key.
  std::vector<uint8_t> other = unhex(MALIVE_K_MALIVE_CATCHER);
  EXPECT_FALSE(meshAliveOpenHeard(other.data(), v.payload, strlen(v.payload), &got, announce));

  uint8_t raw[MALIVE_HEARD_SIZE];
  ASSERT_EQ(mqttV2B64Decode(v.payload, strlen(v.payload), raw, sizeof(raw)), (size_t)MALIVE_HEARD_SIZE);
  EXPECT_EQ(raw[0], 0x48);
  for (size_t at = 0; at < sizeof(raw); at++) {
    uint8_t bad[MALIVE_HEARD_SIZE];
    memcpy(bad, raw, sizeof(raw));
    bad[at] ^= 0x80;
    char text[MALIVE_HEARD_B64 + 1];
    size_t n = mqttV2B64Encode(bad, sizeof(bad), text, sizeof(text));
    EXPECT_FALSE(meshAliveOpenHeard(key.data(), text, n, &got, announce)) << "byte " << at;
  }
  EXPECT_FALSE(meshAliveOpenHeard(key.data(), v.payload, strlen(v.payload) - 4, &got, announce));
}

TEST(MeshAliveHeard, TheSizesAndTheSlots) {
  EXPECT_EQ(MALIVE_KEPT, 132);
  EXPECT_EQ(MALIVE_HEARD_PLAIN, 176);
  EXPECT_EQ(MALIVE_HEARD_SIZE, 205);
  EXPECT_EQ((int)MALIVE_HEARD_B64, 274);
  EXPECT_EQ(MALIVE_TABLE, 16);

  char topic[MQTTCTRL_MAX_TOPIC + 1];
  EXPECT_TRUE(meshAliveHeardTopic(MALIVE_PUB_CATCHER, 0, topic, sizeof(topic)));
  EXPECT_TRUE(meshAliveHeardTopic(MALIVE_PUB_CATCHER, 15, topic, sizeof(topic)));
  EXPECT_FALSE(meshAliveHeardTopic(MALIVE_PUB_CATCHER, 16, topic, sizeof(topic)));
  EXPECT_FALSE(meshAliveHeardTopic(MALIVE_PUB_CATCHER, -1, topic, sizeof(topic)));
  char small[40];
  EXPECT_FALSE(meshAliveHeardTopic(MALIVE_PUB_CATCHER, 0, small, sizeof(small)));
}

TEST(MeshAliveHeard, OnePublishAtATime) {
  EXPECT_EQ(meshAliveNextPublish(0, false, 0, 1000), -1);
  EXPECT_EQ(meshAliveNextPublish(0x0001, false, 0, 1000), 0);         // the first goes at once
  EXPECT_EQ(meshAliveNextPublish(0x8010, false, 0, 1000), 4);         // the lowest slot first
  EXPECT_EQ(meshAliveNextPublish(0x8000, false, 0, 1000), 15);
  EXPECT_EQ(meshAliveNextPublish(0x0002, true, 1000, 1000 + MALIVE_PUBLISH_GAP_MS - 1), -1);
  EXPECT_EQ(meshAliveNextPublish(0x0002, true, 1000, 1000 + MALIVE_PUBLISH_GAP_MS), 1);
  // Across the wrap of millis().
  EXPECT_EQ(meshAliveNextPublish(0x0002, true, 0xFFFFFF00u, 0x100), -1);
  EXPECT_EQ(meshAliveNextPublish(0x0002, true, 0xFFFFFF00u, MALIVE_PUBLISH_GAP_MS - 0x100), 1);
  // At most 40 an hour, under the command server's 60.
  EXPECT_LE(3600000UL / MALIVE_PUBLISH_GAP_MS, 40UL);
}
