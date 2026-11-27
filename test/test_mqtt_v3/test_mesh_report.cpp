// Host tests for reporting (src/helpers/MeshReportLogic.h, lou-21): the zero-hop state packet
// and its ack, the announce along a path and the path ack, who acks, the reporting node's
// table and its ladder. Part of the test_mqtt_v3 suite, whose main() runs these too. The
// packets are in test/data/malive-vectors.json beside the announce they carry.
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <ed_25519.h>
#include "helpers/MeshReportLogic.h"
#include "malive_vectors.h"

namespace {

std::string hexOf(const uint8_t* b, size_t n) {
  static const char d[] = "0123456789ABCDEF";
  std::string s;
  for (size_t i = 0; i < n; i++) { s += d[b[i] >> 4]; s += d[b[i] & 15]; }
  return s;
}

std::vector<uint8_t> bytesOf(const char* h) {
  std::vector<uint8_t> v;
  for (size_t i = 0; h[i] && h[i + 1]; i += 2) {
    unsigned x;
    sscanf(h + i, "%2x", &x);
    v.push_back((uint8_t)x);
  }
  return v;
}

std::vector<uint8_t> announceA1() { return bytesOf(MALIVE_ANNOUNCES[0].payload); }

std::vector<uint8_t> keyOf(uint8_t b) { return std::vector<uint8_t>(32, b); }

}  // namespace

TEST(MeshReport, EveryPacketIsRebuiltByteForByte) {
  std::vector<uint8_t> a = announceA1();
  std::vector<uint8_t> catcher = bytesOf(MALIVE_PUB_CATCHER), node = bytesOf(MALIVE_PUB_NODE);
  ASSERT_GE(sizeof(MALIVE_PACKETS) / sizeof(MALIVE_PACKETS[0]), 5u);
  for (const MAliveVecPacket& v : MALIVE_PACKETS) {
    SCOPED_TRACE(v.name);
    std::vector<uint8_t> path = bytesOf(v.path);
    uint8_t out[MREPORT_DIRECT_MAX];
    size_t n = 0;
    if (strcmp(v.kind, "state") == 0) {
      mreportBuildState(a.data(), v.named ? catcher.data() : NULL, out);
      n = MREPORT_STATE_SIZE;
    } else if (strcmp(v.kind, "ack") == 0) {
      mreportBuildAck(node.data(), mreportId(a.data()), catcher.data(), out);
      n = MREPORT_ACK_SIZE;
    } else if (strcmp(v.kind, "direct") == 0) {
      n = mreportBuildDirect(a.data(), catcher.data(), v.path_len, path.data(), out);
    } else if (strcmp(v.kind, "path-ack") == 0) {
      ASSERT_TRUE(mreportBuildPathAck(node.data(), catcher.data(), mreportId(a.data()), v.path_len, path.data(), out));
      n = MREPORT_PATH_ACK_SIZE;
    }
    EXPECT_EQ(n, v.bytes);
    EXPECT_EQ(hexOf(out, n), v.payload);
  }
}

TEST(MeshReport, TheStatePacketCarriesTheAnnounce) {
  std::vector<uint8_t> a = announceA1();
  std::vector<uint8_t> catcher = bytesOf(MALIVE_PUB_CATCHER);
  uint8_t state[MREPORT_STATE_SIZE], back[MALIVE_PAYLOAD];
  mreportBuildState(a.data(), catcher.data(), state);
  EXPECT_EQ(MREPORT_STATE_SIZE, 167);
  EXPECT_EQ(state[0], 0xA0);
  // Zero-hop only: the top bit, which upstream's Mesh reads that way.
  EXPECT_TRUE(state[0] & 0x80);
  ASSERT_TRUE(mreportStateAnnounce(state, sizeof(state), back));
  EXPECT_EQ(hexOf(back, sizeof(back)), MALIVE_ANNOUNCES[0].payload);
  EXPECT_EQ(mreportStateNamed(state, catcher.data()), 1);
  EXPECT_EQ(mreportStateNamed(state, keyOf(0x11).data()), -1);
  mreportBuildState(a.data(), NULL, state);
  EXPECT_EQ(mreportStateNamed(state, catcher.data()), 0);

  EXPECT_FALSE(mreportStateAnnounce(state, sizeof(state) - 1, back));
  state[0] = 0xB0;
  EXPECT_FALSE(mreportStateAnnounce(state, sizeof(state), back));
  state[0] = 0xA0;
  state[3 + MALIVE_AT_KIND - 1] = 0x4E;
  EXPECT_FALSE(mreportStateAnnounce(state, sizeof(state), back));
  EXPECT_FALSE(mreportStateAnnounce(NULL, MREPORT_STATE_SIZE, back));
}

TEST(MeshReport, TheAckAndThePathAck) {
  std::vector<uint8_t> a = announceA1();
  std::vector<uint8_t> catcher = bytesOf(MALIVE_PUB_CATCHER), node = bytesOf(MALIVE_PUB_NODE);
  uint8_t ack[MREPORT_ACK_SIZE];
  mreportBuildAck(node.data(), mreportId(a.data()), catcher.data(), ack);
  EXPECT_EQ(MREPORT_ACK_SIZE, 41);
  EXPECT_TRUE(mreportIsAck(ack, sizeof(ack)));
  EXPECT_TRUE(ack[0] & 0x80);
  EXPECT_EQ(0, memcmp(ack + 1, node.data(), 4));
  EXPECT_EQ(0, memcmp(ack + 5, a.data() + 101, 4));      // the report id: the signature's first bytes
  EXPECT_EQ(0, memcmp(ack + 9, catcher.data(), 32));
  EXPECT_FALSE(mreportIsAck(ack, sizeof(ack) - 1));
  ack[0] = 0xA0;
  EXPECT_FALSE(mreportIsAck(ack, sizeof(ack)));

  const uint8_t path[] = { 0x11, 0x22, 0x33 };
  uint8_t pa[MREPORT_PATH_ACK_SIZE];
  ASSERT_TRUE(mreportBuildPathAck(node.data(), catcher.data(), mreportId(a.data()), 3, path, pa));
  EXPECT_EQ(MREPORT_PATH_ACK_SIZE, 55);
  EXPECT_TRUE(mreportIsPathAck(pa, sizeof(pa)));
  EXPECT_EQ(pa[0], node[0]);
  EXPECT_EQ(pa[33], 0x4B);
  EXPECT_EQ(pa[38], 3);
  EXPECT_EQ(0, memcmp(pa + 39, path, 3));
  for (size_t i = 42; i < sizeof(pa); i++) EXPECT_EQ(pa[i], 0) << i;
  // Longer than the 35 bytes below which an ANON_REQ is no packet at all.
  EXPECT_GT(MREPORT_PATH_ACK_SIZE, 35);
  // 8 two-byte hashes fit, 9 do not; nor does the reserved hash size.
  uint8_t long_path[18] = {0};
  EXPECT_TRUE(mreportBuildPathAck(node.data(), catcher.data(), mreportId(a.data()), 0x48, long_path, pa));
  EXPECT_FALSE(mreportBuildPathAck(node.data(), catcher.data(), mreportId(a.data()), 0x49, long_path, pa));
  EXPECT_FALSE(mreportBuildPathAck(node.data(), catcher.data(), mreportId(a.data()), 0xC1, long_path, pa));
  ASSERT_TRUE(mreportBuildPathAck(node.data(), catcher.data(), mreportId(a.data()), 3, path, pa));
  pa[38] = 0x49;
  EXPECT_FALSE(mreportIsPathAck(pa, sizeof(pa)));
  pa[38] = 3;
  pa[33] = 0x4D;
  EXPECT_FALSE(mreportIsPathAck(pa, sizeof(pa)));
}

TEST(MeshReport, TheAnnounceAlongAPathIsForTheOneItNames) {
  std::vector<uint8_t> a = announceA1();
  std::vector<uint8_t> catcher = bytesOf(MALIVE_PUB_CATCHER);
  const uint8_t path[] = { 0x11, 0x22 };
  uint8_t d[MREPORT_DIRECT_MAX];
  size_t n = mreportBuildDirect(a.data(), catcher.data(), 2, path, d);
  EXPECT_EQ(n, (size_t)(165 + 3 + 2));
  EXPECT_TRUE(mreportIsDirectFor(d, n, catcher.data()));
  EXPECT_FALSE(mreportIsDirectFor(d, n, keyOf(0x11).data()));
  EXPECT_FALSE(mreportIsDirectFor(d, n - 1, catcher.data()));
  EXPECT_FALSE(mreportIsDirectFor(a.data(), a.size(), catcher.data()));
  // The announce it holds is the flood's, byte for byte.
  EXPECT_EQ(hexOf(d, MALIVE_PAYLOAD), MALIVE_ANNOUNCES[0].payload);
  // No path is no second rung, and the longest fits the largest payload.
  EXPECT_EQ(mreportBuildDirect(a.data(), catcher.data(), 0, path, d), 0u);
  uint8_t sixteen[16] = {0};
  EXPECT_EQ(mreportBuildDirect(a.data(), catcher.data(), 0x48, sixteen, d), 184u);
  EXPECT_EQ(mreportBuildDirect(a.data(), catcher.data(), 0x49, sixteen, d), 0u);
}

TEST(MeshReport, APathTurnsAroundHashByHash) {
  const uint8_t one[] = { 1, 2, 3 };
  uint8_t out[8];
  mreportReversePath(one, 3, out);
  EXPECT_EQ(hexOf(out, 3), "030201");
  const uint8_t two[] = { 1, 2, 3, 4, 5, 6 };
  mreportReversePath(two, 0x43, out);
  EXPECT_EQ(hexOf(out, 6), "050603040102");
  EXPECT_EQ(mreportPathBytes(0x43), 6);
  EXPECT_EQ(mreportPathBytes(0xC1), -1);
}

// ---- who acks -------------------------------------------------------------------------

TEST(MeshReportAcks, TheNamedAcksAtOnceTheOthersWait) {
  for (uint32_t rnd : { 0u, 1u, 200u, 201u, 99999u }) {
    const uint32_t named = mreportStateAckDelay(1, rnd), other = mreportStateAckDelay(-1, rnd),
                   none = mreportStateAckDelay(0, rnd);
    EXPECT_GE(named, 100u);
    EXPECT_LE(named, 300u);
    EXPECT_GE(other, 3000u);
    EXPECT_LE(other, 3200u);
    EXPECT_GE(none, 500u);
    EXPECT_LE(none, 3000u);
  }
  // A flood: the fewest hops first, then the best SNR; zero hops at once.
  EXPECT_LT(mreportFloodAckDelay(0, 40, 200), mreportFloodAckDelay(1, 60, 0));
  EXPECT_LT(mreportFloodAckDelay(1, -100, 200), mreportFloodAckDelay(2, 60, 0));
  EXPECT_LT(mreportFloodAckDelay(2, 20, 0), mreportFloodAckDelay(2, -20, 0));
  EXPECT_EQ(mreportFloodAckDelay(2, 60, 0), mreportFloodAckDelay(2, 127, 0));
  EXPECT_LE(mreportFloodAckDelay(0, 60, 0), 300u);
  EXPECT_TRUE(mreportFloodAckable(0));
  EXPECT_TRUE(mreportFloodAckable(8));
  EXPECT_FALSE(mreportFloodAckable(9));
  EXPECT_TRUE(mreportFloodAckable(0x44));      // 4 two-byte hashes
  EXPECT_FALSE(mreportFloodAckable(0x45));
  EXPECT_FALSE(mreportFloodAckable(0xC1));
}

TEST(MeshReportAcks, AnAckHeardCancelsOne) {
  MreportAcks acks = {};
  const uint8_t r1[] = { 1, 1, 1, 1 }, r2[] = { 2, 2, 2, 2 }, r3[] = { 3, 3, 3, 3 };
  std::vector<uint8_t> node = keyOf(0x44);
  EXPECT_EQ(mreportAckDue(&acks, 0), nullptr);
  EXPECT_TRUE(mreportPlanAck(&acks, MREPORT_ACK_ZERO_HOP, node.data(), r1, 0, NULL, 1000, 3000));
  EXPECT_EQ(mreportAckDue(&acks, 3999), nullptr);
  ASSERT_NE(mreportAckDue(&acks, 4000), nullptr);
  mreportAckHeard(&acks, r2);
  EXPECT_NE(mreportAckDue(&acks, 4000), nullptr);
  mreportAckHeard(&acks, r1);
  EXPECT_EQ(mreportAckDue(&acks, 4000), nullptr);

  // The same report again keeps the sooner; a third report pushes out the latest of two.
  EXPECT_TRUE(mreportPlanAck(&acks, MREPORT_ACK_ZERO_HOP, node.data(), r1, 0, NULL, 0, 3000));
  EXPECT_FALSE(mreportPlanAck(&acks, MREPORT_ACK_ZERO_HOP, node.data(), r1, 0, NULL, 0, 3100));
  EXPECT_TRUE(mreportPlanAck(&acks, MREPORT_ACK_ZERO_HOP, node.data(), r1, 0, NULL, 0, 200));
  EXPECT_EQ(mreportAckDue(&acks, 199), nullptr);
  EXPECT_NE(mreportAckDue(&acks, 200), nullptr);
  EXPECT_TRUE(mreportPlanAck(&acks, MREPORT_ACK_ZERO_HOP, node.data(), r2, 0, NULL, 0, 5000));
  EXPECT_FALSE(mreportPlanAck(&acks, MREPORT_ACK_ZERO_HOP, node.data(), r3, 0, NULL, 0, 6000));
  EXPECT_TRUE(mreportPlanAck(&acks, MREPORT_ACK_ZERO_HOP, node.data(), r3, 0, NULL, 0, 1000));
  mreportAckHeard(&acks, r1);
  MreportAckPlan* p = mreportAckDue(&acks, 1000);
  ASSERT_NE(p, nullptr);
  EXPECT_EQ(0, memcmp(p->report, r3, 4));
  p->pending = false;
  EXPECT_EQ(mreportAckDue(&acks, 100000), nullptr);   // r2 gave way

  // A path ack keeps its path; one longer than a node's table is not planned.
  const uint8_t path[] = { 9, 8, 7 };
  EXPECT_TRUE(mreportPlanAck(&acks, MREPORT_ACK_PATH, node.data(), r2, 3, path, 0, 10));
  p = mreportAckDue(&acks, 10);
  ASSERT_NE(p, nullptr);
  EXPECT_EQ(p->kind, MREPORT_ACK_PATH);
  EXPECT_EQ(p->path_len, 3);
  EXPECT_EQ(hexOf(p->path, 3), "090807");
  p->pending = false;
  uint8_t nine[9] = {0};
  EXPECT_FALSE(mreportPlanAck(&acks, MREPORT_ACK_PATH, node.data(), r2, 9, nine, 0, 10));
  EXPECT_EQ(mreportAckDue(&acks, 100000), nullptr);

  // Across the wrap of millis().
  EXPECT_TRUE(mreportPlanAck(&acks, MREPORT_ACK_ZERO_HOP, node.data(), r1, 0, NULL, 0xFFFFFF00u, 0x200));
  EXPECT_EQ(mreportAckDue(&acks, 0xFFu), nullptr);
  EXPECT_NE(mreportAckDue(&acks, 0x100u), nullptr);
}

// ---- the table ------------------------------------------------------------------------

TEST(MeshReportTable, AHashSizeWithNoHopsIsNoPath) {
  MreportTable t = {};
  bool joined;
  mreportLearn(&t, keyOf(1).data(), 0, true, 0x40, NULL, &joined);
  EXPECT_EQ(mreportBestPath(&t), -1);
}

TEST(MeshReportTable, LearnsNamesAndGivesWay) {
  MreportTable t = {};
  EXPECT_EQ(mreportBest(&t), -1);
  EXPECT_EQ(mreportBestPath(&t), -1);
  bool joined = false;
  EXPECT_EQ(mreportLearn(&t, keyOf(1).data(), -20, false, 0, NULL, &joined), 0);
  EXPECT_TRUE(joined);
  EXPECT_EQ(mreportLearn(&t, keyOf(2).data(), 10, false, 0, NULL, &joined), 1);
  EXPECT_EQ(mreportBest(&t), 1);                       // the stronger, both without first tries
  t.entry[0].first_try = 0x01;
  EXPECT_EQ(mreportBest(&t), 0);                       // a first-try ack counts before SNR
  EXPECT_EQ(mreportBestPath(&t), -1);
  const uint8_t path[] = { 5, 6 };
  EXPECT_EQ(mreportLearn(&t, keyOf(2).data(), 12, true, 2, path, &joined), 1);
  EXPECT_FALSE(joined);
  EXPECT_EQ(t.entry[1].snr, 12);
  EXPECT_EQ(mreportBestPath(&t), 1);
  EXPECT_EQ(hexOf(t.entry[1].path, 2), "0506");
  // A zero-hop ack keeps the path a path ack taught.
  mreportLearn(&t, keyOf(2).data(), 14, false, 0, NULL, &joined);
  EXPECT_EQ(t.entry[1].path_len, 2);
  // A path longer than the table holds is not kept.
  uint8_t nine[9] = {0};
  mreportLearn(&t, keyOf(1).data(), 0, true, 9, nine, &joined);
  EXPECT_EQ(t.entry[0].path_len, 0);

  mreportLearn(&t, keyOf(3).data(), 30, false, 0, NULL, &joined);
  mreportLearn(&t, keyOf(4).data(), -40, false, 0, NULL, &joined);
  EXPECT_EQ(t.count, 4);
  // A fifth replaces the one with the fewest first-try acks, then the weakest SNR: 4.
  EXPECT_EQ(mreportLearn(&t, keyOf(5).data(), 0, false, 0, NULL, &joined), 3);
  EXPECT_TRUE(joined);
  EXPECT_EQ(mreportFind(&t, keyOf(4).data()), -1);
  EXPECT_EQ(mreportFind(&t, keyOf(1).data()), 0);
  EXPECT_EQ(t.entry[3].first_try, 0);
}

TEST(MeshReportTable, ThreeOfFourFirstTriesMakeItReliable) {
  MreportTable t = {};
  bool joined;
  mreportLearn(&t, keyOf(1).data(), 0, false, 0, NULL, &joined);
  mreportLearn(&t, keyOf(2).data(), 0, false, 0, NULL, &joined);
  EXPECT_FALSE(mreportReliable(&t, 0));
  mreportRoundEnd(&t, 0);
  mreportRoundEnd(&t, 0);
  EXPECT_FALSE(mreportReliable(&t, 0));
  mreportRoundEnd(&t, 0);
  EXPECT_EQ(t.entry[0].first_try, 0x07);
  EXPECT_EQ(t.entry[1].first_try, 0x00);
  EXPECT_TRUE(mreportReliable(&t, 0));
  EXPECT_TRUE(mreportReliable(&t, 1));
  EXPECT_FALSE(mreportReliable(&t, 2));                // two rounds in a row needed a fallback
  mreportRoundEnd(&t, 1);
  EXPECT_EQ(t.entry[0].first_try, 0x0E);
  EXPECT_TRUE(mreportReliable(&t, 0));
  mreportRoundEnd(&t, -1);
  EXPECT_EQ(t.entry[0].first_try, 0x0C);                // only the last four
  EXPECT_FALSE(mreportReliable(&t, 0));
}

TEST(MeshReportTable, OnFlashAndBack) {
  EXPECT_EQ(MREPORT_ENTRY_SIZE, 43);
  EXPECT_EQ(MREPORT_TABLE_SIZE, 173);
  MreportTable t = {};
  bool joined;
  const uint8_t path[] = { 7, 8, 9 };
  mreportLearn(&t, keyOf(1).data(), -30, true, 3, path, &joined);
  mreportLearn(&t, keyOf(2).data(), 44, false, 0, NULL, &joined);
  t.entry[1].first_try = 0x0B;
  uint8_t buf[MREPORT_TABLE_SIZE];
  ASSERT_EQ(mreportTableEncode(&t, buf), (size_t)MREPORT_TABLE_SIZE);
  EXPECT_EQ(buf[0], 1);
  MreportTable back;
  ASSERT_TRUE(mreportTableDecode(buf, sizeof(buf), &back));
  ASSERT_EQ(back.count, 2);
  EXPECT_EQ(0, memcmp(&back.entry[0], &t.entry[0], sizeof(MreportObserver)));
  EXPECT_EQ(0, memcmp(&back.entry[1], &t.entry[1], sizeof(MreportObserver)));
  EXPECT_TRUE(mreportReliable(&back, 0));               // so the 12 h rate resumes after a restart

  EXPECT_FALSE(mreportTableDecode(buf, sizeof(buf) - 1, &back));
  EXPECT_EQ(back.count, 0);
  buf[0] = 2;
  EXPECT_FALSE(mreportTableDecode(buf, sizeof(buf), &back));
  EXPECT_FALSE(mreportTableDecode(NULL, 0, &back));
  buf[0] = 1;
  buf[1 + 34] = 0xC1;                                    // a path length no table holds
  ASSERT_TRUE(mreportTableDecode(buf, sizeof(buf), &back));
  EXPECT_EQ(back.entry[0].path_len, 0);
}

// ---- the ladder -----------------------------------------------------------------------

TEST(MeshReportLadder, AFirstTryAckEndsIt) {
  MreportLadder l;
  const uint8_t r[] = { 1, 2, 3, 4 }, other[] = { 4, 3, 2, 1 };
  MreportLadder idle = {};
  EXPECT_EQ(mreportStep(&idle, 0, true), MREPORT_WAIT);
  EXPECT_FALSE(mreportAck(&idle, r, 0));
  mreportStart(&l, r, 1000);
  EXPECT_EQ(mreportStep(&l, 1000, true), MREPORT_SEND_STATE);
  mreportSent(&l, 1000, 0);
  EXPECT_EQ(mreportStep(&l, 8999, true), MREPORT_WAIT);
  EXPECT_FALSE(mreportAck(&l, other, 0));
  EXPECT_TRUE(mreportAck(&l, r, 2));
  EXPECT_EQ(l.first_try_by, 2);
  EXPECT_EQ(mreportStep(&l, 1001, true), MREPORT_DONE);
  EXPECT_FALSE(mreportFellBack(&l));
}

TEST(MeshReportLadder, ThreeTriesThenThePathThenTheFlood) {
  MreportLadder l;
  const uint8_t r[] = { 1, 2, 3, 4 };
  mreportStart(&l, r, 0);
  uint32_t now = 0;
  for (int i = 0; i < 3; i++) {
    ASSERT_EQ(mreportStep(&l, now, true), MREPORT_SEND_STATE) << i;
    mreportSent(&l, now, i == 0 ? 0 : 12000);
    const uint32_t gap = i == 0 ? 8000 : 20000;
    EXPECT_EQ(mreportStep(&l, now + gap - 1, true), MREPORT_WAIT);
    now += gap;
  }
  // An ack on the second try is no first try.
  MreportLadder second = l;
  second.tries = 2;
  mreportAck(&second, r, 1);
  EXPECT_EQ(second.first_try_by, -1);

  EXPECT_EQ(mreportStep(&l, now, true), MREPORT_SEND_DIRECT);
  mreportSent(&l, now, 0);
  EXPECT_EQ(mreportStep(&l, now + 29999, true), MREPORT_WAIT);
  now += 30000;
  EXPECT_EQ(mreportStep(&l, now, true), MREPORT_SEND_FLOOD);
  // The flood could not go: a minute later.
  mreportLater(&l, now);
  EXPECT_EQ(mreportStep(&l, now + 59999, true), MREPORT_WAIT);
  now += 60000;
  EXPECT_EQ(mreportStep(&l, now, true), MREPORT_SEND_FLOOD);
  mreportSent(&l, now, 0);
  EXPECT_EQ(mreportStep(&l, now + 89999, true), MREPORT_WAIT);
  EXPECT_EQ(mreportStep(&l, now + 90000, true), MREPORT_DONE);
  EXPECT_TRUE(mreportFellBack(&l));
  EXPECT_EQ(l.first_try_by, -1);
}

TEST(MeshReportLadder, NoPathGoesStraightToTheFloodAndAPathAckEndsIt) {
  MreportLadder l;
  const uint8_t r[] = { 1, 2, 3, 4 };
  mreportStart(&l, r, 0);
  for (int i = 0; i < 3; i++) {
    ASSERT_EQ(mreportStep(&l, (uint32_t)i * 20000, false), MREPORT_SEND_STATE);
    mreportSent(&l, (uint32_t)i * 20000, 12000);
  }
  EXPECT_EQ(mreportStep(&l, 60000, false), MREPORT_SEND_FLOOD);
  mreportSent(&l, 60000, 0);
  EXPECT_EQ(mreportStep(&l, 61000, false), MREPORT_WAIT);
  EXPECT_TRUE(mreportAck(&l, r, -1));
  EXPECT_EQ(mreportStep(&l, 61000, false), MREPORT_DONE);
  EXPECT_TRUE(mreportFellBack(&l));

  // A path that left the table while its send waited: the flood instead.
  mreportStart(&l, r, 0);
  for (int i = 0; i < 3; i++) mreportSent(&l, 0, 0);
  EXPECT_EQ(mreportStep(&l, 8000, true), MREPORT_SEND_DIRECT);
  mreportLater(&l, 8000);
  EXPECT_EQ(mreportStep(&l, 68000, false), MREPORT_SEND_FLOOD);

  // A zero-hop try that could not go is not counted as one.
  mreportStart(&l, r, 0);
  mreportLater(&l, 0);
  EXPECT_EQ(mreportStep(&l, 60000, false), MREPORT_SEND_STATE);
  EXPECT_EQ(l.tries, 0);
}

TEST(MeshReportLadder, TwelveHoursWhenReliable) {
  EXPECT_EQ(MREPORT_RELIABLE_MS, 43200000UL);
  MeshAliveClock c = {};
  c.ready = true;
  meshAliveSentIn(&c, 0, MREPORT_RELIABLE_MS, 0);
  EXPECT_EQ(c.due_ms, 38880000u);                       // 10.8 h
  meshAliveSentIn(&c, 0, MREPORT_RELIABLE_MS, 2 * (MREPORT_RELIABLE_MS / 10));
  EXPECT_EQ(c.due_ms, 47520000u);                       // 13.2 h
}
