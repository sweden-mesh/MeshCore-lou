// The announce (docs/mqtt-control.md, "Announcing"): an image without Wi-Fi floods a short
// signed message to its owner inside its region, and any Observer node that hears one hands
// it to the command server. Compiled only with the command plane:
// the sender without the Observer bridge, the catching side with it. Every decision is in
// src/helpers/MeshAliveLogic.h (test/test_mqtt_v3); this is the state and the I/O.
#include "MyMesh.h"

#ifdef FORK_ANNOUNCE

// Same shape as AutoReply's and MqttControl's: the filesystem call differs per platform.
#ifdef FORK_LADDER
#define MREPORT_TABLE_FILE  "/mccobs"

static File openRead(FILESYSTEM* fs, const char* filename) {
  #if defined(RP2040_PLATFORM)
    return fs->open(filename, "r");
  #else
    return fs->open(filename);
  #endif
}

static File openWrite(FILESYSTEM* fs, const char* filename) {
  #if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
    fs->remove(filename);
    return fs->open(filename, FILE_O_WRITE);
  #elif defined(RP2040_PLATFORM)
    return fs->open(filename, "w");
  #else
    return fs->open(filename, "w", true);
  #endif
}
#endif

// Where an announce may go: the region home, else the default scope. With neither there is
// nowhere, since an unscoped flood would cross every county.
bool Fork::announceRegion() {
  const RegionEntry* home = _mesh.region_map.getHomeRegion();
  return (home != NULL && !home->isWildcard()) || !_mesh.default_scope.isNull();
}

bool Fork::announceScope(TransportKey* scope) {
  const RegionEntry* home = _mesh.region_map.getHomeRegion();
  if (home != NULL && !home->isWildcard() && _mesh.region_map.getTransportKeysFor(*home, scope, 1) > 0) {
    return true;
  }
  *scope = _mesh.default_scope;
  return !scope->isNull();
}

// A new announce, signed and sealed to the owner: false without a command key to seal to.
bool Fork::buildAnnounce(uint8_t out[MALIVE_PAYLOAD]) {
  uint8_t owner[PUB_KEY_SIZE];
  if (!mesh::Utils::fromHex(owner, PUB_KEY_SIZE, _mqtt_control.pubkey())) return false;
  uint8_t shared[PUB_KEY_SIZE], sealing[MCC3_KEY_LEN];
  char node_hex[PUB_KEY_SIZE * 2 + 1];
  _mesh.self_id.calcSharedSecret(shared, owner);
  mesh::Utils::toHex(node_hex, _mesh.self_id.pub_key, PUB_KEY_SIZE);
  meshAliveDeriveKey(shared, MALIVE_LABEL, node_hex, sealing);

  const uint32_t now = _mesh.getRTCClock()->getCurrentTime();
  const char* version = strstr(FIRMWARE_VERSION, "lou-");
  MeshAlive a;
  a.boot = _mqtt_control.boots();
  a.sequence = ++_announce_sequence;
  a.uptime = _mesh._ms->getMillis() / 1000;
  a.clock = mqttCtrlClockReported(now, clockNeverSet(now));
  a.last_counter = _mqtt_control.counter();
  a.flags = (FORK_AUTO_REPLY ? MCC3_ALIVE_AUTO_REPLY : 0) | (a.clock != 0 ? MCC3_ALIVE_CLOCK_SET : 0);
  a.battery_mv = board.getBattMilliVolts();
  a.version = version != NULL ? version : FIRMWARE_VERSION;
  a.name = _mesh._prefs.node_name;
  meshAliveBuild(sealing, owner, _mesh.self_id.pub_key, &a,
                 [](void* ctx, uint8_t sig[MCC3_SIG_LEN], const uint8_t* msg, size_t len) {
                   ((const mesh::LocalIdentity*)ctx)->sign(sig, msg, (int)len);
                 }, (void*)&_mesh.self_id, out);
  memset(shared, 0, sizeof(shared));
  memset(sealing, 0, sizeof(sealing));
  return true;
}

// The region flood, counted with the answers the node sends over the mesh. False when that
// budget is spent, there is no scope or no packet to send in.
bool Fork::floodAnnounce(const uint8_t* announce) {
  const uint32_t now = _mesh.getRTCClock()->getCurrentTime();
  TransportKey scope;
  if (!_mqtt_control.meshAirAllows(now) || !announceScope(&scope)) return false;
  mesh::Packet* pkt = _mesh.obtainNewPacket();
  if (pkt == NULL) return false;
  pkt->header = PAYLOAD_TYPE_ANON_REQ << PH_TYPE_SHIFT;
  memcpy(pkt->payload, announce, MALIVE_PAYLOAD);
  pkt->payload_len = MALIVE_PAYLOAD;
  const uint32_t air_ms = _mesh._radio->getEstAirtimeFor(pkt->getRawLength() + MALIVE_TRANSPORT_BYTES);
  _mqtt_control.meshAnswered(now, air_ms);
  _mesh.sendFloodScoped(scope, pkt, 0, _mesh._prefs.path_hash_mode + 1);
  debugLine("announce: %u.%u flooded, %u ms on the air", (unsigned)mqttCtrlMeshU32(announce + MALIVE_AT_BOOT),
            (unsigned)mqttCtrlMeshU32(announce + MALIVE_AT_SEQUENCE), (unsigned)air_ms);
  return true;
}

void Fork::loopAnnounce() {
  const char* key = _mqtt_control.pubkey();
  const bool ready = _mqtt_control.isEnabled() && mqttCtrlOwnerReady(key) == MQTTCTRL_OK && announceRegion();
  const uint32_t now_ms = millis();
  if (meshAliveBecameReady(&_announce, ready, strcmp(key, _announce_key_for) != 0)) {
    StrHelper::strncpy(_announce_key_for, key, sizeof(_announce_key_for));
    meshAliveSoon(&_announce, now_ms, _mesh.getRNG()->nextInt(0, 0x7FFFFFFF));
#ifdef FORK_LADDER
    _report.rung = MREPORT_IDLE;
#endif
  }
#ifdef FORK_LADDER
  if (_report.rung != MREPORT_IDLE) {
    if (ready) loopReport();
    else _report.rung = MREPORT_IDLE;
    return;
  }
  uint8_t* announce = _report_announce;
#else
  uint8_t announce[MALIVE_PAYLOAD];
#endif
  if (!meshAliveDue(&_announce, now_ms)) return;
  // One that finds the answer budget spent is tried again in a minute.
  if (!_mqtt_control.meshAirAllows(_mesh.getRTCClock()->getCurrentTime()) || !buildAnnounce(announce)) {
    meshAliveLater(&_announce, now_ms);
    return;
  }
#ifdef FORK_LADDER
  mreportStart(&_report, mreportId(announce), now_ms);
  loopReport();
#else
  if (!floodAnnounce(announce)) {
    meshAliveLater(&_announce, now_ms);
    return;
  }
  meshAliveSent(&_announce, now_ms, _mesh.getRNG()->nextInt(0, 0x7FFFFFFF));
#endif
}

#ifdef FORK_LADDER

// ---- the ladder (MeshReportLogic.h): zero-hop, then a learnt path, then the flood ----------

void Fork::loadObservers() {
  if (!_mesh._fs->exists(MREPORT_TABLE_FILE)) return;
  File file = openRead(_mesh._fs, MREPORT_TABLE_FILE);
  if (!file) return;
  uint8_t buf[MREPORT_TABLE_SIZE];
  size_t len = file.read(buf, sizeof(buf));
  file.close();
  mreportTableDecode(buf, len, &_observers);
}

void Fork::saveObservers() {
  uint8_t buf[MREPORT_TABLE_SIZE];
  size_t len = mreportTableEncode(&_observers, buf);
  File file = openWrite(_mesh._fs, MREPORT_TABLE_FILE);
  if (file) {
    file.write(buf, len);
    file.close();
  }
  _observers_changed = false;
}

void Fork::loopReport() {
  const uint32_t now_ms = millis();
  const int path_at = mreportBestPath(&_observers);
  const uint8_t action = mreportStep(&_report, now_ms, path_at >= 0);
  if (action == MREPORT_WAIT) return;
  if (action == MREPORT_DONE) {
    endReport(now_ms);
    return;
  }
  bool sent;
  if (action == MREPORT_SEND_STATE) sent = sendReportState();
  else if (action == MREPORT_SEND_DIRECT) sent = sendReportDirect(path_at);
  else sent = floodAnnounce(_report_announce);
  if (sent) mreportSent(&_report, now_ms, _mesh.getRNG()->nextInt(0, 0x7FFFFFFF));
  else mreportLater(&_report, now_ms);
}

// The table moves on, is written when an Observer node joined or the reliable rule turned,
// and the next report is 12 or 23 hours away.
void Fork::endReport(uint32_t now_ms) {
  const bool was = mreportReliable(&_observers, 0);
  mreportRoundEnd(&_observers, _report.first_try_by);
  const bool fell_back = mreportFellBack(&_report);
  _report_fallbacks = fell_back ? (uint8_t)min(_report_fallbacks + 1, 2) : 0;
  if (_observers_changed || mreportReliable(&_observers, 0) != was) saveObservers();
  const bool reliable = mreportReliable(&_observers, _report_fallbacks);
  _report.rung = MREPORT_IDLE;
  meshAliveSentIn(&_announce, now_ms, reliable ? MREPORT_RELIABLE_MS : MALIVE_INTERVAL_MS,
                  _mesh.getRNG()->nextInt(0, 0x7FFFFFFF));
  debugLine("report: %u.%u %s%s, next in %u h", (unsigned)mqttCtrlMeshU32(_report_announce + MALIVE_AT_BOOT),
            (unsigned)mqttCtrlMeshU32(_report_announce + MALIVE_AT_SEQUENCE), _report.acked ? "acked" : "not acked",
            _report.first_try_by >= 0 ? " on the first try" : fell_back ? " after a fallback" : "",
            reliable ? 12u : 23u);
}

bool Fork::sendReportState() {
  const uint32_t now = _mesh.getRTCClock()->getCurrentTime();
  if (!_mqtt_control.meshAirAllows(now)) return false;
  const int best = mreportBest(&_observers);
  uint8_t data[MREPORT_STATE_SIZE];
  mreportBuildState(_report_announce, best >= 0 ? _observers.entry[best].key : NULL, data);
  mesh::Packet* pkt = _mesh.createControlData(data, sizeof(data));
  if (pkt == NULL) return false;
  const uint32_t air_ms = _mesh._radio->getEstAirtimeFor(pkt->getRawLength());
  _mqtt_control.meshAnswered(now, air_ms);
  _mesh.sendZeroHop(pkt);
  debugLine("report: try %u, zero-hop, naming %02X%02X, %u ms on the air", (unsigned)_report.tries + 1, data[1],
            data[2], (unsigned)air_ms);
  return true;
}

bool Fork::sendReportDirect(int at) {
  const uint32_t now = _mesh.getRTCClock()->getCurrentTime();
  if (at < 0 || !_mqtt_control.meshAirAllows(now)) return false;
  const MreportObserver* o = &_observers.entry[at];
  mesh::Packet* pkt = _mesh.obtainNewPacket();
  if (pkt == NULL) return false;
  pkt->header = PAYLOAD_TYPE_ANON_REQ << PH_TYPE_SHIFT;
  pkt->payload_len = mreportBuildDirect(_report_announce, o->key, o->path_len, o->path, pkt->payload);
  const uint32_t air_ms = _mesh._radio->getEstAirtimeFor(pkt->payload_len + 2 + mreportPathBytes(o->path_len));
  _mqtt_control.meshAnswered(now, air_ms);
  _mesh.sendDirect(pkt, o->path, o->path_len);
  debugLine("report: along a path of %u to %02X%02X%02X%02X, %u ms on the air", (unsigned)(o->path_len & 63),
            o->key[0], o->key[1], o->key[2], o->key[3], (unsigned)air_ms);
  return true;
}

// An ack, zero-hop, from an Observer node that heard this report.
bool Fork::onControlData(mesh::Packet* pkt) {
  const uint8_t* p = pkt->payload;
  if (!mreportIsAck(p, pkt->payload_len)) return false;
  if (_report.rung != MREPORT_IDLE && memcmp(&p[1], _mesh.self_id.pub_key, 4) == 0
      && memcmp(&p[5], _report.report, MREPORT_ID_LEN) == 0) {
    bool joined;
    const int at = mreportLearn(&_observers, &p[9], (int8_t)(pkt->getSNR() * 4), false, 0, NULL, &joined);
    _observers_changed |= joined;
    mreportAck(&_report, &p[5], at);
    debugLine("report: acked by %02X%02X%02X%02X%s", p[9], p[10], p[11], p[12], joined ? ", new" : "");
  }
  return true;
}

// A path ack, the end of the path an Observer node sent it back along: this node's, and
// nobody else reads it.
bool Fork::onRecvPacket(const mesh::Packet* pkt) {
  const uint8_t* p = pkt->payload;
  if (pkt->getPayloadType() != PAYLOAD_TYPE_ANON_REQ || !pkt->isRouteDirect() || pkt->getPathHashCount() != 0
      || !mreportIsPathAck(p, pkt->payload_len) || p[0] != _mesh.self_id.pub_key[0]) return false;
  if (_report.rung != MREPORT_IDLE && memcmp(&p[34], _report.report, MREPORT_ID_LEN) == 0) {
    bool joined;
    mreportLearn(&_observers, &p[1], (int8_t)(pkt->getSNR() * 4), true, p[38], &p[39], &joined);
    _observers_changed = true;
    mreportAck(&_report, &p[34], -1);
    debugLine("report: a path of %u learnt from %02X%02X%02X%02X", (unsigned)(p[38] & 63), p[1], p[2], p[3], p[4]);
  }
  return true;
}

#endif
#endif

#if defined(WITH_MQTT_COMMAND) && defined(WITH_MQTT_BRIDGE)

// Whatever road an announce came by: one signed by the node it names goes to the command
// server, whoever owns the node, once in ten minutes. False for one that is not, which is
// dropped in silence.
bool Fork::takeAnnounce(const uint8_t* announce, int8_t snr, uint8_t hops, uint8_t via) {
  mesh::Identity node(&announce[1]);
  if (!meshAliveSignatureOk(announce, [](void* ctx, const uint8_t sig[MCC3_SIG_LEN], const uint8_t* msg, size_t len) {
        return ((const mesh::Identity*)ctx)->verify(sig, msg, (int)len);
      }, (void*)&node)) return false;
  if (!meshAliveRecentFresh(&_seen_recent, announce, _mesh._ms->getMillis() / 1000)) return true;
  uint8_t item[MALIVE_SEEN_SIZE];
  meshAliveBuildSeen(announce, snr, hops, via, item);
  meshAliveSeenPush(&_seen, item);
  debugLine("seen: an announce of %02X%02X%02X%02X, %u.%u, %u hop(s), via %u, %u waiting", announce[1],
            announce[2], announce[3], announce[4], (unsigned)mqttCtrlMeshU32(announce + MALIVE_AT_BOOT),
            (unsigned)mqttCtrlMeshU32(announce + MALIVE_AT_SEQUENCE), (unsigned)hops, (unsigned)via,
            (unsigned)_seen.count);
  return true;
}

// Every packet heard, before Mesh has looked at it. A flooded announce is forwarded
// afterwards like any other flood, and the node that flooded it is acked by the Observer node
// that heard it first and closest: zero-hop when it heard the node itself, else along the
// flood's path reversed, which teaches the node that path. A report sent along a path ends
// here when it names this node, and is acked back along it. Another node's path ack on its
// way cancels this node's.
bool Fork::onRecvPacket(const mesh::Packet* pkt) {
  const uint8_t* p = pkt->payload;
  if (pkt->getPayloadType() != PAYLOAD_TYPE_ANON_REQ) return false;
  if (mreportIsPathAck(p, pkt->payload_len)) {
    mreportAckHeard(&_acks, &p[34]);
    return false;
  }
  if (!_mqtt_control.isEnabled()) return false;
  const int8_t snr = (int8_t)(pkt->getSNR() * 4);
  if (pkt->isRouteFlood()) {
    if (!meshAliveIsAnnounce(p, pkt->payload_len)) return false;
    const uint8_t hops = pkt->getPathHashCount();
    if (takeAnnounce(p, snr, hops, MALIVE_VIA_FLOOD) && mreportFloodAckable(pkt->path_len)) {
      mreportPlanAck(&_acks, hops == 0 ? MREPORT_ACK_ZERO_HOP : MREPORT_ACK_PATH, &p[1], mreportId(p), pkt->path_len,
                     pkt->path, millis(), mreportFloodAckDelay(hops, snr, _mesh.getRNG()->nextInt(0, 0x7FFFFFFF)));
    }
    return false;
  }
  if (pkt->getPathHashCount() != 0 || !mreportIsDirectFor(p, pkt->payload_len, _mesh.self_id.pub_key)) return false;
  const uint8_t path_len = p[MALIVE_PAYLOAD + 2];
  if (takeAnnounce(p, snr, path_len & 63, MALIVE_VIA_DIRECT)) {
    mreportPlanAck(&_acks, MREPORT_ACK_PATH, &p[1], mreportId(p), path_len, &p[MREPORT_DIRECT_HEAD], millis(),
                   mreportStateAckDelay(1, _mesh.getRNG()->nextInt(0, 0x7FFFFFFF)));
  }
  return true;
}

// A zero-hop report: its announce goes to the server as a flood's does, and the node is
// acked by whoever is named, else by whoever heard it, unless another's ack is heard first.
// Another node's ack only cancels this node's. Acked whether or not the announce was a copy:
// a node that tries again did not hear the first ack.
bool Fork::onControlData(mesh::Packet* pkt) {
  if (mreportIsAck(pkt->payload, pkt->payload_len)) {
    mreportAckHeard(&_acks, &pkt->payload[5]);
    return true;
  }
  uint8_t announce[MALIVE_PAYLOAD];
  if (!mreportStateAnnounce(pkt->payload, pkt->payload_len, announce)) return false;
  if (!_mqtt_control.isEnabled()
      || !takeAnnounce(announce, (int8_t)(pkt->getSNR() * 4), 0, MALIVE_VIA_ZERO_HOP)) return true;
  const int named = mreportStateNamed(pkt->payload, _mesh.self_id.pub_key);
  mreportPlanAck(&_acks, MREPORT_ACK_ZERO_HOP, &announce[1], mreportId(announce), 0, NULL, millis(),
                 mreportStateAckDelay(named, _mesh.getRNG()->nextInt(0, 0x7FFFFFFF)));
  return true;
}

// An ack goes when it is due, counted with the node's answers over the mesh; one the budget
// has no room for is not sent at all, since a late ack is no ack.
void Fork::loopAcks() {
  MreportAckPlan* p = mreportAckDue(&_acks, millis());
  if (p == NULL) return;
  p->pending = false;
  const uint32_t now = _mesh.getRTCClock()->getCurrentTime();
  if (!_mqtt_control.meshAirAllows(now)) return;
  mesh::Packet* pkt;
  if (p->kind == MREPORT_ACK_ZERO_HOP) {
    uint8_t data[MREPORT_ACK_SIZE];
    mreportBuildAck(p->node_key, p->report, _mesh.self_id.pub_key, data);
    pkt = _mesh.createControlData(data, sizeof(data));
  } else {
    pkt = _mesh.obtainNewPacket();
    if (pkt != NULL) {
      pkt->header = PAYLOAD_TYPE_ANON_REQ << PH_TYPE_SHIFT;
      mreportBuildPathAck(p->node_key, _mesh.self_id.pub_key, p->report, p->path_len, p->path, pkt->payload);
      pkt->payload_len = MREPORT_PATH_ACK_SIZE;
    }
  }
  if (pkt == NULL) return;
  const int path_bytes = mreportPathBytes(p->path_len);
  const uint32_t air_ms = _mesh._radio->getEstAirtimeFor(pkt->payload_len + 2 + path_bytes);
  _mqtt_control.meshAnswered(now, air_ms);
  if (p->kind == MREPORT_ACK_ZERO_HOP) {
    _mesh.sendZeroHop(pkt);
  } else {
    uint8_t back[MREPORT_ACK_PATH_MAX];
    mreportReversePath(p->path, p->path_len, back);
    _mesh.sendDirect(pkt, back, p->path_len);
  }
  debugLine("report: %02X%02X%02X%02X acked, %s, %u ms on the air", p->node_key[0], p->node_key[1], p->node_key[2],
            p->node_key[3], p->kind == MREPORT_ACK_ZERO_HOP ? "zero-hop" : "along its path", (unsigned)air_ms);
}

// One publish at a time, a gap between them, not retained: the server keeps what it needs.
void Fork::loopSeen() {
  const uint8_t* item = meshAliveSeenFront(&_seen);
  if (item == NULL || _alive_topic[0] == 0 || !_mqtt_control.isEnabled() || !_mesh.bridge->controlSlotConnected()) {
    return;
  }
  const uint32_t now_ms = millis();
  if (!meshAliveSeenDue(_seen_published, _seen_published_ms, now_ms)) return;
  _seen_published = true;
  _seen_published_ms = now_ms;

  char node_hex[PUB_KEY_SIZE * 2 + 1], topic[MQTTCTRL_MAX_TOPIC + 1], payload[MALIVE_SEEN_B64 + 1];
  mesh::Utils::toHex(node_hex, _mesh.self_id.pub_key, PUB_KEY_SIZE);
  meshAliveSeenTopic(node_hex, topic, sizeof(topic));
  size_t n = mqttV2B64Encode(item, MALIVE_SEEN_SIZE, payload, sizeof(payload));
  const bool sent = _mesh.bridge->publishControlResult(topic, payload, n, MQTTCTRL_RESULT_QOS);
  debugLine("seen: %02X%02X%02X%02X published%s", item[1], item[2], item[3], item[4], sent ? "" : ", not sent");
  if (sent) meshAliveSeenPop(&_seen);
}

#endif
