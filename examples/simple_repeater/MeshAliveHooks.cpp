// The announce (docs/mqtt-control.md, "Announcing"): an image without Wi-Fi floods a short
// signed message to its owner inside its region, and any Observer node that hears one hands
// it to the command server. Compiled only with the command plane:
// the sender without the Observer bridge, the catching side with it. Every decision is in
// src/helpers/MeshAliveLogic.h (test/test_mqtt_v3); this is the state and the I/O.
#include "MyMesh.h"

#ifdef FORK_ANNOUNCE

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

void Fork::loopAnnounce() {
  const char* key = _mqtt_control.pubkey();
  const bool ready = _mqtt_control.isEnabled() && mqttCtrlOwnerReady(key) == MQTTCTRL_OK && announceRegion();
  const uint32_t now_ms = millis();
  if (meshAliveBecameReady(&_announce, ready, strcmp(key, _announce_key_for) != 0)) {
    StrHelper::strncpy(_announce_key_for, key, sizeof(_announce_key_for));
    meshAliveSoon(&_announce, now_ms, _mesh.getRNG()->nextInt(0, 0x7FFFFFFF));
  }
  if (!meshAliveDue(&_announce, now_ms)) return;
  // Counted with the answers the node sends over the mesh: one that finds that budget spent,
  // or no packet to send in, is tried again in a minute.
  const uint32_t now = _mesh.getRTCClock()->getCurrentTime();
  uint8_t owner[PUB_KEY_SIZE];
  TransportKey scope;
  mesh::Packet* pkt = NULL;
  if (_mqtt_control.meshAirAllows(now) && mesh::Utils::fromHex(owner, PUB_KEY_SIZE, key) && announceScope(&scope)) {
    pkt = _mesh.obtainNewPacket();
  }
  if (pkt == NULL) {
    meshAliveLater(&_announce, now_ms);
    return;
  }

  uint8_t shared[PUB_KEY_SIZE], sealing[MCC3_KEY_LEN];
  char node_hex[PUB_KEY_SIZE * 2 + 1];
  _mesh.self_id.calcSharedSecret(shared, owner);
  mesh::Utils::toHex(node_hex, _mesh.self_id.pub_key, PUB_KEY_SIZE);
  meshAliveDeriveKey(shared, MALIVE_LABEL, node_hex, sealing);

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
  pkt->header = PAYLOAD_TYPE_ANON_REQ << PH_TYPE_SHIFT;
  meshAliveBuild(sealing, owner, _mesh.self_id.pub_key, &a,
                 [](void* ctx, uint8_t sig[MCC3_SIG_LEN], const uint8_t* msg, size_t len) {
                   ((const mesh::LocalIdentity*)ctx)->sign(sig, msg, (int)len);
                 }, (void*)&_mesh.self_id, pkt->payload);
  pkt->payload_len = MALIVE_PAYLOAD;
  memset(shared, 0, sizeof(shared));
  memset(sealing, 0, sizeof(sealing));

  const uint32_t air_ms = _mesh._radio->getEstAirtimeFor(pkt->getRawLength() + MALIVE_TRANSPORT_BYTES);
  _mqtt_control.meshAnswered(now, air_ms);
  _mesh.sendFloodScoped(scope, pkt, 0, _mesh._prefs.path_hash_mode + 1);
  meshAliveSent(&_announce, now_ms, _mesh.getRNG()->nextInt(0, 0x7FFFFFFF));
  debugLine("announce: %u.%u sent, %u ms on the air", (unsigned)a.boot, (unsigned)a.sequence, (unsigned)air_ms);
}

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
// afterwards like any other flood.
void Fork::onRecvPacket(const mesh::Packet* pkt) {
  if (pkt->getPayloadType() != PAYLOAD_TYPE_ANON_REQ || !pkt->isRouteFlood()
      || !meshAliveIsAnnounce(pkt->payload, pkt->payload_len) || !_mqtt_control.isEnabled()) return;
  takeAnnounce(pkt->payload, (int8_t)(pkt->getSNR() * 4), pkt->getPathHashCount(), MALIVE_VIA_FLOOD);
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
