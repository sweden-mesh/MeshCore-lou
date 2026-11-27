// The announce (docs/mqtt-control.md, "Announcing"): an image without Wi-Fi floods a short
// sealed message to its owner inside its region, and an Observer node of the same owner
// that hears one publishes it to the command server. Compiled only with the command plane:
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
  meshAliveBuild(sealing, owner, _mesh.self_id.pub_key, &a, pkt->payload);
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

// Every packet heard, before Mesh has looked at it: an announce made for this node's command
// key goes into the table, and is forwarded afterwards like any other flood. The node cannot
// open one, so the owner's tool is what tells a real one from a forgery.
void Fork::onRecvPacket(const mesh::Packet* pkt) {
  if (pkt->getPayloadType() != PAYLOAD_TYPE_ANON_REQ || !pkt->isRouteFlood()
      || !meshAliveIsAnnounce(pkt->payload, pkt->payload_len) || !_mqtt_control.isEnabled()) return;
  const char* key = _mqtt_control.pubkey();
  uint8_t owner[PUB_KEY_SIZE];
  if (mqttCtrlOwnerReady(key) != MQTTCTRL_OK || !mesh::Utils::fromHex(owner, PUB_KEY_SIZE, key)) return;

  const uint32_t now = _mesh.getRTCClock()->getCurrentTime();
  int slot = -1;
  const MeshAliveVerdict verdict = meshAliveTake(&_heard, owner, pkt->payload, pkt->payload_len,
                                                 mqttCtrlClockReported(now, clockNeverSet(now)),
                                                 (int8_t)(pkt->getSNR() * 4), pkt->getPathHashCount(),
                                                 _mesh._ms->getMillis() / 1000, &slot);
  if (meshAliveKept(verdict)) {
    _heard_dirty |= (uint16_t)(1u << slot);
    debugLine("heard: an announce of %02X%02X%02X%02X, %u.%u, %u hop(s), slot %d%s", pkt->payload[1],
              pkt->payload[2], pkt->payload[3], pkt->payload[4], (unsigned)meshAliveEntryBoot(&_heard.entry[slot]),
              (unsigned)meshAliveEntrySequence(&_heard.entry[slot]), (unsigned)pkt->getPathHashCount(), slot,
              verdict == MALIVE_ADDED ? ", new" : "");
  } else if (verdict == MALIVE_LIMITED) {
    debugLine("heard: an announce of a new node not kept, %d were admitted this hour", MALIVE_NEW_MAX);
  } else if (verdict == MALIVE_OTHER_OWNER) {
    debugLine("heard: an announce for another owner");
  }
}

// Each entry is a retained message of its own on mcc/heard/<this node's key>/<slot>, sealed
// to the owner. One publish at a time, a gap between them. A changed command key empties
// the table and every slot: what was heard was another owner's, sealed to that owner.
void Fork::loopHeard() {
  const char* key = _mqtt_control.pubkey();
  if (strcmp(key, _heard_key_for) != 0) {
    if (_heard_key_for[0] != 0) {
      _heard = MeshAliveTable();
      _heard_dirty = 0xFFFF;
    }
    StrHelper::strncpy(_heard_key_for, key, sizeof(_heard_key_for));
  }
  if (_alive_topic[0] == 0 || !_mqtt_control.isEnabled() || !_mesh.bridge->controlSlotConnected()) return;
  const uint32_t now_ms = millis();
  const int slot = meshAliveNextPublish(_heard_dirty, _heard_published, _heard_published_ms, now_ms);
  if (slot < 0) return;
  _heard_published = true;
  _heard_published_ms = now_ms;

  char node_hex[PUB_KEY_SIZE * 2 + 1], topic[MQTTCTRL_MAX_TOPIC + 1];
  mesh::Utils::toHex(node_hex, _mesh.self_id.pub_key, PUB_KEY_SIZE);
  meshAliveHeardTopic(node_hex, slot, topic, sizeof(topic));
  const MeshAliveEntry* e = &_heard.entry[slot];
  bool sent;
  if (e->used) {
    uint8_t owner[PUB_KEY_SIZE], shared[PUB_KEY_SIZE], sealing[MCC3_KEY_LEN], nonce[MCC3_NONCE_LEN];
    mesh::Utils::fromHex(owner, PUB_KEY_SIZE, key);
    _mesh.self_id.calcSharedSecret(shared, owner);
    meshAliveDeriveKey(shared, MALIVE_HEARD_LABEL, node_hex, sealing);
    _mesh.getRNG()->random(nonce, sizeof(nonce));
    char payload[MALIVE_HEARD_B64 + 1];
    size_t n = meshAliveBuildHeard(sealing, nonce, e, payload, sizeof(payload));
    memset(shared, 0, sizeof(shared));
    memset(sealing, 0, sizeof(sealing));
    sent = _mesh.bridge->publishControlRetained(topic, payload, n, MQTTCTRL_RESULT_QOS);
  } else {
    sent = _mesh.bridge->clearControlRetained(topic, MQTTCTRL_RESULT_QOS);
  }
  if (sent) _heard_dirty &= (uint16_t)~(1u << slot);
  debugLine("heard: slot %d %s%s", slot, e->used ? "published" : "emptied", sent ? "" : ", not sent");
}

#endif
