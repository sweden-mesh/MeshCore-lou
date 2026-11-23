// The relay: an Observer node on the command plane sends its owner's mesh-road request to
// a node the broker does not reach, and publishes what comes back (docs/mqtt-control.md,
// "Relaying"). Compiled only with the command plane and the Observer bridge. Every decision
// is in src/helpers/MqttControlV3.h (test/test_mqtt_v3); this is the state and the I/O.
#include "MyMesh.h"

#if defined(WITH_MQTT_COMMAND) && defined(WITH_MQTT_BRIDGE)

// A forward (kind 0x46) arrives on the node's own command topic. It runs nothing here: the
// request inside is the owner's, signed for the target, and the AEAD under K_fwd is the
// whole proof on this side. Before it opens nothing is answered; after, every outcome is.
void Fork::relayForward() {
  Mcc3Forward fwd;
  MqttCtrlResult opened = _mqtt_control.takeForward(&fwd);
  if (opened != MQTTCTRL_OK) {
    _ctrl_unverified++;
    _ctrl_last_unverified = opened;
    debugLine("relay: a forward did not open (%s)", mqttCtrlResultName(opened));
    return;
  }
  _ctrl_last_verified_ms = millis();

  const uint32_t now = _mesh.getRTCClock()->getCurrentTime();
  const RegionEntry* home = _mesh.region_map.getHomeRegion();
  const bool has_home = home != NULL && !home->isWildcard();
  int status = mcc3RelayAdmit(&_relay, _mqtt_control.relayMode(), now, &fwd, _mesh.self_id.pub_key, has_home);
  if (status == MCC3_FWD_SEND) {
    uint32_t air_ms = 0;
    if (sendRelayRequest(fwd, &air_ms)) {
      mcc3RelaySent(&_relay, now, fwd.route, has_home, air_ms);
      debugLine("relay: forward %u sent %s, %u ms on the air", (unsigned)fwd.counter,
                fwd.route == MCC3_ROUTE_DIRECT ? "direct" : "flood", (unsigned)air_ms);
      return;
    }
    status = MCC3_FWD_SEND_FAILED;
  }
  _relay.refused++;
  debugLine("relay: forward %u refused, %s", (unsigned)fwd.counter, mcc3ForwardStatusName(status));
  MESH_DEBUG_PRINTLN("MqttControl: forward %u refused, status %d", (uint32_t)fwd.counter, (uint32_t)status);
  Mcc3ForwardResult result;
  mcc3ForwardResultInit(&result, fwd.counter, (uint8_t)status);
  publishRelayResult(fwd.rid, result);
}

// The request goes out as this node's own anonymous request, so the target answers this
// node: a fresh tag, then the body exactly as a companion would have been handed it.
bool Fork::sendRelayRequest(const Mcc3Forward& fwd, uint32_t* air_ms) {
  mesh::Identity target(fwd.target);
  uint8_t secret[PUB_KEY_SIZE];
  _mesh.self_id.calcSharedSecret(secret, target);

  uint32_t tag;
  _mesh.getRNG()->random((uint8_t *)&tag, sizeof(tag));
  uint8_t data[MCC3_MESH_REQUEST];
  mqttCtrlMeshPutU32(data, tag);
  memcpy(&data[4], fwd.body, fwd.body_len);
  mesh::Packet* pkt = _mesh.createAnonDatagram(PAYLOAD_TYPE_ANON_REQ, _mesh.self_id, target, secret,
                                               data, 4 + fwd.body_len);
  if (pkt == NULL) return false;
  *air_ms = _mesh._radio->getEstAirtimeFor(pkt->getRawLength());

  if (fwd.route == MCC3_ROUTE_DIRECT) {
    _mesh.sendDirect(pkt, fwd.path, fwd.path_len);
  } else {
    // The region home when the owner asked for it and there is one, else the default scope;
    // sendFloodScoped floods un-scoped when that is not set either.
    TransportKey scope = _mesh.default_scope;
    const RegionEntry* home = fwd.route == MCC3_ROUTE_FLOOD_HOME ? _mesh.region_map.getHomeRegion() : NULL;
    if (home != NULL && !home->isWildcard()) _mesh.region_map.getTransportKeysFor(*home, &scope, 1);
    _mesh.sendFloodScoped(scope, pkt, 0, _mesh._prefs.path_hash_mode + 1);
  }

  _relay_wait.target = target;
  memcpy(_relay_wait.secret, secret, PUB_KEY_SIZE);
  memcpy(_relay_wait.rid, fwd.rid, MCC3_RID_LEN);
  _relay_wait.tag = tag;
  _relay_wait.counter = fwd.counter;
  _relay_wait.sent = fwd.route == MCC3_ROUTE_DIRECT ? MCC3_SENT_DIRECT : MCC3_SENT_FLOOD;
  _relay_wait.since = millis();
  return true;
}

void Fork::publishRelayResult(const uint8_t* rid, Mcc3ForwardResult& result) {
  const Mcc3Keys* keys = _mqtt_control.mcc3Keys();
  char topic[MQTTCTRL_MAX_TOPIC + 1];
  if (keys == NULL || !mcc3ResultTopic(rid, topic, sizeof(topic))) return;
  const uint32_t now = _mesh.getRTCClock()->getCurrentTime();
  result.clock = now >= MQTTConnectionPolicy::kSyncedClockEpoch ? now : 0;
  uint8_t nonce[MCC3_NONCE_LEN];
  _mesh.getRNG()->random(nonce, sizeof(nonce));
  static char sealed[MCC3_FWD_RES_B64 + 1];   // loop task only
  size_t n = mcc3BuildForwardResult(keys->fwd, nonce, &result, sealed, sizeof(sealed));
  if (n > 0) _mesh.bridge->publishControlResult(topic, sealed, n, MQTTCTRL_RESULT_QOS);
}

void Fork::loopRelay() {
  if (!_relay.waiting || !mcc3RelayWaitOver(_relay_wait.since, millis())) return;
  _relay.waiting = false;
  debugLine("relay: forward %u, no answer", (unsigned)_relay_wait.counter);
  Mcc3ForwardResult result;
  mcc3ForwardResultInit(&result, _relay_wait.counter, MCC3_FWD_NO_ANSWER);
  result.sent = _relay_wait.sent;
  publishRelayResult(_relay_wait.rid, result);
}

// While a forward waits its target is a peer, so Mesh can decrypt the RESPONSE, or the path
// return carrying one, that a node which never logged in here sends back. A target that is
// a client of this node as well is tried here first: its answer to the forward would else go
// to the client's side, which has no use for it, and the forward would end with no answer.
bool Fork::isRelayPeer(const uint8_t* hash) {
  return _relay.waiting && _relay_wait.target.isHashMatch(hash);
}

// The answer, when it begins with the tag this node wrote: what the target sent after it,
// the SNR it arrived with and the path a path return taught, for the owner's next forward.
void Fork::onRelayResponse(mesh::Packet* packet, uint8_t path_len, const uint8_t* path,
                           const uint8_t* data, size_t len) {
  Mcc3ForwardResult result;
  mcc3ForwardResultInit(&result, _relay_wait.counter, MCC3_FWD_ANSWERED);
  if (!_relay.waiting || !mcc3RelayTakeResponse(_relay_wait.tag, data, len, &result)) return;
  _relay.waiting = false;
  _relay.answered++;
  debugLine("relay: forward %u answered, %u bytes", (unsigned)_relay_wait.counter, (unsigned)len);
  result.sent = _relay_wait.sent;
  result.snr = (int8_t)(packet->getSNR() * 4);
  mcc3ForwardResultPath(&result, path_len, path);
  publishRelayResult(_relay_wait.rid, result);
}

void Fork::describeRelay(char* reply) {
  const uint32_t now = _mesh.getRTCClock()->getCurrentTime();
  const uint32_t left_ms = _relay.budget.air.leftMs(now);
  mqttCtrlRelayDescribe(_mqtt_control.relayMode(), _relay.forwarded, _relay.answered, _relay.refused,
                        _relay.budget.air.cooling(now) ? (uint8_t)MQTTCTRL_AIR_COOL : _relay.budget.air.phase(now), left_ms, _relay.budget.floodsToday(now), reply,
                        MQTTCTRL_MAX_REPLY);
}

#endif
