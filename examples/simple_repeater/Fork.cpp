#include "MyMesh.h"
#include <helpers/ForkText.h>

void Fork::begin(FILESYSTEM* fs) {
#ifdef WITH_MQTT_BRIDGE
  otaBegin();
#endif
#ifdef WITH_AUTO_REPLY
  _auto_reply.begin(fs, &_mesh.region_map);
#endif
#ifdef WITH_MQTT_COMMAND
  _mqtt_control.begin(fs);
#endif
#ifdef WITH_MQTT_BRIDGE
  // Before the slot is mended: a plane switched off here is one the mending leaves alone.
  settleArrival();
#ifdef WITH_MQTT_COMMAND
  repairMqttControlSlot();
#endif
#endif
}

#ifdef WITH_MQTT_BRIDGE
void Fork::attachBridge(MQTTBridge* bridge) {
#ifdef WITH_MQTT_COMMAND
  // Each slot's client id ends in a tag only this node can compute: a signature is
  // deterministic, so the same key gives the same tag on every boot. Only with the
  // command plane, which is what puts two slots of one node on one broker; without
  // it every slot keeps the Observer's own client id (TODO 22a ruling 18).
  static const char tag_label[] = "mqtt client id";
  uint8_t tag_sig[SIGNATURE_SIZE];
  _mesh.self_id.sign(tag_sig, (const uint8_t *) tag_label, sizeof(tag_label) - 1);
  char tag[MQTT_SLOT_CLIENT_TAG_LEN + 1];
  mesh::Utils::toHex(tag, tag_sig, MQTT_SLOT_CLIENT_TAG_LEN / 2);
  bridge->setClientIdTag(tag);

  setupMqttControl(bridge);
#endif
}
#endif

const char* Fork::observerIata() const {
#ifdef WITH_MQTT_BRIDGE
  return _mesh._cli.getObserverPrefs()->mqtt_iata;
#else
  return NULL;
#endif
}

void Fork::loop() {
#ifdef WITH_MQTT_BRIDGE
#ifdef WITH_MQTT_COMMAND
  loopMqttControl();
  loopMqttPing();
#endif
  otaLoop();
#endif
}

#if defined(WITH_AUTO_REPLY) || defined(WITH_MQTT_COMMAND)
bool Fork::onAnonRequest(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender,
                         const uint8_t* data, size_t len) {
#ifdef WITH_MQTT_COMMAND
  if (onMeshCommand(packet, secret, sender, data, len)) return true;
#endif
#ifdef WITH_AUTO_REPLY
  if (onPrivateTest(packet, secret, sender, data, len)) return true;
#endif
  return false;
}
#endif

bool Fork::loginRefused(const mesh::Identity& sender) {
  return loginThrottled(&_logins, sender.pub_key, _mesh._ms->getMillis());
}

void Fork::loginFailed(const mesh::Identity& sender) {
  loginThrottleFailed(&_logins, sender.pub_key, _mesh._ms->getMillis());
}

void Fork::loginPassed(const mesh::Identity& sender) {
  loginThrottleClear(&_logins, sender.pub_key);
}

bool Fork::handleCommand(uint32_t sender_timestamp, char* command, char* reply, bool mesh_admin) {
#ifdef WITH_WEBCONFIG
  const bool network_up = activeNetworkLink().isConnected();
#else
  const bool network_up = false;
#endif
#ifdef NRF52_PLATFORM
  const bool ble_dfu = true;
#else
  const bool ble_dfu = false;
#endif
  if (sender_timestamp != 0 && forkOpensBoardToRange(command, network_up, ble_dfu)) {
    strcpy(reply, "Err - serial only: it opens the board to anyone in Wi-Fi/BLE range");
    return true;
  }
#ifdef WITH_MQTT_BRIDGE
  if (handleOtaCommand(command, reply)) return true;
#endif
#ifdef WITH_MQTT_COMMAND
  if (handleMqttCommand(sender_timestamp, mesh_admin, command, reply)) return true;
#endif
#ifdef WITH_AUTO_REPLY
  if (handleAutoReplyCommand(sender_timestamp, command, reply)) return true;
#endif
  return false;
}
