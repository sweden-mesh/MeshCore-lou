#include "MyMesh.h"

void Fork::begin(FILESYSTEM* fs) {
#ifdef WITH_MQTT_BRIDGE
  otaBegin();
#endif
#ifdef WITH_AUTO_REPLY
  _auto_reply.begin(fs);
#endif
#ifdef WITH_MQTT_COMMAND
  _mqtt_control.begin(fs);
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
#ifdef WITH_MQTT_COMMAND
  loopMqttControl();
  loopMqttPing();
#endif
#ifdef WITH_MQTT_BRIDGE
  otaLoop();
#endif
}

bool Fork::handleCommand(uint32_t sender_timestamp, char* command, char* reply) {
#ifdef WITH_MQTT_BRIDGE
  if (handleOtaCommand(command, reply)) return true;
#endif
#ifdef WITH_MQTT_COMMAND
  if (handleMqttCommand(sender_timestamp, command, reply)) return true;
#endif
#ifdef WITH_AUTO_REPLY
  if (handleAutoReplyCommand(command, reply)) return true;
#endif
  return false;
}
