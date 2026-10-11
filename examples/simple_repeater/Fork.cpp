#include "MyMesh.h"

void Fork::begin(FILESYSTEM* fs) {
#ifdef WITH_AUTO_REPLY
  _auto_reply.begin(fs);
#endif
#ifdef WITH_MQTT_BRIDGE
  _mesh.mqtt_control.begin(fs);
#endif
}

#ifdef WITH_MQTT_BRIDGE
void Fork::attachBridge(MQTTBridge* bridge) {
  // Each slot's client id ends in a tag only this node can compute: a signature is
  // deterministic, so the same key gives the same tag on every boot.
  static const char tag_label[] = "mqtt client id";
  uint8_t tag_sig[SIGNATURE_SIZE];
  _mesh.self_id.sign(tag_sig, (const uint8_t *) tag_label, sizeof(tag_label) - 1);
  char tag[MQTT_SLOT_CLIENT_TAG_LEN + 1];
  mesh::Utils::toHex(tag, tag_sig, MQTT_SLOT_CLIENT_TAG_LEN / 2);
  bridge->setClientIdTag(tag);

  _mesh.setupMqttControl(bridge);
}
#endif

void Fork::loop() {
#ifdef WITH_MQTT_BRIDGE
  _mesh.loopMqttControl();
  _mesh.loopMqttPing();
#endif
#if defined(WITH_MQTT_BRIDGE) && defined(OTA_MANIFEST_BASE)
  _mesh.autoOtaTick();
#endif
}

bool Fork::handleCommand(uint32_t sender_timestamp, char* command, char* reply) {
#ifdef WITH_MQTT_BRIDGE
  if (strcmp(command, "get ota") == 0) {
#if defined(OTA_MANIFEST_BASE)
    sprintf(reply, "> channel %s, auto %s/%uh, last check %s, next %s",
            OTA_MANIFEST_BASE, _mesh.mqtt_control.otaAuto() ? "on" : "off",
            (unsigned)_mesh.mqtt_control.otaCheckHours(),
            _mesh._ota_last_result[0] ? _mesh._ota_last_result : "(none yet)",
            _mesh._ota_auto_start_at ? "scheduled" : "-");
#else
    strcpy(reply, "> no channel in this build (built without build.sh)");
#endif
    return true;
  }
  MqttControl& control = _mesh.mqtt_control;
  if (strcmp(command, "set mqtt.cmd on") == 0 && control.slot() == 0) {
    _mesh.autoSetupMqttControl(reply);
    return true;
  }
  if (strcmp(command, "mqtt.cmd ping") == 0) {
    _mesh.pingMqttControl(reply);
    return true;
  }
  if (strcmp(command, "get mqtt.cmd") == 0) {
    _mesh.describeMqttControl(reply);
    return true;
  }
  if (mqttCtrlTouchesSlot(command, control.slot())) {
    sprintf(reply, "Err - slot %d is the command plane's: move it with set mqtt.cmd.slot first (not over the plane)",
            control.slot());
    return true;
  }
  if (control.handleCommand(sender_timestamp, RUNTIME_MQTT_SLOTS, command, reply)) return true;
#endif

#ifdef WITH_AUTO_REPLY
  if (handleAutoReplyCommand(command, reply)) return true;
#endif
  return false;
}
