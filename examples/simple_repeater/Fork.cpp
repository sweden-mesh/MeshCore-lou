#include "MyMesh.h"
#include <helpers/OtaAutoLogic.h>

void Fork::begin(FILESYSTEM* fs) {
#ifdef WITH_AUTO_REPLY
  _auto_reply.begin(fs);
#endif
#ifdef WITH_MQTT_COMMAND
  _mqtt_control.begin(fs);
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

#ifdef WITH_MQTT_COMMAND
  setupMqttControl(bridge);
#endif
}
#endif

void Fork::loop() {
#ifdef WITH_MQTT_COMMAND
  loopMqttControl();
  loopMqttPing();
#endif
#if defined(WITH_MQTT_COMMAND) && defined(OTA_MANIFEST_BASE)
  _mesh.autoOtaTick();
#endif
}

bool Fork::handleCommand(uint32_t sender_timestamp, char* command, char* reply) {
#ifdef WITH_MQTT_BRIDGE
  if (strcmp(command, "get ota") == 0) {
#if defined(OTA_MANIFEST_BASE)
#ifdef WITH_MQTT_COMMAND
    const bool ota_auto = _mqtt_control.otaAuto();
    const unsigned ota_hours = _mqtt_control.otaCheckHours();
#else
    const bool ota_auto = false;
    const unsigned ota_hours = OTA_AUTO_CHECK_HOURS_DEFAULT;
#endif
    sprintf(reply, "> channel %s, auto %s/%uh, last check %s, next %s",
            OTA_MANIFEST_BASE, ota_auto ? "on" : "off", ota_hours,
            _mesh._ota_last_result[0] ? _mesh._ota_last_result : "(none yet)",
            _mesh._ota_auto_start_at ? "scheduled" : "-");
#else
    strcpy(reply, "> no channel in this build (built without build.sh)");
#endif
    return true;
  }
#endif
#ifdef WITH_MQTT_COMMAND
  if (handleMqttCommand(sender_timestamp, command, reply)) return true;
#endif

#ifdef WITH_AUTO_REPLY
  if (handleAutoReplyCommand(command, reply)) return true;
#endif
  return false;
}
