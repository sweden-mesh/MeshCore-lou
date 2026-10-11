// The command plane's side of the repeater: its topics on the bridge, the queue a
// signed command waits in, the result it publishes, and `mqtt.cmd ping`. Compiled
// only with WITH_MQTT_COMMAND; MyMesh reaches it through Fork.
#include "MyMesh.h"

#ifdef WITH_MQTT_COMMAND

// `set mqtt.cmd on` with no slot configured, the one line a fresh node needs
// (operator decision 2026-10-08): take a free slot (mqttCtrlPickSlot says which:
// slot 2 first on a board that runs two at once, else 3 up), give it the
// `mccontrol` preset with packets filtered off (status and neighbours still go,
// which the plane's statistics use), point the control plane at it, enable, and
// say what was done. Slot 1 and the active-slot cap are not touched: when the cap
// is reached the reply names the cure and nothing is set.
void Fork::autoSetupMqttControl(char* reply) {
  MQTTPrefs* obs = _mesh._cli.getObserverPrefs();
  const char* presets[RUNTIME_MQTT_SLOTS];
  for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) presets[i] = obs->mqtt_slot_preset[i];
  const bool two_slot_board = MQTTBridge::getMaxActiveSlots() <= 2;
  int idx = mqttCtrlPickSlot(presets, RUNTIME_MQTT_SLOTS, two_slot_board);
  if (idx < 0) {
    strcpy(reply, "Err - no free slot 3-6: set mqttN.preset none on one, or set mqtt.cmd.slot <n>");
    return;
  }
  // Taking slot 2 from analyzer-eu frees the position it takes; anything else needs room.
  const bool was_analyzer = strcasecmp(presets[idx], MQTTCTRL_SLOT2_DEFAULT) == 0;
  if (!was_analyzer && _mesh.bridge != NULL && !_mesh.bridge->hasRoomForAnotherSlot()) {
    sprintf(reply, "Err - this board runs %d slots at once and all are taken: turn one off "
                   "(set mqtt2.preset none) and send 'set mqtt.cmd on' again",
            MQTTBridge::getMaxActiveSlots());
    return;
  }
  const MQTTPresetDef* p = findMQTTPreset("mccontrol");
  if (p == NULL) { strcpy(reply, "Err - no mccontrol preset in this build"); return; }
  StrHelper::strncpy(obs->mqtt_slot_preset[idx], "mccontrol", sizeof(obs->mqtt_slot_preset[idx]));
  obs->mqtt_slot_packet_filter[idx] = 0;        // packets off; status and neighbours still publish
  _mesh._cli.savePrefs(_mesh._fs);
  _mqtt_control.setSlotAndEnable((uint8_t)(idx + 1));
  sprintf(reply, "OK - slot %d%s, mccontrol (%s), packets off; reboot to apply", idx + 1,
          was_analyzer ? " (was analyzer-eu, now off)" : "", p->server_url);
}

// Build this node's control topics once and hand the bridge a list it can
// re-subscribe from on every reconnect. Nothing is allocated per message or per
// reconnect: docs/mbedtls-tls-footprint.md records a measured largest-free-block
// ratchet on this exact path, so the buffers are members and stay that way.
void Fork::setupMqttControl(MQTTBridge* bridge) {
  const char* iata = observerIata();
  if (iata == NULL || iata[0] == 0) return;      // no region, no control plane
  if (_mqtt_control.slot() == 0) return;         // no slot to listen on

  char node_hex[PUB_KEY_SIZE * 2 + 1];
  mesh::Utils::toHex(node_hex, _mesh.self_id.pub_key, PUB_KEY_SIZE);   // the whole key names the node (2026-10-08)

  if (!MqttControl::buildTopic(iata, node_hex, _ctrl_topic, sizeof(_ctrl_topic))) return;
  if (!MqttControl::buildBroadcastTopic(iata, _ctrl_broadcast, sizeof(_ctrl_broadcast))) return;
  MqttControl::buildResultTopic(iata, node_hex, _ctrl_result, sizeof(_ctrl_result));

  mqttCtrlBuildTopic(iata, node_hex, "ping", _ctrl_ping_topic, sizeof(_ctrl_ping_topic));

  _ctrl_topics[0] = _ctrl_topic;
  _ctrl_topics[1] = _ctrl_broadcast;
  refreshMqttControlV2Key();
  bridge->setControlSink(&_control_link, _ctrl_topics, 2, _mqtt_control.slot() - 1);
}

// `mqtt.cmd ping`: the broker echoes a ping on our own /ping as a pong on our own /cmd,
// so a pong proves the slot is up, the publish went through, the /cmd subscription
// holds and the broker is judging this node's topics -- the whole plane, on the spot.
// Nothing waits here: the ping is armed and sent, and loopMqttPing settles it when the
// pong comes or 10 s pass, so the node never stops repeating for it.
void Fork::pingMqttControl(char* reply) {
  const int slot = _mqtt_control.slot();
  if (!_mqtt_control.isEnabled() || slot == 0 || _mesh.bridge == NULL || _ctrl_ping_topic[0] == 0) {
    mqttCtrlPingAnswer(MQTTCTRL_PING_OFF, slot, 0, NULL, reply, MQTTCTRL_MAX_REPLY);
    return;
  }
  if (!_mesh.bridge->controlSlotConnected()) {
    mqttCtrlPingAnswer(MQTTCTRL_PING_NOT_CONNECTED, slot, 0, NULL, reply, MQTTCTRL_MAX_REPLY);
    return;
  }

  uint8_t raw[MQTTCTRL_PING_NONCE_LEN / 2];
  _mesh.getRNG()->random(raw, sizeof(raw));
  char nonce[MQTTCTRL_PING_NONCE_LEN + 1];
  mesh::Utils::toHex(nonce, raw, sizeof(raw));
  char payload[sizeof(MQTTCTRL_PING_PREFIX) + MQTTCTRL_PING_NONCE_LEN];
  if (!mqttCtrlArmPing(&_ping, nonce, payload, sizeof(payload), millis())) {
    strcpy(reply, "Err - a ping is already waiting: read 'get mqtt.cmd'");
    return;
  }
  if (!_mesh.bridge->publishControlResult(_ctrl_ping_topic, payload, strlen(payload), MQTTCTRL_RESULT_QOS)) {
    mqttCtrlPingRefused(&_ping);
    mqttCtrlPingAnswer(MQTTCTRL_PING_PUBLISH_REFUSED, slot, 0, NULL, reply, MQTTCTRL_MAX_REPLY);
    return;
  }
  _ping_started = true;
  strcpy(reply, "OK - ping sent, read 'get mqtt.cmd' for the pong");
}

// Settles a ping in flight. A ping that came over the plane has its result held back
// until now, and is published as the one r2 that answers it.
void Fork::loopMqttPing() {
  if (!mqttCtrlPingPoll(&_ping, millis())) return;
  if (!_ping_remote) return;
  _ping_remote = false;
  char link[24], reply[MQTTCTRL_MAX_REPLY];
  _mesh.bridge->controlSlotLink(link, sizeof(link));
  mqttCtrlPingAnswer((MqttCtrlPingStep)_ping.last, _mqtt_control.slot(), _ping.last_ms, link,
                     reply, sizeof(reply));
  publishMqttControlResult(MQTTCTRL_OK, _ping_outcome, reply);   // the command ran; the reply says how
}

// `get mqtt.cmd` on one line: on/off and the counter as before, then the slot's
// connection, whether the broker acknowledged the /cmd subscription, and how long
// ago the key last vouched for a command.
void Fork::describeMqttControl(char* reply) {
  char age[20];
  if (_ctrl_last_verified_ms == 0) {
    strcpy(age, "none yet");
  } else {
    sprintf(age, "%lu s ago", (millis() - _ctrl_last_verified_ms) / 1000UL);
  }
  const int slot = _mqtt_control.slot();
  if (slot == 0 || _mesh.bridge == NULL) {
    sprintf(reply, "> %s, counter %u, no slot", _mqtt_control.isEnabled() ? "on" : "off",
            (unsigned)_mqtt_control.counter());
    return;
  }
  char ping[64];
  if (_ping.waiting) {
    strcpy(ping, "waiting");
  } else if (_ping.last == MQTTCTRL_PING_OK) {
    sprintf(ping, "pong in %u ms", (unsigned)_ping.last_ms);
  } else if (_ping.last == MQTTCTRL_PING_NO_PONG) {
    sprintf(ping, "no pong in %d s", MQTTCTRL_PING_TIMEOUT_MS / 1000);
  } else if (_ping.last == MQTTCTRL_PING_PUBLISH_REFUSED) {
    strcpy(ping, "publish refused");
  } else {
    strcpy(ping, "-");
  }
  sprintf(reply, "> %s, counter %u, slot %d %s, /cmd %s, last command %s, ping %s",
          _mqtt_control.isEnabled() ? "on" : "off", (unsigned)_mqtt_control.counter(), slot,
          _mesh.bridge->controlSlotConnected() ? "connected" : "not connected",
          _mesh.bridge->controlSubscribed() ? "subscribed" : "not subscribed", age, ping);
}

// Drained on the loop task, never on the MQTT event task: verification wants more
// stack than that task has, and executing a command runs a flash write that would
// stall the network stack's own thread.
void Fork::loopMqttControl() {
  refreshMqttControlV2Key();
  if (!_mqtt_control.hasPending()) return;

  // A staged command is always resolved -- run or discarded -- never left in the
  // slot. These two returns used to leave it pending, which latched the slot for
  // the life of the boot and dropped every command after it, including the ones
  // sent once a key had finally been provisioned.
  const char* owner_hex = _mqtt_control.pubkey();
  MqttCtrlResult ready = mqttCtrlOwnerReady(owner_hex);
  if (ready != MQTTCTRL_OK) {
    _mqtt_control.discard();
    MESH_DEBUG_PRINTLN("MqttControl: no usable mqtt.cmd.pubkey, command discarded");
    return;
  }

  mesh::Identity owner;
  if (!mesh::Utils::fromHex(owner.pub_key, PUB_KEY_SIZE, owner_hex)) {
    _mqtt_control.discard();
    MESH_DEBUG_PRINTLN("MqttControl: mqtt.cmd.pubkey unreadable, command discarded");
    return;
  }

  char reply[MQTTCTRL_MAX_REPLY];
  MqttCtrlOutcome outcome;
  _ping_started = false;
  MqttCtrlResult result = _mqtt_control.drain(owner, _mesh.getRTCClock()->getCurrentTime(),
                                              &_control_link, reply, sizeof(reply), &outcome);
  MESH_DEBUG_PRINTLN("MqttControl: result %d, reply '%s'", (uint32_t)result, reply);

  // Only an outcome the command key vouched for is published -- see the note on
  // drain(). A refusal that got this far still publishes: a node that refuses in
  // silence is indistinguishable from one that is switched off or un-flashed,
  // and this fleet runs several firmware versions at once, so that ambiguity is
  // exactly what makes it unreadable.
  if (outcome.authentic) {
    _ctrl_last_verified_ms = millis();
    if (_ping_started) {
      // A ping sent from here is answered once it settles (loopMqttPing), not now.
      _ping_remote = true;
      _ping_outcome = outcome;
    } else {
      publishMqttControlResult(result, outcome, reply);
    }
  }

  // Rollback (ar-11): a freshly flashed image is pending until it proves itself, and
  // the proof is this -- the radio is up, WiFi and the bridge reached the broker, and
  // the control plane verified a signed command, so the owner can still reach the
  // node. Marked valid here and nowhere earlier; until then a reboot (watchdog, power)
  // returns to the previous image, and the control plane comes back with it.
  if (outcome.authentic) markRunningImageValid("a verified command");
}

// The result topic is built once in setupMqttControl and is empty when the node
// has no region, in which case there is no control plane to answer on.
// The v2 key (TODO 17a): X25519 of this node's identity and the command key, through
// HKDF with this node's command topic. Derived when the key it was made from is not the
// one now set -- at boot, and after `set mqtt.cmd.pubkey` -- and never otherwise: every
// v2 message after that costs symmetric work only.
void Fork::refreshMqttControlV2Key() {
  const char* owner_hex = _mqtt_control.pubkey();
  if (_ctrl_topic[0] == 0 || strcmp(owner_hex, _mqtt_control.v2KeyFor()) == 0) return;
  uint8_t key[MQTTV2_KEY_LEN] = {0};
  uint8_t owner[PUB_KEY_SIZE];
  if (mqttCtrlOwnerReady(owner_hex) == MQTTCTRL_OK
      && mesh::Utils::fromHex(owner, PUB_KEY_SIZE, owner_hex)) {
    uint8_t shared[PUB_KEY_SIZE];
    _mesh.self_id.calcSharedSecret(shared, owner);
    mqttV2DeriveKey(shared, _ctrl_topic, key);
    memset(shared, 0, sizeof(shared));
    _mqtt_control.setV2Key(key, owner_hex, _ctrl_topic);
  } else {
    _mqtt_control.setV2Key(key, "", _ctrl_topic);
  }
  memset(key, 0, sizeof(key));
}

void Fork::publishMqttControlResult(MqttCtrlResult result, const MqttCtrlOutcome& outcome,
                                      const char* reply) {
  if (_mesh.bridge == NULL || _ctrl_result[0] == 0) return;

  // A sealed command is answered sealed (r3): code, command and reply readable only by
  // the command key's holder. Its tag stands where r2's signature does.
  if (outcome.v2) {
    static char sealed[MQTTV2_MAX_RESULT];   // loop task only; too big for its stack
    size_t n = mqttV2BuildResult(_mqtt_control.v2Key(), outcome.counter, (int)result,
                                 outcome.command, reply, sealed, sizeof(sealed));
    if (n > 0) _mesh.bridge->publishControlResult(_ctrl_result, sealed, n, MQTTCTRL_RESULT_QOS);
    return;
  }

  // A refusal runs no command and leaves the reply empty; the code field still
  // says why, which is what lets a requester tell "refused" from "never arrived".
  // Signed with this node's identity key (r2, ar-11): a result is published where
  // anyone can write, and the signature is what makes it this node's word.
  char payload[MQTTCTRL_MAX_RESULT];
  size_t n = mqttCtrlFormatSignedResult(payload, sizeof(payload), _ctrl_result, outcome.counter,
                                        (int)result, outcome.command, reply,
                                        [](void* ctx, uint8_t sig[64], const uint8_t* msg, size_t len) {
                                          ((mesh::LocalIdentity*)ctx)->sign(sig, msg, (int)len);
                                        }, &_mesh.self_id);
  if (n == 0) return;

  _mesh.bridge->publishControlResult(_ctrl_result, payload, n, MQTTCTRL_RESULT_QOS);
}

// `get stats`, readable over the plane: the counters every status publish carries, read
// from the mesh itself -- the radio, the dispatcher, the board -- and the bridge's queue
// when it runs. Any sender_timestamp: it says no more than the status topic does. The
// `stats-*` dumps it stands in for stay serial-only.
void Fork::formatNodeStats(char* reply) {
  const long queue = _mesh.bridge != NULL && _mesh.bridge->isRunning() ? _mesh.bridge->getQueueSize() : -1;
  mqttCtrlFormatNodeStats(reply, MQTTCTRL_MAX_REPLY, _mesh._cli.getBoard()->getBattMilliVolts(),
                          _mesh._ms->getMillis() / 1000, (int16_t)_mesh._radio->getNoiseFloor(),
                          _mesh.getTotalAirTime() / 1000, _mesh.getReceiveAirTime() / 1000,
                          (long)(_mesh.getNumSentFlood() + _mesh.getNumSentDirect()),
                          (long)(_mesh.getNumRecvFlood() + _mesh.getNumRecvDirect()),
                          _mesh.getErrFlags(), (long)_mesh._radio->getPacketsRecvErrors(), queue);
}

void Fork::ControlLink::onControlMessage(const char* topic, const uint8_t* payload, size_t len) {
  // A pong is the broker's answer to `mqtt.cmd ping`, never a command: it is taken
  // here, before any parsing, and goes no further whether it matches or not.
  if (mqttCtrlIsPong(payload, len)) {
    mqttCtrlTakePong(&fork._ping, payload, len, millis());
    return;
  }
  fork._mqtt_control.stage(topic, payload, len);
}

void Fork::ControlLink::runCommand(uint32_t sender_timestamp, char* command, char* reply) {
  fork._mesh.handleCommand(sender_timestamp, command, reply);
}

// The command plane's own verbs, and the guard that keeps every other command off the
// slot the plane rides.
bool Fork::handleMqttCommand(uint32_t sender_timestamp, char* command, char* reply) {
  if (strcmp(command, "set mqtt.cmd on") == 0 && _mqtt_control.slot() == 0) {
    autoSetupMqttControl(reply);
    return true;
  }
  if (strcmp(command, "mqtt.cmd ping") == 0) {
    pingMqttControl(reply);
    return true;
  }
  if (strcmp(command, "get mqtt.cmd") == 0) {
    describeMqttControl(reply);
    return true;
  }
  if (memcmp(command, "get stats", 9) == 0 && (command[9] == 0 || command[9] == ' ' ||
                                               command[9] == '\n' || command[9] == '\r')) {
    formatNodeStats(reply);
    return true;
  }
  if (mqttCtrlTouchesSlot(command, _mqtt_control.slot())) {
    sprintf(reply, "Err - slot %d is the command plane's: move it with set mqtt.cmd.slot first (not over the plane)",
            _mqtt_control.slot());
    return true;
  }
  return _mqtt_control.handleCommand(sender_timestamp, RUNTIME_MQTT_SLOTS, command, reply);
}

#endif
