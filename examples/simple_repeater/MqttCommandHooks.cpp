// The command plane's side of the repeater: its topics on the bridge, the queue a
// signed command waits in, the result it publishes, `cmd ping`, and the mesh road.
// Compiled only with WITH_MQTT_COMMAND; without the Observer bridge only the mesh road
// is (mesh only). The relay is in MqttRelayHooks.cpp. MyMesh reaches it through Fork.
#include "MyMesh.h"

#ifdef WITH_MQTT_COMMAND

#include <math.h>
#include <stdarg.h>
#include <helpers/SensorReadout.h>

#ifdef WITH_MQTT_BRIDGE

#include <helpers/MqttControlSlotRepair.h>

// `set cmd on` with no slot configured, the one line a fresh node needs
// (operator decision 2026-10-08): take a free slot (mqttCtrlPickSlot says which:
// slot 2 first on a board that runs two at once, else 3 up), give it what
// mqttCtrlPlanSlot says -- the `mccontrol` preset, or with a host a custom slot on a
// region's own broker -- with every packet type on (the broker collects the region's
// packets as well as status and neighbours), point the control plane at it, enable, and
// say what was done. Slot 1 and the active-slot cap are not touched: when the cap
// is reached the reply names the cure and nothing is set. With a slot already set,
// that slot is the one rewritten: with a host a node moves to its region's broker in
// one line, and bare it goes back to the preset. The slot is saved to the Observer's
// own file before the plane is pointed at it; a save that fails leaves the slot as it
// was and the plane untouched.
void Fork::autoSetupMqttControl(const MqttCtrlSlotPlan& plan, char* reply) {
  MQTTPrefs* obs = _mesh._cli.getObserverPrefs();
  const char* presets[RUNTIME_MQTT_SLOTS];
  for (int i = 0; i < RUNTIME_MQTT_SLOTS; i++) presets[i] = obs->mqtt_slot_preset[i];
  const bool two_slot_board = MQTTBridge::getMaxActiveSlots() <= 2;
  int idx = mqttCtrlSetupSlot(_mqtt_control.slot(), presets, RUNTIME_MQTT_SLOTS, two_slot_board);
  if (idx < 0) {
    strcpy(reply, "Err - no free slot 3-6: set mqttN.preset none on one, or set cmd.slot <n>");
    return;
  }
  // A slot that already runs something (analyzer-eu in slot 2, or the plane's own) frees
  // the position it takes; an empty one needs room.
  const bool was_analyzer = strcasecmp(presets[idx], MQTTCTRL_SLOT2_DEFAULT) == 0;
  if (mqttCtrlPresetFree(presets[idx]) && _mesh.bridge != NULL && !_mesh.bridge->hasRoomForAnotherSlot()) {
    sprintf(reply, "Err - this board runs %d slots at once and all are taken: turn one off "
                   "(set mqtt2.preset none) and send 'set cmd on' again",
            MQTTBridge::getMaxActiveSlots());
    return;
  }
  const char* server = plan.server;
  if (plan.server[0] == 0) {
    const MQTTPresetDef* p = findMQTTPreset(plan.preset);
    if (p == NULL) { strcpy(reply, "Err - no mccontrol preset in this build"); return; }
    server = p->server_url;
  }
  MqttCtrlSlotPlan was;
  StrHelper::strncpy(was.preset, obs->mqtt_slot_preset[idx], sizeof(was.preset));
  StrHelper::strncpy(was.server, obs->mqtt_slot_host[idx], sizeof(was.server));
  StrHelper::strncpy(was.audience, obs->mqtt_slot_audience[idx], sizeof(was.audience));
  was.filter = obs->mqtt_slot_packet_filter[idx];
  mqttCtrlApplySlotPlan(&plan, obs->mqtt_slot_preset[idx], sizeof(obs->mqtt_slot_preset[idx]),
                        obs->mqtt_slot_host[idx], sizeof(obs->mqtt_slot_host[idx]),
                        obs->mqtt_slot_audience[idx], sizeof(obs->mqtt_slot_audience[idx]),
                        &obs->mqtt_slot_packet_filter[idx]);
  if (!_mesh._cli.saveObserverPrefs(_mesh._fs)) {
    mqttCtrlApplySlotPlan(&was, obs->mqtt_slot_preset[idx], sizeof(obs->mqtt_slot_preset[idx]),
                          obs->mqtt_slot_host[idx], sizeof(obs->mqtt_slot_host[idx]),
                          obs->mqtt_slot_audience[idx], sizeof(obs->mqtt_slot_audience[idx]),
                          &obs->mqtt_slot_packet_filter[idx]);
    sprintf(reply, "Err - the MQTT settings could not be saved: slot %d and the plane are unchanged",
            idx + 1);
    return;
  }
  _mqtt_control.setSlotAndEnable((uint8_t)(idx + 1));
  sprintf(reply, "OK - slot %d%s, %s (%s), packets on; reboot to apply", idx + 1,
          was_analyzer ? " (was analyzer-eu, now off)" : "", plan.preset, server);
}

// At start, before the bridge reads the slots: a command slot still on the password login
// of before the `mccontrol` preset is put on the preset, as a bare `set cmd on` would
// (mqttCtrlRepairPlaneSlot). The plane itself is left as it is, on or off. A save that
// fails leaves the slot as it was, to be tried again at the next start.
void Fork::repairMqttControlSlot() {
  if (findMQTTPreset(MQTTCTRL_PLANE_PRESET) == NULL) return;
  MQTTPrefs* obs = _mesh._cli.getObserverPrefs();
  const int slot = _mqtt_control.slot();
  MqttCtrlSlotLogin was;
  if (!mqttCtrlRepairPlaneSlot(obs, slot, _mesh._cli.observerPrefsHeld(), &was)) return;
  if (!_mesh._cli.saveObserverPrefs(_mesh._fs)) {
    mqttCtrlSlotLoginWrite(obs, slot - 1, &was);
    return;
  }
  Serial.printf("CMD: slot %d was on the old login; moved to the mccontrol preset\n", slot);
}

// Build this node's control topics once and hand the bridge a list it can
// re-subscribe from on every reconnect. Nothing is allocated per message or per
// reconnect: docs/mbedtls-tls-footprint.md records a measured largest-free-block
// ratchet on this exact path, so the buffers are members and stay that way.
//
// mcc3 (lou-20) needs no region: the node's own mcc/cmd/<key>, the ping on mcc/ping/<key>,
// alive on mcc/alive/<key> with the slot's will clearing it. The old scheme is kept beside
// it while the node has a region, on its own per-node topic only: the broadcast topic is
// gone (IATA-2: no broadcast of any kind).
void Fork::setupMqttControl(MQTTBridge* bridge) {
  if (_mqtt_control.slot() == 0) return;         // no slot to listen on

  char node_hex[PUB_KEY_SIZE * 2 + 1];
  mesh::Utils::toHex(node_hex, _mesh.self_id.pub_key, PUB_KEY_SIZE);   // the whole key names the node (2026-10-08)

  if (!mcc3Topic("cmd", node_hex, _mcc3_topic, sizeof(_mcc3_topic))
      || !mcc3Topic("alive", node_hex, _alive_topic, sizeof(_alive_topic))
      || !mcc3Topic("ping", node_hex, _ctrl_ping_topic, sizeof(_ctrl_ping_topic))) return;
  size_t topics = 0;
  _ctrl_topics[topics++] = _mcc3_topic;

  const char* iata = observerIata();
  if (iata != NULL && iata[0] != 0 && MqttControl::buildTopic(iata, node_hex, _ctrl_topic, sizeof(_ctrl_topic))) {
    MqttControl::buildResultTopic(iata, node_hex, _ctrl_result, sizeof(_ctrl_result));
    _ctrl_topics[topics++] = _ctrl_topic;
  }
  refreshMqttControlV2Key();
  refreshMcc3Keys();
  bridge->setControlWill(_alive_topic);
  bridge->setControlSink(&_control_link, _ctrl_topics, topics, _mqtt_control.slot() - 1);
}

// The node's region home for its alive message, "" when none.
const char* Fork::homeRegion() {
  const RegionEntry* home = _mesh.region_map.getHomeRegion();
  if (home == NULL) return "";
  const char* name = home->name[0] == '#' ? home->name + 1 : home->name;
  return strcmp(name, "*") == 0 ? "" : name;
}

// The alive message (IATA-2 design §3): sealed to the owner, retained on mcc/alive/<key>,
// the owner's only way to find its nodes. None while there is no command key, since there
// is nobody to seal it to; the will clears it when the link dies.
void Fork::loopAlive() {
  if (_alive_topic[0] == 0 || !_mqtt_control.isEnabled()) return;
  const uint32_t now = millis();
  const bool up = _mesh.bridge->controlSlotConnected();
  mqttCtrlAliveLink(&_alive, up, now, _mesh.getRNG()->nextInt(0, 0x7FFFFFFF));

  const char* key = _mqtt_control.pubkey();
  const char* region = homeRegion();
  const uint16_t minutes = _mqtt_control.aliveMinutes();
  if (strcmp(key, _alive_key_for) != 0 || strcmp(region, _alive_region) != 0 || minutes != _alive_minutes) {
    StrHelper::strncpy(_alive_key_for, key, sizeof(_alive_key_for));
    StrHelper::strncpy(_alive_region, region, sizeof(_alive_region));
    _alive_minutes = minutes;
    mqttCtrlAliveNudge(&_alive, now, _mesh.getRNG()->nextInt(0, 0x7FFFFFFF));
  }
  if (!mqttCtrlAliveDue(&_alive, now)) return;
  mqttCtrlAliveSent(&_alive, now, minutes * 60UL, _mesh.getRNG()->nextInt(0, 0x7FFFFFFF));

  refreshMcc3Keys();
  const Mcc3Keys* keys = _mqtt_control.mcc3Keys();
  if (keys == NULL) return;

  const uint32_t clock = _mesh.getRTCClock()->getCurrentTime();
  const bool clock_set = clock >= MQTTConnectionPolicy::kSyncedClockEpoch;
  const char* version = strstr(FIRMWARE_VERSION, "lou-");
  Mcc3Alive a;
  a.boot = _mqtt_control.boots();
  a.sequence = ++_alive_sequence;
  a.uptime = _mesh._ms->getMillis() / 1000;
  a.clock = clock_set ? clock : 0;
  a.last_counter = _mqtt_control.counter();
  a.interval = minutes * 60UL;
  a.flags = (_ctrl_topic[0] ? MCC3_ALIVE_OLD_SCHEME : 0) | (FORK_UPLINK ? MCC3_ALIVE_UPLINK : 0)
            | (FORK_AUTO_REPLY ? MCC3_ALIVE_AUTO_REPLY : 0) | (clock_set ? MCC3_ALIVE_CLOCK_SET : 0)
            | (_mqtt_control.relayMode() == MQTTCTRL_RELAY_OWN ? MCC3_ALIVE_RELAY : 0);
  a.mesh = mcc3AliveMeshMode(_mqtt_control.meshMode());
  for (int i = 0; i < 4; i++) a.fingerprint[i] = (uint8_t)mqttCtrlHexByte(key[2 * i], key[2 * i + 1]);
  a.via = _mqtt_control.keyVia();
  a.version = version != NULL ? version : FIRMWARE_VERSION;
  a.region = region;
  a.name = _mesh._prefs.node_name;

  uint8_t nonce[MCC3_NONCE_LEN];
  _mesh.getRNG()->random(nonce, sizeof(nonce));
  char payload[MCC3_ALIVE_B64 + 1];
  size_t n = mcc3BuildAlive(keys->alive, nonce, &a, payload, sizeof(payload));
  if (n > 0) _mesh.bridge->publishControlRetained(_alive_topic, payload, n, MQTTCTRL_RESULT_QOS);
}

// `cmd ping`: the broker echoes a ping on our own /ping as a pong on our own /cmd,
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
    strcpy(reply, "Err - a ping is already waiting: read 'get cmd'");
    return;
  }
  if (!_mesh.bridge->publishControlResult(_ctrl_ping_topic, payload, strlen(payload), MQTTCTRL_RESULT_QOS)) {
    mqttCtrlPingRefused(&_ping);
    mqttCtrlPingAnswer(MQTTCTRL_PING_PUBLISH_REFUSED, slot, 0, NULL, reply, MQTTCTRL_MAX_REPLY);
    return;
  }
  _ping_started = true;
  strcpy(reply, "OK - ping sent, read 'get cmd' for the pong");
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

#endif

// `get cmd` on one line: on/off and the counter as before, then the slot's
// connection, whether the broker granted or refused the /cmd subscription, how long ago
// the key last vouched for a command, and how many arrived that it did not.
void Fork::describeMqttControl(char* reply) {
#ifndef WITH_MQTT_BRIDGE
  sprintf(reply, "> %s, counter %u, mesh only", _mqtt_control.isEnabled() ? "on" : "off",
          (unsigned)_mqtt_control.counter());
  size_t used = strlen(reply);
  mqttCtrlMeshNote(MQTTCTRL_MESH_ON, _mesh_ok, _mesh_refused, &reply[used], MQTTCTRL_MAX_REPLY - used);
#else
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
    size_t used = strlen(reply);
    mqttCtrlMeshNote(_mqtt_control.meshMode(), _mesh_ok, _mesh_refused, &reply[used],
                     MQTTCTRL_MAX_REPLY - used);
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
          mqttSubStateName(_mesh.bridge->controlSubState()), age, ping);
  size_t used = strlen(reply);
  mqttCtrlMeshNote(_mqtt_control.meshMode(), _mesh_ok, _mesh_refused, &reply[used],
                   MQTTCTRL_MAX_REPLY - used);
  used = strlen(reply);
  mqttCtrlRefusalNote(_ctrl_unverified, _ctrl_last_unverified, &reply[used], MQTTCTRL_MAX_REPLY - used);
#endif
}

#ifdef WITH_MQTT_BRIDGE

// Drained on the loop task, never on the MQTT event task: verification wants more
// stack than that task has, and executing a command runs a flash write that would
// stall the network stack's own thread.
void Fork::loopMqttControl() {
  refreshMqttControlV2Key();
  refreshMcc3Keys();
  refreshRekeyKeys();
  if (_mqtt_control.rekeyJustDone()) debugLine("rekey: the new key signed a command and is the key now");
  const bool up = _mesh.bridge != NULL && _mesh.bridge->controlSlotConnected();
  _mesh_down_since = mqttCtrlMeshDownSince(up, _mesh_down_since, millis());
  if (_mesh.bridge != NULL) loopAlive();
  loopRelay();
  const uint32_t dropped = _mqtt_control.dropped();
  if (dropped != _ctrl_dropped_seen) {
    debugLine("mqtt: %u arrival(s) dropped, the queue was full (%u since boot)",
              (unsigned)(dropped - _ctrl_dropped_seen), (unsigned)dropped);
    _ctrl_dropped_seen = dropped;
  }
  if (!_mqtt_control.hasPending()) return;

  // A staged command is always resolved -- run or discarded -- never left at the
  // front of the queue, and one a pass. Left there by either of these two returns it
  // would hold back every command after it for the life of the boot, including the
  // ones sent once a key had finally been provisioned.
  const char* owner_hex = _mqtt_control.pubkey();
  MqttCtrlResult ready = mqttCtrlOwnerReady(owner_hex);
  if (ready != MQTTCTRL_OK) {
    _mqtt_control.discard();
    _ctrl_unverified++;
    _ctrl_last_unverified = ready;
    debugLine("mqtt: a command discarded, no usable cmd.pubkey");
    MESH_DEBUG_PRINTLN("MqttControl: no usable cmd.pubkey, command discarded");
    return;
  }

  mesh::Identity owner;
  if (!mesh::Utils::fromHex(owner.pub_key, PUB_KEY_SIZE, owner_hex)) {
    _mqtt_control.discard();
    _ctrl_unverified++;
    _ctrl_last_unverified = MQTTCTRL_ERR_NO_OWNER_KEY;
    MESH_DEBUG_PRINTLN("MqttControl: cmd.pubkey unreadable, command discarded");
    return;
  }

  if (_mqtt_control.forwardPending()) {
    relayForward();
    return;
  }

  char reply[MQTTCTRL_MAX_REPLY];
  MqttCtrlOutcome outcome;
  _ping_started = false;
  MqttCtrlResult result = _mqtt_control.drain(owner, _mesh.getRTCClock()->getCurrentTime(),
                                              &_control_link, reply, sizeof(reply), &outcome);
  MESH_DEBUG_PRINTLN("MqttControl: result %d, reply '%s'", (uint32_t)result, reply);
  debugLine("mqtt: a command, %s, %s", outcome.authentic ? "the key's" : "not the key's",
            mqttCtrlResultName(result));

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
  } else if (result != MQTTCTRL_OK) {
    _ctrl_unverified++;
    _ctrl_last_unverified = result;
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
// one now set -- at boot, and after `set cmd.pubkey` -- and never otherwise: every
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
  if (_mesh.bridge == NULL) return;

  // mcc3: every outcome the key vouched for, sealed under a fresh nonce, on the reply topic
  // the command named. Code, command and reply are the owner's alone.
  if (outcome.mcc3) {
    const Mcc3Keys* keys = _mqtt_control.mcc3Keys();
    char topic[MQTTCTRL_MAX_TOPIC + 1];
    if (keys == NULL || !mcc3ResultTopic(outcome.rid, topic, sizeof(topic))) return;
    const uint32_t now = _mesh.getRTCClock()->getCurrentTime();
    uint8_t nonce[MCC3_NONCE_LEN];
    _mesh.getRNG()->random(nonce, sizeof(nonce));
    static char sealed[MCC3_MAX_RESULT];   // loop task only; too big for its stack
    size_t n = mcc3BuildResult(keys->cmd, nonce, outcome.counter, (int)result,
                               now >= MQTTConnectionPolicy::kSyncedClockEpoch ? now : 0,
                               outcome.command, reply, sealed, sizeof(sealed));
    if (n > 0) _mesh.bridge->publishControlResult(topic, sealed, n, MQTTCTRL_RESULT_QOS);
    return;
  }
  if (_ctrl_result[0] == 0) return;

  // A sealed command that ran is answered sealed (r3): code, command and reply readable
  // only by the command key's holder. Its tag stands where r2's signature does.
  if (outcome.v2 && mqttV2SealsResult(result)) {
    static char sealed[MQTTV2_MAX_RESULT];   // loop task only; too big for its stack
    size_t n = mqttV2BuildResult(_mqtt_control.v2Key(), outcome.counter, (int)result,
                                 outcome.command, reply, sealed, sizeof(sealed));
    if (n > 0) _mesh.bridge->publishControlResult(_ctrl_result, sealed, n, MQTTCTRL_RESULT_QOS);
    return;
  }

  // A refusal runs no command and leaves the reply empty; the code field still
  // says why, which is what lets a requester tell "refused" from "never arrived".
  // Signed with this node's identity key (r2, ar-11): a result is published where
  // anyone can write, and the signature is what makes it this node's word. A refused
  // v2 command is answered here too, without its command, which came sealed.
  char payload[MQTTCTRL_MAX_RESULT];
  size_t n = mqttCtrlFormatSignedResult(payload, sizeof(payload), _ctrl_result, outcome.counter,
                                        (int)result, outcome.v2 ? "" : outcome.command, reply,
                                        [](void* ctx, uint8_t sig[64], const uint8_t* msg, size_t len) {
                                          ((mesh::LocalIdentity*)ctx)->sign(sig, msg, (int)len);
                                        }, &_mesh.self_id);
  if (n == 0) return;

  _mesh.bridge->publishControlResult(_ctrl_result, payload, n, MQTTCTRL_RESULT_QOS);
}

void Fork::ControlLink::onControlMessage(const char* topic, const uint8_t* payload, size_t len) {
  // A pong is the broker's answer to `cmd ping`, never a command: it is taken
  // here, before any parsing, and goes no further whether it matches or not.
  if (mqttCtrlIsPong(payload, len)) {
    mqttCtrlTakePong(&fork._ping, payload, len, millis());
    return;
  }
  fork._mqtt_control.stage(topic, payload, len);
}
#endif

// `get stats`, readable on either road: the counters every status publish carries, read
// from the mesh itself -- the radio, the dispatcher, the board -- and the bridge's queue
// when there is one and it runs. Any sender_timestamp: it says no more than the status topic
// does. The `stats-*` dumps it stands in for stay serial-only.
void Fork::formatNodeStats(char* reply) {
#ifdef WITH_MQTT_BRIDGE
  const long queue = _mesh.bridge != NULL && _mesh.bridge->isRunning() ? _mesh.bridge->getQueueSize() : -1;
  const long recv_errors = (long)_mesh._radio->getPacketsRecvErrors();
#else
  const long queue = -1, recv_errors = -1;   // the Observer's radio wrapper counts them
#endif
  mqttCtrlFormatNodeStats(reply, MQTTCTRL_MAX_REPLY, board.getBattMilliVolts(),
                          _mesh._ms->getMillis() / 1000, (int16_t)_mesh._radio->getNoiseFloor(),
                          _mesh.getTotalAirTime() / 1000, _mesh.getReceiveAirTime() / 1000,
                          (long)(_mesh.getNumSentFlood() + _mesh.getNumSentDirect()),
                          (long)(_mesh.getNumRecvFlood() + _mesh.getNumRecvDirect()),
                          _mesh._err_flags, recv_errors, queue);
}

// `get sensors`: the battery, the MCU's temperature where the board has one, and what the
// board's sensors report for a telemetry request, less any position. The mesh's own
// telemetry buffer is borrowed: a telemetry request fills it afresh before it reads it.
void Fork::formatSensors(char* reply) {
  _mesh.telemetry.reset();
  sensors.querySensors(TELEM_PERM_BASE | TELEM_PERM_ENVIRONMENT, _mesh.telemetry);
  const float temperature = board.getMCUTemperature();
  sensorReadoutFormat(reply, SENSOR_READOUT_MAX + 1, board.getBattMilliVolts(),
                      isnan(temperature) ? SENSOR_READOUT_NO_TEMP : (int)lroundf(temperature * 10),
                      _mesh.telemetry.getBuffer(), _mesh.telemetry.getSize());
}

void Fork::debugLine(const char* fmt, ...) {
  if (!_ctrl_debug) return;
  char line[120];
  va_list args;
  va_start(args, fmt);
  vsnprintf(line, sizeof(line), fmt, args);
  va_end(args);
  Serial.print("mcc: ");
  Serial.println(line);
}

int Fork::searchPeers(const uint8_t* hash, int* indexes, int room) {
  int n = 0;
#ifdef WITH_MQTT_BRIDGE
  if (n < room && isRelayPeer(hash)) indexes[n++] = RELAY_PEER;
#endif
  const uint32_t now_ms = millis();
  for (int i = 0; i < MQTTCTRL_REQUESTERS && n < room; i++) {
    if (!_requesters.listening(i, now_ms) || _requesters.entry[i].key[0] != hash[0]) continue;
    if (_mesh.acl.getClient(_requesters.entry[i].key, PUB_KEY_SIZE) != NULL) continue;   // a client keeps its own entry
    indexes[n++] = REQUESTER_PEER + i;
  }
  return n;
}

bool Fork::peerSecret(uint8_t* dest_secret, int peer_idx) {
#ifdef WITH_MQTT_BRIDGE
  if (peer_idx == RELAY_PEER) {
    memcpy(dest_secret, _relay_wait.secret, PUB_KEY_SIZE);
    return true;
  }
#endif
  if (peer_idx < REQUESTER_PEER || peer_idx >= REQUESTER_PEER + MQTTCTRL_REQUESTERS) return false;
  memcpy(dest_secret, _requesters.entry[peer_idx - REQUESTER_PEER].secret, PUB_KEY_SIZE);
  return true;
}

// Nothing but a path is expected of either peer, and a relay's target may answer in a
// datagram: anything else from them is dropped here, never read as a client's.
bool Fork::onPeerData(mesh::Packet* packet, uint8_t type, int peer_idx, const uint8_t* data, size_t len) {
#ifdef WITH_MQTT_BRIDGE
  if (peer_idx == RELAY_PEER) {
    if (type == PAYLOAD_TYPE_RESPONSE) onRelayResponse(packet, MCC3_PATH_NONE, NULL, data, len);
    return true;
  }
#endif
  return peer_idx >= REQUESTER_PEER && peer_idx < REQUESTER_PEER + MQTTCTRL_REQUESTERS;
}

bool Fork::onPeerPath(mesh::Packet* packet, int peer_idx, const uint8_t* path, uint8_t path_len,
                      uint8_t extra_type, const uint8_t* extra, uint8_t extra_len, bool* reciprocate) {
  *reciprocate = false;
#ifdef WITH_MQTT_BRIDGE
  if (peer_idx == RELAY_PEER) {
    if (extra_type == PAYLOAD_TYPE_RESPONSE) onRelayResponse(packet, path_len, path, extra, extra_len);
    // The target is told the way its answer came, so that it need not flood the next one.
    // Mesh sends that only for a return that was flooded, direct along `path`.
    *reciprocate = true;
    if (packet->isRouteFlood()) {
      const int out = mqttCtrlPathBytes(path_len, MAX_PATH_SIZE), back = packet->getPathByteLen();
      const int sealed = (1 + back + 5 + CIPHER_BLOCK_SIZE - 1) / CIPHER_BLOCK_SIZE * CIPHER_BLOCK_SIZE;
      const uint32_t air_ms = _mesh._radio->getEstAirtimeFor(2 + (out < 0 ? 0 : out) + 2 + CIPHER_MAC_SIZE + sealed);
      _relay.budget.air.spend(_mesh.getRTCClock()->getCurrentTime(), air_ms);
      debugLine("relay: the target is sent the way back, %u hop(s), %u ms on the air",
                (unsigned)(packet->path_len & 63), (unsigned)air_ms);
    }
    return true;
  }
#endif
  if (peer_idx < REQUESTER_PEER || peer_idx >= REQUESTER_PEER + MQTTCTRL_REQUESTERS) return false;
  const bool kept = _requesters.learn(peer_idx - REQUESTER_PEER, path, path_len);
  debugLine("mesh: the way back to a sender, %u hop(s)%s", (unsigned)(path_len & 63), kept ? "" : ", not kept");
  return true;
}

void Fork::ControlLink::runCommand(uint32_t sender_timestamp, char* command, char* reply) {
  fork._mesh.handleCommand(sender_timestamp, command, reply);
}

// The command plane's own verbs, and the guard that keeps every other command off the
// slot the plane rides.
bool Fork::handleMqttCommand(uint32_t sender_timestamp, bool mesh_admin, char* command, char* reply) {
  if (strcmp(command, "get cmd") == 0) {
    describeMqttControl(reply);
    return true;
  }
  if (memcmp(command, "get stats", 9) == 0 && (command[9] == 0 || command[9] == ' ' ||
                                               command[9] == '\n' || command[9] == '\r')) {
    formatNodeStats(reply);
    return true;
  }
  if (strcmp(command, "get sensors") == 0) {
    formatSensors(reply);
    return true;
  }
  if (strcmp(command, "get cmd.debug") == 0) {
    sprintf(reply, "> %s", _ctrl_debug ? "on" : "off");
    return true;
  }
  // The serial console's alone: the lines go nowhere else, and it lasts until the next boot.
  if (memcmp(command, "set cmd.debug ", 14) == 0) {
    const bool on = strcmp(&command[14], "on") == 0;
    if (sender_timestamp != 0 || mesh_admin) {
      strcpy(reply, "Err - the serial console only");
    } else if (!on && strcmp(&command[14], "off") != 0) {
      strcpy(reply, "Err - use: set cmd.debug on|off");
    } else {
      _ctrl_debug = on;
      strcpy(reply, "OK");
    }
    return true;
  }
#ifdef WITH_MQTT_BRIDGE
  MqttCtrlSlotPlan plan;
  const MqttCtrlSetup setup = mqttCtrlPlanSlot(command, &plan);
  if (setup == MQTTCTRL_SETUP_BAD_HOST) {
    sprintf(reply, "Err - use: set cmd on [<broker host name, up to %d characters>]",
            MQTTCTRL_HOST_MAX);
    return true;
  }
  if (setup == MQTTCTRL_SETUP_HOST || setup == MQTTCTRL_SETUP_PRESET) {
    autoSetupMqttControl(plan, reply);
    return true;
  }
  if (strcmp(command, "cmd ping") == 0) {
    pingMqttControl(reply);
    return true;
  }
  if (strcmp(command, "get cmd.mesh") == 0) {
    mqttCtrlMeshDescribe(_mqtt_control.meshMode(), _mesh_down_since, millis(), reply, MQTTCTRL_MAX_REPLY);
    return true;
  }
  if (memcmp(command, "set cmd.mesh ", 13) == 0) {
    uint8_t mode;
    if (!mqttCtrlMeshParseMode(&command[13], &mode)) {
      strcpy(reply, "Err - use: set cmd.mesh off|on|auto");
      return true;
    }
    _mqtt_control.setMeshMode(mode);
    strcpy(reply, "OK");
    return true;
  }
  if (strcmp(command, "get relay") == 0) {
    describeRelay(reply);
    return true;
  }
  if (memcmp(command, "set relay ", 10) == 0) {
    uint8_t mode;
    if (!mqttCtrlRelayParseMode(&command[10], &mode)) {
      strcpy(reply, "Err - use: set relay off|own");
      return true;
    }
    _mqtt_control.setRelayMode(mode);
    strcpy(reply, "OK");
    return true;
  }
  if (mqttCtrlTouchesSlot(command, _mqtt_control.slot())) {
    sprintf(reply, "Err - slot %d is the command plane's: move it with set cmd.slot first (not over the plane)",
            _mqtt_control.slot());
    return true;
  }
#endif
  return _mqtt_control.handleCommand(mqttCtrlKeyCallerOf(sender_timestamp, mesh_admin),
                                     _mesh._prefs.password, _mesh._prefs.guest_password,
                                     MQTTCTRL_SLOTS, command, reply);
}

// The mesh road (operator 2026-11-16): a signed command in an anonymous request to this node,
// for when Wi-Fi or the broker is down, and the only road on an image without them. Verified
// as a command on /cmd is, against the topic this node would have received it on, and
// answered with a response to whoever asked. Anything that is not answered stays silent,
// as a build without the road is.
bool Fork::onMeshCommand(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender,
                         const uint8_t* data, size_t len) {
  if (mcc3MeshIsRequest(data, len)) {
    onMcc3MeshCommand(packet, secret, sender, data, len);
    return true;
  }
  if (!mqttCtrlMeshIsRequest(data, len)) return false;
  if (!mqttCtrlMeshListening(_mqtt_control.isEnabled(), FORK_UPLINK, _mqtt_control.meshMode())) {
    debugLine("mesh: a request (old scheme) heard, not listening: cmd %s, mesh %s",
              _mqtt_control.isEnabled() ? "on" : "off", mqttCtrlMeshModeName(_mqtt_control.meshMode()));
    return true;
  }

  MqttCtrlMeshRequest req;
  char node_hex[PUB_KEY_SIZE * 2 + 1];
  char topic[MQTTCTRL_MAX_TOPIC + 1];
  mesh::Identity owner;
  mesh::Utils::toHex(node_hex, _mesh.self_id.pub_key, PUB_KEY_SIZE);
  if (mqttCtrlMeshParse(data, len, &req) != MQTTCTRL_OK
      || !MqttControl::buildTopic(mqttCtrlMeshRegion(FORK_UPLINK, observerIata()), node_hex, topic, sizeof(topic))
      || mqttCtrlOwnerReady(_mqtt_control.pubkey()) != MQTTCTRL_OK
      || !mesh::Utils::fromHex(owner.pub_key, PUB_KEY_SIZE, _mqtt_control.pubkey())) {
    _mesh_refused++;
    debugLine("mesh: a request (old scheme) refused before the signature: unreadable, or no command key");
    return true;
  }

  char reply[MQTTCTRL_MAX_REPLY];
  bool answer = false;
  const bool open = mqttCtrlMeshRoadOpen(FORK_UPLINK, _mqtt_control.meshMode(), _mesh_down_since, millis());
  const uint32_t now = _mesh.getRTCClock()->getCurrentTime();
  MqttCtrlResult result = _mqtt_control.meshCommand(owner, topic, req, now, open, &_control_link,
                                                    reply, &answer);
  if (result == MQTTCTRL_OK) _mesh_ok++;
  else _mesh_refused++;
  MESH_DEBUG_PRINTLN("MqttControl: mesh result %d, reply '%s'", (uint32_t)result, reply);
  debugLine("mesh: a request (old scheme), %s, %s", mqttCtrlResultName(result), answer ? "answered" : "no answer");
  if (answer) answerMeshCommand(packet, secret, sender, req.tag, req.env.counter, result, reply, false, false);
  return true;
}

// The mcc3 mesh road (0xC2, lou-20): the same road, the request encrypted to this node and
// signed inside, the response sealed to the owner, so the companion carrying either reads
// neither. Every refusal before the signature and the answer budget is silent.
void Fork::onMcc3MeshCommand(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender,
                             const uint8_t* data, size_t len) {
  if (!mqttCtrlMeshListening(_mqtt_control.isEnabled(), FORK_UPLINK, _mqtt_control.meshMode())) {
    debugLine("mesh: a request heard, not listening: cmd %s, mesh %s",
              _mqtt_control.isEnabled() ? "on" : "off", mqttCtrlMeshModeName(_mqtt_control.meshMode()));
    return;
  }
  refreshMcc3Keys();
  mesh::Identity owner;
  const Mcc3Keys* keys = mesh::Utils::fromHex(owner.pub_key, PUB_KEY_SIZE, _mqtt_control.pubkey())
                           ? _mqtt_control.mcc3Keys() : NULL;
  Mcc3Command cmd;
  MqttCtrlResult result = mcc3MeshOpen(keys, _mesh.self_id.pub_key, _mqtt_control.counter(), data, len,
                                       [](void* ctx, const uint8_t sig[MCC3_SIG_LEN], const uint8_t* msg, size_t n) {
                                         return ((const mesh::Identity*)ctx)->verify(sig, msg, (int)n);
                                       }, &owner, &cmd);
  // Not the key's: a key that waits (`rekey`) is tried, and takes over if it signed this.
  if (result == MQTTCTRL_ERR_COMMAND_CHARS || result == MQTTCTRL_ERR_SIG_INVALID) {
    refreshRekeyKeys();
    const Mcc3Keys* waiting = _mqtt_control.rekeyKeys(millis());
    mesh::Identity next;
    if (waiting != NULL && mesh::Utils::fromHex(next.pub_key, PUB_KEY_SIZE, _mqtt_control.rekeyWaiting(millis()))) {
      MqttCtrlResult again = mcc3MeshOpen(waiting, _mesh.self_id.pub_key, _mqtt_control.counter(), data, len,
                                          [](void* ctx, const uint8_t sig[MCC3_SIG_LEN], const uint8_t* msg, size_t n) {
                                            return ((const mesh::Identity*)ctx)->verify(sig, msg, (int)n);
                                          }, &next, &cmd);
      if (again == MQTTCTRL_OK) {
        _mqtt_control.rekeyTakeOver();
        _mqtt_control.rekeyJustDone();
        debugLine("rekey: the new key signed a request and is the key now");
        result = MQTTCTRL_OK;
      }
    }
  }
  if (result != MQTTCTRL_OK) {
    _mesh_refused++;
    debugLine("mesh: a request refused before it ran: %s%s", mqttCtrlResultName(result),
              keys == NULL ? " (no command key)" : "");
    return;
  }

  char reply[MQTTCTRL_MAX_REPLY];
  bool answer = false;
  const bool open = mqttCtrlMeshRoadOpen(FORK_UPLINK, _mqtt_control.meshMode(), _mesh_down_since, millis());
  result = _mqtt_control.meshCommand(cmd, _mesh.getRTCClock()->getCurrentTime(), open, &_control_link,
                                     reply, &answer);
  if (result == MQTTCTRL_OK) _mesh_ok++;
  else _mesh_refused++;
  MESH_DEBUG_PRINTLN("MqttControl: mcc3 mesh result %d, reply '%s'", (uint32_t)result, reply);
  debugLine("mesh: a request, counter %u, %s, %s", (unsigned)cmd.counter, mqttCtrlResultName(result),
            answer ? "answered" : "no answer");
  if (answer) {
    answerMeshCommand(packet, secret, sender, cmd.tag, cmd.counter, result, reply, true,
                      (cmd.flags & MCC3_MESH_FLAG_ZERO_HOP) != 0);
  }
}

// The mcc3 keys (IATA-2): X25519 of this node's identity and the command key, through HKDF
// with this node's key. Derived when the key they were made from is not the one now set --
// at boot, after `set cmd.pubkey` -- and never otherwise.
void Fork::refreshMcc3Keys() {
  const char* owner_hex = _mqtt_control.pubkey();
  if (strcmp(owner_hex, _mqtt_control.mcc3KeyFor()) == 0) return;
  Mcc3Keys keys;
  memset(&keys, 0, sizeof(keys));
  uint8_t owner[PUB_KEY_SIZE];
  if (mqttCtrlOwnerReady(owner_hex) == MQTTCTRL_OK && mesh::Utils::fromHex(owner, PUB_KEY_SIZE, owner_hex)) {
    uint8_t shared[PUB_KEY_SIZE];
    char node_hex[PUB_KEY_SIZE * 2 + 1];
    _mesh.self_id.calcSharedSecret(shared, owner);
    mesh::Utils::toHex(node_hex, _mesh.self_id.pub_key, PUB_KEY_SIZE);
    mcc3DeriveKeys(shared, node_hex, &keys);
    memset(shared, 0, sizeof(shared));
    _mqtt_control.setMcc3Keys(keys, owner_hex, _mesh.self_id.pub_key);
  } else {
    _mqtt_control.setMcc3Keys(keys, "", _mesh.self_id.pub_key);
  }
  memset(&keys, 0, sizeof(keys));
}

// The keys of a command key that waits (`rekey`), derived once when it is offered.
void Fork::refreshRekeyKeys() {
  const char* next_hex = _mqtt_control.rekeyWaiting(millis());
  if (next_hex[0] == 0 || strcmp(next_hex, _mqtt_control.rekeyKeyFor()) == 0) return;
  uint8_t next[PUB_KEY_SIZE];
  if (!mesh::Utils::fromHex(next, PUB_KEY_SIZE, next_hex)) return;
  Mcc3Keys keys;
  uint8_t shared[PUB_KEY_SIZE];
  char node_hex[PUB_KEY_SIZE * 2 + 1];
  _mesh.self_id.calcSharedSecret(shared, next);
  mesh::Utils::toHex(node_hex, _mesh.self_id.pub_key, PUB_KEY_SIZE);
  mcc3DeriveKeys(shared, node_hex, &keys);
  memset(shared, 0, sizeof(shared));
  _mqtt_control.setRekeyKeys(keys, next_hex);
  memset(&keys, 0, sizeof(keys));
  debugLine("rekey: a new key waits, %.8s...", next_hex);
}

// Back the way upstream answers a login (chooseReplyRoute): a flooded request gets its path
// returned with the answer, a direct one goes back along a stored path, or floods. With
// `zero_hop`, which the sender asks for when it heard this node directly, the answer is one
// transmission with no path, however the request came.
void Fork::answerMeshCommand(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender,
                             uint32_t tag, uint32_t counter, MqttCtrlResult result, const char* reply,
                             bool sealed, bool zero_hop) {
  uint32_t random;
  _mesh.getRNG()->random((uint8_t *)&random, sizeof(random));
  const uint32_t delay_millis = mqttCtrlMeshAnswerDelay(packet->isRouteFlood(), random);
  // The way back: a client's own path, else the one this sender brought after an earlier
  // answer. The sender is a peer from now, so that it can bring one.
  ClientInfo* client = _mesh.acl.getClient(sender.pub_key, PUB_KEY_SIZE);
  const uint8_t* out_path = NULL;
  uint8_t out_path_len = OUT_PATH_UNKNOWN;
  if (client != NULL && client->out_path_len != OUT_PATH_UNKNOWN) {
    out_path = client->out_path;
    out_path_len = client->out_path_len;
  } else if (const MqttCtrlRequester* known = _requesters.pathTo(sender.pub_key)) {
    out_path = known->path;
    out_path_len = known->path_len;
  }
  _requesters.note(sender.pub_key, secret, millis());
  const bool have_out_path = out_path != NULL;
  auto route = mesh::chooseReplyRoute(packet->isRouteFlood(), false, have_out_path);
  const bool path_return = !zero_hop && route == mesh::REPLY_ROUTE_PATH_RETURN;

  uint8_t data[MQTTCTRL_MESH_RESP_HEAD + MQTTCTRL_MAX_REPLY];
  size_t room = min(mqttCtrlMeshResponseRoom(path_return, packet->getPathByteLen()), sizeof(data));
  const uint32_t now = _mesh.getRTCClock()->getCurrentTime();
  size_t n;
  if (sealed) {
    uint8_t nonce[MCC3_NONCE_LEN];
    _mesh.getRNG()->random(nonce, sizeof(nonce));
    n = mcc3MeshBuildResponse(_mqtt_control.mcc3Keys()->cmd, nonce, tag, counter, (int)result,
                              now >= MQTTConnectionPolicy::kSyncedClockEpoch ? now : 0, reply, room, data);
  } else {
    n = mqttCtrlMeshFormatResponse(data, room, tag, now, counter, (int)result, reply);
  }
  if (n == 0) return;

  mesh::Packet* out = path_return
      ? _mesh.createPathReturn(sender, secret, packet->path, packet->path_len, PAYLOAD_TYPE_RESPONSE, data, n)
      : _mesh.createDatagram(PAYLOAD_TYPE_RESPONSE, sender, secret, data, n);
  if (out == NULL) return;
  const uint32_t air_ms = _mesh._radio->getEstAirtimeFor(out->getRawLength());
  _mqtt_control.meshAnswered(now, air_ms);
  debugLine("mesh: the answer to %u, %u bytes, %u ms on the air, %s, in %u ms", (unsigned)counter, (unsigned)n, (unsigned)air_ms,
            zero_hop ? "no hops" : path_return ? "flooded with its path"
              : route == mesh::REPLY_ROUTE_DIRECT_OUT_PATH ? "along the way back" : "flooded", (unsigned)delay_millis);
  if (path_return) {
    _mesh.sendFloodReply(out, delay_millis, packet->getPathHashSize());
  } else if (zero_hop) {
    _mesh.sendZeroHop(out, delay_millis);
  } else if (route == mesh::REPLY_ROUTE_DIRECT_OUT_PATH) {
    _mesh.sendDirect(out, out_path, out_path_len, delay_millis);
  } else {
    _mesh.sendFloodReply(out, delay_millis, packet->getPathHashSize());
  }
}

#endif
