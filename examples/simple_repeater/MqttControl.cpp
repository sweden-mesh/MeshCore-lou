#ifdef WITH_MQTT_COMMAND

#include "MqttControl.h"
#include <helpers/OtaAutoLogic.h>

#include <helpers/TxtDataHelpers.h>

#define MQTTCTRL_CONFIG_FILE  "/mqttcontrol"

// The broker permits meshcore/ and silently discards everything else -- a publish
// elsewhere is accepted, acked and dropped, with no error visible to the sender.
// Measured against mqtt.meshat.se on 2026-09-01: meshcore/JKG/<node>/cmd arrives,
// meshhealth/v1/JKG/<node>/cmd does not. This is the topic CLAUDE.md specified.

// Same shape as AutoReply's: the filesystem call differs per platform, and each
// feature keeps its own copy rather than adding a shared header upstream edits.
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

// The node's own MQTT-originated commands run with the RTC time rather than 0.
// Zero is not a clock, it is a privilege signal: 'set prv.key', 'erase' and
// replacing 'cmd.pubkey' are gated on it, and serial and the web CLI both rely
// on physical or password authentication as their boundary. A remote caller has
// neither, so it must never present itself as local. The deny list in
// MqttControlLogic.h is the independent second guard on the same door.
MqttControl::MqttControl()
  : _fs(NULL), _enabled(false), _counter(0), _slot(0), _key_via(MQTTCTRL_KEY_VIA_USB),
    _alive_minutes(0), _boot(0), _mcc3_ready(false),
#ifdef WITH_MQTT_BRIDGE
#endif
    _commands(MQTTCTRL_CMD_MAX, MQTTCTRL_CMD_WINDOW_SECS),
    _transmits(MQTTCTRL_TRIGGER_MAX, MQTTCTRL_TRIGGER_WINDOW),
    _mesh_mode(MQTTCTRL_MESH_AUTO), _relay_mode(MQTTCTRL_RELAY_OWN)
{
  _pubkey[0] = 0;
  _ota_legacy[0] = 0;
  _ota_legacy[1] = OTA_AUTO_CHECK_HOURS_DEFAULT;
  _mcc3_key_for[0] = 0;
  memset(_node_key, 0, sizeof(_node_key));
  _rekey[0] = 0;
  _rekey_since = 0;
  _rekey_offered = false;
  _rekey_key_for[0] = 0;
  _rekey_done = false;
  memset(&_rekey_mcc3, 0, sizeof(_rekey_mcc3));
#ifdef WITH_MQTT_BRIDGE
  mqttCtrlQueueReset(&_queue);
#endif
}

void MqttControl::begin(FILESYSTEM* fs) {
  _fs = fs;
  load();
#ifdef WITH_MQTT_BRIDGE
  // Alive messages are ordered by (boot, sequence), so the boot counter moves before any
  // can go out; a message from an earlier boot then reads as older whatever its sequence.
  _boot++;
  save();
#endif
}

void MqttControl::load() {
  if (!_fs->exists(MQTTCTRL_CONFIG_FILE)) return;

  File file = openRead(_fs, MQTTCTRL_CONFIG_FILE);
  if (!file) return;
  uint8_t buf[MQTTCTRL_CONFIG_LEN];
  size_t len = file.read(buf, sizeof(buf));
  file.close();

  // The byte layout, every version of it, is mqttCtrlConfigDecode's (MqttControlLogic.h).
  MqttCtrlStoredConfig c;
  toStored(&c);
  if (!mqttCtrlConfigDecode(buf, len, MQTTCTRL_SLOTS, &c)) return;
  _enabled = c.enabled;
  _counter = c.counter;
  _slot = c.slot;
  memcpy(_pubkey, c.pubkey, sizeof(_pubkey));
  memcpy(_ota_legacy, c.ota_legacy, sizeof(_ota_legacy));
  _mesh_mode = c.mesh_mode;
  _key_via = c.key_via;
  _alive_minutes = c.alive_minutes;
  _boot = c.boot;
  _relay_mode = c.relay_mode;
}

void MqttControl::toStored(MqttCtrlStoredConfig* c) const {
  c->enabled = _enabled;
  c->counter = _counter;
  c->slot = _slot;
  memcpy(c->pubkey, _pubkey, sizeof(c->pubkey));
  memcpy(c->ota_legacy, _ota_legacy, sizeof(c->ota_legacy));
  c->mesh_mode = _mesh_mode;
  c->key_via = _key_via;
  c->alive_minutes = _alive_minutes;
  c->boot = _boot;
  c->relay_mode = _relay_mode;
}

void MqttControl::save() {
  MqttCtrlStoredConfig c;
  toStored(&c);
  uint8_t buf[MQTTCTRL_CONFIG_LEN];
  size_t len = mqttCtrlConfigEncode(&c, buf, sizeof(buf));
  File file = openWrite(_fs, MQTTCTRL_CONFIG_FILE);
  if (file) {
    file.write(buf, len);
    file.close();
  }
}

static bool buildOne(const char* iata, const char* leaf, const char* suffix,
                     char* out, size_t out_size) {
  return mqttCtrlBuildTopic(iata, leaf, suffix, out, out_size);
}

bool MqttControl::buildTopic(const char* iata, const char* node_hex,
                             char* out, size_t out_size) {
  return buildOne(iata, node_hex, "cmd", out, out_size);
}

#ifdef WITH_MQTT_BRIDGE

void MqttControl::stage(const char* topic, const uint8_t* payload, size_t len) {
  // Runs on the client's esp-mqtt event task, which has a fraction of the stack the
  // bridge task has and none of the loop task's right to touch flash. Copy, queue,
  // and get out; MQTTBridge.cpp:1630-1636 says the same about publishing. A full
  // queue drops the newer and counts it.
  if (!_enabled) return;
  mqttCtrlQueuePush(&_queue, topic, payload, len);
}

MqttCtrlResult MqttControl::drain(const mesh::Identity& owner, uint32_t now,
                                  MqttCommandRunner* runner, char* reply, size_t reply_size,
                                  MqttCtrlOutcome* out) {
  if (reply != NULL && reply_size > 0) reply[0] = 0;
  if (out != NULL) {
    out->authentic = false; out->mcc3 = false; out->counter = 0; out->command[0] = 0;
  }
  const MqttCtrlStaged* staged = mqttCtrlQueueFront(&_queue);
  if (staged == NULL) return MQTTCTRL_OK;

  MqttCtrlResult result = MQTTCTRL_OK;
  MqttCtrlEnvelope env;
  Mcc3Command mcc3;

  do {
    if (mcc3IsCommandTopic(staged->topic)) {
      // mcc3: the AEAD under K_cmd, then the owner's signature inside it; the topic is
      // this node's own, the only mcc/ topic it subscribes to.
      if (!_mcc3_ready) { result = MQTTCTRL_ERR_NO_OWNER_KEY; break; }
      result = mcc3OpenCommand(&_mcc3, _node_key, staged->payload, staged->payload_len,
                               [](void* ctx, const uint8_t sig[MCC3_SIG_LEN], const uint8_t* msg, size_t len) {
                                 return ((const mesh::Identity*)ctx)->verify(sig, msg, (int)len);
                               }, (void*)&owner, &mcc3);
      // Not the key's: a key that waits (`rekey`) is tried, and takes over if it signed this.
      const Mcc3Keys* waiting = result != MQTTCTRL_OK ? rekeyKeys(millis()) : NULL;
      mesh::Identity next;
      if (waiting != NULL && mesh::Utils::fromHex(next.pub_key, PUB_KEY_SIZE, _rekey)) {
        MqttCtrlResult again = mcc3OpenCommand(waiting, _node_key, staged->payload, staged->payload_len,
                                 [](void* ctx, const uint8_t sig[MCC3_SIG_LEN], const uint8_t* msg, size_t len) {
                                   return ((const mesh::Identity*)ctx)->verify(sig, msg, (int)len);
                                 }, (void*)&next, &mcc3);
        if (again == MQTTCTRL_OK) {
          rekeyTakeOver();
          result = MQTTCTRL_OK;
        }
      }
      if (result != MQTTCTRL_OK) break;
      memset(&env, 0, sizeof(env));
      env.counter = mcc3.counter;
      env.expiry = mcc3.expiry;
      env.command = mcc3.command;
      env.command_len = mcc3.command_len;
      if (out != NULL) {
        out->mcc3 = true;
        memcpy(out->rid, mcc3.rid, MCC3_RID_LEN);
      }
    } else {
      // Nothing else is subscribed to; whatever a broker delivers here anyway is no command.
      result = MQTTCTRL_ERR_BAD_VERSION;
      break;
    }
    result = execute(env, staged->topic, false, now, runner, reply, out);
  } while (false);

  mqttCtrlQueuePop(&_queue);
  return result;
}

MqttCtrlResult MqttControl::takeForward(Mcc3Forward* out) {
  const MqttCtrlStaged* staged = mqttCtrlQueueFront(&_queue);
  MqttCtrlResult result = mcc3OpenForward(mcc3Keys(), staged->payload, staged->payload_len, out);
  mqttCtrlQueuePop(&_queue);
  return result;
}
#endif

// Everything after the key has vouched for a command, on either road.
MqttCtrlResult MqttControl::execute(const MqttCtrlEnvelope& env, const char* topic, bool mesh,
                                    uint32_t now, MqttCommandRunner* runner, char* reply,
                                    MqttCtrlOutcome* out) {
  // Past this line the sender held the command key, so the outcome is safe to
  // publish however it turns out -- and the counter and command it signed are
  // what let the requester tell which question the answer belongs to.
  if (out != NULL) {
    out->authentic = true;
    out->counter = env.counter;
    size_t n = env.command_len < MQTTCTRL_MAX_COMMAND ? env.command_len : MQTTCTRL_MAX_COMMAND;
    memcpy(out->command, env.command, n);
    out->command[n] = 0;
  }

  MqttCtrlResult result = mesh ? mqttCtrlAuthoriseMesh(&env, _counter, now, FORK_AUTO_REPLY, FORK_UPLINK)
                               : mqttCtrlAuthorise(&env, _counter, now, FORK_AUTO_REPLY);
  if (result != MQTTCTRL_OK) return result;

  // The limiters are stateful and spend budget when asked, so they come after
  // every stateless check: otherwise anyone could drain the budget with garbage
  // that was going to be refused anyway.
  bool transmit = mqttCtrlIsTransmitCommand(env.command, env.command_len);

  // Stateless, so it runs before the limiters spend anything.
  result = mqttCtrlTransmitTopicResult(mqttCtrlBroadcastRefused(env.command, env.command_len), topic);
  if (result != MQTTCTRL_OK) return result;

  // One limiter is asked, never both: a limiter spends when asked, and the two
  // budgets are disjoint. A transmit costs a transmit; a parameter change costs a
  // command.
  const bool general_ok = mqttCtrlSpendsCommandBudget(transmit) ? _commands.allow(now) : true;
  const bool transmit_ok = mqttCtrlSpendsTransmitBudget(transmit) ? _transmits.allow(now) : true;
  result = mqttCtrlRateResult(transmit, general_ok, transmit_ok);
  if (result != MQTTCTRL_OK) return result;

  // Persisted before the command runs, never after. A counter written afterwards
  // is reopened by whatever crashes mid-command, and a silently repeated
  // 'trigger test' spends airtime nobody asked for. The cost is that a crashed
  // command is not retried, which is the right way round.
  _counter = env.counter;
  save();

  char command[MQTTCTRL_MAX_COMMAND + 1];
  memcpy(command, env.command, env.command_len);
  command[env.command_len] = 0;
  // `rekey` never reaches the console: only a command the key in use signed gets here.
  if (mqttCtrlIsRekey(command, env.command_len)) {
    char hex[PUB_KEY_SIZE * 2 + 1];
    if (!mqttCtrlRekeyParse(command, env.command_len, hex)) {
      strcpy(reply, "Err - use: rekey <the new PUBLIC key, 43 base64url characters>");
    } else if (strcasecmp(hex, _pubkey) == 0) {
      strcpy(reply, "Err - that is the key in use");
    } else {
      strcpy(_rekey, hex);
      _rekey_since = millis();
      _rekey_offered = true;
      _rekey_key_for[0] = 0;
      strcpy(reply, "OK - the new key waits 60 min: send a command signed by it");
    }
    return MQTTCTRL_OK;
  }
  if (runner != NULL) {
    runner->runCommand(mqttCtrlSenderStamp(now), command, reply);
  }
  return MQTTCTRL_OK;
}

void MqttControl::rekeyTakeOver() {
  strcpy(_pubkey, _rekey);
  _key_via = MQTTCTRL_KEY_VIA_REKEY;
  _mcc3 = _rekey_mcc3;
  strcpy(_mcc3_key_for, _rekey);
  _mcc3_ready = true;
  _rekey[0] = 0;
  _rekey_key_for[0] = 0;
  _rekey_offered = false;
  memset(&_rekey_mcc3, 0, sizeof(_rekey_mcc3));
  _rekey_done = true;
  save();
}

MqttCtrlResult MqttControl::meshCommand(const mesh::Identity& owner, const char* topic,
                                        const MqttCtrlMeshRequest& req, uint32_t now, bool open,
                                        MqttCommandRunner* runner, char* reply, bool* answer) {
  reply[0] = 0;
  *answer = false;
  uint8_t signed_bytes[MQTTCTRL_MAX_SIGNED];
  size_t signed_len = 0;
  if (!mqttCtrlBuildSignedMessage(topic, &req.env, signed_bytes, sizeof(signed_bytes), &signed_len)) {
    return MQTTCTRL_ERR_TOO_LONG;
  }
  if (!owner.verify(req.env.signature, signed_bytes, signed_len)) return MQTTCTRL_ERR_SIG_INVALID;
  if (!mqttCtrlCounterAccepted(_counter, req.env.counter)) return MQTTCTRL_ERR_REPLAY;
  if (_mesh_answered_any && !mqttCtrlCounterAccepted(_mesh_answered, req.env.counter)) return MQTTCTRL_ERR_REPLAY;
  if (!_mesh_answers.allows(now)) return MQTTCTRL_ERR_RATE_LIMITED;
  *answer = true;
  _mesh_answered = req.env.counter;
  _mesh_answered_any = true;
  if (!open) return MQTTCTRL_ERR_MESH_CLOSED;
  return execute(req.env, topic, true, now, runner, reply, NULL);
}

MqttCtrlResult MqttControl::meshCommand(const Mcc3Command& cmd, uint32_t now, bool open,
                                        MqttCommandRunner* runner, char* reply, bool* answer) {
  reply[0] = 0;
  *answer = false;
  if (_mesh_answered_any && !mqttCtrlCounterAccepted(_mesh_answered, cmd.counter)) return MQTTCTRL_ERR_REPLAY;
  if (!_mesh_answers.allows(now)) return MQTTCTRL_ERR_RATE_LIMITED;
  *answer = true;
  _mesh_answered = cmd.counter;
  _mesh_answered_any = true;
  if (!open) return MQTTCTRL_ERR_MESH_CLOSED;
  MqttCtrlEnvelope env;
  memset(&env, 0, sizeof(env));
  env.counter = cmd.counter;
  env.expiry = cmd.expiry;
  env.command = cmd.command;
  env.command_len = cmd.command_len;
  return execute(env, "", true, now, runner, reply, NULL);
}

bool MqttControl::handleCommand(MqttCtrlKeyCaller caller, const char* password,
                                const char* guest_password, int slot_count,
                                const char* command, char* reply) {
  // The key that authorises every signed command. A local caller sets, clears and reads
  // it; a remote admin may give a keyless node its first key and read its fingerprint;
  // the plane reaches neither, and its deny list refuses both as the second, independent
  // guard. The public half only, and the name says so: a private seed is also 64 hex
  // characters, and nothing here could tell the two apart.
  bool set_key = memcmp(command, "set cmd.pubkey", 14) == 0
                 && (command[14] == 0 || command[14] == ' ');
  if (set_key || strcmp(command, "get cmd.pubkey") == 0) {
    if (caller == MQTTCTRL_KEY_REMOTE) {
      strcpy(reply, "Err - serial only");
      return true;
    }
    if (!set_key) {
      if (_pubkey[0] == 0) {
        strcpy(reply, "> (not set)");
      } else if (caller == MQTTCTRL_KEY_LOCAL) {
        sprintf(reply, "> %s, set via %s", _pubkey, mqttCtrlKeyViaName(_key_via));
      } else {
        char fingerprint[MQTTCTRL_KEY_FINGERPRINT_LEN + 1];
        mqttCtrlKeyFingerprint(_pubkey, fingerprint);
        sprintf(reply, "> %s..., set via %s", fingerprint, mqttCtrlKeyViaName(_key_via));
      }
      return true;
    }
    const char* refusal = mqttCtrlKeySetRefusal(caller, _pubkey[0] != 0, password, guest_password);
    if (refusal != NULL) {
      strcpy(reply, refusal);
      return true;
    }
    const char* key = command[14] ? &command[15] : "";
    if (key[0] == 0 && caller == MQTTCTRL_KEY_LOCAL) {
      _pubkey[0] = 0;
      _key_via = MQTTCTRL_KEY_VIA_USB;
      save();
      strcpy(reply, "OK - key cleared");
    } else if (mqttOwnerKeyValid(key)) {
      strcpy(_pubkey, key);
      _key_via = caller == MQTTCTRL_KEY_LOCAL ? MQTTCTRL_KEY_VIA_USB : MQTTCTRL_KEY_VIA_ADMIN;
      save();
      strcpy(reply, "OK");
    } else {
      strcpy(reply, "Err - use: set cmd.pubkey <64 hex characters, the PUBLIC key>");
    }
    return true;
  }

#ifdef WITH_MQTT_BRIDGE
  // Read once at boot, when the bridge registers its subscriptions; a live change
  // would have to move them between clients from another core, for a setting that
  // changes about once in a node's life.
  if (memcmp(command, "set cmd.slot ", 13) == 0) {
    uint8_t slot = 0;
    if (!mqttCtrlParseSlot(&command[13], slot_count, &slot)) {
      sprintf(reply, "Err - use: set cmd.slot 0-%d", slot_count);
      return true;
    }
    _slot = slot;
    save();
    strcpy(reply, "OK - reboot to apply");
    return true;
  }

  if (strcmp(command, "get cmd.slot") == 0) {
    if (_slot == 0) strcpy(reply, "> 0 (none)");
    else sprintf(reply, "> %d", _slot);
    return true;
  }

  if (memcmp(command, "set alive.interval ", 19) == 0) {
    uint16_t minutes;
    if (!mqttCtrlAliveParseMinutes(&command[19], &minutes)) {
      sprintf(reply, "Err - use: set alive.interval %d-%d (minutes)", MQTTCTRL_ALIVE_MIN_MINUTES,
              MQTTCTRL_ALIVE_MAX_MINUTES);
      return true;
    }
    _alive_minutes = minutes;
    save();
    strcpy(reply, "OK");
    return true;
  }

  if (strcmp(command, "get alive.interval") == 0) {
    sprintf(reply, "> %d min", aliveMinutes());
    return true;
  }
#endif

  if (memcmp(command, "set cmd ", 8) == 0) {
    bool on = false;
    if (!forkParseOnOff(&command[8], &on)) {
      strcpy(reply, "Err - use: set cmd on [<broker host>]|off");
      return true;
    }
    _enabled = on;
    save();
    strcpy(reply, "OK");
    return true;
  }

  if (strcmp(command, "get cmd") == 0) {
    sprintf(reply, "> %s, counter %d", _enabled ? "on" : "off", (uint32_t)_counter);
    return true;
  }

  return false;
}

#endif
