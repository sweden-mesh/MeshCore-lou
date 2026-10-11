#include "MqttControl.h"

#ifdef WITH_MQTT_COMMAND

#include <helpers/OtaAutoLogic.h>

#include <helpers/MQTTPresets.h>
#include <helpers/TxtDataHelpers.h>

#define MQTTCTRL_CONFIG_FILE  "/mqttcontrol"
#define MQTTCTRL_CONFIG_VER_1 1
#define MQTTCTRL_CONFIG_VER   3      // v3 (ar-11): ota.auto and ota.check.hours appended

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
// 'set mqtt.cmd.pubkey' are gated on it, and serial and the web CLI both rely on
// physical or password authentication as their boundary. A remote caller has
// neither, so it must never present itself as local. The allowlist in
// MqttControlLogic.h is the independent second guard on the same door.
MqttControl::MqttControl()
  : _fs(NULL), _enabled(false), _counter(0), _slot(0),
    _ota_auto(false), _ota_check_hours(OTA_AUTO_CHECK_HOURS_DEFAULT), _v2_ready(false),
    _commands(MQTTCTRL_CMD_MAX, MQTTCTRL_CMD_WINDOW_SECS),
    _transmits(MQTTCTRL_TRIGGER_MAX, MQTTCTRL_TRIGGER_WINDOW)
{
  _pubkey[0] = 0;
  _v2_key_for[0] = 0;
  _v2_topic[0] = 0;
  _staged.pending = false;
  _staged.payload_len = 0;
  _staged.topic[0] = 0;
  _staged.payload[0] = 0;
}

void MqttControl::begin(FILESYSTEM* fs) {
  _fs = fs;
  load();
}

void MqttControl::load() {
  if (!_fs->exists(MQTTCTRL_CONFIG_FILE)) return;

  File file = openRead(_fs, MQTTCTRL_CONFIG_FILE);
  if (file) {
    uint8_t ver = 0;
    file.read(&ver, 1);
    // Append-only, as /autoreply is. A v1 file has no slot and no key, so it loads
    // deaf and keyless: guessing a slot would subscribe on a broker that may refuse
    // it, and the key it used lives in mqtt.owner, which is somebody's ownership
    // claim rather than a command key.
    if (ver >= MQTTCTRL_CONFIG_VER_1) {
      uint8_t enabled = 0;
      file.read(&enabled, 1);
      file.read((uint8_t *) &_counter, sizeof(_counter));
      if (ver >= 2) {
        file.read(&_slot, 1);
        file.read((uint8_t *) _pubkey, sizeof(_pubkey));
      }
      if (ver >= 3) {
        uint8_t a = 0;
        file.read(&a, 1);
        file.read(&_ota_check_hours, 1);
        _ota_auto = a != 0;
      }
      if (_ota_check_hours == 0) _ota_check_hours = OTA_AUTO_CHECK_HOURS_DEFAULT;
      _enabled = enabled != 0;
      if (_slot > RUNTIME_MQTT_SLOTS) _slot = 0;
      _pubkey[sizeof(_pubkey) - 1] = 0;
    }
    file.close();
  }
}

void MqttControl::save() {
  File file = openWrite(_fs, MQTTCTRL_CONFIG_FILE);
  if (file) {
    uint8_t ver = MQTTCTRL_CONFIG_VER;
    uint8_t enabled = _enabled ? 1 : 0;
    file.write(&ver, 1);
    file.write(&enabled, 1);
    file.write((const uint8_t *) &_counter, sizeof(_counter));
    file.write(&_slot, 1);
    file.write((const uint8_t *) _pubkey, sizeof(_pubkey));
    uint8_t a = _ota_auto ? 1 : 0;
    file.write(&a, 1);
    file.write(&_ota_check_hours, 1);
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

bool MqttControl::buildBroadcastTopic(const char* iata, char* out, size_t out_size) {
  return buildOne(iata, "all", "cmd", out, out_size);
}

bool MqttControl::buildResultTopic(const char* iata, const char* node_hex,
                                   char* out, size_t out_size) {
  return buildOne(iata, node_hex, "res", out, out_size);
}

void MqttControl::stage(const char* topic, const uint8_t* payload, size_t len) {
  // Runs on the client's esp-mqtt event task, which has a fraction of the stack the
  // bridge task has and none of the loop task's right to touch flash. Copy, flag,
  // and get out; MQTTBridge.cpp:1630-1636 says the same about publishing.
  if (!_enabled || _staged.pending) return;          // a full slot drops the newer
  if (topic == NULL || payload == NULL) return;
  if (len == 0 || len > MQTTCTRL_MAX_PAYLOAD) return;
  if (strlen(topic) > MQTTCTRL_MAX_TOPIC) return;

  memcpy(_staged.topic, topic, strlen(topic) + 1);
  memcpy(_staged.payload, payload, len);
  _staged.payload[len] = 0;
  _staged.payload_len = len;
  _staged.pending = true;
}

MqttCtrlResult MqttControl::drain(const mesh::Identity& owner, uint32_t now,
                                  MqttCommandRunner* runner, char* reply, size_t reply_size,
                                  MqttCtrlOutcome* out) {
  if (reply != NULL && reply_size > 0) reply[0] = 0;
  if (out != NULL) { out->authentic = false; out->v2 = false; out->counter = 0; out->command[0] = 0; }
  if (!_staged.pending) return MQTTCTRL_OK;

  MqttCtrlResult result = MQTTCTRL_OK;
  MqttCtrlEnvelope env;
  char v2_text[MQTTV2_CMD_PAD_LARGE + 1];

  do {
    if (mqttV2IsEnvelope(_staged.payload, _staged.payload_len)) {
      // Sealed (v2): only on this node's own topic -- a broadcast stays v1 -- and the
      // AEAD opened before anything else is believed. The tag proves the holder of the
      // command key, which is what the v1 signature check proves below.
      if (!_v2_ready) { result = MQTTCTRL_ERR_NO_OWNER_KEY; break; }
      if (strcmp(_staged.topic, _v2_topic) != 0) { result = MQTTCTRL_ERR_BAD_VERSION; break; }
      result = mqttV2OpenCommand(_v2_key, _staged.payload, _staged.payload_len, &env, v2_text);
      if (result != MQTTCTRL_OK) break;
      if (env.command_len > MQTTCTRL_MAX_COMMAND) { result = MQTTCTRL_ERR_TOO_LONG; break; }
      if (out != NULL) out->v2 = true;
    } else {
      result = mqttCtrlParseEnvelope(_staged.payload, _staged.payload_len, &env);
      if (result != MQTTCTRL_OK) break;

      // The signature is checked before anything it protects, and over the topic as
      // well as the body: without the topic bound in, a command signed for one node
      // could be captured and republished on another's, and each node's own counter
      // would never notice.
      uint8_t signed_bytes[MQTTCTRL_MAX_SIGNED];
      size_t signed_len = 0;
      if (!mqttCtrlBuildSignedMessage(_staged.topic, &env, signed_bytes,
                                      sizeof(signed_bytes), &signed_len)) {
        result = MQTTCTRL_ERR_TOO_LONG;
        break;
      }
      if (!owner.verify(env.signature, signed_bytes, signed_len)) {
        result = MQTTCTRL_ERR_SIG_INVALID;   // parsed as hex, did not verify
        break;
      }
    }
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

    result = mqttCtrlAuthorise(&env, _counter, now);
    if (result != MQTTCTRL_OK) break;

    // The limiters are stateful and spend budget when asked, so they come after
    // every stateless check: otherwise anyone could drain the budget with garbage
    // that was going to be refused anyway.
    bool transmit = mqttCtrlIsTransmitCommand(env.command, env.command_len);

    // Stateless, so it runs before the limiters spend anything.
    result = mqttCtrlTransmitTopicResult(transmit, _staged.topic);
    if (result != MQTTCTRL_OK) break;

    // One limiter is asked, never both: a limiter spends when asked, and the two
    // budgets are disjoint. A transmit costs a transmit; a parameter change costs a
    // command.
    const bool general_ok = mqttCtrlSpendsCommandBudget(transmit) ? _commands.allow(now) : true;
    const bool transmit_ok = mqttCtrlSpendsTransmitBudget(transmit) ? _transmits.allow(now) : true;
    result = mqttCtrlRateResult(transmit, general_ok, transmit_ok);
    if (result != MQTTCTRL_OK) break;

    // Persisted before the command runs, never after. A counter written afterwards
    // is reopened by whatever crashes mid-command, and a silently repeated
    // 'trigger test' spends airtime nobody asked for. The cost is that a crashed
    // command is not retried, which is the right way round.
    _counter = env.counter;
    save();

    char command[MQTTCTRL_MAX_COMMAND + 1];
    memcpy(command, env.command, env.command_len);
    command[env.command_len] = 0;
    if (runner != NULL) {
      runner->runCommand(mqttCtrlSenderStamp(now), command, reply);
    }
  } while (false);

  _staged.pending = false;
  return result;
}

bool MqttControl::handleCommand(uint32_t sender_timestamp, int slot_count,
                                const char* command, char* reply) {
  // The key that authorises every signed command, so neither half of it is reachable
  // from anything but a caller who is physically present. The MQTT allowlist refuses
  // it too; this is the second, independent guard. The public half only, and the
  // name says so: a private seed is also 64 hex characters, and nothing here could
  // tell the two apart.
  bool set_key = memcmp(command, "set mqtt.cmd.pubkey", 19) == 0
                 && (command[19] == 0 || command[19] == ' ');
  if (set_key || strcmp(command, "get mqtt.cmd.pubkey") == 0) {
    if (sender_timestamp != 0) {
      strcpy(reply, "Err - serial only");
      return true;
    }
    if (!set_key) {
      sprintf(reply, "> %s", _pubkey[0] ? _pubkey : "(not set)");
      return true;
    }
    const char* key = command[19] ? &command[20] : "";
    if (key[0] == 0) {
      _pubkey[0] = 0;
      save();
      strcpy(reply, "OK - key cleared");
    } else if (mqttOwnerKeyValid(key)) {
      strcpy(_pubkey, key);
      save();
      strcpy(reply, "OK");
    } else {
      strcpy(reply, "Err - use: set mqtt.cmd.pubkey <64 hex characters, the PUBLIC key>");
    }
    return true;
  }

  // Read once at boot, when the bridge registers its subscriptions; a live change
  // would have to move them between clients from another core, for a setting that
  // changes about once in a node's life.
  if (memcmp(command, "set mqtt.cmd.slot ", 18) == 0) {
    uint8_t slot = 0;
    if (!mqttCtrlParseSlot(&command[18], slot_count, &slot)) {
      sprintf(reply, "Err - use: set mqtt.cmd.slot 0-%d", slot_count);
      return true;
    }
    _slot = slot;
    save();
    strcpy(reply, "OK - reboot to apply");
    return true;
  }

  if (strcmp(command, "get mqtt.cmd.slot") == 0) {
    if (_slot == 0) strcpy(reply, "> 0 (none)");
    else sprintf(reply, "> %d", _slot);
    return true;
  }

  if (memcmp(command, "set mqtt.cmd ", 13) == 0) {
    bool on = false;
    if (!autoReplyParseOnOff(&command[13], &on)) {
      strcpy(reply, "Err - use: set mqtt.cmd on|off");
      return true;
    }
    _enabled = on;
    save();
    strcpy(reply, "OK");
    return true;
  }

  if (memcmp(command, "set ota.auto ", 13) == 0) {
    bool on = false;
    if (!autoReplyParseOnOff(&command[13], &on)) {
      strcpy(reply, "Err - use: set ota.auto on|off");
      return true;
    }
    _ota_auto = on;
    save();
    sprintf(reply, "OK - automatic update %s, checked every %u h, never 00-06 local", on ? "on" : "off", (unsigned)_ota_check_hours);
    return true;
  }
  if (memcmp(command, "set ota.check.hours ", 20) == 0) {
    int hours = atoi(&command[20]);
    if (hours < OTA_AUTO_CHECK_HOURS_MIN || hours > OTA_AUTO_CHECK_HOURS_MAX) {
      sprintf(reply, "Err - use: set ota.check.hours %d-%d", OTA_AUTO_CHECK_HOURS_MIN, OTA_AUTO_CHECK_HOURS_MAX);
      return true;
    }
    _ota_check_hours = (uint8_t)hours;
    save();
    sprintf(reply, "OK - checked every %d h", hours);
    return true;
  }
  if (strcmp(command, "get ota.auto") == 0) {
    sprintf(reply, "> %s, every %u h", _ota_auto ? "on" : "off", (unsigned)_ota_check_hours);
    return true;
  }

  if (strcmp(command, "get mqtt.cmd") == 0) {
    sprintf(reply, "> %s, counter %d", _enabled ? "on" : "off", (uint32_t)_counter);
    return true;
  }

  return false;
}

#endif
