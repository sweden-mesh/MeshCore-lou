// Signed pull OTA, in every Observer image of this fork whatever its features: the
// settings in /ota, 'get ota', the automatic check, and the proof that marks a newly
// flashed image good. The manifest, the signature and the download are the board's
// (ESP32Board.cpp); the deferred flash itself is MyMesh's, as in the Observer.
#include "MyMesh.h"

#ifdef WITH_MQTT_BRIDGE

#include <helpers/ForkText.h>

#define OTA_SETTINGS_FILE        "/ota"
#define OTA_LEGACY_SETTINGS_FILE "/mqttcontrol"

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

static size_t readSettings(FILESYSTEM* fs, const char* filename, uint8_t* buf, size_t size) {
  if (!fs->exists(filename)) return 0;
  File file = openRead(fs, filename);
  if (!file) return 0;
  size_t n = file.read(buf, size);
  file.close();
  return n;
}

// /ota when it exists; otherwise what a release up to ar-13 kept in /mqttcontrol,
// which is read and left as it is, whether or not this build has the command plane.
void Fork::otaBegin() {
  uint8_t buf[OTA_AUTO_LEGACY_LEN];
  size_t n = readSettings(_mesh._fs, OTA_SETTINGS_FILE, buf, sizeof(buf));
  if (n > 0) {
    otaAutoDecode(buf, n, &_ota_auto, &_ota_check_hours);
  } else {
    n = readSettings(_mesh._fs, OTA_LEGACY_SETTINGS_FILE, buf, sizeof(buf));
    otaAutoDecodeLegacy(buf, n, &_ota_auto, &_ota_check_hours);
  }
}

void Fork::otaSave() {
  File file = openWrite(_mesh._fs, OTA_SETTINGS_FILE);
  if (file) {
    uint8_t buf[OTA_AUTO_FILE_LEN];
    otaAutoEncode(buf, _ota_auto, _ota_check_hours);
    file.write(buf, sizeof(buf));
    file.close();
  }
}

bool Fork::handleOtaCommand(char* command, char* reply) {
  if (strcmp(command, "get ota") == 0) {
#if defined(OTA_MANIFEST_BASE)
    sprintf(reply, "> channel %s, auto %s/%uh, last check %s, next %s",
            OTA_MANIFEST_BASE, _ota_auto ? "on" : "off", (unsigned)_ota_check_hours,
            _ota_last_result[0] ? _ota_last_result : "(none yet)",
            _ota_auto_start_at ? "scheduled" : "-");
#else
    strcpy(reply, "> no channel in this build (built without build.sh)");
#endif
    return true;
  }
  if (memcmp(command, "set ota.auto ", 13) == 0) {
    bool on = false;
    if (!forkParseOnOff(&command[13], &on)) {
      strcpy(reply, "Err - use: set ota.auto on|off");
      return true;
    }
    _ota_auto = on;
    otaSave();
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
    otaSave();
    sprintf(reply, "OK - checked every %d h", hours);
    return true;
  }
  if (strcmp(command, "get ota.auto") == 0) {
    sprintf(reply, "> %s, every %u h", _ota_auto ? "on" : "off", (unsigned)_ota_check_hours);
    return true;
  }
  return false;
}

void Fork::otaLoop() {
#if defined(OTA_MANIFEST_BASE)
  autoOtaTick();
#endif
  proveImageByBridge();
}

#ifdef ESP_PLATFORM
#include <esp_ota_ops.h>
// The Arduino core would mark the image valid at boot; verifyRollbackLater() says
// we will do it ourselves, once the image has shown it works.
extern "C" bool verifyRollbackLater() { return true; }

// Rollback (ar-11): a freshly flashed image is pending until it proves itself, and
// only then is it marked valid; until then a reboot (watchdog, power) returns to the
// previous image. What counts as proof is the caller's: a verified signed command
// with the command plane, the bridge without it (otaImageProvenByBridge).
void Fork::markRunningImageValid(const char* proof) {
  if (_image_valid) return;
  _image_valid = true;
  const esp_partition_t* running = esp_ota_get_running_partition();
  esp_ota_img_states_t state;
  if (running && esp_ota_get_state_partition(running, &state) == ESP_OK &&
      state == ESP_OTA_IMG_PENDING_VERIFY) {
    esp_ota_mark_app_valid_cancel_rollback();
    MESH_DEBUG_PRINTLN("OTA: running image marked valid after %s", proof);
  }
}
#else
void Fork::markRunningImageValid(const char*) { _image_valid = true; }
#endif

// While the node is not listening for commands nothing is ever verified, so the bridge
// is the proof: a slot has published since boot, and the image has stayed up ten
// minutes (otaImageProven). Asked every few seconds until it holds, then never again.
void Fork::proveImageByBridge() {
  if (_image_valid) return;
#ifdef WITH_MQTT_COMMAND
  // Listening means a signed command could arrive and verify: on, a slot, topics (a
  // region) and a usable command key.
  const bool listening = _mqtt_control.isEnabled() && _mqtt_control.slot() != 0 &&
                         _ctrl_topic[0] != 0 && mqttCtrlOwnerReady(_mqtt_control.pubkey()) == MQTTCTRL_OK;
#else
  const bool listening = false;
#endif
  if (listening) return;
  const unsigned long now = millis();
  if (now < OTA_PROOF_UPTIME_MS || (long)(now - _ota_proof_next) < 0) return;
  _ota_proof_next = now + 5000;
  bool published = false;
  for (int i = 0; i < RUNTIME_MQTT_SLOTS && !published; i++) {
    MQTTBridge::SlotStatusSnapshot slot;
    published = MQTTBridge::getSlotStatusSnapshot(i, &slot) && slot.publish_ok > 0;
  }
  if (otaImageProven(false, listening, now, published)) {
    markRunningImageValid("the bridge published and it ran ten minutes");
  }
}

#if defined(OTA_MANIFEST_BASE)
// Automatic pull OTA (ar-11): `set ota.auto on`. A check when the interval is up; when a
// newer signed build is on offer, the update is scheduled after this node's own hold-off
// (0..60 min from its key, so a region spreads over the hour) and never in the night
// window, through the same deferred path `ota update` uses -- the bridge is paused,
// the image verified, the node rebooted, and the old image returns if the new one
// never proves itself (docs/ota.md). The schedule is OtaAutoLogic.h.
void Fork::autoOtaTick() {
  if (!_ota_auto || _mesh._ota_update_at != 0) return;
  uint32_t now = _mesh.getRTCClock()->getCurrentTime();
  if (now == 0) return;
  uint32_t local_now = now + (uint32_t)((int32_t)_mesh._cli.getObserverPrefs()->timezone_offset * 3600);   // hours
  if (_ota_auto_start_at) {
    if (local_now >= _ota_auto_start_at) {
      _ota_auto_start_at = 0;
      Serial.println("OTA: automatic update starting");
      _mesh.beginDeferredOtaUpdate();
    }
    return;
  }
  if (!otaAutoCheckDue(now, _ota_last_check, _ota_check_hours)) return;
  _ota_last_check = now;
  char reply[160];
  bool available = _mesh._cli.getBoard()->otaFromManifest(_mesh.getFirmwareVer(), true, reply);
  StrHelper::strncpy(_ota_last_result, reply, sizeof(_ota_last_result));
  Serial.print("OTA: automatic check: "); Serial.println(reply);
  if (!available) return;
  uint32_t holdoff = otaAutoHoldoffSecs(_mesh.self_id.pub_key, PUB_KEY_SIZE);
  _ota_auto_start_at = otaAutoStartAt(local_now, holdoff);
  Serial.printf("OTA: update scheduled in %lu s\n", (unsigned long)(_ota_auto_start_at - local_now));
}
#endif

#endif
