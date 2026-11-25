#pragma once

#include "MQTTPrefsStorage.h"
#include "MqttControlLogic.h"

#ifdef WITH_MQTT_BRIDGE

// The command slot's repair at start. A node set up before the `mccontrol` preset has the
// plane on a custom slot that signs in with a password (mqttCtrlSlotNeedsRepair); what
// cures it is what a bare `set cmd on` writes, so that is done for it, once, before the
// bridge reads the slots. The plane's own settings are not part of it: a plane that was
// switched off gets its slot mended and stays off.

// One slot's login as MQTTPrefs holds it: what the repair changes, and what goes back
// when the save fails.
struct MqttCtrlSlotLogin {
  char preset[sizeof(((MQTTPrefs *) 0)->mqtt_slot_preset[0])];
  char host[sizeof(((MQTTPrefs *) 0)->mqtt_slot_host[0])];
  char username[sizeof(((MQTTPrefs *) 0)->mqtt_slot_username[0])];
  char password[sizeof(((MQTTPrefs *) 0)->mqtt_slot_password[0])];
  char audience[sizeof(((MQTTPrefs *) 0)->mqtt_slot_audience[0])];
  uint16_t port;
  uint16_t filter;
};

static inline void mqttCtrlSlotLoginRead(const MQTTPrefs* prefs, int idx, MqttCtrlSlotLogin* login) {
  memcpy(login->preset, prefs->mqtt_slot_preset[idx], sizeof(login->preset));
  memcpy(login->host, prefs->mqtt_slot_host[idx], sizeof(login->host));
  memcpy(login->username, prefs->mqtt_slot_username[idx], sizeof(login->username));
  memcpy(login->password, prefs->mqtt_slot_password[idx], sizeof(login->password));
  memcpy(login->audience, prefs->mqtt_slot_audience[idx], sizeof(login->audience));
  login->port = prefs->mqtt_slot_port[idx];
  login->filter = prefs->mqtt_slot_packet_filter[idx];
}

static inline void mqttCtrlSlotLoginWrite(MQTTPrefs* prefs, int idx, const MqttCtrlSlotLogin* login) {
  memcpy(prefs->mqtt_slot_preset[idx], login->preset, sizeof(login->preset));
  memcpy(prefs->mqtt_slot_host[idx], login->host, sizeof(login->host));
  memcpy(prefs->mqtt_slot_username[idx], login->username, sizeof(login->username));
  memcpy(prefs->mqtt_slot_password[idx], login->password, sizeof(login->password));
  memcpy(prefs->mqtt_slot_audience[idx], login->audience, sizeof(login->audience));
  prefs->mqtt_slot_port[idx] = login->port;
  prefs->mqtt_slot_packet_filter[idx] = login->filter;
}

// Puts the plane's slot (1-based, 0 = none) on the preset when it is an old password
// slot, and says whether anything changed; the caller saves, and on a failed save writes
// 'was' back. The username, the password and the port go as well: a preset ignores them,
// but left in the file they would sign the slot in again the day it is made custom.
// Nothing is touched while the settings are held: they are this boot's defaults standing
// in for a file that could not be read, and must not be written over it.
static inline bool mqttCtrlRepairPlaneSlot(MQTTPrefs* prefs, int plane_slot, bool settings_held,
                                           MqttCtrlSlotLogin* was) {
  if (prefs == NULL || was == NULL || settings_held) return false;
  if (plane_slot < 1 || plane_slot > MQTT_PREFS_SLOT_COUNT) return false;
  const int idx = plane_slot - 1;
  if (!mqttCtrlSlotNeedsRepair(prefs->mqtt_slot_preset[idx], prefs->mqtt_slot_host[idx],
                               prefs->mqtt_slot_username[idx], prefs->mqtt_slot_audience[idx])) {
    return false;
  }
  MqttCtrlSlotPlan plan;
  if (mqttCtrlPlanSlot("set cmd on", &plan) != MQTTCTRL_SETUP_PRESET) return false;
  mqttCtrlSlotLoginRead(prefs, idx, was);
  mqttCtrlApplySlotPlan(&plan, prefs->mqtt_slot_preset[idx], sizeof(prefs->mqtt_slot_preset[idx]),
                        prefs->mqtt_slot_host[idx], sizeof(prefs->mqtt_slot_host[idx]),
                        prefs->mqtt_slot_audience[idx], sizeof(prefs->mqtt_slot_audience[idx]),
                        &prefs->mqtt_slot_packet_filter[idx]);
  memset(prefs->mqtt_slot_username[idx], 0, sizeof(prefs->mqtt_slot_username[idx]));
  memset(prefs->mqtt_slot_password[idx], 0, sizeof(prefs->mqtt_slot_password[idx]));
  prefs->mqtt_slot_port[idx] = 0;
  return true;
}

#endif
