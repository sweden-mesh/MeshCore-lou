#pragma once

#include <ForkFeatures.h>
#include <Mesh.h>
#include <helpers/IdentityStore.h>
#include <helpers/LoginThrottle.h>
#ifdef WITH_AUTO_REPLY
  #include "AutoReply.h"
#endif
#ifdef WITH_MQTT_BRIDGE
  #include <helpers/OtaAutoLogic.h>
#endif
#ifdef WITH_MQTT_COMMAND
  #ifdef WITH_MQTT_BRIDGE
    #include <helpers/bridges/MQTTBridge.h>
  #endif
  #include "MqttControl.h"
#endif

class MyMesh;
#ifdef WITH_MQTT_BRIDGE
class MQTTBridge;
#endif

/**
 * \brief  The fork's features, as the one object MyMesh holds.
 *
 * MyMesh calls into this at a handful of points -- begin, the bridge setup, loop,
 * the end of its own command parser -- and every feature hangs off those calls in
 * its own file, compiled only when its switch is on (include/ForkFeatures.h). The
 * features are fixed when the image is built, so the dispatch is static: no table,
 * no registration, nothing on the heap. MyMesh names this class a friend, so the
 * feature code reaches the mesh's own state rather than growing one accessor per
 * field on a file upstream keeps editing.
 */
class Fork {
  MyMesh& _mesh;
  LoginThrottle _logins = {};
#ifdef WITH_MQTT_BRIDGE
  // Signed pull OTA, in every Observer image (ForkOta.cpp).
  bool _ota_auto = false;
  uint8_t _ota_check_hours = OTA_AUTO_CHECK_HOURS_DEFAULT;
  uint32_t _ota_last_check = 0;        // unix secs of the last automatic check (RAM: a reboot re-checks)
  uint32_t _ota_auto_start_at = 0;     // local unix secs the scheduled update may start, 0 = none
  char _ota_last_result[64] = {0};
  bool _image_valid = false;           // marked valid, or found not to need it
  OtaImageProof _image_proof = {};     // what a pending image has shown so far
  const char* _image_proof_by = NULL;  // the network proof, for the log line
  unsigned long _ota_proof_next = 0;

  void otaBegin();
  void otaSave();
  bool handleOtaCommand(char* command, char* reply);
  void otaLoop();
  void autoOtaTick();
  void markRunningImageValid(const char* proof);
  void proveImageByBridge();
#endif
#ifdef WITH_AUTO_REPLY
  AutoReply _auto_reply;

  bool handleAutoReplyCommand(uint32_t sender_timestamp, char* command, char* reply);
  // The node's region, or NULL: `region home`, else `region default` unless country-wide
  // (autoReplyNodeRegion). What auto-reply's channel follows when 'autoreply.region' is unset.
  const char* nodeRegion();
  bool autoReplyScope(TransportKey* scope, const char* name);
  void sendAutoReplyFlood(mesh::Packet* pkt, uint32_t delay_millis, uint8_t path_hash_size,
                          const char* scope);
  uint32_t slottedReplyDelay();
  bool triggerProbe(const char* id, size_t id_len, uint8_t mode, char* reply);
  bool triggerPrivateProbe(const char* pubkey_hex, const char* id, size_t id_len, char* reply);
  bool onPrivateTest(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender,
                     const uint8_t* data, size_t len);
#endif
#ifdef WITH_MQTT_COMMAND
  MqttControl _mqtt_control;
  // The queue runs commands through a runner and, with the Observer bridge, the bridge
  // delivers to a sink; this member is both, so neither interface is a base of MyMesh.
  struct ControlLink : public MqttCommandRunner
#ifdef WITH_MQTT_BRIDGE
                     , public MQTTBridge::ControlSink
#endif
  {
    Fork& fork;
    explicit ControlLink(Fork& f) : fork(f) { }
#ifdef WITH_MQTT_BRIDGE
    void onControlMessage(const char* topic, const uint8_t* payload, size_t len) override;
#endif
    void runCommand(uint32_t sender_timestamp, char* command, char* reply) override;
  } _control_link { *this };
  uint32_t _mesh_down_since = 0;               // millis() the command slot went down, 0 while up
  uint32_t _mesh_ok = 0;                       // commands run over the mesh road
  uint32_t _mesh_refused = 0;                  // ... and requests on it that ran nothing

  bool handleMqttCommand(uint32_t sender_timestamp, bool mesh_admin, char* command, char* reply);
  void describeMqttControl(char* reply);
  void refreshMcc3Keys();
  bool onMeshCommand(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender,
                     const uint8_t* data, size_t len);
  void onMcc3MeshCommand(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender,
                         const uint8_t* data, size_t len);
  void answerMeshCommand(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender,
                         uint32_t tag, uint32_t counter, MqttCtrlResult result, const char* reply,
                         bool sealed);
#endif
#if defined(WITH_MQTT_COMMAND) && defined(WITH_MQTT_BRIDGE)
  // Owned here so the bridge's subscription list outlives every reconnect: mcc/cmd/<key>,
  // and in lou-20 the old scheme's per-node topic beside it while the node has a region.
  char _mcc3_topic[MQTTCTRL_MAX_TOPIC + 1] = {0};
  char _alive_topic[MQTTCTRL_MAX_TOPIC + 1] = {0};
  char _ctrl_topic[MQTTCTRL_MAX_TOPIC + 1] = {0};
  char _ctrl_result[MQTTCTRL_MAX_TOPIC + 1] = {0};
  const char* _ctrl_topics[2];
  MqttCtrlAliveClock _alive = {};
  uint32_t _alive_sequence = 0;
  // What alive says that is worth telling at once when it changes (mqttCtrlAliveNudge).
  char _alive_key_for[PUB_KEY_SIZE * 2 + 1] = {0};
  char _alive_region[MCC3_ALIVE_MAX_REGION + 2] = {0};
  uint16_t _alive_minutes = 0;
  MqttCtrlPing _ping = {};
  bool _ping_started = false;                 // the command just run armed a ping
  bool _ping_remote = false;                  // a ping that came over the plane is waiting
  MqttCtrlOutcome _ping_outcome;              // what its r2 answers, once it settles
  unsigned long _ctrl_last_verified_ms = 0;   // millis() of the last command the key vouched for
  uint32_t _ctrl_unverified = 0;               // commands refused before the key vouched for them
  uint8_t _ctrl_last_unverified = 0;           // ... and the last one's MqttCtrlResult
  char _ctrl_ping_topic[MQTTCTRL_MAX_TOPIC + 1] = {0};

  void setupMqttControl(MQTTBridge* bridge);
  void autoSetupMqttControl(const MqttCtrlSlotPlan& plan, char* reply);
  void pingMqttControl(char* reply);
  void formatNodeStats(char* reply);
  void loopMqttPing();
  void refreshMqttControlV2Key();
  void loopMqttControl();
  void loopAlive();
  const char* homeRegion();
  void publishMqttControlResult(MqttCtrlResult result, const MqttCtrlOutcome& outcome,
                                const char* reply);
#endif

public:
  explicit Fork(MyMesh& mesh) : _mesh(mesh) { }

  // After the ACL is loaded: each feature reads its own settings file.
  void begin(FILESYSTEM* fs);
#ifdef WITH_MQTT_BRIDGE
  // Before the bridge starts: anything that must be registered with it first.
  void attachBridge(MQTTBridge* bridge);
#endif
  // Every loop, after the radio.
  void loop();
  // A command upstream's own verbs did not take, before the common CLI sees it.
  // Returns true when a feature answered it in 'reply'. 'mesh_admin' is true only for a
  // command from a client logged in over the mesh with the admin password.
  bool handleCommand(uint32_t sender_timestamp, char* command, char* reply, bool mesh_admin);

  // The failed-login throttle, around every password login (handleLoginReq).
  bool loginRefused(const mesh::Identity& sender);
  void loginFailed(const mesh::Identity& sender);
  void loginPassed(const mesh::Identity& sender);

  // The Observer's region code (`set mqtt.iata`): what the command plane's topics are
  // named by and what auto-reply's legacy '#test-<iata>' channel is derived from. NULL
  // in a build without the Observer bridge, which has no region code at all.
  const char* observerIata() const;

  // Mesh::searchChannelsByHash and Mesh::onGroupDataRecv. Without auto-reply the
  // repeater knows no channel, which is what Mesh's own defaults say.
#ifdef WITH_AUTO_REPLY
  int searchChannelsByHash(const uint8_t* hash, mesh::GroupChannel channels[], int max_matches);
  void onGroupDataRecv(mesh::Packet* packet, uint8_t type, const mesh::GroupChannel& channel,
                       uint8_t* data, size_t len);
#else
  int searchChannelsByHash(const uint8_t*, mesh::GroupChannel[], int) { return 0; }
  void onGroupDataRecv(mesh::Packet*, uint8_t, const mesh::GroupChannel&, uint8_t*, size_t) { }
#endif

  // An anonymous request, before upstream reads it as a login or a query. Returns true
  // when it was a feature's, answered or refused, and upstream must not see it.
#if defined(WITH_AUTO_REPLY) || defined(WITH_MQTT_COMMAND)
  bool onAnonRequest(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender,
                     const uint8_t* data, size_t len);
#else
  bool onAnonRequest(mesh::Packet*, const uint8_t*, const mesh::Identity&, const uint8_t*, size_t) {
    return false;
  }
#endif
};
