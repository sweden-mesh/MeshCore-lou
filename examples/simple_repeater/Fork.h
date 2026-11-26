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
  // After the features have read their settings: a feature the image before this one did
  // not have is switched off, once (helpers/ForkArrival.h).
  void settleArrival();
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
  bool _ctrl_debug = false;                    // `set cmd.debug on`: until the next boot
  MqttCtrlRequesters _requesters;              // who was answered over the mesh, and the way back

  // One line on the serial console for each command heard and where it stopped, while
  // `set cmd.debug on` is in force. Never a key, a signature or more of a command than
  // its outcome.
  void debugLine(const char* fmt, ...);
  bool clockNeverSet(uint32_t now) const;
  void formatNodeStats(char* reply);
  void formatSensors(char* reply);

  bool handleMqttCommand(uint32_t sender_timestamp, bool mesh_admin, char* command, char* reply);
  void describeMqttControl(char* reply);
  void refreshMcc3Keys();
  void refreshRekeyKeys();
  bool onMeshCommand(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender,
                     const uint8_t* data, size_t len);
  void onMcc3MeshCommand(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender,
                         const uint8_t* data, size_t len);
  void answerMeshCommand(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender,
                         uint32_t tag, uint32_t counter, MqttCtrlResult result, const char* reply,
                         bool zero_hop);
#endif
#if defined(WITH_MQTT_COMMAND) && defined(WITH_MQTT_BRIDGE)
  // Owned here so the bridge's subscription list outlives every reconnect: mcc/cmd/<key>.
  char _mcc3_topic[MQTTCTRL_MAX_TOPIC + 1] = {0};
  char _alive_topic[MQTTCTRL_MAX_TOPIC + 1] = {0};
  const char* _ctrl_topics[1];
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
  uint32_t _ctrl_dropped_seen = 0;             // arrivals the full queue dropped, as last put on a debug line
  char _ctrl_ping_topic[MQTTCTRL_MAX_TOPIC + 1] = {0};
  // The relay (MqttRelayHooks.cpp): one forward at a time waits for its target's answer,
  // and the target is a peer of this node only while it does.
  Mcc3Relay _relay;
  struct RelayWait {
    mesh::Identity target;
    uint8_t secret[PUB_KEY_SIZE];
    uint8_t rid[MCC3_RID_LEN];               // where the result goes
    uint32_t tag;                            // what the answer must begin with
    uint32_t counter;
    uint32_t request;                        // the request's own counter, for the log (0: an old request)
    uint8_t sent;                            // MCC3_SENT_DIRECT or MCC3_SENT_FLOOD
    unsigned long since;                     // millis() the request went out
  } _relay_wait;

  void relayForward();
  bool sendRelayRequest(const Mcc3Forward& fwd, uint32_t* air_ms);
  bool isRelayPeer(const uint8_t* hash);
  void publishRelayResult(const uint8_t* rid, Mcc3ForwardResult& result);
  void onRelayResponse(mesh::Packet* packet, uint8_t path_len, const uint8_t* path,
                       const uint8_t* data, size_t len);
  void loopRelay();
  void describeRelay(char* reply);

  void repairMqttControlSlot();
  void setupMqttControl(MQTTBridge* bridge);
  void autoSetupMqttControl(const MqttCtrlSlotPlan& plan, char* reply);
  void pingMqttControl(char* reply);
  void loopMqttPing();
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

  // The command plane's peers, which are no clients of this node: the relay's target while a
  // forward waits for its answer, and whoever was answered over the mesh, for the path it
  // sends back. Mesh::searchPeersByHash, getPeerSharedSecret, onPeerDataRecv and
  // onPeerPathRecv. RELAY_PEER and REQUESTER_PEER + n stand in MyMesh's matching_peer_indexes
  // for them, above every client index and the neighbour-discovery overlay's. searchPeers
  // returns how many it wrote; the others true when the peer was the plane's and upstream
  // must not look it up. `reciprocate` is what Mesh::onPeerPathRecv returns then: whether the
  // sender of a flooded path return is sent the path it took.
  static const int RELAY_PEER = 2000;
  static const int REQUESTER_PEER = 2001;
#ifdef WITH_MQTT_COMMAND
  int searchPeers(const uint8_t* hash, int* indexes, int room);
  bool peerSecret(uint8_t* dest_secret, int peer_idx);
  bool onPeerData(mesh::Packet* packet, uint8_t type, int peer_idx, const uint8_t* data, size_t len);
  bool onPeerPath(mesh::Packet* packet, int peer_idx, const uint8_t* path, uint8_t path_len,
                  uint8_t extra_type, const uint8_t* extra, uint8_t extra_len, bool* reciprocate);
#else
  int searchPeers(const uint8_t*, int*, int) { return 0; }
  bool peerSecret(uint8_t*, int) { return false; }
  bool onPeerData(mesh::Packet*, uint8_t, int, const uint8_t*, size_t) { return false; }
  bool onPeerPath(mesh::Packet*, int, const uint8_t*, uint8_t, uint8_t, const uint8_t*, uint8_t, bool*) {
    return false;
  }
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
