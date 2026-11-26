#pragma once

#include <Arduino.h>
#include <ForkFeatures.h>
#include <Mesh.h>
#include <helpers/ForkText.h>
#include <helpers/IdentityStore.h>
#include <helpers/MqttControlLogic.h>
#include <helpers/MqttControlV3.h>
#include <helpers/TxtDataHelpers.h>
#ifdef WITH_MQTT_BRIDGE
  #include <helpers/MQTTPresets.h>
  #define MQTTCTRL_SLOTS  RUNTIME_MQTT_SLOTS
#else
  // Mesh only: no slot is listened on, and the one a file names is kept as it was written.
  #define MQTTCTRL_SLOTS  255
#endif


// Runs an allowlisted command through the node's CLI. An interface rather than a
// direct call on MyMesh, so this class stays free of the application it serves and
// its tests need no mesh at all.
struct MqttCommandRunner {
  virtual ~MqttCommandRunner() { }
  virtual void runCommand(uint32_t sender_timestamp, char* command, char* reply) = 0;
};

/**
 * \brief  Accepts signed commands over MQTT and runs them through the node's CLI.
 *
 * A login to the broker this rides on costs nothing to make, and any login may
 * publish a command to any node. Nothing here trusts the transport: a command is
 * executed only if it carries an Ed25519 signature by the key set with 'set cmd.pubkey' over the
 * topic and body together, its counter has never been seen before, it has not
 * expired, it is on the allowlist, and the rate limiter still has budget.
 *
 * The decisions are all in src/helpers/MqttControlLogic.h, where they are attacked
 * on the host (test/test_mqtt_control). This class is the state, the key and the I/O.
 *
 * Off unless 'set cmd on', deaf until 'set cmd.slot <n>' names the MQTT slot
 * to listen on (read at boot), and inert regardless without a key.
 */
// What drain() reports back so the caller can publish a result that names the
// request it answers. The counter is the correlation id: strictly increasing,
// persisted per node, and chosen by the requester.
struct MqttCtrlOutcome {
  bool authentic;                            // signature verified; safe to publish
  bool mcc3;                                 // came on mcc/cmd, so is answered sealed on mcc/r/<rid>
  uint32_t counter;                          // the request's counter
  uint8_t rid[MCC3_RID_LEN];                 // mcc3: the reply id the command named
  char command[MQTTCTRL_MAX_COMMAND + 1];    // echoed back, NUL-terminated

  MqttCtrlOutcome() : authentic(false), mcc3(false), counter(0) { command[0] = 0; }
};

class MqttControl {
  FILESYSTEM* _fs;
  bool _enabled;
  uint32_t _counter;          // highest command counter accepted, persisted
  uint8_t _slot;              // 1-based MQTT slot to listen and answer on, 0 = none
  char _pubkey[PUB_KEY_SIZE * 2 + 1];   // hex public key commands must be signed by
  uint8_t _key_via;           // MqttCtrlKeyVia: how _pubkey was set
  // Version 3 ends in the two automatic-OTA bytes releases up to ar-13 kept here. OTA
  // keeps its settings in /ota now; the bytes are carried as read, so an image that
  // rolls back to one of those releases still finds what it wrote.
  uint8_t _ota_legacy[2];
  uint16_t _alive_minutes;    // 0 = the default
  uint32_t _boot;             // boots of an image with the uplink, persisted
  // mcc3 (IATA-2): the node's three keys with its command key, derived once per key and
  // kept in RAM only, on every image -- the mesh road needs them too.
  Mcc3Keys _mcc3;
  bool _mcc3_ready;
  char _mcc3_key_for[PUB_KEY_SIZE * 2 + 1];    // the command key they were derived from
  // `rekey`: the key that waits (RAM only), its keys once derived, and whether it just took over.
  char _rekey[PUB_KEY_SIZE * 2 + 1];
  unsigned long _rekey_since;
  bool _rekey_offered;
  Mcc3Keys _rekey_mcc3;
  char _rekey_key_for[PUB_KEY_SIZE * 2 + 1];
  bool _rekey_done;
  uint8_t _node_key[PUB_KEY_SIZE];
#ifdef WITH_MQTT_BRIDGE
  MqttCtrlQueue _queue;                        // arrivals, MQTT event task to loop task
#endif
  MqttCtrlBudget _commands;
  MqttCtrlBudget _transmits;
  uint8_t _mesh_mode;         // MqttCtrlMeshMode
  uint8_t _relay_mode;        // MqttCtrlRelayMode
  MqttCtrlAirBudget _mesh_answers;
  // The newest counter answered over the mesh, run or refused. The saved counter moves only
  // when a command runs, so without this a refused request (the road closed, a denied
  // command) could be sent again by anyone who heard it, and be answered again.
  uint32_t _mesh_answered = 0;
  bool _mesh_answered_any = false;

  void load();
  void save();
  void toStored(MqttCtrlStoredConfig* c) const;
  MqttCtrlResult execute(const MqttCtrlEnvelope& env, bool mesh, uint32_t now, bool clock_never_set,
                         MqttCommandRunner* runner, char* reply, MqttCtrlOutcome* out);

public:
  MqttControl();

  void begin(FILESYSTEM* fs);
  bool isEnabled() const { return _enabled; }
  uint32_t counter() const { return _counter; }
  uint8_t slot() const { return _slot; }
  // `set cmd on` with no slot configured chooses one (MyMesh::autoSetupMqttControl).
  void setSlotAndEnable(uint8_t slot) { _slot = slot; _enabled = true; save(); }
  // Off and nothing else: the key, the slot and the counter stay (Fork::settleArrival).
  void switchOff() { if (_enabled) { _enabled = false; save(); } }
  const char* pubkey() const { return _pubkey; }
  uint8_t keyVia() const { return _key_via; }
  uint8_t meshMode() const { return _mesh_mode; }
  // An answer went out over the mesh: `air_ms` is the radio's estimate for its packet.
  void meshAnswered(uint32_t now, uint32_t air_ms) { _mesh_answers.spend(now, air_ms); }
  void setMeshMode(uint8_t mode) { _mesh_mode = mode; save(); }
  uint8_t relayMode() const { return _relay_mode; }
  void setRelayMode(uint8_t mode) { _relay_mode = mode; save(); }
  uint16_t aliveMinutes() const { return mqttCtrlAliveMinutes(_alive_minutes); }
  uint32_t boots() const { return _boot; }

  const char* mcc3KeyFor() const { return _mcc3_key_for; }
  void setMcc3Keys(const Mcc3Keys& keys, const char* key_for, const uint8_t* node_key) {
    _mcc3 = keys;
    StrHelper::strncpy(_mcc3_key_for, key_for, sizeof(_mcc3_key_for));
    memcpy(_node_key, node_key, PUB_KEY_SIZE);
    _mcc3_ready = key_for[0] != 0;
  }
  // NULL while there is no command key to seal to.
  const Mcc3Keys* mcc3Keys() const { return _mcc3_ready ? &_mcc3 : NULL; }

  // `rekey` (mqttCtrlRekeyParse): the key that waits, "" when none does or its hour is over.
  const char* rekeyWaiting(unsigned long now_ms) {
    if (!mqttCtrlRekeyWaiting(_rekey_offered, _rekey_since, now_ms)) { _rekey_offered = false; return ""; }
    return _rekey;
  }
  const char* rekeyKeyFor() const { return _rekey_key_for; }
  void setRekeyKeys(const Mcc3Keys& keys, const char* key_for) {
    _rekey_mcc3 = keys;
    StrHelper::strncpy(_rekey_key_for, key_for, sizeof(_rekey_key_for));
  }
  // Its keys, or NULL while none waits or they are not derived yet.
  const Mcc3Keys* rekeyKeys(unsigned long now_ms) {
    const char* k = rekeyWaiting(now_ms);
    return k[0] != 0 && strcmp(k, _rekey_key_for) == 0 ? &_rekey_mcc3 : NULL;
  }
  // The waiting key signed a command: it is the key from here on, saved.
  void rekeyTakeOver();
  // True once after a takeover, for the caller's log line.
  bool rekeyJustDone() { const bool d = _rekey_done; _rekey_done = false; return d; }

#ifdef WITH_MQTT_BRIDGE
  // Called on the MQTT event task. Copies and queues, nothing more: verification and
  // execution both need more stack than that task has, and executing a command
  // there would run a flash write on the network stack's own thread.
  void stage(const char* topic, const uint8_t* payload, size_t len);
  bool hasPending() const { return mqttCtrlQueueFront(&_queue) != NULL; }
  uint32_t dropped() const { return mqttCtrlQueueDropped(&_queue); }   // arrivals that found the queue full

  // Resolve the oldest staged command without executing it. It leaves the queue only
  // when it is disposed of, so every path that declines to run one must call this
  // or it stays at the front and holds back everything after it.
  void discard() { mqttCtrlQueuePop(&_queue); }

  // A forward for the relay shares this node's mcc/cmd topic with its commands and is told
  // from one by its kind byte. takeForward opens the oldest staged one under K_fwd and
  // takes it off the queue whatever the verdict; nothing it holds reaches the CLI.
  bool forwardPending() const {
    const MqttCtrlStaged* staged = mqttCtrlQueueFront(&_queue);
    return staged != NULL && mcc3IsCommandTopic(staged->topic)
           && mcc3PayloadKind(staged->payload, staged->payload_len) == MCC3_KIND_FORWARD;
  }
  MqttCtrlResult takeForward(Mcc3Forward* out);

  // Called on the loop task. Verifies the oldest staged command against 'owner' and runs
  // it through 'mesh' if it passes, writing a human-readable outcome into 'reply'
  // (at least 160 bytes, the CLI's own budget). Returns the verdict either way, so
  // the caller can publish a refusal without having to guess why.
  // 'out', when given, carries what the caller needs to publish an attributable
  // result: whether the signature verified, and the counter and command it
  // vouched for. 'authentic' decides whether a result may be published:
  // verification happens before the rate limiter (deliberately -- the limiters
  // spend budget when asked, so every stateless check runs first), which means a
  // bad-signature refusal is not rate limited. Publishing those would let anyone
  // who can log in to the broker drive unlimited publishes out of
  // this node by sending garbage. A flag set at the point of truth, rather than
  // a classification of result codes, so a code added later cannot drift into
  // the wrong half.
  MqttCtrlResult drain(const mesh::Identity& owner, uint32_t now,
                       MqttCommandRunner* runner, char* reply, size_t reply_size,
                       MqttCtrlOutcome* out = NULL);
#endif

  // The same, for a command that came over the mesh (0xC2), which mcc3MeshOpen has already
  // opened and verified. 'clock_never_set' is whether 'now' is a clock nobody set
  // (mqttCtrlClockUnset). 'open' is mqttCtrlMeshRoadOpen now. 'answer' says whether the
  // outcome may go back over the air: only once the key has vouched for the command, its
  // counter is new and the mesh budget allowed it, so that nobody who heard a request can
  // make the node transmit by sending it again.
  MqttCtrlResult meshCommand(const Mcc3Command& cmd, uint32_t now, bool clock_never_set, bool open,
                             MqttCommandRunner* runner, char* reply, bool* answer);

  // 'slot_count' bounds 'set cmd.slot'; see mqttCtrlParseSlot. 'caller' says who may
  // touch the key (mqttCtrlKeySetRefusal); 'password' and 'guest_password' are the node's,
  // which a remote admin's first install is judged by.
  bool handleCommand(MqttCtrlKeyCaller caller, const char* password, const char* guest_password,
                     int slot_count, const char* command, char* reply);
};
