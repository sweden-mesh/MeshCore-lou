#pragma once

#include <Arduino.h>
#include <Mesh.h>
#include <helpers/AutoReplyLogic.h>
#include <helpers/IdentityStore.h>
#include <helpers/RegionMap.h>
#include <helpers/SlidingBudget.h>

// the keyword that triggers a reply (matched on its own, case-insensitive)
#ifndef AUTOREPLY_KEYWORD
  #define AUTOREPLY_KEYWORD   "test"
#endif

#define AUTOREPLY_MAX_TEXT    112
// the requester's name is echoed back so they can pick their reply out of several
#define AUTOREPLY_MAX_SENDER  16
// '#test-' plus the longest region name: a companion's 32-byte channel name
#define AUTOREPLY_MAX_CHANNEL 32
// a region name bounding how far a reply floods, or empty for the request's own scope
#define AUTOREPLY_MAX_REGION  31
#define AUTOREPLY_MAX_PAYLOAD (5 + AUTOREPLY_MAX_TEXT)   // timestamp + flags + text
// how many leading bytes of a requester's key name it in a private reply's brackets
#define AUTOREPLY_PRIVATE_WHO 4

// The reply budgets live in AutoReplyLogic.h, where the host suite can reach them.

// Where a built reply goes. For a flood, nothing but the mode; for a private mode
// the requester's public key, decoded from the request that carried it.
struct AutoReplyTarget {
  uint8_t mode;
  uint8_t pubkey[PUB_KEY_SIZE];
};

// One channel the node answers on, and the budgets its requests spend.
struct AutoReplyLane {
  char name[AUTOREPLY_MAX_CHANNEL];   // empty = this lane answers nothing
  mesh::GroupChannel channel;
  AutoReplyBudgets budgets;

  AutoReplyLane() { name[0] = 0; }
  bool ready() const { return name[0] != 0; }
};

/**
 * \brief  Replies to a keyword on the node's regional test channel, with a signal
 *         + path report.
 *
 * The channel is '#test-<region>', named by 'set autoreply.region' -- the same name
 * that bounds how far a reply floods -- and its key is the first 16 bytes of sha256
 * of that name, so there is no PSK to configure or share, and any client that adds a
 * channel of the same name can use it. While 'autoreply.legacy' is on (the default)
 * the node also answers on '#test-<iata>', the channel releases before ar-12 derived
 * from 'set mqtt.iata', so an upgrade never silences a node. Switched on with
 * 'set autoreply on'; a node with neither channel stays silent either way.
 *
 * Every repeater in range answers the same trigger, so requests from further away than
 * 'autoreply.hops' are ignored, replies are rate limited per sender and in total, and
 * are staggered by a random delay.
 *
 * How a reply is sent is the requester's choice first and the node's second: a
 * request may name a mode (see AutoReplyLogic.h), and one that names none is answered
 * in the mode set with 'set autoreply.mode' -- flood, the group text every node sends
 * today, or private/direct, a text message to the requester alone.
 */
class AutoReply {
  FILESYSTEM* _fs;
  bool _enabled;
  bool _legacy;                 // also answer on '#test-<iata>'
  uint8_t _hops;                // max hop count of a request we will answer
  bool _direct_flood;           // flood the answer to a request that arrived direct
  uint16_t _window_start;       // seconds after the request that the window opens
  uint16_t _window_end;         // and closes; every reply lands between them
  uint8_t _slots;               // how many slots the window is cut into
  char _region[AUTOREPLY_MAX_REGION + 1];   // scope for the reply, empty = mirror the request
  uint8_t _mode;                // how a request that names no mode is answered
  uint8_t _slot;                // assigned reply slot, 0 = derive one from our key
  bool _private;                // answer a private test request sent to this node directly

  void toStored(AutoReplyStoredConfig* c) const;
  void fromStored(const AutoReplyStoredConfig& c);
  // The region's own channel and the legacy one. When both name one channel
  // (a region spelled like the IATA code) only the first is kept.
  AutoReplyLane _lanes[2];
  // The private path keeps its own budget: a burst of private requests must not be
  // able to spend the channel's replies, nor the other way round.
  SlidingBudget _private_limiter;
  AutoReplySender _private_senders[AUTOREPLY_MAX_SENDERS];
  uint8_t _next_private;

  void refreshChannels(const char* iata);
  static void deriveLane(AutoReplyLane& lane, const char* name);
  bool anyChannel() const { return _lanes[0].ready() || _lanes[1].ready(); }
  void describeChannels(char* out, size_t size) const;
  void load();
  void save();
  int buildReport(const mesh::Packet* req, const char* node_name, float rssi,
                  uint32_t timestamp, const char* who_name, size_t who_len,
                  const char* id, size_t id_len, uint8_t* dest);

public:
  AutoReply();

  void begin(FILESYSTEM* fs);

  /**
   * \brief  Handle the 'set/get autoreply[.*]' commands.
   * \param  iata  the node's region code, or NULL when the build has none
   * \param  regions  the node's region table; a region must be in it to be set
   * \returns  true if the command was ours (and 'reply' was filled in)
   */
  bool handleCommand(const char* iata, RegionMap& regions, const char* command, char* reply);

  /**
   * \brief  Whether a request that arrived direct is answered with a flood.
   */
  bool directFlood() const { return _direct_flood; }
  uint16_t windowStart() const { return _window_start; }
  uint16_t windowEnd() const { return _window_end; }
  uint8_t slots() const { return _slots; }
  // 0 means unassigned; the caller derives a slot from the node's key instead.
  uint8_t slot() const { return _slot; }
  const char* replyRegion() const { return _region; }
  /**
   * \brief  The standing reply mode, for a request that names none (AUTOREPLY_MODE_*).
   */
  uint8_t mode() const { return _mode; }
  /**
   * \brief  Whether a private test request -- an anonymous request to this node,
   *         never a channel message -- is answered at all. Off unless switched on:
   *         it is an unauthenticated packet that makes this node transmit.
   */
  bool privateEnabled() const { return _private; }

  /**
   * \brief  Charge a private test request from 'pubkey' against its limits.
   *
   * The per-key cooldown first, so one requester retrying cannot spend the others'
   * share; then the private path's own global cap, which is what bounds a burst of
   * requests each under a fresh key. A request refused by either gets no reply at
   * all -- there is no cheaper answer that would not still be a transmission.
   *
   * \returns  true if a reply may be sent
   */
  bool privateAllowed(const uint8_t* pubkey, const char* id, size_t id_len,
                      uint32_t timestamp);

  /**
   * \brief  The channel to originate a probe on.
   *
   * The legacy '#test-<iata>' while that is answered, the region's channel after: the
   * measurement moves channel once, when a region switches legacy off, and until
   * then a probe must reach the nodes that answer only the old one.
   *
   * Readiness is only that a channel is derived. It is
   * deliberately independent of 'autoreply on', which governs whether this node
   * *answers* a request -- a node can be asked to originate a probe without
   * answering probes itself, and conflating the two would make the second
   * vantage point depend on a setting that has nothing to do with it.
   *
   * \param  iata  the node's region code, re-derives the channel when it changes
   * \returns  true and fills 'out' when a channel exists
   */
  bool probeChannel(const char* iata, mesh::GroupChannel* out) {
    refreshChannels(iata);
    const AutoReplyLane& lane = _lanes[1].ready() ? _lanes[1] : _lanes[0];
    if (!lane.ready() || out == NULL) return false;
    *out = lane.channel;
    return true;
  }

  /**
   * \brief  Match our channels, for Mesh::searchChannelsByHash()
   * \param  iata  the node's region code, re-derives the channel when it changes
   */
  int searchChannelsByHash(const char* iata, const uint8_t* hash, mesh::GroupChannel channels[],
                           int max_matches);

  /**
   * \brief  Test an incoming group text for the trigger, and build the reply payload.
   *
   * The payload has the same layout for a group text and for a private text message,
   * so 'dest' serves either; 'target' says which, and for a private one to whom.
   *
   * \param  channel  the channel the request arrived on, which picks the budgets it spends
   * \param  dest  OUT - reply payload, needs AUTOREPLY_MAX_PAYLOAD bytes
   * \param  target  OUT - how to send it: AUTOREPLY_MODE_FLOOD, or PRIVATE/DIRECT with the key
   * \returns  length of the payload, or 0 to stay silent
   */
  int buildReply(const mesh::Packet* req, const mesh::GroupChannel& channel,
                 const uint8_t* data, size_t len,
                 const char* node_name, float rssi, uint32_t timestamp, uint8_t* dest,
                 AutoReplyTarget* target);

  /**
   * \brief  Test the body of a private (anonymous) request for the trigger, and build
   *         the same report for its sender.
   * \param  sender  the key the request came from and the reply goes back to
   * \param  body  the request text after the sub-type byte
   * \param  dest  OUT - reply payload, needs AUTOREPLY_MAX_PAYLOAD bytes
   * \returns  length of the payload, or 0 to send nothing
   */
  int buildPrivateReply(const mesh::Packet* req, const mesh::Identity& sender,
                        const uint8_t* body, size_t len, const char* node_name, float rssi,
                        uint32_t timestamp, uint8_t* dest);
};
