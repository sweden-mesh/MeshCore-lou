// Auto-reply's side of the repeater: the channel it answers on, the reply to a test,
// the slot a reply waits for, and the probes it originates. Compiled only with
// WITH_AUTO_REPLY; MyMesh reaches it through Fork.
#include "MyMesh.h"

#ifdef WITH_AUTO_REPLY

// Resolve the region an auto-reply should be scoped to: the configured one when
// set, otherwise whatever scope the request itself arrived under.
//
// Bounding a reply by region rather than by hop count is deliberate. The question
// this feature exists to answer is how much of the mesh is connected, and a hop
// cap answers a different one -- how much comes back to whoever asked -- while
// quietly hiding the far side of the mesh. A region is a stated boundary; a hop
// count is an accident of where the requester happens to sit.
bool Fork::autoReplyScope(TransportKey* scope) {
  const char* name = _auto_reply.replyRegion();
  if (name == NULL || name[0] == 0) return false;

  // Without regard to case first: the name is stored folded, the table may not be.
  const RegionEntry* entry = autoReplyFindRegion(_mesh.region_map, name);
  if (entry == NULL) entry = _mesh.region_map.findByNamePrefix(name);
  if (entry == NULL) return false;
  return _mesh.region_map.getTransportKeysFor(*entry, scope, 1) > 0;
}

// Every flood auto-reply sends goes out here: in the 'autoreply.region' scope when one is
// set and in the table, and otherwise by upstream's own rule, which mirrors the scope the
// request arrived under. Nothing else this repeater floods back -- a login's answer, an
// ACK, a remote CLI reply -- is scoped by that setting: those are upstream's, and so is
// the choice of their scope (TODO 22a ruling 11).
void Fork::sendAutoReplyFlood(mesh::Packet* pkt, uint32_t delay_millis, uint8_t path_hash_size) {
  TransportKey scope;
  if (autoReplyScope(&scope)) {
    _mesh.sendFloodScoped(scope, pkt, delay_millis, path_hash_size);
  } else {
    _mesh.sendFloodReply(pkt, delay_millis, path_hash_size);
  }
}

// Where this node's reply lands in the window today: its assigned slot if it has one,
// the slot its own key derives if it has not. The day comes from the node's own clock,
// so every node agrees on the order without a command being sent and the order holds
// between midnights; an unsynced clock reads as day 0, a legal ordering rather than a
// refusal to answer.
uint32_t Fork::slottedReplyDelay() {
  const uint8_t slots = _auto_reply.slots();
  const uint32_t day = autoReplyDayNumber(_mesh.getRTCClock()->getCurrentTime());
  const uint8_t index = autoReplySlotIndex(_auto_reply.slot(), _mesh.self_id.pub_key,
                                           PUB_KEY_SIZE, slots, day);
  return autoReplySlotDelayMs(autoReplyRotatedSlot(index, slots, day), slots,
                              (uint32_t) _auto_reply.windowStart() * 1000UL,
                              (uint32_t) _auto_reply.windowEnd() * 1000UL,
                              (uint32_t) _mesh.getRNG()->nextInt(0, 0x7FFFFFFF));
}

int Fork::searchChannelsByHash(const uint8_t* hash, mesh::GroupChannel channels[], int max_matches) {
  return _auto_reply.searchChannelsByHash(observerIata(), hash, channels, max_matches);
}

void Fork::onGroupDataRecv(mesh::Packet* packet, uint8_t type, const mesh::GroupChannel& channel,
                             uint8_t* data, size_t len) {
  if (type != PAYLOAD_TYPE_GRP_TXT) return;

  // Anything we flood is kept inside the scope of the request when it had one, and
  // 'autoreply.hops' bounds how far away a request may be to get one at all. A request
  // that arrived direct is the one case we can answer without flooding at all, which
  // 'autoreply.direct.flood off' trades reach for.
  bool zero_hop = autoReplyReplyIsZeroHop(packet->getPathHashCount(), _auto_reply.directFlood());

  uint8_t temp[AUTOREPLY_MAX_PAYLOAD];
  AutoReplyTarget target;
  int payload_len = _auto_reply.buildReply(packet, channel, data, len, _mesh._prefs.node_name,
                                          radio_driver.getLastRSSI(),
                                          _mesh.getRTCClock()->getCurrentTimeUnique(), temp, &target);
  if (payload_len == 0) return;

  if (target.mode != AUTOREPLY_MODE_FLOOD) {
    // A private reply: the same payload as a text message addressed to the
    // requester's key, which only they can read and no repeater re-broadcasts as
    // a channel message. Direct sends it back down the path the request came in
    // on, reversed; a request that arrived direct needs no path at all.
    mesh::Identity dest(target.pubkey);
    uint8_t secret[PUB_KEY_SIZE];
    _mesh.self_id.calcSharedSecret(secret, dest);
    auto reply = _mesh.createDatagram(PAYLOAD_TYPE_TXT_MSG, dest, secret, temp, payload_len);
    if (!reply) {
      MESH_DEBUG_PRINTLN("AutoReply: could not build private reply packet, pool empty");
      return;
    }
    uint32_t delay_millis = slottedReplyDelay();
    if (target.mode == AUTOREPLY_MODE_DIRECT && packet->getPathHashCount() == 0) {
      MESH_DEBUG_PRINTLN("AutoReply: sending private zero-hop reply in %d ms", (uint32_t)delay_millis);
      _mesh.sendZeroHop(reply, delay_millis);
    } else if (target.mode == AUTOREPLY_MODE_DIRECT) {
      uint8_t back[MAX_PATH_SIZE];
      uint8_t back_len = autoReplyReversePath(packet->path, packet->path_len, back);
      MESH_DEBUG_PRINTLN("AutoReply: sending private direct reply in %d ms", (uint32_t)delay_millis);
      _mesh.sendDirect(reply, back, back_len, delay_millis);
    } else {
      MESH_DEBUG_PRINTLN("AutoReply: sending private flood reply in %d ms", (uint32_t)delay_millis);
      sendAutoReplyFlood(reply, delay_millis, packet->getPathHashSize());
    }
    return;
  }

  auto reply = _mesh.createGroupDatagram(PAYLOAD_TYPE_GRP_TXT, channel, temp, payload_len);
  if (reply) {
    // Every repeater in range answers the same request, and their storms otherwise
    // land on top of each other. Measured 2026-08-30: replies that overlapped another
    // transmission reached a median of 2 relays against 5 for one sent into clear
    // air, and 16 of 18 multi-reply events contained an overlapping pair. So a reply
    // leaves in this node's own slot rather than after a random wait. The slot, the
    // window and the slot count are all runtime-settable, because the right values
    // are not knowable from one mesh and re-flashing this fleet takes months.
    uint32_t delay_millis = slottedReplyDelay();
    const char* how = zero_hop ? "zero-hop"
                    : (_mesh.recv_pkt_region && !_mesh.recv_pkt_region->isWildcard()) ? "scoped flood"
                    : "un-scoped flood";
    MESH_DEBUG_PRINTLN("AutoReply: sending %s reply in %d ms", how, (uint32_t)delay_millis);
    if (zero_hop) {
      _mesh.sendZeroHop(reply, delay_millis);
    } else {
      sendAutoReplyFlood(reply, delay_millis, packet->getPathHashSize());
    }
  } else {
    MESH_DEBUG_PRINTLN("AutoReply: could not build reply packet, pool empty");
  }
}

// A private test request (Mode M): an anonymous request to this node alone, carrying
// the keyword and an optional id after sub-type 0xF0. Answered with the channel report,
// built by the same code, as a response to whoever's key asked.
//
// Upstream's anonymous requests are answered at once, because somebody is watching a
// screen for a login. Nobody waits on a test, and every repeater a fleet-wide
// 'trigger private' reaches answers at the same moment, so the answer takes this node's
// slot like every other auto-reply. The way home is upstream's own choice
// (chooseReplyRoute): a flooded request gets the path it collected back with the
// answer, as a login does, so a requester with no path here gains one; a direct one
// carries no path of its own and goes back along the stored one, or floods.
bool Fork::onAnonRequest(mesh::Packet* packet, const uint8_t* secret, const mesh::Identity& sender,
                         const uint8_t* data, size_t len) {
  if (!autoReplyIsPrivateTest(data, len, AUTOREPLY_KEYWORD)) return false;

  uint8_t report[AUTOREPLY_MAX_PAYLOAD];
  int report_len = _auto_reply.buildPrivateReply(packet, sender, &data[5], len - 5,
                                                 _mesh._prefs.node_name, radio_driver.getLastRSSI(),
                                                 _mesh.getRTCClock()->getCurrentTimeUnique(), report);
  if (report_len == 0) return true;   // switched off or over budget: still never a login

  uint32_t delay_millis = slottedReplyDelay();
  MESH_DEBUG_PRINTLN("AutoReply: answering private test in %d ms", (uint32_t)delay_millis);

  ClientInfo* client = _mesh.acl.getClient(sender.pub_key, PUB_KEY_SIZE);
  bool have_out_path = client != NULL && client->out_path_len != OUT_PATH_UNKNOWN;
  auto route = mesh::chooseReplyRoute(packet->isRouteFlood(), false, have_out_path);

  if (route == mesh::REPLY_ROUTE_PATH_RETURN) {
    mesh::Packet* path = _mesh.createPathReturn(sender, secret, packet->path, packet->path_len,
                                                PAYLOAD_TYPE_RESPONSE, report, report_len);
    if (path) sendAutoReplyFlood(path, delay_millis, packet->getPathHashSize());
    return true;
  }
  mesh::Packet* reply = _mesh.createDatagram(PAYLOAD_TYPE_RESPONSE, sender, secret, report, report_len);
  if (reply == NULL) return true;
  if (route == mesh::REPLY_ROUTE_DIRECT_OUT_PATH) {
    _mesh.sendDirect(reply, client->out_path, client->out_path_len, delay_millis);
  } else {
    sendAutoReplyFlood(reply, delay_millis, packet->getPathHashSize());
  }
  return true;
}

// Originate a probe on the test channel -- the second vantage point this whole
// sprint exists for. Every run so far has started at one node, so degree in the
// derived graph is as much a fact about where we sit as about the mesh.
//
// The body is the same text a person sends by hand, so the nodes that answer it
// are answering the same question they always answer and the measurements
// compare. The channel is always derived from the region, never a literal: a
// probe that went to a hardcoded channel would be measuring someone else's mesh.
bool Fork::triggerProbe(const char* id, size_t id_len, uint8_t mode, char* reply) {
  mesh::GroupChannel channel;
  if (!_auto_reply.probeChannel(observerIata(), &channel)) {
    strcpy(reply, "Err - no channel to probe on: set autoreply.region");
    return false;
  }

  // A private reply comes back to whoever's key the probe carries, and the probe
  // is ours, so that is our own.
  char self_hex[PUB_KEY_SIZE * 2 + 1];
  mesh::Utils::toHex(self_hex, _mesh.self_id.pub_key, PUB_KEY_SIZE);

  char body[AUTOREPLY_MAX_PAYLOAD];
  size_t body_len = autoReplyBuildProbe(body, sizeof(body), _mesh._prefs.node_name,
                                        AUTOREPLY_KEYWORD, id, id_len, mode, self_hex);
  if (body_len == 0) {
    strcpy(reply, "Err - could not build probe");
    return false;
  }

  // A group text is timestamp-prefixed like any other, so a probe looks on the
  // wire exactly like the one a client sends.
  uint8_t payload[AUTOREPLY_MAX_PAYLOAD];
  uint32_t now = _mesh.getRTCClock()->getCurrentTimeUnique();
  memcpy(payload, &now, 4);
  payload[4] = 0;                       // flags/attempt, as a client sends
  memcpy(payload + 5, body, body_len);
  size_t payload_len = 5 + body_len;

  auto pkt = _mesh.createGroupDatagram(PAYLOAD_TYPE_GRP_TXT, channel, payload, payload_len);
  if (pkt == NULL) {
    strcpy(reply, "Err - packet pool empty");
    return false;
  }

  // Scoped to the configured region when there is one, un-scoped otherwise.
  // Deliberately not the 'recv_pkt_region' fallback sendFloodReply uses: that
  // member holds the scope of the last packet *received*, which for a probe
  // originated from MQTT is unrelated to anything and would scope the probe to
  // wherever the last traffic happened to come from.
  TransportKey scope;
  if (autoReplyScope(&scope)) {
    _mesh.sendFloodScoped(scope, pkt, (uint32_t)0, (uint8_t)1);
  } else {
    _mesh.sendFlood(pkt, (uint32_t)0, (uint8_t)1);
  }

  if (id != NULL && id_len > 0) {
    snprintf(reply, AUTOREPLY_MAX_REPLY, "OK - probe sent, id %.*s", (int)id_len, id);
  } else {
    strcpy(reply, "OK - probe sent");
  }
  return true;
}

// The requester's side of a private test: an anonymous request to one node, the
// keyword and the echoed id after the sub-type byte, flooded and scoped exactly as
// a channel probe is so a target with no path from here still hears it. The
// answer comes back as a RESPONSE addressed to this node; the observer feed sees
// it arrive, which is the measurement, whether or not this node can read it.
bool Fork::triggerPrivateProbe(const char* pubkey_hex, const char* id, size_t id_len,
                                 char* reply) {
  // The key sits inside the command text, followed by the id when there is one,
  // and fromHex wants it alone.
  char key_hex[PUB_KEY_SIZE * 2 + 1];
  memcpy(key_hex, pubkey_hex, PUB_KEY_SIZE * 2);
  key_hex[PUB_KEY_SIZE * 2] = 0;
  uint8_t key[PUB_KEY_SIZE];
  mesh::Utils::fromHex(key, PUB_KEY_SIZE, key_hex);
  mesh::Identity target(key);

  uint8_t secret[PUB_KEY_SIZE];
  _mesh.self_id.calcSharedSecret(secret, target);

  uint8_t inner[5 + AUTOREPLY_MAX_TEXT];
  uint32_t tag = _mesh.getRTCClock()->getCurrentTimeUnique();
  memcpy(inner, &tag, 4);
  inner[4] = AUTOREPLY_ANON_TEST_SUBTYPE;
  size_t body_len = autoReplyBuildProbe((char *) &inner[5], sizeof(inner) - 5, NULL,
                                        AUTOREPLY_KEYWORD, id, id_len);
  if (body_len == 0) {
    strcpy(reply, "Err - could not build request");
    return false;
  }

  auto pkt = _mesh.createAnonDatagram(PAYLOAD_TYPE_ANON_REQ, _mesh.self_id, target, secret, inner,
                                5 + body_len);
  if (pkt == NULL) {
    strcpy(reply, "Err - packet pool empty");
    return false;
  }

  TransportKey scope;
  if (autoReplyScope(&scope)) {
    _mesh.sendFloodScoped(scope, pkt, (uint32_t)0, (uint8_t)1);
  } else {
    _mesh.sendFlood(pkt, (uint32_t)0, (uint8_t)1);
  }

  if (id != NULL && id_len > 0) {
    snprintf(reply, AUTOREPLY_MAX_REPLY, "OK - private request sent to %.8s.., id %.*s",
             pubkey_hex, (int)id_len, id);
  } else {
    snprintf(reply, AUTOREPLY_MAX_REPLY, "OK - private request sent to %.8s..", pubkey_hex);
  }
  return true;
}

// 'set/get autoreply[.*]' and the two triggers. A trigger is answered on serial in
// every build with auto-reply, and over the command plane only where that admits it.
bool Fork::handleAutoReplyCommand(char* command, char* reply) {
  if (_auto_reply.handleCommand(observerIata(), _mesh.region_map, command, reply)) {
    return true;
  }
  const char* trigger_id = NULL;
  const char* trigger_key = NULL;
  size_t trigger_id_len = 0;
  uint8_t trigger_mode = AUTOREPLY_MODE_DEFAULT;
  if (autoReplyParseTrigger(command, AUTOREPLY_KEYWORD, &trigger_id, &trigger_id_len,
                            &trigger_mode)) {
    triggerProbe(trigger_id, trigger_id_len, trigger_mode, reply);
    return true;
  }
  if (autoReplyParsePrivateTrigger(command, &trigger_key, &trigger_id, &trigger_id_len)) {
    triggerPrivateProbe(trigger_key, trigger_id, trigger_id_len, reply);
    return true;
  }
  return false;
}

#endif
