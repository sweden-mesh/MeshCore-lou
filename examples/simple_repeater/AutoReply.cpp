#include "AutoReply.h"

#ifdef WITH_AUTO_REPLY

#include <helpers/TxtDataHelpers.h>

#define AUTOREPLY_CONFIG_FILE   "/autoreply"

#define MAX_PATH_HASHES_SHOWN   8    // keep the reply short, it is airtime

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

AutoReply::AutoReply()
  : _fs(NULL), _enabled(false), _hops(8), _direct_flood(true),
    _window_start(AUTOREPLY_WINDOW_START_DEF), _window_end(AUTOREPLY_WINDOW_END_DEF),
    _slots(AUTOREPLY_SLOTS_DEF), _mode(AUTOREPLY_MODE_FLOOD), _private(AUTOREPLY_PRIVATE_DEF),
    _slot(AUTOREPLY_SLOT_UNASSIGNED), _legacy(AUTOREPLY_LEGACY_DEF),
    _private_limiter(AUTOREPLY_MAX_REPLIES, AUTOREPLY_WINDOW_SECS)
{
  _region[0] = 0;
  memset(_private_senders, 0, sizeof(_private_senders));
  _next_private = 0;
}

bool AutoReply::privateAllowed(const uint8_t* pubkey, const char* id, size_t id_len,
                               uint32_t timestamp) {
  uint32_t key_id = autoReplyRequestId(autoReplyKeyId(pubkey, PUB_KEY_SIZE), id, id_len);
  if (!autoReplySenderAllowed(_private_senders, AUTOREPLY_MAX_SENDERS, _next_private, key_id,
                              timestamp, AUTOREPLY_WINDOW_SECS)) {
    MESH_DEBUG_PRINTLN("AutoReply: private request from %02X%02X.. already answered in the last %d s",
                       (uint32_t)pubkey[0], (uint32_t)pubkey[1], (uint32_t)AUTOREPLY_WINDOW_SECS);
    return false;
  }
  if (!_private_limiter.allow(timestamp)) {
    MESH_DEBUG_PRINTLN("AutoReply: private requests rate limited, %d already answered in the last %d s",
                       (uint32_t)AUTOREPLY_MAX_REPLIES, (uint32_t)AUTOREPLY_WINDOW_SECS);
    return false;
  }
  return true;
}

void AutoReply::begin(FILESYSTEM* fs) {
  _fs = fs;
  load();
}

// A hashtag channel's key is the first 16 bytes of sha256 of its name, so a lane is
// re-keyed only when the name it should answer on has changed.
void AutoReply::deriveLane(AutoReplyLane& lane, const char* name) {
  if (strcmp(name, lane.name) == 0) return;
  StrHelper::strncpy(lane.name, name, sizeof(lane.name));
  if (!lane.ready()) return;

  memset(lane.channel.secret, 0, sizeof(lane.channel.secret));
  mesh::Utils::sha256(lane.channel.secret, 16, (const uint8_t *) name, strlen(name));
  mesh::Utils::sha256(lane.channel.hash, sizeof(lane.channel.hash), lane.channel.secret, 16);
  MESH_DEBUG_PRINTLN("AutoReply: channel '%s' (hash %02X)", name, (uint32_t)lane.channel.hash[0]);
}

// The region is ours, but the IATA code behind the legacy channel is owned by the
// observer config and can change at any time, so both are re-derived on every use.
void AutoReply::refreshChannels(const char* iata) {
  char region_name[AUTOREPLY_MAX_CHANNEL];
  char legacy_name[AUTOREPLY_MAX_CHANNEL];
  autoReplyChannelNames(_region, iata, _legacy, region_name, legacy_name, sizeof(region_name));
  deriveLane(_lanes[0], region_name);
  deriveLane(_lanes[1], legacy_name);
}

// "#test-se-jkp + legacy #test-jkg", for the replies that say where the node answers.
void AutoReply::describeChannels(char* out, size_t size) const {
  if (_lanes[0].ready() && _lanes[1].ready()) {
    snprintf(out, size, "%s + legacy %s", _lanes[0].name, _lanes[1].name);
  } else if (_lanes[0].ready()) {
    snprintf(out, size, "%s", _lanes[0].name);
  } else if (_lanes[1].ready()) {
    snprintf(out, size, "legacy %s", _lanes[1].name);
  } else {
    snprintf(out, size, "no channel - set autoreply.region");
  }
}

void AutoReply::load() {
  if (!_fs->exists(AUTOREPLY_CONFIG_FILE)) return;

  File file = openRead(_fs, AUTOREPLY_CONFIG_FILE);
  if (!file) return;
  uint8_t buf[AUTOREPLY_CONFIG_MAX_BYTES];
  size_t len = file.read(buf, sizeof(buf));
  file.close();

  // The byte layout, every version of it, is autoReplyConfigDecode's -- kept in the
  // logic header so the host suite can test it, which this file cannot be.
  AutoReplyStoredConfig c;
  toStored(&c);
  if (!autoReplyConfigDecode(buf, len, &c)) return;
  fromStored(c);
}

void AutoReply::save() {
  AutoReplyStoredConfig c;
  toStored(&c);
  uint8_t buf[AUTOREPLY_CONFIG_MAX_BYTES];
  size_t len = autoReplyConfigEncode(&c, buf, sizeof(buf));
  if (len == 0) return;

  File file = openWrite(_fs, AUTOREPLY_CONFIG_FILE);
  if (file) {
    file.write(buf, len);
    file.close();
  }
}

void AutoReply::toStored(AutoReplyStoredConfig* c) const {
  autoReplyConfigDefaults(c);
  c->enabled = _enabled;
  c->hops = _hops;
  c->direct_flood = _direct_flood;
  memcpy(c->region, _region, sizeof(c->region));
  c->mode = _mode;
  c->priv = _private;
  c->slot = _slot;
  c->window_start = _window_start;
  c->window_end = _window_end;
  c->slots = _slots;
  c->legacy = _legacy;
}

void AutoReply::fromStored(const AutoReplyStoredConfig& c) {
  _enabled = c.enabled;
  _hops = c.hops;
  _direct_flood = c.direct_flood;
  memcpy(_region, c.region, sizeof(_region));
  _region[sizeof(_region) - 1] = 0;
  _mode = c.mode;
  _private = c.priv;
  _slot = c.slot;
  _window_start = c.window_start;
  _window_end = c.window_end;
  _slots = c.slots;
  _legacy = c.legacy;
}

int AutoReply::searchChannelsByHash(const char* iata, const uint8_t* hash,
                                    mesh::GroupChannel channels[], int max_matches) {
  refreshChannels(iata);
  if (!_enabled) return 0;
  const uint8_t hashes[2] = { _lanes[0].channel.hash[0], _lanes[1].channel.hash[0] };
  const bool ready[2] = { _lanes[0].ready(), _lanes[1].ready() };
  int idx[2];
  int n = autoReplyMatchingChannels(hashes, ready, 2, hash[0], idx, min(max_matches, 2));
  for (int i = 0; i < n; i++) {
    MESH_DEBUG_PRINTLN("AutoReply: channel '%s' matched", _lanes[idx[i]].name);
    channels[i] = _lanes[idx[i]].channel;
  }
  return n;
}

bool AutoReply::handleCommand(const char* iata, RegionMap& regions, const char* command,
                              char* reply) {
  refreshChannels(iata);

  char where[2 * AUTOREPLY_MAX_CHANNEL + 12];
  describeChannels(where, sizeof(where));

  if (memcmp(command, "set autoreply ", 14) == 0) {
    if (!autoReplyParseOnOff(&command[14], &_enabled)) {
      strcpy(reply, "Err - use: set autoreply on|off");
      return true;
    }
    save();
    if (_enabled && !anyChannel()) {
      strcpy(reply, "OK - on, but no channel yet: set autoreply.region <name>");
    } else {
      sprintf(reply, "OK - %s", _enabled ? where : "off");
    }
    return true;
  }

  if (autoReplyCommandIs(command, "set autoreply.channel")) {
    strcpy(reply, "Err - the channel is #test-<region>: set autoreply.region <name>");
    return true;
  }

  if (memcmp(command, "set autoreply.legacy ", 21) == 0) {
    if (!autoReplyParseOnOff(&command[21], &_legacy)) {
      strcpy(reply, "Err - use: set autoreply.legacy on|off");
      return true;
    }
    save();
    refreshChannels(iata);
    describeChannels(where, sizeof(where));
    sprintf(reply, "OK - %s", where);
    return true;
  }

  if (strcmp(command, "get autoreply.legacy") == 0) {
    sprintf(reply, "> %s", autoReplyLegacyState(_legacy, iata != NULL));
    return true;
  }

  if (memcmp(command, "set autoreply.hops ", 19) == 0) {
    int hops = atoi(&command[19]);
    if (hops < 0 || hops > 63) {
      strcpy(reply, "Err - must be 0..63");
    } else {
      _hops = (uint8_t)hops;
      save();
      strcpy(reply, "OK");
    }
    return true;
  }

  if (memcmp(command, "set autoreply.direct.flood ", 27) == 0) {
    if (!autoReplyParseOnOff(&command[27], &_direct_flood)) {
      strcpy(reply, "Err - use: set autoreply.direct.flood on|off");
      return true;
    }
    save();
    strcpy(reply, "OK");
    return true;
  }

  if (memcmp(command, "set autoreply.window ", 21) == 0) {
    long start_s = 0, end_s = 0;
    if (sscanf(&command[21], "%ld %ld", &start_s, &end_s) != 2
        || !autoReplyWindowValid(start_s, end_s, _slots)) {
      sprintf(reply, "Err - use: set autoreply.window <start> <end> in seconds, "
                     "end<=%d and at least %d s per slot",
              AUTOREPLY_WINDOW_MAX, AUTOREPLY_SLOT_MIN_SECS);
    } else {
      _window_start = (uint16_t) start_s;
      _window_end = (uint16_t) end_s;
      save();
      strcpy(reply, "OK");
    }
    return true;
  }

  if (strcmp(command, "get autoreply.window") == 0) {
    sprintf(reply, "> %d %d", (uint32_t) _window_start, (uint32_t) _window_end);
    return true;
  }

  if (memcmp(command, "set autoreply.slots ", 20) == 0) {
    long slots = atol(&command[20]);
    if (!autoReplySlotsValid(slots, _window_start, _window_end)) {
      sprintf(reply, "Err - must be %d..%d and leave at least %d s per slot",
              AUTOREPLY_SLOTS_MIN, AUTOREPLY_SLOTS_MAX, AUTOREPLY_SLOT_MIN_SECS);
    } else {
      _slots = (uint8_t) slots;
      save();
      strcpy(reply, "OK");
    }
    return true;
  }

  if (strcmp(command, "get autoreply.slots") == 0) {
    sprintf(reply, "> %d", (uint32_t) _slots);
    return true;
  }

  if (memcmp(command, "set autoreply.slot ", 19) == 0) {
    long slot = atol(&command[19]);
    if (!autoReplySlotValid(slot)) {
      sprintf(reply, "Err - must be %d..%d (%d = unassigned)",
              AUTOREPLY_SLOT_UNASSIGNED, AUTOREPLY_SLOT_MAX, AUTOREPLY_SLOT_UNASSIGNED);
    } else {
      _slot = (uint8_t) slot;
      save();
      strcpy(reply, "OK");
    }
    return true;
  }

  if (strcmp(command, "get autoreply.slot") == 0) {
    if (_slot == AUTOREPLY_SLOT_UNASSIGNED) {
      strcpy(reply, "> 0 (unassigned; the slot comes from this node's own key)");
    } else {
      sprintf(reply, "> %d", (uint32_t) _slot);
    }
    return true;
  }

  if (memcmp(command, "set autoreply.delay", 19) == 0
      || strcmp(command, "get autoreply.delay") == 0) {
    // Retired in favour of the window and the slot. Answering with an error rather
    // than silently ignoring it means a provisioning note that still carries the old
    // command fails loudly on the first node instead of quietly doing nothing on all
    // of them.
    strcpy(reply, "Err - autoreply.delay is gone; use autoreply.window and autoreply.slots");
    return true;
  }

  if (memcmp(command, "set autoreply.region ", 21) == 0) {
    // Empty clears it: no region channel, and a reply mirrors whatever scope the
    // request arrived under. A name must already be a region of this node's, since
    // it is also the scope every reply floods in.
    char name[AUTOREPLY_REGION_NAME_MAX + 1];
    int verdict = autoReplyRegionVerdict(&command[21], name, sizeof(name),
        [&regions](const char* n) { return autoReplyFindRegion(regions, n) != NULL; });
    if (verdict == AUTOREPLY_REGION_BAD_NAME) {
      sprintf(reply, "Err - a region is %d-%d of a-z 0-9, groups joined by single '-' (se-jkp-mul)",
              AUTOREPLY_REGION_NAME_MIN, AUTOREPLY_REGION_NAME_MAX);
      return true;
    }
    if (verdict == AUTOREPLY_REGION_NOT_IN_TABLE) {
      sprintf(reply, "Err - %s is not in the region table: region put %s first", name, name);
      return true;
    }
    StrHelper::strncpy(_region, name, sizeof(_region));
    save();
    refreshChannels(iata);
    describeChannels(where, sizeof(where));
    sprintf(reply, "OK - %s", where);
    return true;
  }

  if (strcmp(command, "get autoreply.region") == 0) {
    sprintf(reply, "> %s", _region[0] ? _region : "(none: request scope, no region channel)");
    return true;
  }

  if (memcmp(command, "set autoreply.mode ", 19) == 0) {
    if (!autoReplyParseModeName(&command[19], &_mode)) {
      strcpy(reply, "Err - use: set autoreply.mode flood|private|direct");
      return true;
    }
    save();
    strcpy(reply, "OK");
    return true;
  }

  if (memcmp(command, "set autoreply.private ", 22) == 0) {
    if (!autoReplyParseOnOff(&command[22], &_private)) {
      strcpy(reply, "Err - use: set autoreply.private on|off");
      return true;
    }
    save();
    strcpy(reply, "OK");
    return true;
  }

  if (strcmp(command, "get autoreply.private") == 0) {
    sprintf(reply, "> %s", _private ? "on" : "off");
    return true;
  }

  if (strcmp(command, "get autoreply.mode") == 0) {
    sprintf(reply, "> %s", autoReplyModeName(_mode));
    return true;
  }

  if (strcmp(command, "get autoreply.direct.flood") == 0) {
    sprintf(reply, "> %s", _direct_flood ? "on" : "off");
    return true;
  }

  if (strcmp(command, "get autoreply.channel") == 0) {
    sprintf(reply, "> %s", where);
    return true;
  }

  if (strcmp(command, "get autoreply.hops") == 0) {
    sprintf(reply, "> %d", _hops);
    return true;
  }

  if (strcmp(command, "get autoreply") == 0) {
    // The channel, the scope and legacy on one line, so a site check sees all three. The
    // scope is the region only when the table has it; otherwise replies take the
    // request's, and the line says so. Channels last: they are what can be long, and
    // 160 characters hold the longest region and IATA code.
    const char* scope = !_region[0] ? "request scope"
                      : autoReplyFindRegion(regions, _region) || regions.findByNamePrefix(_region)
                        ? "scope"
                      : "not in table: request scope";
    snprintf(reply, 160, "> %s, mode %s, private %s, direct %s, %d hops, region %s (%s), "
                         "legacy %s: %s",
             _enabled ? "on" : "off", autoReplyModeName(_mode), _private ? "on" : "off",
             _direct_flood ? "flood" : "0-hop", _hops, _region[0] ? _region : "-", scope,
             autoReplyLegacyState(_legacy, iata != NULL), where);
    return true;
  }

  return false;   // not one of ours
}

int AutoReply::buildReply(const mesh::Packet* req, const mesh::GroupChannel& channel,
                          const uint8_t* data, size_t len,
                          const char* node_name, float rssi, uint32_t timestamp, uint8_t* dest,
                          AutoReplyTarget* target) {
  AutoReplyLane* lane = NULL;
  for (AutoReplyLane& l : _lanes) {
    if (l.ready() && memcmp(l.channel.secret, channel.secret, sizeof(channel.secret)) == 0) lane = &l;
  }
  if (!_enabled || lane == NULL) return 0;
  if (len < 6) {                                      // timestamp + flags + at least one char
    MESH_DEBUG_PRINTLN("AutoReply: ignored, message too short (len=%d)", (uint32_t)len);
    return 0;
  }
  if ((data[4] >> 2) != TXT_TYPE_PLAIN) {             // only plain chat text
    MESH_DEBUG_PRINTLN("AutoReply: ignored, not plain text (txt_type=%d)", (uint32_t)(data[4] >> 2));
    return 0;
  }

  uint8_t hop_count = req->getPathHashCount();
  if (!autoReplyHopsAllowed(hop_count, _hops)) {
    MESH_DEBUG_PRINTLN("AutoReply: ignored, %d hops away (max %d)", (uint32_t)hop_count,
                       (uint32_t)_hops);
    return 0;
  }

  char text[AUTOREPLY_MAX_TEXT];
  size_t text_len = min(len - 5, sizeof(text) - 1);
  memcpy(text, &data[5], text_len);
  text[text_len] = 0;

  AutoReplyRequest request = autoReplyParseRequest(text, AUTOREPLY_KEYWORD);
  if (!request.is_trigger) {
    MESH_DEBUG_PRINTLN("AutoReply: not the keyword - got '%s', want '%s'", request.message,
                       AUTOREPLY_KEYWORD);
    return 0;
  }

  // A request that asks for silence is answered by the observer uplink alone: the
  // reception is reported over MQTT whatever happens here, and nothing goes on
  // the air. It spends no reply budget, since there is no reply.
  uint8_t mode = autoReplyResolveMode(request.mode, _mode, request.pubkey_hex != NULL);
  if (mode == AUTOREPLY_MODE_SILENT) {
    MESH_DEBUG_PRINTLN("AutoReply: '%.*s' asked for no reply", (int)request.sender_len,
                       request.sender);
    return 0;
  }

  // Per-sender first, so someone retrying cannot spend everyone else's share of
  // the global budget. Only real triggers are charged against either limit.
  uint32_t sender_id = autoReplyRequestId(
      autoReplySenderId(request.sender, request.sender_len), request.id, request.id_len);
  if (!autoReplySenderAllowed(lane->budgets.senders, AUTOREPLY_MAX_SENDERS,
                              lane->budgets.next_sender, sender_id, timestamp,
                              AUTOREPLY_WINDOW_SECS)) {
    MESH_DEBUG_PRINTLN("AutoReply: '%.*s' was already answered in the last %d s",
                       (int)request.sender_len, request.sender, (uint32_t)AUTOREPLY_WINDOW_SECS);
    return 0;
  }
  if (!lane->budgets.limiter.allow(timestamp)) {
    MESH_DEBUG_PRINTLN("AutoReply: rate limited on %s, %d replies already sent in the last %d s",
                       lane->name, (uint32_t)AUTOREPLY_MAX_REPLIES, (uint32_t)AUTOREPLY_WINDOW_SECS);
    return 0;
  }

  int reply_len = buildReport(req, node_name, rssi, timestamp, request.sender,
                              request.sender_len, request.id, request.id_len, dest);

  // A private mode was resolved only if the request carried a key, so the decode
  // cannot fail on length; the key's characters were checked when it was parsed.
  target->mode = mode;
  if (mode != AUTOREPLY_MODE_FLOOD) {
    mesh::Utils::fromHex(target->pubkey, PUB_KEY_SIZE, request.pubkey_hex);
  }

  MESH_DEBUG_PRINTLN("AutoReply: replying '%s' (%s)", (const char *) &dest[5],
                     autoReplyModeName(mode));
  return reply_len;
}

// The report itself: what this node heard, for whoever asked. One body for every
// path a request can take, so a private answer says exactly what a channel one
// would, and the two measurements compare.
int AutoReply::buildReport(const mesh::Packet* req, const char* node_name, float rssi,
                           uint32_t timestamp, const char* who_name, size_t who_len,
                           const char* id, size_t id_len, uint8_t* dest) {
  uint8_t hop_count = req->getPathHashCount();

  // the repeaters this request came through (flood routing appends each hop)
  char path_hex[MAX_PATH_HASHES_SHOWN * 9 + 4];
  uint8_t hash_size = req->getPathHashSize();
  uint8_t shown = min(hop_count, (uint8_t)MAX_PATH_HASHES_SHOWN);
  if (shown == 0) {
    strcpy(path_hex, "direct");
  } else {
    char* wp = path_hex;
    for (uint8_t i = 0; i < shown; i++) {
      if (i > 0) *wp++ = ',';
      mesh::Utils::toHex(wp, &req->path[i * hash_size], hash_size);
      wp += hash_size * 2;
    }
    if (shown < hop_count) { strcpy(wp, ".."); wp += 2; }
    *wp = 0;
  }

  // reply uses the same payload layout as the request
  memcpy(dest, &timestamp, 4);
  dest[4] = (TXT_TYPE_PLAIN << 2);

  // bounded, as the name and the path can both be long
  char who[AUTOREPLY_MAX_SENDER + 4];
  if (who_len > 0) {
    int n = min((int)who_len, AUTOREPLY_MAX_SENDER);
    snprintf(who, sizeof(who), "[%.*s] ", n, who_name);
  } else {
    who[0] = 0;
  }

  // The correlation id, echoed so a requester can tie a reply to the request that
  // provoked it. With reply delays measured in minutes, arrival time can no longer
  // do that job.
  char tag[AUTOREPLY_ID_LEN + 3];
  if (id != NULL) {
    snprintf(tag, sizeof(tag), "#%.*s ", (int)id_len, id);
  } else {
    tag[0] = 0;
  }

  // Field order is a decision, not a default: snprintf truncates from the right,
  // and AUTOREPLY_MAX_TEXT is 112 against a name, a bracketed requester and a path
  // that can each be long. The id sits ahead of the measurements so a crowded
  // reply loses path hashes -- which already truncate gracefully with ".." -- before
  // it loses the thing that says which request this answers.
  char* out = (char *) &dest[5];
  snprintf(out, AUTOREPLY_MAX_TEXT, "%s: %s%sSNR %s RSSI %d %dh %s", node_name, who, tag,
           StrHelper::ftoa(req->getSNR()), (int)rssi, (uint32_t)hop_count, path_hex);
  return 5 + strlen(out);
}

// A private test request: the same report, to whoever's key asked for it. The
// requester is named in the brackets by the leading bytes of that key, since a
// key is what the packet carries and nobody can type somebody else's. Gated by
// its own switch and charged to its own budget; a request refused by either gets
// nothing back.
int AutoReply::buildPrivateReply(const mesh::Packet* req, const mesh::Identity& sender,
                                 const uint8_t* body, size_t len, const char* node_name,
                                 float rssi, uint32_t timestamp, uint8_t* dest) {
  if (!_enabled || !anyChannel() || !_private) return 0;

  char text[AUTOREPLY_MAX_TEXT];
  size_t text_len = min(len, sizeof(text) - 1);
  memcpy(text, body, text_len);
  text[text_len] = 0;

  const char* id;
  size_t id_len;
  if (!autoReplyParsePrivateTest(text, AUTOREPLY_KEYWORD, &id, &id_len)) {
    MESH_DEBUG_PRINTLN("AutoReply: private request is not the keyword - got '%s'", text);
    return 0;
  }
  if (!privateAllowed(sender.pub_key, id, id_len, timestamp)) return 0;

  char who[AUTOREPLY_PRIVATE_WHO * 2 + 1];
  mesh::Utils::toHex(who, sender.pub_key, AUTOREPLY_PRIVATE_WHO);
  int reply_len = buildReport(req, node_name, rssi, timestamp, who, strlen(who), id, id_len,
                              dest);
  MESH_DEBUG_PRINTLN("AutoReply: private reply '%s'", (const char *) &dest[5]);
  return reply_len;
}

#endif
