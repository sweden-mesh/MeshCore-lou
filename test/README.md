# Host unit tests

Fast, hardware-free unit tests for the fork's pure logic, run on the host with
GoogleTest via PlatformIO's `native` environment. They cover the extractable
observer/WebConfig logic (validation, preset table, topic templates, key
parsing) — the parts that don't depend on the ESP32, radio, or network stack.
Integration behavior (AsyncTCP transport, WiFi/MQTT, SoftAP) is exercised
separately; see "Local testing without hardware" in `MQTT_IMPLEMENTATION.md`.

## Running

```sh
pio test -e native                      # all suites
pio test -e native -f test_webconfig_keys   # a single suite
```

A green `[PASSED]` per suite means GoogleTest returned 0 (all assertions
passed). PlatformIO's "0 test cases" line is just its Unity-style counter and
does not reflect the GoogleTest count — run the built binary directly
(`.pio/build/native/program`) to see the per-assertion breakdown.

## Suites

| Suite | Source under test | Covers |
|-------|-------------------|--------|
| `test_mqtt_presets` | `src/helpers/MQTTPresets.h` | preset lookup; table integrity (unique names, non-empty URLs, JWT-audience invariant, names fit the slot buffer); `mqttPresetNeedsSlotCredentials`; slot-count constants |
| `test_observer_validation` | `src/helpers/MQTTObserverValidation.h` | IATA (exactly 3 alphanumerics), owner key (64 hex), NTP hostname, and the buffer-fit check behind the #17 length validation — including boundaries and nulls |
| `test_webconfig_keys` | `src/helpers/WebConfigKeys.h` | POST-key allowlist, secret detection, admin-password classification/validation, slot-index bounds, and the short-key out-of-bounds guard (attacker-supplied keys) |
| `test_topic_template` | `src/helpers/MQTTTopicTemplate.h` | `{iata}/{device}/{token}/{type}` expansion, overflow/NUL-termination, and a buffer-size fuzz |
| `test_mqtt_topic_router` | `src/helpers/MQTTTopicRouter.h` | complete preset/custom topic-routing contract; MeshRank all types except raw; required identifiers; invalid inputs/slots; exact buffer boundaries |
| `test_mqtt_connection_policy` | `src/helpers/MQTTConnectionPolicy.h` | reconnect guard/backoff/stagger and breaker transitions; stable reset; JWT lifetime/renewal policy; exact timing boundaries and 32-bit `millis()` rollover; WiFi current-outage start sticky across STA reconnect attempts |
| `test_network_policy` | `src/helpers/NetworkPolicy.h` | transport-neutral MQTT link-transition actions and `start ota` selected-LAN versus forced/fallback SoftAP choice |
| `test_network_hostname` | `src/helpers/NetworkHostname.h` | DHCP-safe `meshcore-` hostname generation; invalid-character collapse; empty fallback; exact length boundary; stable identity suffix on truncation |
| `test_alert_fault_policy` | `src/helpers/AlertFaultPolicy.h` | WiFi/MQTT fault edge detector; `OutageSnapshot` (down / started_ms / initiating reason) fed to tick and `formatWifiAlert`; reason-8 reconnects change neither duration nor initiating reason; flap between status polls; down at `millis()==0`; packed 64-bit cross-task word; rate-limit floor and first-fire; 5 s poll cadence and `millis()` rollover |
| `test_display_viewport` | `src/helpers/ui/DisplayViewport.h`, `src/helpers/ui/DisplayFrameSignature.h` | logical-to-physical portrait mapping; fractional span coverage; fitted-width conversion; preferred/fallback text scaling; stable visible-frame change detection |
| `test_mqtt_packet_queue_policy` | `src/helpers/MQTTPacketQueuePolicy.h` | queue-full eviction; stale-disconnect flush; adaptive drain limits; bounded QoS0 retries; exact timing boundaries and 32-bit `millis()` rollover |
| `test_mqtt_packet_filter` | `src/helpers/MQTTPacketFilter.h` | per-slot 0-15 allowlist parsing/formatting, numeric and named spellings; exact bounds; membership; candidate/eligible split and retry-completion policy; pre-queue union gate; default-mask detection |
| `test_mqtt_runtime_buffer_lifecycle` | `src/helpers/MQTTRuntimeBufferLifecycle.h` | idempotent allocation/release; partial-allocation degradation; retry of only missing buffers |
| `test_mqtt_prefs_codec` | `src/helpers/MQTTPrefsStorage.h`, `src/helpers/MQTTPrefsCodec.h` | binary pre-slot/3-slot/6-slot migration fixtures; v1 header integrity; downgrade preservation; shortest-payload write policy (default filters stay downgrade-readable) |
| `test_mqtt_prefs_serializer` | `src/helpers/MQTTPrefsSerializer.h`, `src/helpers/ConfigSerializer.*` | semantic nested `/mqtt.json` round trips; numeric slot keys; required/future version handling; strict length/overflow/duplicate rejection; safe semantic repair; scratch-before-live loading |
| `test_mqtt_prefs_atomic_store` | `src/helpers/MQTTPrefsAtomicStore.h`, `src/helpers/MQTTPrefsRecovery.h` | production JSON begin/write/checksum-finish/schema-verify/commit orchestration; first-migration and rename-boundary recovery; legacy `/node_prefs` handoff; failure cleanup and original-file preservation |
| `test_mqtt_payload_builder` | `src/helpers/MQTTPayloadBuilder.cpp` | status/packet/raw JSON contracts; optional fields; escaping; RX metrics and path; score handling; exact buffer bounds; maximum representative payloads |
| `test_autoreply` | `src/helpers/AutoReplyLogic.h` | repeater auto-reply: the `#test-<iata>` channel derived from the region code (folding, unset/placeholder regions, exhaustive proof it cannot produce a shared channel); the `#test-<region>` channel named by `autoreply.region` (shape, 3-25 length, folding, the region-table rule) beside the legacy channel, with per-channel budgets; `"<sender>: <message>"` splitting and standalone-keyword matching; per-sender cooldown ring with window boundaries and eviction |
| `test_radio_activity_window` | `src/helpers/RadioActivityWindow.h` | 20-minute minute-bucketed RX window: totals and derived rates; bucket rotation and oldest-to-newest ordering; expiry at the boundary; ring clear after 20 minutes of silence; warm-up versus steady-state denominators; peak minute; last-packet age and staleness; counter saturation; `millis()` rollover, including the minute boundary a `now_ms / 60000` quotient would corrupt |
| `test_observer_dashboard` | `src/helpers/ui/ObserverDashboard.h` | R8 TFT observer dashboard against a recording `DisplayDriver` in both orientation profiles: compact number/byte/age formatting and the 5 s age quantisation; per-row character budgets; on-panel and inside-the-margin bounds; no silent portrait scale fallback; non-overlapping row rectangles and each row's repaint covering everything it draws; 20-bar graph scaling, ordering and empty/spike cases; per-row signatures and the partial-repaint policy |
| `test_touch_tap_detector` | `src/helpers/ui/TouchTapDetector.h` | debounced rising-edge detection for the polled Expansion Kit touch panel: idle quiet; one tap per touch; long presses do not repeat; sub-debounce blips ignored; contact bounce still counts once; minimum gap between accepted taps; `millis()` rollover; reset semantics |
| `test_utils` | `src/Utils.cpp` | `Utils::toHex` (upstream) |
| `test_mqtt_control` | `src/helpers/MqttControlLogic.h` | the signed control envelope: field split, the exact byte range the signature covers, replay counter, expiry and clock-fails-closed, `get stats` as one bounded line (`mqttCtrlFormatNodeStats`), a trigger over the plane (admitted with auto-reply and refused at the trigger parser if malformed, refused outright without it), the command allowlist and its prefix-boundary rule, with and without auto-reply in the image (triggers and `autoreply` settings refused without it; the verdict fixtures `command-verdicts.txt` and `command-verdicts-rc.txt`), the transmit/general rate split, command-key readiness, the `mqtt.cmd.slot` range, and the numeric stability of the result codes; the slot `set mqtt.cmd on` takes (slot 2 without PSRAM when empty or `analyzer-eu`, 3-6 with PSRAM) and every command form that would change the slot the plane rides refused, spacing included; `mqtt.cmd ping`: the nonce armed and matched, a stale, foreign or second pong ignored, a pong never parsed as a command, the failing step named, the verb admitted exactly; the non-blocking state machine: settles once on the pong or at 10 s, across the millis wrap, one ping at a time |
| `test_mqtt_lifecycle` | `src/helpers/MQTTLifecycle.h` | bridge start/run/stop as a state machine: idempotent start and stop, stop before full initialisation, resource rollback on start failure, restart after stop, and the stop-timeout fallback |
| `test_mqtt_reply_format` | `src/helpers/MQTTReplyFormat.h` | `replyAppendf`, the bounded clamping printf-append behind the status/stats/diag CLI formatters — proves the out-of-bounds-write bound holds for any input size rather than by input-size accident |
| `test_mqtt_wire_scratch` | `src/Packet.cpp` wire sizing | the accept/reject edges of `canSerialize()`. `Packet::writeTo()` returns a `uint8_t` and so cannot report an overrun, and it trusts the packet's own length fields — these cases are what keep it in bounds |
| `test_config_serializer` | `src/helpers/ConfigSerializer.h` | serial config save/load round-trips: escaped characters, leading and trailing whitespace, unmatched braces and missing commas |
| `test_mesh_tables` | `src/helpers/SimpleMeshTables.h` | duplicate suppression: `wasSeen` is a pure query that never inserts, `markSeen` affects only its own packet, and the flood/direct duplicate counters increment on the right path |
| `test_utf8_helpers` | `src/helpers/UTF8Helpers.h` | truncation that never splits a code point, and rejection of malformed, truncated and unexpected-continuation sequences |
| `test_webconfig_batch` | `src/helpers/WebConfigBatch.h` | the config-batch / reboot / stop state machine: reqid replay without re-applying, busy only while pending, 25 ms inter-command pacing with inclusive release, and `millis()` rollover. Mirrors `WebConfigServer.cpp`; see the scope note in the header |
| `test_mqtt_slot_auth` | `src/helpers/MQTTSlotAuth.h` | how a slot signs in (JWT or password, the stale-audience case) and its label; one client id per slot, the node id, slot number and a private tag, never shared by two slots nor computable from the public key |
| `test_fork_seams` | `include/ForkFeatures.h`, `src/helpers/ForkText.h`; also in envs `native_ar`, `native_rc` and `native_arrc`, each with its combination's switches on | where the features meet: the feature token for every combination, its codes in the fixed order `as` `ar` `rc` and never a dash, and the token this build's own switches give; `forkParseOnOff`, the on/off reader every feature's settings share; the fixed-length region code and key checks auto-reply uses (so it needs no Observer header) |
| `test_fork_settings` | `AutoReplyLogic.h`, `MqttControlLogic.h`, `OtaAutoLogic.h` (the three settings codecs) | a node flashed arrc → ar → rc → arrc with settings changed on the way loses nothing, and an absent feature's file stays byte for byte; an ar-13 node's OTA bytes are read by lou-14 and carried for a rollback; `/mqttcontrol` versions 1-3 read |
| `test_mqtt_v2` | `src/helpers/MqttControlV2.h` | **env `native_v2`**, against the real rweather/Crypto and ed25519: ChaCha20-Poly1305 (RFC 8439) and HKDF (RFC 5869) vectors, both sides agreeing on the key, the nonce from the counter, padding at 64/65/160/161 and 256/257/512, the tag checked first, counter and expiry bound by the tag, an r3 round trip, no nonce reused across a reboot, a v1 payload never taken for v2; writes the shared fixture `v2-vectors-ar-13.txt` |
| `test_kiss_modem` | `examples/kiss_modem/KissModem.h` | KISS framing over the modem path (`native_kiss_modem` environment) |

## Conventions (and how to add a suite)

- Each `test/test_<name>/` directory builds into its **own** GoogleTest program
  and must define its own `main()` (`::testing::InitGoogleTest` + `RUN_ALL_TESTS`).
- Tests are **host-only**: include only pure headers. Arduino/crypto stubs live
  in `test/mocks/` (on the include path via `-I test/mocks`).
- Firmware headers are included from `src` (via `-I src`, e.g.
  `#include "helpers/MQTTPresets.h"`). Some are guarded or ESP-flavored, so a
  suite may need shims **before** the include — e.g. `test_mqtt_presets` does
  `#define WITH_MQTT_BRIDGE 1` (the preset table is behind that flag) and
  `#define PROGMEM` (the embedded CA-cert strings are PROGMEM-qualified).
- To add a suite: create `test/test_<name>/test_<name>.cpp` with a `main()`, and
  add any host-only source it links to the `native` env's `build_src_filter` in
  `platformio.ini` (header-only code needs no source entry). No other wiring.
- Keep logic testable by extracting pure functions into headers (as
  `MQTTObserverValidation.h` / `WebConfigKeys.h` / `MQTTTopicTemplate.h` do) and
  having the firmware call the same functions.
