# Remote control over MQTT

> Feature `rc` (`WITH_MQTT_COMMAND`): in the `rc` and `arrc` Observer images ([fork.md](fork.md)).
> In an `rc` image without auto-reply, `trigger test`, `trigger private` and the `autoreply`
> settings are refused as `not-allowed`.

An observer node can accept commands published to it over MQTT: parameter changes, and a
request to send a test now, on the channel or to one repeater alone. It is **off by default** and inert without a configured command key.

Flashing a fleet takes months. This exists so that changing a parameter afterwards costs a
signed publish rather than another flashing round.

## The threat model in one line

A login to the command broker costs nothing to make, and **any login may publish a command to
any node**, so nothing here trusts the transport: a command runs only if it carries a valid
Ed25519 signature by the command key this node was given.

## Turning it on

```
set mqtt.cmd.pubkey <64 hex characters>   # serial, or a remote admin's first key; the PUBLIC half of the signing key
set mqtt.cmd on                           # takes a slot, or puts the plane's back on the preset; reboot to apply
set mqtt.cmd on <host>                    # the same on a region's own broker (lou-18)
get mqtt.cmd                              # state, counter, slot, /cmd subscription, last command
mqtt.cmd ping                             # the whole plane, end to end, on the spot (ar-12)
```

**`set mqtt.cmd on` with no slot configured sets the node up by itself** (2026-10-08): it
takes a free slot, gives it the built-in `mccontrol` preset -- the default command broker,
`mqtts://mqtt-meshcore.louie.se:8883`, token login like the collectors -- with every packet type on
(so the broker collects the region's packets beside the status and neighbours the plane's statistics use), points the
control plane at that slot, enables it, and answers
`OK - slot 3, mccontrol (mqtts://mqtt-meshcore.louie.se:8883), packets on; reboot to apply`.

Which slot (operator 2026-10-10, from ar-12):

- **Slot 1 is the observer's and is never taken.**
- **On a board without PSRAM**, which runs two slots at once, slot 2 is the plane's and is
  taken first when it holds `none` or the Observer's default `analyzer-eu`. Taking
  `analyzer-eu` turns that uplink off, and the reply says so:
  `OK - slot 2 (was analyzer-eu, now off), mccontrol (...), packets on; reboot to apply`.
  Any other preset in slot 2 is a collector the owner chose and is left alone; the pick moves
  on to 3-6.
- **With PSRAM** the pick is the first of slots 3-6 whose preset is `none`; slot 2 is never
  taken there, whatever it holds.

**The plane's slot is not changed by anything else.** While `mqtt.cmd.slot` names a slot,
every command that would change it is refused with the reason, by serial or over the plane:
`set mqttN.<anything>` for that slot, and `set mqtt.analyzer.us|eu on|off`, which write slots
1 and 2. Over the plane such a command would cut the line it arrived on. To change the slot,
move the plane first with `set mqtt.cmd.slot`, which the command plane does not admit.

When no slot can run another connection the reply says so and names the cure -- turn one off
(`set mqtt2.preset none`) -- rather than doing it for you.

**A region's own command broker** (lou-18): `set mqtt.cmd on <host>` does the same with a
custom slot in place of the preset -- server `mqtts://<host>:8883`, the host as the login
token's audience, every packet type on -- and answers
`OK - slot 3, custom (mqtts://mqtt.meshcore-vgr.se:8883), packets on; reboot to apply`. The
host is a name: letters, digits, `.` and `-`, up to 50 characters; a URL, a port or anything
else is refused. The slot is chosen as above, or, when the plane already has one, that slot
is rewritten, so a node moves from the shared broker to its region's (or between two
regional ones) in one line. The bare `set mqtt.cmd on` stays the shared broker, and from
lou-19, on a node whose plane already has a slot, it rewrites that slot back to the
`mccontrol` preset (server and audience cleared, every packet type on) and answers
`OK - slot 3, mccontrol (mqtts://mqtt-meshcore.louie.se:8883), packets on; reboot to apply`:
the one-line repair for a plane slot that was pointed elsewhere. Before lou-19 it only turned
the plane on and left the slot as it was. Either form saves the slot to the Observer's
settings before the plane is pointed at it, and refuses, changing nothing, when that save
fails. On lou-18 the host form saved the wrong settings file, so its answer was right but
the slot was back as it was after the reboot. Like every
`set mqtt.cmd`, it is not admitted over the broker; the mesh road's repair allowance (below)
admits both forms. On firmware before lou-18 the same slot is set by hand:

```
set mqttN.preset custom · set mqttN.server mqtts://broker.example:8883 · set mqttN.audience broker.example
set mqttN.filter all
set mqtt.cmd.slot <n>                     # the MQTT slot to listen and answer on; reboot to apply
```

The key and the slot are both needed. With `mqtt.cmd on` but no command key, every command is refused -- and,
importantly, *discarded*. The node holds one staged command at a time and a full slot drops
the newer arrival, so a refusal that left the slot occupied would silently swallow every
later command for the rest of the boot, including the ones sent once a key was finally
provisioned. Refusing and clearing are the same act (`mqttCtrlOwnerReady`, tested in
`test_mqtt_control`).

`mqtt.cmd.pubkey` is not `mqtt.owner`. `mqtt.owner` is the Observer firmware's own setting: it
names the person who owns the node, and travels in the login token to the stats services. The
command key is one key for a whole fleet, held by whoever runs the control plane, so the two
are kept apart and an operator's ownership claim does not have to give way to it. Both
`get mqtt.cmd.pubkey` and `set mqtt.cmd.pubkey` answer a caller at the serial port or the
local console, where `get` shows the whole key and how it was set, and an empty `set` clears it.

A remote admin, logged in over the mesh with the admin password, may give a node its **first**
key, so a board on a mast needs no climb (lou-19). Only while no key is set: replacing or
clearing one stays with serial. And only once the admin password is not the default
`password`, is at least 8 characters and is not the guest password; the reply says which rule
failed. Over admin, `get mqtt.cmd.pubkey` shows the key's first 8 hex characters and `set via
admin` or `set via usb`. The status message carries neither: it goes to every slot, the public
brokers among them, where a key's fingerprint would group nodes by owner. The plane itself
never reaches the key: it is told apart from a remote admin by an explicit flag on the admin
login's path, never by the clock, and the deny list refuses it as well. Every password login is
throttled: a sender key that gives a wrong password 5 times is refused for 10 minutes.

## Which broker

Commands arrive on one MQTT slot and results leave by the same one, `mqtt.cmd.slot`, from 1 to
the board's slot count (3 without PSRAM, 6 with); `0`, the default, listens nowhere. The node
subscribes on that slot alone. The stats presets refuse subscriptions -- `meshcore-mqtt.meshat.se`
is the one that forced this -- so the stats go out on their preset slot as before, and the
control plane rides a broker of its own on another:

```
set mqtt1.preset meshat.se            # stats, unchanged
set mqtt2.preset custom               # plus slot 2's server and audience
set mqtt.cmd.slot 2
reboot
```

**If the slot used to hold a JWT preset, check how it signs in.** On a custom slot the audience
is the switch for JWT, and `set mqttN.preset custom` does not clear it — so the slot goes on
opening TLS and presenting a token where a password login was meant, while `get mqttN.preset`
and `get mqttN.server` read exactly as intended. `get mqtt.stats` ends each slot with the mode it
is really in — `s2=11/0 pw` or `s2=0/4 jwt` — and `set mqttN.audience` with no value clears it.

**Each slot connects with its own client id**, the node's 8-hex id, the slot number and a tag
derived from the node's private key (`A0586238-3-9F04C21B`), so one node may keep an Observer
slot and the command slot on the same broker. The tag keeps the id private: a broker closes
the older session when a new one takes its id, and on a broker with public credentials an id
computable from the node's key would let anyone knock its slot off.
Before ar-12 every slot of a board was esp-mqtt's `ESP32_<MAC>`, and a broker refused the
second login for as long as the first held the id. The per-slot id and the `pw`/`jwt` word in
`get mqtt.stats` come with this feature: an image without it ([fork.md](fork.md)) keeps the
Observer's own client ids and `get mqtt.stats` line.

The slot is read at boot, when the subscriptions are made. It cannot be set remotely: a signed
`set mqtt.cmd.slot 0` would leave a node that only a serial cable could bring back.

## mcc3: keyed by the node, sealed to its owner (lou-20)

From lou-20 the plane has a second scheme beside the one below, **mcc3**, and lou-21 will keep
only mcc3. No region anywhere: not in a topic, a key, a signature or a gate, so a node whose
`mqtt.iata` is unset is still on the plane, and an owner sees all of its nodes wherever they
are. The byte contract is mccontrol-spec's `docs/wire-format-mcc3.md` (v0.3.0); its vectors
are this tree's `test/data/mcc3-vectors.json`, rebuilt byte for byte by `test/test_mqtt_v3`.

```
mcc/cmd/{NODE}      commands to this node; the only topic it subscribes to under mcc/
mcc/r/{RID}         results, on the reply id the sealed command names (random per mccontrol session)
mcc/alive/{NODE}    the node's alive message, retained; the slot's will empties it
mcc/ping/{NODE}     `mqtt.cmd ping`; the broker answers `pong|<nonce>` on mcc/cmd/{NODE}
```

There is no broadcast topic of any kind: a county act is one sealed command per node. In lou-20
the old scheme's `meshcore/{IATA}/all/cmd` is not subscribed either; its per-node topic is,
while `mqtt.iata` is set (below).

- **Keys.** `S` = X25519 of the node's identity and the command key (`set mqtt.cmd.pubkey`),
  and four keys from it by HKDF-SHA256 with info `mcc3/cmd/`, `mcc3/mesh/`, `mcc3/alive/` and
  `mcc3/fwd/` + the node's key in hex. Derived once per command key, kept in RAM.
- **A command** is ChaCha20-Poly1305 under the first, padded to one of two sizes, and holds the
  command key's Ed25519 signature over the node's key, the road, the flags, counter, expiry,
  reply id and command. The node opens the AEAD, then checks the signature: a command for one
  node verifies on no other, and an MQTT one is never taken as a mesh one. Then the counter,
  expiry, deny list and rate limits exactly as below. Everything before the signature is
  silent (counted in `get mqtt.cmd` as unverified); every outcome after it is answered, sealed
  under a fresh random nonce, on `mcc/r/{RID}`.
- **The flags byte** is reserved for delegation, which is not defined yet: a node refuses any
  envelope whose flags are not zero, silently, as `bad-version`. One bit is defined, on the
  mesh road only: `0x02`, answer with zero hops (see "Relaying" below).
- **Over the mesh** the request is sub-type `0xC2`, always 136 bytes, its command at most 57
  bytes; it is encrypted (ChaCha20, no tag) and its integrity is the signature inside. The
  response is sealed to the owner: the companion that carries either reads neither. The road's
  rules, budget and allowance are those of the v1 road below.
- **Alive.** At the first connect (after 0-120 s), then every `alive.interval` minutes times a
  fresh draw of 0.5-1.5, and 5-60 s after a reconnect, a new command key, a new `region home`
  or a new interval, the node publishes one retained message, sealed to its owner and always
  252 characters: its boot counter and sequence, uptime, clock, last counter, interval, which
  schemes and features it has, the mesh road's mode, the command key's fingerprint and how it
  was set, its version, `region home` and name. It is the owner's only way to find its nodes;
  anyone else learns that the node is on the plane and nothing more. None without a command
  key. `set alive.interval <5-1440>` (minutes, default 15), `get alive.interval`; admitted
  over the plane.

lou-20 speaks both schemes: mcc3 always, and the old v1/v2 on `meshcore/{IATA}/{NODE}/cmd` with
`r2`/`r3` on `/res`, and the `0xC1` mesh road, as before, so a tool that does not know mcc3 yet
still reaches the node. Bit 0 of the alive message's flags says the old topic is subscribed.

## Topics

```
meshcore/{IATA}/{NODE}/cmd     to one node
meshcore/{IATA}/all/cmd        to every node in the region
meshcore/{IATA}/{NODE}/res     the node's answer
meshcore/{IATA}/{NODE}/ping    the node's ping; the broker answers `pong|<nonce>` on its /cmd
```

`{NODE}` is the node's **whole public key**, 64 upper-case hex characters -- the same id the
observer's own `status` and `packets` topics carry. Until 2026-10-08 (builds up to ar-10) it
was the first four bytes; the whole key is what a broker needs so that one ACL pattern -- the
login username `v1_<key>` must appear in the topic -- keeps each node to its own `cmd` and
`res`. Tools keep showing the first eight hex characters as the node's name. A tool that
talks to both forms addresses a node by whichever its firmware carries; the broadcast topic
is the same for both.

**The prefix must be `meshcore/`.** The broker permits that namespace and silently discards
everything else: a publish elsewhere is accepted, QoS-1 acked, and dropped, with no error the
publisher can see. This was measured against `mqtt.meshat.se` on 2026-09-01, after every signed
command to a correctly configured node went unanswered — `meshcore/JKG/<node>/cmd` arrives,
`meshhealth/v1/JKG/<node>/cmd` does not.

An earlier version used a project-specific prefix to keep control traffic out of the namespace
observer tooling watches. That separation was never needed: the tooling matches on the leaf
(`+/packets`, `+/status`), so `/cmd` and `/res` never collided with it.

## Checking the plane: `get mqtt.cmd` and `mqtt.cmd ping`

`get mqtt.cmd` answers on one line (from ar-12):

```
> on, counter 41, slot 2 connected, /cmd subscribed, last command 312 s ago, ping pong in 230 ms
```

whether the slot is connected, whether the broker acknowledged the subscription since it
connected, how long ago the command key last vouched for a command, and how the last ping
ended: `pong in N ms`, `no pong in 10 s`, `publish refused`, `waiting` or `-` (no ping since boot).
From lou-18 a command refused before the key vouched for it -- no command key, the wrong one,
a broken envelope -- adds `, unverified <n> (last <reason>)`, the reason as mccontrol names it
(`sig-invalid`, `no-owner-key`, ...). Such a refusal is never answered, since anyone on the
broker can send one, so this is where it shows: `sig-invalid` means the node holds another
command key than the sender's (`get mqtt.cmd.pubkey`).

`mqtt.cmd ping` proves the rest, at the console and without the owner's laptop. The node
publishes `ping|<8-hex nonce>` on its own `/ping`, answers at once, and goes on repeating:

```
OK - ping sent, read 'get mqtt.cmd' for the pong
Err - slot 2 not connected
Err - publish refused
Err - a ping is already waiting: read 'get mqtt.cmd'
```

The command broker answers `pong|<same nonce>` on the node's own `/cmd`; `get mqtt.cmd` shows
the round trip, or `no pong in 10 s` -- the `/cmd` subscription, or a broker that does not
answer pings. The node's identity key is never a registered command key, so a message it put
on `/cmd` itself would be dropped by the broker by design; the echo has to be the broker's.

A pong is not a command. It is recognised before any signature parsing, so it costs a string
compare, never an Ed25519 verify; it is never executed, answered, logged or counted towards
the signed command that marks a new OTA image valid; and it is taken only with the nonce of
the one ping in flight, which it consumes, so a second or a stale pong changes nothing.

`mqtt.cmd ping` is admitted over the plane as a read, inside the ten-commands-an-hour budget.
Sent that way, its `r2` result is held until the ping settles and then carries the outcome --
`OK - pong in 230 ms on slot 2 (mqtts, jwt)` or `Err - no pong in 10 s: ...` -- once. It puts
nothing on the air. The broker's half (`mcbroker`) answers a ping only on the session's own
key, at most once per key per 10 s, never on `all`, and never fans the ping out.

## v2: commands and results sealed end to end (ar-13)

From ar-13 a node also accepts a **v2** command on its own topic, readable only by the holder
of the command key and the node (firmware TODO 17, byte contract in 17a):

```
v2|<counter>|<expiry>|<base64url(ciphertext || tag)>|<128-hex Ed25519 signature>
r3|<counter>|<base64url(ciphertext || tag)>
```

The key is HKDF-SHA256 over the X25519 agreement of the command key and the node's identity,
with info `mccontrol-v2|` + the node's command topic, derived once per command key (at boot and
after `set mqtt.cmd.pubkey`) and kept in RAM. ChaCha20-Poly1305; the nonce is the direction
(0 command, 1 result), seven zero bytes and the command's counter, big-endian -- the counter
is strictly increasing and persisted before the command runs, so no nonce repeats. Commands are
padded to 64 or 160 bytes, results to 256 or 512, so length does not name the command. The node
opens the AEAD first and drops a forgery before any other work; then the counter, expiry,
rate limits and deny list apply to the opened text exactly as for v1. The outer signature is
for the broker. A v2 command that ran is answered with an `r3`; a v1 command with `r2`, as
before. A v2 command the node refuses (replay, expired, rate limit, deny list) is answered with an
`r2` whose command field is empty (lou-19): a refusal does not consume the counter, so an `r3`
for it could repeat the nonce of an earlier or later `r3` under the same counter. The `r2` shows
the counter and the refusal code, never the sealed command. Broadcasts stay v1. A tool sends v2 only to a node whose `ver` is ar-13 or later.

## The envelope

```
payload      = <signed-part> "|" <128 hex Ed25519 signature>
signed-part  = "v1|" <counter> "|" <expiry> "|" <command>
signed bytes = <topic> "\n" <signed-part>
```

Not JSON. Signing a JSON document requires canonicalisation, and every canonicalisation bug is
a signature-bypass bug; here the signed region is a literal byte range of the payload as it
arrived. The payload is split at the **last** `|`, verified, and only then parsed.

**The topic is inside the signature.** One signature is therefore valid for exactly one
destination: a command captured from one node cannot be replayed at another, and a per-node
command cannot be replayed as a broadcast. Neither case is visible to a counter, because each
node keeps its own.

## What a node checks, in order

```
feature enabled → command key set → signature valid
  → counter strictly greater than the stored one → not expired
  → rate limit → command not on the deny list
  → store the counter → run it → publish the result
```

- **The counter is stored before the command runs**, never after. A counter written afterwards
  is reopened by whatever crashes mid-command, and a silently repeated trigger spends
  airtime nobody asked for. The cost is that a crashed command is not retried, which is the
  right way round.
- **Expiry fails closed without a clock.** If NTP has not synced, every command is refused
  rather than accepted on a guess. A command may not be valid more than an hour ahead.
- **The rate limit applies to validly signed commands** — 50 an hour (10 before lou-20), and 2 transmits, on
  separate counters: a trigger spends a transmit, a `set` or `get` spends a command, and
  neither spends the other's.
  **The hour slides.** No span of 3600 s holds more than the budget, wherever it starts; a
  fixed window would let a command late in one hour and a full budget early in the next
  through together — three floods in two seconds. A refused command spends nothing, and a
  clock stepping backwards costs at most an hour of refusals, never an extra allowance.
  A signing key that leaks must not become a mesh-flood weapon; the airtime is not ours.

## What may be sent

**Everything the CLI answers, except a deny list.** Until 2026-10-08 this was an allowlist of
fourteen entries; the operator's decision that day makes the control plane a command centre for a
repeater's owner, and the list to review is now what is *refused*
(`mqttCtrlCommandDenied` in `src/helpers/MqttControlLogic.h`, one test per group in
`test/test_mqtt_control`). A command must begin with an admitted verb -- `set`, `get`,
`region`, `trigger test`, `trigger private`, `neighbor.remove`, `sensor`, `gps`, `powersaving`,
`clock`, and exactly `ver`, `reboot`, `clkreboot`, `neighbors`, `board`, `memory`,
`clear stats`, `ota check` -- and match nothing below. A verb the CLI grows later does not reach
the mesh until someone adds it.

| denied | why |
|---|---|
| `set prv.key`, `set public.key` | identity: a changed key is a different node, and the fleet, the maps and every history line lose it |
| `set mqtt.cmd*` (`.slot`, `.pubkey`), `get mqtt.cmd.pubkey` | the plane itself: a signed command that repoints the slot or the key silently removes the node from control, and only a serial visit undoes that. The standard MQTT settings -- `mqttN.*`, `mqtt.presets`, `mqtt.iata`, `mqtt.*` -- are deliberately admitted: a broker may go away and another must be reachable without a visit |
| `password`, `wifi.pwd`, `wifi.ssid`, `guest.password`, `alert.psk`, `bridge.secret`, `snmp.community`, `mqtt.email`, `mqtt.owner`, `owner.info`, `tls*`, `get prv*`, `get mqttN.password/.token/.username` | credentials and ownership, read and written: a result is public on the broker, and a write of these takes over something other than the node. The secrets are denied by bare prefix, so no suffix reaches them |
| `erase`, `start *` (webconfig, the SoftAP OTA), `poweroff`, `shutdown`, `set bootloader.ver` | no way back from the road. `reboot` and `clkreboot` are admitted: settings need them to apply. `ota check` is admitted as a read, and from lou-19 `ota update` to one node: the image is signed and the old one comes back if the new one never proves itself ([ota.md](ota.md)) |
| `set lat`, `set lon`, `get lat`, `get lon`, `set role`, `set repeat` | position is evidence the whole mesh relies on, and whether a node publishes where it is belongs to its owner per node (the advert), not to a signed read whose result is public; `repeat off` is how a leaked key would silence a region in ten commands |
| `set freq`, `set radio*`, `set tx`, `set extra.sf`, `set dutycycle`, `tempradio` | a wrong value takes the node off the mesh with no remote way back |
| `advert*`, `alert *`, `set advert.interval`, `set flood.advert.interval` | transmissions; `trigger` is the one sanctioned transmit, on its own budget |
| `time <epoch>` | the clock judges expiry; `time` steps it forward by any amount. `clock sync` steps it to the node's own now and is admitted |
| `log`, `stats-*` | serial-only already (`sender_timestamp == 0`); listed so the two gates agree |

What this admits that the allowlist did not: every tuning write (`txdelay`, `rxdelay`, `af`,
`cad`, `int.thresh`, `flood.max*`, `path.hash.mode`, `loop.detect`, `multi.acks`, ...), every
`mqtt.*` and `mqttN.*` setting, `set name`, every read that names no secret, `neighbors`,
`reboot`.

**`get stats`** is the one read added for this plane: the node's own counters -- the block
every status publish carries -- as one line of short pairs that fits the 160-byte reply,
`> batt=4261mV up=1496188s noise=-114 tx=5518s rx=25369s sent=9065 recv=44345 err=10
rxerr=13369 q=0`. The counters are read from the mesh itself and `q` from the bridge's queue,
left out while the bridge is not running; a value the node cannot measure is left out. It is
the command plane's own command, so an image without it does not have it. The `stats-*` dumps
it stands in for stay serial-only.

**`get sensors`** (lou-20) reads what the node measures, on either road and on an image without
an uplink too: `> batt=3881mV mcu=21.5C temp=23.5C hum=40.5% press=1013.2hPa temp/2=-4.5C`.
`batt` and `mcu` (the MCU's own temperature, where the board has one) come from the board; the
rest is what the board's sensors report for a telemetry request, with the channel after a
slash when it is not the node's own. A position is left out. The line is at most 125 bytes,
what a sealed answer over the mesh carries, and ends on a whole pair. `get stats` is answered
on an image without an uplink too.

**`set mqtt.cmd.debug on|off`** (lou-20, the serial console only, until the next boot) prints
one line, `mcc: ...`, for each command or forward heard on either road and where it stopped:
not listening, refused before it ran and why, run, answered, and the airtime of what went
out. It prints no key, no signature and no command text. `get mqtt.cmd.debug` says which.

A `set` of a key the CLI does not know travels and is answered "unknown": the deny
list bounds what a command may *do*, not whether it is well formed, and the CLI stays the
authority on the latter.

The auto-reply family and the triggers are as before, in an image that has auto-reply
([fork.md](fork.md)). In one built without it (`rc`), every command below that starts with
`trigger`, `set autoreply` or `get autoreply` is refused as `not-allowed` before any budget is
spent, rather than reaching a CLI that would answer "unknown"; the region map is unaffected.
The verdict for every known command, both ways, is in `test/data/command-verdicts.txt` (with
auto-reply) and `command-verdicts-rc.txt` (without), written by `test_mqtt_control`.

```
set autoreply on|off · set autoreply.hops · set autoreply.direct.flood
set autoreply.slot · set autoreply.window · set autoreply.slots
set autoreply.region · set autoreply.mode · set autoreply.private
get autoreply* · trigger test [<id>] [<F|P|D|S>] · trigger private <64 hex> [<id>]
region · region put <name> [<parent>] · region allowf <name> · region denyf <name>
region remove <name> · region default <name> · region home <name> · region save
```

**The region map is admitted whole**, so a scope rollout across a fleet is one signed publish
per node -- or one to `meshcore/{IATA}/all/cmd`, since changing the map costs no airtime and the
broadcast guard applies only to triggers. The reply to a bare `region` is the map as the CLI
prints it, so a change can be checked from the result topic. Two things to know before sending:

- `region denyf *` and `region remove` can cut a repeater out of its own area. They are admitted
  on purpose; the node does not second-guess a signed command, so the tool that sends them is
  where the question gets asked.
- `region def` with the tree syntax (`a|* b|*`) carries `|`, which is the envelope's field
  separator, and is refused before the deny list is consulted. Add names one at a time with
  `region put <name> *`, which also leaves existing names, their flags and their parents alone.

`trigger test` originates a probe on the channel, naming a mode the way a request sent by hand
does; `trigger private` sends a test request to the one repeater whose key is given, and the
answer comes back to this node alone. Both are described in
[Repeater auto-reply](autoreply.md).

The deny list is deliberately independent of the second guard: MQTT commands run with the
node's clock rather than the `0` that marks a locally-privileged caller, so `set prv.key`,
`erase`, `log`, the `stats-*` dumps and `set mqtt.cmd.pubkey` refuse them anyway. Either alone
should be enough; both together mean one of them can be wrong.

**The deny list matches with the boundary rule, and the secrets without one.** A family entry
ends at end-of-string, a space or a dot, so `set radio` denies `set radio.rxgain` but not a
setting that merely starts with the same letters, and `set tx` does not deny `set txdelay`.
The secrets (`prv`, `password`, `wifi.pwd`, the command key, ...) are denied by bare prefix,
because `CommonCLI`'s own `handleGetCmd` matches with an unbounded `memcmp` and `get prv.keyx`
would otherwise reach the key's handler.

A node on older firmware refuses most of this with `not-allowed`. That is the mixed fleet
working as intended, and a reader must record it as "did not answer" rather than as an absent
setting.

### A transmit command may not be broadcast

`trigger test` or `trigger private` sent to `meshcore/{IATA}/all/cmd` is refused, on principle
rather than on budget.

The rate limits are per node — two triggers an hour each. That bounds what one node does and
says nothing about one publish reaching every node in a region, each of them then transmitting
inside the same few seconds, every one within its own budget. The workspace rule is explicit
that any design which scales transmissions with the number of nodes is wrong, and a broadcast
trigger is exactly that shape: the more of the mesh adopts this firmware, the worse the storm
it enables.

Broadcasting a *parameter* change stays allowed — setting a value costs no airtime. Only
transmitting is refused, and the check is stateless so it runs before the limiters spend
anything.

`ota update` is refused there too, with the same code (lou-19). It costs no airtime, but it
restarts every node it reaches: one publish would take a region off the air at once, on an image
no node had yet shown to work. Sent to one node it is a command like any other, on the command
budget.

`reboot` is refused there for the same reason (lou-19, operator 2026-11-17): one publish would
restart the whole region together. Sent to one node it is admitted as before.

## Over the mesh, when Wi-Fi or the broker is down (lou-19)

A node whose Wi-Fi or broker fails is still on the mesh. The same signed `v1` command can then
reach it as an anonymous request from a companion, sub-type `0xC1`, encrypted to the node alone:

```
request   tag (4) | 0xC1 | counter (4) | expiry (4) | signature (64) | command (1-59 bytes)
response  tag (4) | node clock (4) | counter (4) | code (1) | reply
```

Integers little-endian. The node rebuilds the topic it would have received the command on,
`meshcore/{IATA}/{own key}/cmd`, and the text `v1|<counter>|<expiry>|<command>`, and verifies the
signature over both exactly as on `/cmd`. One signature is therefore valid on both roads, and the
counter is one counter: a command that arrives both ways runs once.

The checks are the plane's, with three differences:

- **The repair allowance.** Over the mesh, and only there, `set wifi.ssid <name>`,
  `set wifi.pwd <password>` and `set mqtt.cmd on [<host>]` are admitted, so a node can be put
  back on its network and its broker; `reboot` applies them. The command is encrypted to the
  node on this road, where on the broker it is plain text. Everything else the deny list holds
  stays denied, and the command still runs with a non-zero `sender_timestamp`.
- **An unset clock.** A node cut off from NTP may have only the firmware's 2024 default. Then
  the expiry is not checked and the counter alone stops a replay.
- **A flooded request is answered 15 to 30 s later**, at random, once its copies have died
  down around the node: an answer sent at once goes out while the repeaters around are still
  repeating the request, and is lost (measured at Gisebo, 2026-11-23). A request that came
  direct is answered at once.
- **An airtime budget for the answers**, on top of the plane's own budget: the first answer
  opens a burst of 15 minutes in which answers may fill 5 % of the time (45 s on the air), the
  15 minutes after it hold 1 % (9 s), and the answer after that opens the next burst. It is
  counted in the radio's own estimate for each answer, so the shares hold on any radio
  setting; the answer that crosses the line is the last. A request that the key did not sign,
  whose counter is not new, or that is over this budget is not answered at all, so nobody who
  heard a request can make the node transmit by sending it again. A request that was answered
  with a refusal counts as seen too, until the next restart.
- **The way back.** A request that came direct tells the node no path to its sender. Whoever was
  answered over the mesh is therefore listened to for five minutes for MeshCore's reciprocal
  path: a relay sends it when a flooded answer reaches it (the path that answer took, sent
  direct), and a companion does of its own accord. The node keeps the path in RAM, for the three
  senders it answered last, and answers their next direct requests along it. Until it has one
  (after a restart, or for a sender never reached by a flood) the answer to a direct request is
  flooded in the node's default scope, as before. A path that has stopped working shows as no
  answer to a direct command: one flooded command renews it, because the answer to a flooded
  request is always flooded.

`set mqtt.cmd.mesh off|on|auto` (console or admin login; denied on both roads) says when the
road is open. `auto`, the default, opens it once the command slot has been down 15 minutes, so
a node whose broker answers never takes commands over the air; until then a signed request is
answered `mesh-closed` (code 19). `get mqtt.cmd.mesh` says which, and `get mqtt.cmd` adds
`, mesh <mode> ok <n> refused <n>`. With `set mqtt.cmd off` the road is closed too. `reboot`
answers nothing, over the mesh as over MQTT. A firmware without the road reads `0xC1` as a
login whose password no one can type, and answers nothing.

### Mesh only: boards without Wi-Fi

An `rc` or `arrc` image built without the Observer bridge -- an nRF52 board, or an ESP32 built
as a plain repeater -- has no Wi-Fi and no MQTT, and the mesh road is its only road. Everything
above holds, with these differences:

- **The topic is `meshcore/mesh/{own key}/cmd`.** Such an image has no `mqtt.iata`, so the
  region in the topic it rebuilds is always the word `mesh`, and that is what a sender signs
  for a node it knows as mesh only. `get mqtt.cmd` says `mesh only`.
- **The road is always open** while `set mqtt.cmd on`: there is no MQTT to wait for, so
  `mqtt.cmd.mesh` does not exist there, and a mode carried over in `/mqttcontrol` from an
  Observer image is ignored.
- **What only an uplink means is refused** as `not-allowed` (14): the repair allowance, which
  repairs an uplink there is none of, `ota check`, `ota update`, `mqtt.cmd ping` and the broker
  slots' settings (`set mqttN.*`). The deny list applies in full.

On an Observer image the mesh road already reaches the broker slots' settings (`set mqttN.*`),
as the deny list admits them, so a broken Observer feed can be repaired over the mesh.

Set it up on the console: `set mqtt.cmd.pubkey <64 hex>` (serial only, as everywhere), then
`set mqtt.cmd on`.

## Relaying: one node's MQTT for another node's command (lou-20)

A node without Wi-Fi, or whose Wi-Fi is down, can only be reached over the mesh, and until now
that took a companion radio near it. From lou-20 an Observer node of the same owner can do the
sending. That node is the **relay**; the node the command is for is the **target**.

mccontrol builds the mesh-road request for the target as before (`0xC2`, or `0xC1` for a lou-19
target), and wraps it in a **forward** to the relay, on the relay's own `mcc/cmd/{NODE}`. The
relay sends the request to the target as its own anonymous request, waits up to 120 s for the
answer, and publishes a **forward result** on the `mcc/r/{RID}` the forward named. Forward and
result are sealed under a fourth key, HKDF info `mcc3/fwd/` + the relay's key, from the same
`S`. The relay cannot read a `0xC2` request or its response: they are sealed between the target
and its owner.

A forward runs nothing on the relay. It never reaches the CLI, so the deny list and the command
counter are not involved. This is the plane's second sanctioned transmit, beside `trigger`.

- **The switch.** `set mqtt.relay off|own`, `get mqtt.relay`. The default is `own`: the relay
  serves the holder of its own command key and nobody else. A node without a command key never
  relays. The owner may switch it over the plane; it is not under `mqtt.cmd`, so the deny list
  admits it. Observer `rc` and `arrc` images only.
- **The budget.** The relay's requests have the same airtime budget as a node's answers: a
  burst of 15 minutes at 5 % (45 s on the air, about 26 requests), then 15 minutes at 1 %
  (9 s), then a burst again. A flood also costs every repeater that hears it, so floods keep
  limits of their own: one a minute in a burst, one in five minutes in a cooldown, 100 in a
  day, and of those that leave the region home (the default scope, or any flood from a relay
  with no region home) two an hour. One forward waits at a time. Fixed. A request that could
  not be sent spends nothing. The budgets are kept in RAM: a restart opens a burst.
- **The way back.** When a flooded answer reaches the relay, it sends the target the path that
  answer took, direct along the path the answer taught (MeshCore's reciprocal path; counted in
  the airtime budget). The target then answers direct commands along it instead of flooding.
- **The route** is the owner's choice per forward: direct along a path the forward carries (no
  path means one transmission, for a target the relay hears itself), a flood in the relay's
  `region home`, or a flood in its default scope. A flood in `region home` uses the default
  scope when there is no home, and both are un-scoped when the relay has no scope at all.
- **Replay.** A forward carries a counter and an expiry at most 300 s ahead of the relay's
  clock. The relay keeps the last counter in RAM and refuses a forward while its clock is
  unset. After a reboot a forward from the last 300 s could be sent once more; the target's own
  counter then refuses it.
- **The result** says what happened: `answered` with the target's response, `no-answer` (sent,
  nothing came back; the target may still have run the command), or why nothing was sent:
  `off`, `expired`, `replay`, `bad-body`, `busy`, `rate-limited`, `clock-unset`, `send-failed`.
  With an answer come its SNR at the relay and, when the answer returned a path, that path,
  which mccontrol can send direct along next time.
- `get mqtt.relay` answers `> own, forwarded 3, answered 2, refused 1, burst, 39.9 s airtime
  left, floods today 1 of 100`, the counts since boot, or `> off`. Bit 4 of the alive message's flags says the
  node relays.

Anything that is not a forward of the owner's is dropped in silence and counted in
`get mqtt.cmd` as unverified, as a command is.

**The zero-hop flag** is for the target, on every lou-20 image. Flags bit `0x02` in a `0xC2`
request, inside the signature, says: answer with one transmission and no path. The target then
answers directly to the sender, however the request arrived. mccontrol sets it only when the
relay hears the target directly and sends with no hops, so the whole exchange is two
transmissions. If the link works one way only, the answer is lost although the command ran.
Any other flag bit is still refused.

## What is not defended

- **Confidentiality, for `v1` and broadcasts.** A `v2` command and its `r3` result are sealed end
  to end between the owner's key and the node (see the envelope above): the broker and other
  logins see only the topic, the counter, the expiry and the padded length. A `v1` command, its
  `r1`/`r2` result and every broadcast are readable by every login, and the plaintext listener
  carries them in the clear; older firmware and older tools use only these. So nothing secret may
  appear in a command or a result in any version -- which is what the deny list keeps true.
  **What a result may never carry,** and so what the deny list refuses as a read: any key
  (`prv.key`, the command key, `mqtt.owner`, `bridge.secret`), any credential (`password`,
  `guest.password`, `wifi.pwd`, a slot's `password`, `token` or `username`), which network it
  is on (`wifi.ssid`), and where or whose it is (`lat`, `lon`, `owner.info`) — an advert may
  publish a position, but that is the operator's choice to make per node, not something a
  signed read whose result is public should decide. A slot's `server` and `preset` are
  readable since 2026-10-08, because they are settable over this plane and a change must be
  checkable. `NothingAResultMayNeverCarryCanBeRead` pins the list. What else is readable is
  configuration, which anyone in range could largely infer by listening.
- **Availability.** Anyone can flood the broker. The node's rate limit bounds the airtime
  consequence; it cannot make the broker quiet.
- **A compromised command key.** Whoever holds it can do anything not on the deny list, which
  since 2026-10-08 is most of what a repeater does — short of silencing it, moving it, re-keying
  it or taking it off the control plane. Rotation needs serial access.

## The result

A node that verified a command publishes the outcome to its own result topic:

```
meshcore/{IATA}/{NODE}/res
r2|<counter>|<code>|<command>|<reply>|<128 hex Ed25519 signature>      ar-11 and later
r1|<counter>|<code>|<command>|<reply>                                   up to ar-10
```

**The result is signed by the node** from ar-11: Ed25519 by the node's own identity key over
`"<result topic>\n" + "r2|<counter>|<code>|<command>|<reply>"` -- the same shape as a command's
signature, so one verifier serves both, and the key to check with is the one the topic names.
Nothing here trusts the transport with a node's name either: an unsigned line could be
published as `ok` in a node's name by anything the broker lets write there; now a tool shows a
result as *verified* when the signature checks, *unverified* for an `r1` from older firmware,
and a bad signature as what it is. The reply shortens so the signature always fits the line.

The counter is the one the requester chose, which makes it the correlation id: the topic says
which node answered, the counter says which question it answered. Split on the first four
separators and take the remainder as the reply, then (for `r2`) cut the last separator and the
128 hex after it -- a command can never contain a separator (`mqttCtrlCommandCharsOk` refuses
it), so only the reply can, and only in the middle.

It is published at **QoS 1, not retained**. The QoS is not there for delivery: in this bridge a
QoS 0 publish is a synchronous write from the calling task, and the result is published from the
loop task while the bridge's task writes packets to the same socket. On firmware up to
`v1.17.0-observer-autoreply-2` and `8530d4bb` that interleaving makes the broker drop the node —
**one reconnect per command** — so on those builds space commands by 30 s and retry on silence.
At QoS 1 the MQTT task is the only writer. *Reasoned from the code and compiled; not yet seen on
a node, because nothing is flashed during the freeze.*

A line too long for the buffer is **truncated, never dropped**. The reply is last and every
earlier field is bounded, so a clamped line still parses.

**Only an outcome whose signature verified is published.** Verification runs before the rate
limiter — the limiters spend budget when asked, so every stateless check comes first — which
means a bad-signature refusal is not rate limited, and publishing those would let anyone who
can log in to the broker drive unlimited publishes out of the node. A legitimate
requester holds the command key, so its commands always draw an answer whether they succeed or
are refused; nothing readable is lost.

| Code | Meaning |
|---|---|
| 0 | ran; `reply` holds the output |
| 9 | replayed — counter not greater than the last one stored |
| 10 | expired |
| 11 | expiry too far in the future |
| 12 | no trusted clock; expiry fails closed |
| 14 | on the deny list, or not an admitted verb — a permanent no |
| 17 | rate limited — ask again later |
| 18 | a transmit command addressed to every node at once |

Codes are appended to the enum and never renumbered, so a stored result keeps its meaning.

