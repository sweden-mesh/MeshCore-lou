# Remote control over MQTT

> Feature `rc` (`WITH_MQTT_COMMAND`): in every `rc` and `arrc` image ([fork.md](fork.md)); on a
> board without the Observer it works over the mesh only
> ([Mesh only](#mesh-only-boards-without-wi-fi)).
> **From lou-20 the settings are named `cmd`** (`set cmd on`, `cmd.pubkey`, `cmd.slot`,
> `cmd.mesh`, `cmd ping`) and relaying is `set relay`. The names of lou-18 and older
> (`mqtt.cmd`, `mqtt.cmd.pubkey`, ...) are gone: a node answers them as unknown. The
> stored settings carry over. Coming from lou-20 or older:
> [Upgrading to lou-21](#upgrading-to-lou-21).
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
set cmd.pubkey <64 hex characters>   # serial, or a remote admin's first key; the PUBLIC half of the signing key
set cmd on                           # takes a slot, or puts the plane's back on the preset; reboot to apply
set cmd on <host>                    # the same on a region's own broker (lou-18)
get cmd                              # state, counter, slot, /cmd subscription, last command
cmd ping                             # the whole plane, end to end, on the spot (ar-12)
```

**`set cmd on` with no slot configured sets the node up by itself** (2026-10-08): it
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

**The plane's slot is not changed by anything else.** While `cmd.slot` names a slot,
every command that would change it is refused with the reason, by serial or over the plane:
`set mqttN.<anything>` for that slot, and `set mqtt.analyzer.us|eu on|off`, which write slots
1 and 2. Over the plane such a command would cut the line it arrived on. To change the slot,
move the plane first with `set cmd.slot`, which the command plane does not admit.

When no slot can run another connection the reply says so and names the cure -- turn one off
(`set mqtt2.preset none`) -- rather than doing it for you.

**A region's own command broker** (lou-18): `set cmd on <host>` does the same with a
custom slot in place of the preset -- server `mqtts://<host>:8883`, the host as the login
token's audience, every packet type on -- and answers
`OK - slot 3, custom (mqtts://mqtt.meshcore-vgr.se:8883), packets on; reboot to apply`. The
host is a name: letters, digits, `.` and `-`, up to 50 characters; a URL, a port or anything
else is refused. The slot is chosen as above, or, when the plane already has one, that slot
is rewritten, so a node moves from the shared broker to its region's (or between two
regional ones) in one line. The bare `set cmd on` stays the shared broker: on a node whose
plane already has a slot, it rewrites that slot back to the `mccontrol` preset (server and
audience cleared, every packet type on) and answers
`OK - slot 3, mccontrol (mqtts://mqtt-meshcore.louie.se:8883), packets on; reboot to apply`.
It is the one-line repair for a plane slot that was pointed elsewhere. Either form saves the
slot to the Observer's settings before the plane is pointed at it, and refuses, changing
nothing, when that save fails:
`Err - the MQTT settings could not be saved: slot 3 and the plane are unchanged`. Like every
`set cmd`, it is not admitted over the broker; the mesh road's repair allowance (below)
admits both forms. The same slot can be set by hand:

```
set mqttN.preset custom · set mqttN.server mqtts://broker.example:8883 · set mqttN.audience broker.example
set mqttN.filter all
set cmd.slot <n>                     # the MQTT slot to listen and answer on; reboot to apply
```

The key and the slot are both needed. With `cmd on` but no command key, every command is
refused and *discarded*. The node holds four arriving messages in a queue and takes them up
in the order they came. A refused message left at the front of that queue would hold back
every later command for the rest of the boot, including the ones sent once a key was finally
provisioned. Refusing and clearing are the same act (`mqttCtrlOwnerReady`, tested in
`test_mqtt_control`).

`cmd.pubkey` is not `mqtt.owner`. `mqtt.owner` is the Observer firmware's own setting: it
names the person who owns the node, and travels in the login token to the stats services. The
command key is one key for all of one owner's nodes, so the two
are kept apart and an operator's ownership claim does not have to give way to it. Both
`get cmd.pubkey` and `set cmd.pubkey` answer a caller at the serial port or the
local console, where `get` shows the whole key and how it was set, and an empty `set` clears it.

A remote admin, logged in over the mesh with the admin password, may give a node its **first**
key, so a board on a mast needs no climb (lou-19). Only while no key is set: replacing or
clearing one stays with serial. And only once the admin password is not the default
`password`, is at least 8 characters and is not the guest password; the reply says which rule
failed. Over admin, `get cmd.pubkey` shows the key's first 8 hex characters and `set via
admin` or `set via usb`. The status message carries neither: it goes to every slot, the public
brokers among them, where a key's fingerprint would group nodes by owner. The plane itself
never reaches the key: it is told apart from a remote admin by an explicit flag on the admin
login's path, never by the clock, and the deny list refuses it as well. Every password login is
throttled: a sender key that gives a wrong password 5 times is refused for 10 minutes.

## Upgrading to lou-21

What changes for a node that comes from lou-20 or older:

- **One scheme is left.** lou-20 still took commands on `meshcore/{IATA}/{NODE}/cmd`, answered
  on `/res`, and took the `0xC1` request over the mesh. lou-21 takes none of them: it
  subscribes to `mcc/cmd/{NODE}` alone and answers on `mcc/r/{RID}`
  ([mcc3](#mcc3-keyed-by-the-node-sealed-to-its-owner-lou-20)). A tool must speak mcc3;
  mccontrol does. A tool that knows only the old scheme gets no answer, and an old request
  over the mesh is dropped without one.
- **A command slot from before lou-17 mends itself.** A node whose remote control was set up
  before the `mccontrol` preset signs in to the command server with a username and password,
  and that login is refused the `mcc/` topics. At the first start on lou-21 the node moves the
  slot to the preset by itself ("Which broker" below). Nothing has to be typed.
- **An `ar` or `rc` Observer node arrives at the full image.** From lou-21 an Observer board
  has one image, `arrc`, and a node on `ar` or `rc` takes it by its ordinary update
  ([ota.md](ota.md)). The feature the old image did not have starts switched off, once, at the
  first start after the update. A node from `ar` has remote command off and keeps the command
  key its settings held: `set cmd.pubkey <key>` if `get cmd.pubkey` says `(not set)`, then
  `set cmd on` and `reboot`. A node from `rc` has auto-reply off: `set autoreply on`. The
  serial console says which:
  `OTA: this node came from an ar image: remote command starts switched off`.
  An `arrc` node is not touched.
- **`refused: clock?` in `get mqtt.status`.** A slot that signs in with a token was refused by
  its broker while no NTP server has confirmed the node's clock. A token made from a wrong
  clock is expired on arrival. The node asks for a time sync by itself after such a refusal,
  and the sync is tried again until a server answers: after 30 s, 1 min and 5 min, then
  every 15 min, and from 30 s again when the network comes back or the clock is set by
  hand. If it stays: check that the network lets NTP through, or set the clock on the
  console with `time <epoch>`; the tokens are then made again at once. `no clock` means the clock was never set (the board started at
  its power-on date) and the slot waits for one; the cure is the same.
  `get mqttN.diag` says `clock not verified: run time <epoch> or check NTP` or
  `clock not set: run time <epoch> or check NTP`.
- **Four arriving messages are held; lou-20 held one.** A stranger's publish on a node's command topic
  no longer pushes the owner's command out ("Relaying", "One at a time").

For a node that comes from lou-18 or older, also:

- **The names changed, the settings did not.** `mqtt.cmd` is `cmd`: `set cmd on [<host>]`,
  `set cmd off`, `get cmd`, `set cmd.pubkey`, `set cmd.slot`, `cmd ping`. The old names are
  answered as unknown. The command key, its counter and the slot are read from the same file
  as before, so a node that was on the plane is on it after the update.
- **`set cmd on <host>` once more.** On lou-18 `set mqtt.cmd on <host>` saved the wrong
  settings file, so its answer was right and the slot was back as it was after the reboot. A
  node meant for a region's own broker needs `set cmd on <host>` and a `reboot` after the
  update.
- **The bare `set cmd on` rewrites the plane's slot** to the shared broker
  (`mqtt-meshcore.louie.se`). On lou-18 it only turned the plane on. On a node whose plane is
  on another broker, give the host.
- **No command to a whole region.** `meshcore/{IATA}/all/cmd` is gone. A change for many nodes
  is one command to each.
- **On by default after the update,** on a node with a command key: the alive message
  (`alive.interval`), the mesh road in `auto` (`cmd.mesh`) and, on an Observer image, the relay
  for the node's own key (`set relay off` stops it). The command budget is 50 an hour, from 10.
- **Rolling back to lou-18 keeps the command key, the counter and the slot:** they are stored
  where lou-18 reads them. What came after (`cmd.mesh`, `relay`, `alive.interval`) lou-18
  does not read.

Outside the plane, from lou-20 password logins are throttled (above) and, on ESP32,
`start ota` and the setup access point answer only on serial and the local console
([fork-overview.md](fork-overview.md)).

## Which broker

Commands arrive on one MQTT slot and results leave by the same one, `cmd.slot`, from 1 to
the board's slot count (3 without PSRAM, 6 with); `0`, the default, listens nowhere. The node
subscribes on that slot alone. The stats presets refuse subscriptions -- `meshcore-mqtt.meshat.se`
is the one that forced this -- so the stats go out on their preset slot as before, and the
control plane rides a broker of its own on another:

```
set mqtt1.preset meshat.se            # stats, unchanged
set mqtt2.preset custom               # plus slot 2's server and audience
set cmd.slot 2
reboot
```

**If the slot used to hold a JWT preset, check how it signs in.** On a custom slot the audience
is the switch for JWT, and `set mqttN.preset custom` does not clear it — so the slot goes on
opening TLS and presenting a token where a password login was meant, while `get mqttN.preset`
and `get mqttN.server` read exactly as intended. `get mqtt.stats` ends each slot with the mode it
is really in — `s2=11/0 pw` or `s2=0/4 jwt` — and `set mqttN.audience` with no value clears it.

**A command slot from before the `mccontrol` preset is mended at start.** A node set
up before lou-17 has the plane on a custom slot that signs in with a username and password on
`mqtt.louie.se`. The broker lets that login in and refuses it the `mcc/` topics, so the slot
reads connected and no command arrives. At every start the node looks at the plane's slot, and
one that is a custom slot with a username, no audience and one of the plane's broker names
(`mqtt.louie.se`, `mqtt-meshcore.louie.se`, `mqtt.meshcore-jkp.se`) is rewritten as a bare
`set cmd on` would: the `mccontrol` preset, every packet type, and the old username, password
and port cleared. The serial console says `CMD: slot N was on the old login; moved to the
mccontrol preset`, once, and the slot connects on the preset in the same start. A plane that was
`off` stays off with its slot mended. A slot `set cmd on <host>` wrote (it has an audience), a
custom slot on any other broker, and settings that could not be read at start are left alone.

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
`set cmd.slot 0` would leave a node that only a serial cable could bring back.

## mcc3: keyed by the node, sealed to its owner (lou-20)

The plane has one scheme, **mcc3**. No region anywhere: not in a topic, a key, a signature or
a gate, so a node whose `mqtt.iata` is unset is still on the plane, and an owner sees all of
its nodes wherever they are. The byte contract is mccontrol-spec's
`docs/wire-format-mcc3.md`; its vectors are this tree's `test/data/mcc3-vectors.json`, rebuilt
byte for byte by `test/test_mqtt_v3`. The scheme of lou-19 and older, which lou-20 still
accepted, is gone ([Upgrading to lou-21](#upgrading-to-lou-21)).

- **Keys.** `S` = X25519 of the node's identity and the command key (`set cmd.pubkey`),
  and four keys from it by HKDF-SHA256 with info `mcc3/cmd/`, `mcc3/mesh/`, `mcc3/alive/` and
  `mcc3/fwd/` + the node's key in hex. Derived once per command key, kept in RAM.
- **A command** is ChaCha20-Poly1305 under the first, padded to one of two sizes, and holds the
  command key's Ed25519 signature over the node's key, the road, the flags, counter, expiry,
  reply id and command. The node opens the AEAD, then checks the signature: a command for one
  node verifies on no other, and an MQTT one is never taken as a mesh one. Then the counter,
  expiry, deny list and rate limits ("What a node checks, in order"). Everything before the
  signature is silent (counted in `get cmd` as unverified); every outcome after it is
  answered, sealed under a fresh random nonce, on `mcc/r/{RID}`.
- **The flags byte** is reserved for delegation, which is not defined yet: a node refuses any
  envelope whose flags are not zero, silently, as `bad-version`. One bit is defined, on the
  mesh road only: `0x02`, answer with zero hops (see "Relaying" below).
- **Over the mesh** the request is sub-type `0xC2`, always 136 bytes, its command at most 57
  bytes; it is encrypted (ChaCha20, no tag) and its integrity is the signature inside. The
  response is sealed to the owner: the companion that carries either reads neither. The road's
  rules, budget and allowance are under "Over the mesh" below.
- **Alive.** At the first connect (after 0-120 s), then every `alive.interval` minutes times a
  fresh draw of 0.5-1.5, and 5-60 s after a reconnect, a new command key, a new `region home`
  or a new interval, the node publishes one retained message, sealed to its owner and always
  252 characters: its boot counter and sequence, uptime, clock, last counter, interval, which
  features it has, the mesh road's mode, the command key's fingerprint and how it was set, its
  version, `region home` and name. It is the owner's only way to find its nodes; anyone else
  learns that the node is on the plane and nothing more. None without a command key.
  `set alive.interval <5-1440>` (minutes, default 15), `get alive.interval`; admitted over the
  plane. A mesh-only image has no MQTT and sends no alive message: its owner adds it to the
  tools by its public key. Bit 0 of the message's flags is reserved and never set: lou-20 set
  it while it still subscribed to the old topic.

## Topics

```
mcc/cmd/{NODE}      commands and forwards to this node, and the broker's pong; the only topic it subscribes to
mcc/r/{RID}         results, on the reply id the sealed command names (random per mccontrol session)
mcc/alive/{NODE}    the node's alive message, retained; the slot's will empties it
mcc/ping/{NODE}     `cmd ping`; the broker answers `pong|<nonce>` on mcc/cmd/{NODE}
```

`{NODE}` is the node's **whole public key**, 64 upper-case hex characters -- the same id the
observer's own `status` and `packets` topics carry. Tools keep showing the first eight hex
characters as the node's name. `{RID}` is 16 random bytes as 32 upper-case hex characters. It
travels only inside a sealed command or forward.

There is no topic addressed to more than one node: no region, county, owner or broadcast
topic. A change for many nodes is one sealed command to each.

A retained message on the command topic is one the broker replays at every connect. The node
drops it before anything else looks at it.

## Checking the plane: `get cmd` and `cmd ping`

`get cmd` answers on one line (from ar-12):

```
> on, counter 41, slot 2 connected, jwt, /cmd subscribed, last command 312 s ago, ping pong in 230 ms
```

whether the slot is connected, how it signs in (from lou-21: `jwt`, as the `mccontrol` preset
and a slot `set cmd on <host>` wrote do, or `password`), what the broker said about the subscriptions since it
connected (`subscribed`, `not subscribed` while no answer has come, and from lou-21 `refused`
when it refused one of the plane's topics, which stays across a reconnect until the broker
grants them), how
long ago the command key last vouched for a command, and how the last ping
ended: `pong in N ms`, `no pong in 10 s`, `publish refused`, `waiting` or `-` (no ping since boot).
From lou-18 a command refused before the key vouched for it -- no command key, the wrong one,
a broken envelope -- adds `, unverified <n> (last <reason>)`, the reason as mccontrol names it
(`sig-invalid`, `no-owner-key`, ...). Such a refusal is never answered, since anyone on the
broker can send one, so this is where it shows: `sig-invalid` means the node holds another
command key than the sender's (`get cmd.pubkey`).

A slot that signs in with a password on one of the plane's own brokers reads
`password (run set cmd on)`: the command server takes that login and refuses it the `mcc/`
topics, so `/cmd refused` follows it. `set cmd on` and a reboot put the slot on the preset. A
node updated from before lou-17 gets this done for it at start ("Which broker"); the hint is
for a slot the start could not mend, or one made by hand since.

When the slot is not connected, look at `get mqtt.status` first: from lou-21 a slot whose login
the broker refused (CONNACK 4 or 5) while no NTP server has confirmed the node's clock shows as
`refused: clock?`, a slot held back because the clock was never set shows as `no clock`, and
`get mqttN.diag` adds `clock not verified: run time <epoch> or check NTP`.

`cmd ping` proves the rest, at the console and without the owner's laptop. The node
publishes `ping|<8-hex nonce>` on its own `mcc/ping/{NODE}`, answers at once, and goes on
repeating:

```
OK - ping sent, read 'get cmd' for the pong
Err - the command plane is off: set cmd on
Err - slot 2 not connected
Err - publish refused
Err - the server refuses /cmd on slot 2: set cmd on, reboot
Err - a ping is already waiting: read 'get cmd'
```

The command broker answers `pong|<same nonce>` on the node's own `mcc/cmd/{NODE}`; `get cmd`
shows the round trip, or `no pong in 10 s` -- the `/cmd` subscription, or a broker that does
not answer pings. The echo has to be the broker's: it shows that the broker is judging this
node's topics. From lou-21 a node the server has refused the plane's topic (`/cmd refused`)
sends no ping, since no pong can reach it, and says so.

A pong is not a command. It is recognised before anything is opened, so it costs a string
compare, never an Ed25519 verify; it is never executed, answered, logged or counted towards
the signed command that marks a new OTA image valid; and it is taken only with the nonce of
the one ping in flight, which it consumes, so a second or a stale pong changes nothing.

**After a network drop** the slot's MQTT client reconnects by itself. Measured on the bench
(2026-11-24): the node was back on the plane about 3 minutes after the network returned. A new
alive message follows 5-60 s after the reconnect. Until then `get cmd` says `not connected`.

`cmd ping` is admitted over the plane as a read, inside the 50-commands-an-hour budget.
Sent that way, its result is held until the ping settles and then carries the outcome --
`OK - pong in 230 ms on slot 2 (mqtts, jwt)` or `Err - no pong in 10 s: ...` -- once. It puts
nothing on the air. The broker's half (`mcbroker`) answers a ping only on the session's own
key, at most once per key per 10 s, and never fans the ping out.

## The envelope

```
payload = base64url( 'C' ‖ flags ‖ nonce (12) ‖ ChaCha20-Poly1305[K_cmd]( counter ‖ expiry ‖ RID ‖ signature ‖ command ) )
signed  = "mcc3/sig|" ‖ node key (32) ‖ road ‖ flags ‖ counter ‖ expiry ‖ RID ‖ command
```

`‖` joins two fields. The payload is base64url without padding. The command is 1 to 160
bytes, zero-padded to 64 or to 160, so a payload is 182 or 278 bytes (243 or 371 characters)
and its length does not name the command. Integers are little-endian. The road byte is `0x00`
on MQTT and `0x01` over the mesh, where there is no RID. Every offset is in mccontrol-spec's
`docs/wire-format-mcc3.md`, "Command on MQTT".

Not JSON. Signing a JSON document requires canonicalisation, and every canonicalisation bug is
a signature-bypass bug; here every field has a fixed place and the signed bytes are built from
the fields as the node read them.

**The node's key and the road are inside the signature.** One signature is therefore valid for
exactly one node on one road: a command captured from one node cannot be replayed at another,
and an MQTT command cannot be replayed over the mesh. Neither case is visible to a counter,
because each node keeps its own.

## What a node checks, in order

```
plane on → command key set → the envelope's size, kind and flags
  → the seal opens under K_cmd → the command's characters → signature valid
  → counter strictly greater than the stored one → not expired
  → command not on the deny list → rate limit
  → store the counter → run it → publish the sealed result
```

- **Up to the signature a refusal is silent.** Anyone on the broker can publish to a node's
  topic, so nothing is answered before the command key has vouched for the command. `get cmd`
  counts these as `unverified` and names the last one: `no-owner-key`, `bad-fields` (the size
  or the kind), `bad-version` (a flags byte that is not 0), `command-chars`, `sig-invalid`
  (the seal or the signature). From the counter on, every outcome is answered ("The result").
- **A key that waits is tried too.** When the key in use did not sign the command and a
  `rekey` is waiting, the waiting key is tried, and takes over if it signed it ("Replacing the
  command key").
- **The counter is stored before the command runs**, never after. A counter written afterwards
  is reopened by whatever crashes mid-command, and a silently repeated trigger spends
  airtime nobody asked for. The cost is that a crashed command is not retried, which is the
  right way round.
- **Expiry fails closed without a clock.** A clock that reads 0 refuses every command
  (`no-clock`) rather than accepting one on a guess. A command may not be valid more than an
  hour ahead of the node's clock, so a clock that is behind refuses it as `expiry-too-far`.
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
`clear stats`, `ota check`, `ota update`, `cmd ping`, `rekey <key>` -- and match nothing below. A verb the CLI grows later does not reach
the mesh until someone adds it.

| denied | why |
|---|---|
| `set prv.key`, `set public.key` | identity: a changed key is a different node, and the fleet, the maps and every history line lose it |
| `set cmd*` (`.slot`, `.pubkey`), `get cmd.pubkey` | the plane itself: a signed command that repoints the slot or the key silently removes the node from control, and only a serial visit undoes that. The standard MQTT settings -- `mqttN.*`, `mqtt.presets`, `mqtt.iata`, `mqtt.*` -- are deliberately admitted: a broker may go away and another must be reachable without a visit |
| `password`, `wifi.pwd`, `wifi.ssid`, `guest.password`, `alert.psk`, `bridge.secret`, `snmp.community`, `mqtt.email`, `mqtt.owner`, `owner.info`, `tls*`, `get prv*`, `get mqttN.password/.token/.username` | credentials and ownership, read and written: a read would put a secret in a result, and a write of these takes over something other than the node. The secrets are denied by bare prefix, so no suffix reaches them |
| `erase`, `start *` (webconfig, the SoftAP OTA), `poweroff`, `shutdown`, `set bootloader.ver` | no way back from the road. `reboot` and `clkreboot` are admitted: settings need them to apply. `ota check` is admitted as a read, and from lou-19 `ota update` to one node: the image is signed and the old one comes back if the new one never proves itself ([ota.md](ota.md)) |
| `set lat`, `set lon`, `get lat`, `get lon`, `set role`, `set repeat` | position is evidence the whole mesh relies on, and whether a node publishes where it is belongs to its owner per node (the advert), not to a signed read; `repeat off` is how a leaked key would silence a region in ten commands |
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

**`set cmd.debug on|off`** (lou-20, the serial console only, until the next boot) prints
one line, `mcc: ...`, for each command or forward heard on either road and where it stopped:
not listening, refused before it ran and why, run, answered, and the airtime of what went
out. It prints no key, no signature and no command text. `get cmd.debug` says which.

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
per node. The reply to a bare `region` is the map as the CLI prints it, so a change can be
checked from the result. Two things to know before sending:

- `region denyf *` and `region remove` can cut a repeater out of its own area. They are admitted
  on purpose; the node does not second-guess a signed command, so the tool that sends them is
  where the question gets asked.
- `region def` with the tree syntax (`a|* b|*`) carries `|`, which no command may hold: it is
  refused as `command-chars` before the deny list is consulted. Add names one at a time with
  `region put <name> *`, which also leaves existing names, their flags and their parents alone.

`trigger test` originates a probe on the channel, naming a mode the way a request sent by hand
does; `trigger private` sends a test request to the one repeater whose key is given, and the
answer comes back to this node alone. Both are described in
[Repeater auto-reply](autoreply.md).

The deny list is deliberately independent of the second guard: MQTT commands run with the
node's clock rather than the `0` that marks a locally-privileged caller, so `set prv.key`,
`erase`, `log`, the `stats-*` dumps and `set cmd.pubkey` refuse them anyway. Either alone
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

## Over the mesh, when Wi-Fi or the broker is down (lou-19)

A node whose Wi-Fi or broker fails is still on the mesh. A signed command can then reach it
as an anonymous request from a companion, sub-type `0xC2`, always 136 bytes:

```
request   tag (4) | 0xC2 | flags (1) | counter (4) | ChaCha20[K_mesh]( expiry (4) | signature (64) | command (1-57 bytes), zero-padded to 58 )
response  tag (4) | 'R' | nonce (12) | ChaCha20-Poly1305[K_cmd]( counter (4) | code (1) | node clock (4) | reply ) | tag (16)
```

Integers little-endian. The request has no authentication tag: it is encrypted to the node,
and the signature inside guards it. The signature is the command key's, over the node's key,
the road byte `0x01`, the flags, the counter, the expiry and the command. A command signed for
MQTT therefore does not verify here, and the other way round. The counter is one counter for
both roads: a command whose counter the node has taken on one road is a replay on the other.
The response is sealed to the owner and not padded, to save airtime; the companion that
carries it cannot read it. Every offset is in mccontrol-spec's `docs/wire-format-mcc3.md`,
"The mesh road".

What the node checks, in order:

```
sub-type 0xC2 → plane on, cmd.mesh not off → 136 bytes → flags 0 or 0x02 → command key set
  → counter strictly greater than the stored one → decrypt → the command's characters
  → signature valid → not answered before → the answer budget
  → road open → not expired → deny list and repair allowance → rate limit
  → store the counter → run it → answer
```

Everything on the first two lines is silent: nothing is sent. A request that stops between
"136 bytes" and "the answer budget" is counted in `get cmd` under `refused`. From "road open"
on, every outcome is answered.

The checks after the signature are the plane's, with these differences:

- **The repair allowance.** Over the mesh, and only there, `set wifi.ssid <name>`,
  `set wifi.pwd <password>` and `set cmd on [<host>]` are admitted, so a node can be put
  back on its network and its broker; `reboot` applies them. Everything else the deny list
  holds stays denied, and the command still runs with a non-zero `sender_timestamp`.
- **An unset clock.** A board that does not seed its clock starts at the firmware's 2024
  default, and an ESP32 that lost power at 1 March 2026, counting up from there. Until that
  clock is set (by a time server, by hand or by `time <epoch>`, below) the expiry is not
  checked and the counter alone stops a replay. An ESP32 that restarts without losing power
  keeps its clock, and with it whether anybody set it, with or without a network. Such a
  node reports its clock as 0 in its alive message, its results and its answers.
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

`set cmd.mesh off|on|auto` (console or admin login; denied on both roads) says when the
road is open. `auto`, the default, opens it once the command slot has been down 15 minutes, so
a node whose broker answers never takes commands over the air; until then a signed request is
answered `mesh-closed` (code 19). `get cmd.mesh` says which, and `get cmd` adds
`, mesh <mode> ok <n> refused <n>`. With `set cmd off` the road is closed too.

From lou-21 a slot that is connected while the server refuses it the plane's topic (`get cmd`
reads `/cmd refused`) counts as down as well: a node whose login the command server only half
accepts hears no command over MQTT, so after the same 15 minutes it can be reached, and mended,
over the air. `get cmd.mesh` then reads `> auto, open: the server refuses /cmd 17 min` where it
would read `MQTT down 17 min`. The moment between a connect and the broker's answer is not
counted as down, unless the server refused the node the last time: a refusal is kept until the
server grants the topic, so a refused slot that drops and reconnects every few minutes still
opens the road 15 minutes after the first refusal.

**A node answers over the mesh on an airtime budget of its own:** 5 % of 15 minutes, then 1 %
(9 s) of the next 15, then a burst again. A request that arrives when the budget is used up
is not answered at all, and `get cmd` counts it under `refused`. Wait a few minutes and send
it again.
 `reboot`
answers nothing, over the mesh as over MQTT.

**A request of the old scheme is dropped.** lou-20 and older took the command as sub-type
`0xC1`, signed and in the clear. lou-21 does not parse, verify or answer one. It still takes
the request off the login handler's hands, so it never counts as a failed login against the
sender's key. With `set cmd.debug on` the console prints
`mcc: mesh: a request heard, old scheme, dropped`.

### Mesh only: boards without Wi-Fi

An `rc` or `arrc` image built without the Observer bridge -- an nRF52 board, or an ESP32 built
as a plain repeater -- has no Wi-Fi and no MQTT, and the mesh road is its only road. Everything
above holds, with these differences:

- **No topic and no region.** A request signs the node's key and the road, so a node with no
  MQTT and no `mqtt.iata` needs neither. `get cmd` says `mesh only`.
- **The road is always open** while `set cmd on`: there is no MQTT to wait for, so
  `cmd.mesh` does not exist there, and a mode carried over in `/mqttcontrol` from an
  Observer image is ignored.
- **What only an uplink means is refused** as `not-allowed` (14): the repair allowance, which
  repairs an uplink there is none of, `ota check`, `ota update`, `cmd ping` and the broker
  slots' settings (`set mqttN.*`). The deny list applies in full.

On an Observer image the mesh road already reaches the broker slots' settings (`set mqttN.*`),
as the deny list admits them, so a broken Observer feed can be repaired over the mesh.

Set it up on the console: `set cmd.pubkey <64 hex>` (serial, or a remote admin's first key), then
`set cmd on`, which answers `OK` and needs no reboot. `get cmd` then answers
`> on, counter <n>, mesh only, mesh on ok 0 refused 0`: the two counts are the requests heard
since the last restart. Step by step, with the check from a companion or through a relay:
[quick-check-guide.md](quick-check-guide.md), 8c.

A mesh-only board is updated by USB or Bluetooth DFU, as stock MeshCore is. There is no update
over the mesh.

## Relaying: one node's MQTT for another node's command (lou-20)

A node without Wi-Fi, or whose Wi-Fi is down, can only be reached over the mesh, and before
lou-20 that took a companion radio near it. From lou-20 an Observer node of the same owner can
do the sending. That node is the **relay**; the node the command is for is the **target**.

mccontrol builds the mesh-road request for the target as before (`0xC2`), and wraps it in a
**forward** to the relay, on the relay's own `mcc/cmd/{NODE}`. The
relay sends the request to the target as its own anonymous request, waits up to 120 s for the
answer, and publishes a **forward result** on the `mcc/r/{RID}` the forward named. Forward and
result are sealed under a fourth key, HKDF info `mcc3/fwd/` + the relay's key, from the same
`S`. The relay cannot read a `0xC2` request or its response: they are sealed between the target
and its owner.

A forward runs nothing on the relay. It never reaches the CLI, so the deny list and the command
counter are not involved. This is the plane's second sanctioned transmit, beside `trigger`.

- **The switch.** `set relay off|own`, `get relay`. The default is `own`: the relay
  serves the holder of its own command key and nobody else. A node without a command key never
  relays. The owner may switch it over the plane; it is not under `cmd`, so the deny list
  admits it. Observer `rc` and `arrc` images only.
- **The budget.** The relay's requests have the same airtime budget as a node's answers: a
  burst of 15 minutes at 5 % (45 s on the air, about 26 requests), then 15 minutes at 1 %
  (9 s), then a burst again. A flood also costs every repeater that hears it, so floods keep
  limits of their own: one a minute in a burst, one in five minutes in a cooldown, 100 in a
  day, and of those that leave the region home (the default scope, or any flood from a relay
  with no region home) two an hour. One forward waits at a time. Fixed. A request that could
  not be sent spends nothing. The budgets are kept in RAM: a restart opens a burst.
- **One at a time.** From the moment a request is sent until the target's answer, or 120 s,
  the relay holds that one forward. A forward that arrives meanwhile is answered `busy` and is
  not sent. The node holds four arriving messages (commands and forwards alike) and takes
  them up in the order they came, one a pass of its main loop, so a stranger's message on the
  node's topic does not push the owner's out. lou-20 and older held one. A fifth that arrives
  while four wait is dropped, unanswered, and counted: `set cmd.debug on` prints
  `mcc: mqtt: 1 arrival(s) dropped, the queue was full (1 since boot)`. Send one and wait for
  its result.
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
  A body that is not a whole `0xC2` request is a `bad-body`, an old-scheme (`0xC1`) request
  among them.
  With an answer come its SNR at the relay and, when the answer returned a path, that path,
  which mccontrol can send direct along next time.
- `get relay` answers `> own, forwarded 3, answered 2, refused 1, burst, 39.9 s airtime
  left, floods today 1 of 100`, the counts since boot, or `> off`. Bit 4 of the alive message's flags says the
  node relays.

Anything that is not a forward of the owner's is dropped in silence and counted in
`get cmd` as unverified, as a command is.

**The zero-hop flag** is for the target, on every image from lou-20. Flags bit `0x02` in a `0xC2`
request, inside the signature, says: answer with one transmission and no path. The target then
answers directly to the sender, however the request arrived. mccontrol sets it only when the
relay hears the target directly and sends with no hops, so the whole exchange is two
transmissions. If the link works one way only, the answer is lost although the command ran.
Any other flag bit is still refused.

## What is not defended

- **Who talks to whom, and when.** Commands, results, forwards and alive messages are sealed
  between the owner's key and the node: the broker and other logins read none of them. They
  do see the topic, and so the node's key, the time and the padded length. Over the mesh the
  counter and the flags of a request are in the clear as well.
  **What a result may never carry,** and so what the deny list refuses as a read: any key
  (`prv.key`, the command key, `mqtt.owner`, `bridge.secret`), any credential (`password`,
  `guest.password`, `wifi.pwd`, a slot's `password`, `token` or `username`), which network it
  is on (`wifi.ssid`), and where or whose it is (`lat`, `lon`, `owner.info`). An advert may
  publish a position, but that is the operator's choice to make per node. A slot's `server`
  and `preset` are readable since 2026-10-08, because they are settable over this plane and a
  change must be checkable. `NothingAResultMayNeverCarryCanBeRead` pins the list.
- **Availability.** Anyone can flood the broker. The node's rate limit bounds the airtime
  consequence; it cannot make the broker quiet.
- **A compromised command key.** Whoever holds it can do anything not on the deny list, which
  since 2026-10-08 is most of what a repeater does — short of silencing it, moving it, re-keying
  it or taking it off the control plane. Rotation is `rekey`, signed by the key in use; a key
  the owner no longer holds needs serial access.

## The result

A node that verified a command publishes the outcome on the reply topic the command named:

```
mcc/r/{RID}
payload = base64url( 'R' ‖ nonce (12) ‖ ChaCha20-Poly1305[K_cmd]( counter ‖ code ‖ node clock ‖ command length ‖ command ‖ reply ) )
```

The sealed part is zero-padded to 256 bytes, or to 512 when it is longer, so a result is 285
or 541 bytes (380 or 722 characters). The node clock is 0 while the clock is unset. Every
offset is in mccontrol-spec's `docs/wire-format-mcc3.md`, "Result on MQTT".

**The result is sealed and carries no signature.** Only the node and the holder of the command key have
`K_cmd`, so a result that opens is the node's own, and nobody else on the broker can read it
or write one in the node's name. Each result has a fresh random nonce: a refusal does not
consume the counter, so a nonce made from the counter would repeat.

The topic and the clear part name no node. The owner tries the `K_cmd` of each node it awaits
an answer from on that reply id. The counter inside is the one the requester chose, which
makes it the correlation id: it says which question was answered.

It is published at **QoS 1, not retained**. The QoS is not there for delivery: in this bridge a
QoS 0 publish is a synchronous write from the calling task, and the result is published from the
loop task while the bridge's task writes packets to the same socket. On firmware up to
`v1.17.0-observer-autoreply-2` and `8530d4bb` that interleaving makes the broker drop the node —
**one reconnect per command** — so on those builds space commands by 30 s and retry on silence.
At QoS 1 the MQTT task is the only writer. *Reasoned from the code and compiled.*

A reply too long for the result is **cut, never dropped**, on a character boundary. The reply
is last and every earlier field is bounded, so a cut result still opens.

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
| 18 | not returned: there is no topic addressed to more than one node. lou-19 and older gave it for a transmit command addressed to every node at once |
| 19 | mesh-closed: the mesh road is not open (`cmd.mesh`) |

Codes are appended to the enum and never renumbered, so a stored result keeps its meaning.

## Mending a clock over the mesh: `time <epoch>`

A node without Wi-Fi has no time source. One whose clock is still at the firmware default
(before 2025) skips the expiry check and is guarded by the counter alone. One whose clock was set
once and has since fallen weeks behind refuses every command as `expiry-too-far`. The mesh road
therefore admits one command the deny list otherwise refuses: `time <epoch>`, all digits.

It is judged by its own word, not by the clock it is sent to mend: the time it names must be at
or before the command's own signed expiry, by an hour at most. The counter still refuses a
replay, and the console's `time` only ever moves a clock forward, so a clock that is ahead is
still a serial visit. Over MQTT `time` stays denied: an Observer node has NTP, and a broker can
hold a command back. What is left to weigh: whoever holds the command key can push a mesh-only
node's clock far ahead once, after which the owner's commands expire until someone visits it.

## Replacing the command key without a visit: `rekey`

`rekey <new PUBLIC key>` is a command like any other, signed by the key in use, on MQTT or the
mesh. The key is 32 bytes as 43 base64url characters, so the command fits the mesh road. The new
key only waits, in RAM, for 60 minutes or until the next boot; the key in use stays the key. The
moment a command arrives that the waiting key signed, it takes over: the node saves it (`get
cmd.pubkey` on the console then says `set via rekey`), derives its keys and seals the answer and
its next alive to it. A mistyped or lost key therefore changes nothing: no command signed by it
ever comes. The console has no `rekey`; `set cmd.pubkey` there is unchanged and stays out of the
plane's reach. What `rekey` cannot stop: whoever holds a node's command key can replace it before
the owner does, and then only a serial visit gets the node back.

## Joining the log lines

With `set cmd.debug on`, the relay's lines name the request's own counter beside the forward's
(`relay: forward 7, request 1795513703, sent direct`), and the target's name the same counter
(`mesh: a request, counter 1795513703`, `mesh: the answer to 1795513703`). mccontrol shows it too.
A forward the relay refuses is named with its status:
`relay: forward 7, request 1795513703, refused, busy`.
