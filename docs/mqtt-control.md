# Remote control over MQTT

An observer node can accept commands published to it over MQTT: parameter changes, and a
request to send a test now, on the channel or to one repeater alone. It is **off by default** and inert without a configured command key.

Flashing a fleet takes months. This exists so that changing a parameter afterwards costs a
signed publish rather than another flashing round.

## The threat model in one line

`mqtt.meshat.se` and brokers like it publish their credentials. **Anyone can publish to any
topic**, so nothing here trusts the transport: a command runs only if it carries a valid
Ed25519 signature by the command key this node was given.

## Turning it on

```
set mqtt.cmd.pubkey <64 hex characters>   # serial only; the PUBLIC half of the signing key
set mqtt.cmd on                           # with no slot set: takes one, see below; reboot to apply
get mqtt.cmd                              # state, and the highest command counter seen
```

**`set mqtt.cmd on` with no slot configured sets the node up by itself** (2026-10-08): it
takes the first of slots 3-6 whose preset is `none`, gives it the built-in `mccontrol` preset
-- the default command broker, `mqtts://mqtt.louie.se:8883`, token login like the collectors
-- with packets filtered off (status and neighbours still publish there, which the plane's
statistics use), points the control plane at that slot, enables it, and answers
`OK - slot 3, mccontrol (mqtts://mqtt.louie.se:8883), packets off; reboot to apply`. Slots 1
and 2 are the observer's own and are never taken. A board that runs two slots at once (no
PSRAM) with both analyzer slots up has no room for a third, and the reply says so and names
the cure -- turn one off (`set mqtt2.preset none`) -- rather than doing it for you: the
observer's defaults are the owner's to change. A region running its own broker sets the slot
by hand as before:

```
set mqttN.preset custom · set mqttN.server mqtts://broker.example:8883 · set mqttN.audience broker.example
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
`get mqtt.cmd.pubkey` and `set mqtt.cmd.pubkey` answer only a caller at the serial port or the
local console; an empty `set` clears the key.

## Which broker

Commands arrive on one MQTT slot and results leave by the same one, `mqtt.cmd.slot`, from 1 to
the board's slot count (3 without PSRAM, 6 with); `0`, the default, listens nowhere. The node
subscribes on that slot alone. The stats presets refuse subscriptions -- `meshcore-mqtt.meshat.se`
is the one that forced this -- so the stats go out on their preset slot as before, and the
control plane rides a broker of its own on another:

```
set mqtt1.preset meshat.se            # stats, unchanged
set mqtt2.preset custom               # plus the custom broker settings for slot 2
set mqtt.cmd.slot 2
reboot
```

**If the slot used to hold a JWT preset, check how it signs in.** On a custom slot the audience
is the switch for JWT, and `set mqttN.preset custom` does not clear it — so the slot goes on
opening TLS and presenting a token to a plain broker, while `get mqttN.preset` and
`get mqttN.server` read exactly as intended. `get mqtt.stats` ends each slot with the mode it
is really in — `s2=11/0 pw` or `s2=0/4 jwt` — and `set mqttN.audience` with no value clears it.

The slot is read at boot, when the subscriptions are made. It cannot be set remotely: a signed
`set mqtt.cmd.slot 0` would leave a node that only a serial cable could bring back.

## Topics

```
meshcore/{IATA}/{NODE}/cmd     to one node
meshcore/{IATA}/all/cmd        to every node in the region
meshcore/{IATA}/{NODE}/res     the node's answer
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
- **The rate limit applies to validly signed commands** — 10 an hour, and 2 transmits, on
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
| `erase`, `start *` (webconfig, the SoftAP OTA), `ota update`, `poweroff`, `shutdown`, `set bootloader.ver` | no way back from the road. `reboot` and `clkreboot` are admitted: settings need them to apply. `ota check` is admitted as a read; `ota update` waits for a signed image and rollback |
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
rxerr=13369 q=0`. A value the node cannot measure is left out; a bridge not yet started
answers `> (no stats sources)`. The `stats-*` dumps it stands in for stay serial-only. A `set` of a key the CLI does not know travels and is answered "unknown": the deny
list bounds what a command may *do*, not whether it is well formed, and the CLI stays the
authority on the latter.

The auto-reply family and the triggers are as before:

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

## What is not defended

- **Confidentiality.** Commands and results are public on a public broker. Nothing secret may
  appear in either — which is what the deny list keeps true.
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
A result topic is a place anyone with the broker's credentials can write, so an unsigned line
let a stranger publish `ok` in a node's name; now a tool shows a result as *verified* when the
signature checks, *unverified* for an `r1` from older firmware, and a bad signature as what it
is. The reply shortens so the signature always fits the line.

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
means a bad-signature refusal is not rate limited, and publishing those would let anyone on a
broker with public credentials drive unlimited publishes out of the node. A legitimate
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

