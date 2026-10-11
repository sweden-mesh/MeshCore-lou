# The fork: MeshCore Observer with auto-reply and signed remote control

**This is the standard [MeshCore Observer](https://observer.gessaman.com/) firmware, plus two
features**, each of which an image may or may not carry: from lou-14 they are built in any
combination ([fork.md](fork.md)), and an image's version says which (`...-lou-14-arrc-...`).
Core MeshCore images of the fork carry auto-reply alone.

Everything Observer does is still here and unchanged — MQTT uplink to all six broker slots,
WiFi and timezone config, fault alerts, the web flasher config portal. If you already run an
Observer repeater, nothing you have set up changes.

The two additions:

1. **Auto-reply.** Your repeaters answer the word `test` with a signal report. Anyone in
   range can check coverage by sending one message. No login, no contact setup, no admin
   rights, nothing to install.
2. **Remote control over MQTT.** You can change a repeater's settings, or ask it to send a
   test, with a signed message published to the broker — instead of driving to it. **Off by
   default**, and inert until you provision a key. Read the next section before you turn it
   on; it is the part of this firmware that deserves your attention.

```
you        test
STO-1      [louie] SNR 6.5 RSSI -92 0h direct
STO-2      [louie] SNR -4.0 RSSI -104 2h A3,1B
```

Each repeater that hears you replies with the SNR and RSSI it heard you at, how far away it
is in hops, and which repeaters your message travelled through. Your name comes back in
brackets, so when several people test at once everyone can find their own reply.

---

## Remote control, and the key that secures it

Flashing a fleet takes months. This exists so that changing a setting afterwards costs a
signed publish rather than another round of climbing towers.

**Start from the threat model, because it is unusual.** Public MeshCore MQTT brokers publish
their credentials — `mqtt.meshat.se` does. **Anyone can publish to any topic on them.** So
this feature trusts the transport with nothing at all. Reaching a node's command topic is not
a permission; it is the starting position everyone already has.

### Two separate keypairs. Do not confuse them.

| | **Your node's mesh identity** | **Your command signing key** |
|---|---|---|
| What it is | The repeater's own keypair, the one it has always had | A keypair **you** generate, for commanding your fleet |
| What it does | Mesh addressing, encryption, direct messages | Signs remote commands |
| Where the **private** half lives | On the node | **With you. Never on a node, never at the broker.** |
| Where the **public** half lives | Advertised on the mesh | On each node you provision, as `mqtt.cmd.pubkey` |

**A node never holds a secret that can command anything — not even itself.** It stores 64 hex
characters: the *public* half of your signing key. That is enough to check a signature and
useless for making one. Somebody who steals a repeater, dumps its flash, or reads every byte
the broker has ever carried still cannot issue a single command to any node, including the one
they took apart.

This is a different key from the node's mesh identity, on purpose. The mesh identity is
published — it is how the node is addressed. A published key cannot also be the key that
authorises commands.

### Turning it on

```
set mqtt.cmd.pubkey <64 hex characters>   # serial only — the PUBLIC half of your signing key
set mqtt.cmd on
set mqtt.cmd.slot <n>                 # the MQTT slot to listen and answer on; reboot to apply
get mqtt.cmd                          # state, and the highest command counter seen
```

All three are needed, and `mqtt.cmd.slot` must name a slot on a broker that allows
subscriptions — the stats presets do not. See `docs/mqtt-control.md`. `mqtt.cmd on` with no
command key refuses everything. **`set mqtt.cmd.pubkey` cannot be done remotely** — only over
serial or the local console — so a remote attacker cannot point a node at their own key.

This is not `mqtt.owner`. That one is the Observer firmware's ownership claim sent to the stats
services, and stays yours; the command key is shared by the whole fleet you command.

To turn it off again: `set mqtt.cmd off`.

### What a node checks before it obeys

In this order, and it stops at the first failure:

1. the feature is on, and a command key is provisioned
2. the **Ed25519 signature** verifies against that key — over the topic *and* the payload
   together, so a command signed for one node cannot be replayed at another, and a per-node
   command cannot be replayed as a broadcast
3. the **counter** is strictly greater than the highest one this node has stored — a captured
   command cannot be replayed later. The counter is stored *before* the command runs
4. the command has **not expired**, and a node with no trusted clock fails closed
5. the **rate limit** — 20 commands an hour, of which at most 4 may transmit. This applies to
   *validly signed* commands: even your own key cannot turn a repeater into a flood weapon
6. the command is on a short **allowlist** — the auto-reply settings, a few read-only `get`s,
   and the two `trigger` commands. Everything else is refused before it reaches the CLI.
   There is no general `set`, no `erase`, and no way to change the command key

Two things are deliberately out of reach of the remote path no matter what it carries:
`set prv.key`, `erase` and `set mqtt.cmd.pubkey`, which require a locally-privileged caller; and a
broadcast that would make every node transmit at once.

### What this does not defend against

**Availability.** Anyone can flood the broker, and the node's rate limit is what bounds the
airtime that costs you — not the broker traffic. **Confidentiality of commands.** The envelope
is signed, not encrypted: anyone watching the broker can read what you asked a node to do.
Nothing secret should travel this way, and nothing does.

Full detail, including the wire format and every refusal code, is in
[`docs/mqtt-control.md`](mqtt-control.md).

---

## Auto-reply: turning it on — three steps

**1. Flash a repeater with this firmware.** Grab the file for your board from this repo's
[Releases](https://github.com/the-louie/MeshCore-observer/releases) page.

* **Upgrading a node you already run?** Use the plain `….bin` at offset `0x10000` — it keeps
  your settings, node identity, MQTT slots and WiFi credentials.
* **Starting fresh, or unsure?** Use `…-merged.bin` at offset `0x0`. It wipes the device and
  you set it up from scratch.

**2. Connect a console.** USB serial at **115200 baud**, or the repeater's admin console in
your MeshCore client app if you are already logged in to it remotely.

**3. Type one command:**

```
set autoreply on
```

That is it. Check it took:

```
get autoreply
> on, mode flood, private on, direct flood, 8 hops, region - (request scope), legacy on: legacy #test-sto
```

Now add the channel it named — `#test-sto` above — in your MeshCore client, send `test` to
it, and every repeater in range answers.

That is the legacy channel, `#test-<iata>` from the node's `mqtt.iata`. To answer on your
region's own channel as well, name the region (it must be in the node's region table):

```
region put se-sto
region save
set autoreply.region se-sto
> OK - #test-se-sto + legacy #test-sto
```

> **If `get autoreply` says `no channel`**, the node has neither a region nor an IATA code.
> Set one of them: `set autoreply.region <name>` as above, or `set mqtt.iata STO`. Observer
> nodes that already publish to MQTT have the IATA code set, because it is what they publish
> under.

To turn it off again: `set autoreply off`.

## Settings

| Command | Default | What it does |
|---|---|---|
| `set autoreply on\|off` | `off` | Whether this repeater answers the trigger. |
| `set autoreply.hops <0-63>` | `8` | How many hops away a request may be and still get an answer. `0` = direct neighbours only. |
| `set autoreply.direct.flood on\|off` | `on` | Whether a request that arrived direct is answered with a flood. `off` sends a single zero-hop packet that no repeater relays — cheapest, but it never reaches anyone who cannot hear this repeater directly. |
| `set autoreply.slot <0-64>` | `0` | This repeater's place in the reply order. Every repeater that hears a request answers it, and two replies in the same moment collide; two in different slots cannot. **`0` means unassigned**, and the repeater derives a slot from its own public key instead — so a mesh where nobody hands out slots still spreads its replies, at the cost of the occasional coincidence. Assign slots and there are none. |
| `set autoreply.window <start> <end>` | `10 120` | The seconds after a request inside which every reply lands. It starts late enough for the request's own flood to be over, and for repeaters on older firmware to have answered. Nobody is waiting on a test reply, so a long window costs only patience while a collision costs the measurement. Up to 600 s, with at least 4 s per slot. |
| `set autoreply.slots <1-64>` | `16` | How many slots the window is cut into. More is not better: past about one slot per 4 s they become narrower than the replies they separate. |
| `set autoreply.region <name>` | *(none)* | The test channel `#test-<name>` and the region every reply is scoped to; it must be in the region table. `a-z0-9` groups joined by single hyphens, 3-25 characters. Empty: no region channel, and replies mirror the request's scope. |
| `set autoreply.legacy on\|off` | `on` | Also answer on `#test-<iata>`, from `mqtt.iata` -- the channel releases before ar-12 used -- so an upgrade never silences a node. |
| `set autoreply.mode flood\|private\|direct` | `flood` | How a request that names no mode is answered. `private` and `direct` answer with a text message to the requester alone, and only when the request carries their key. |
| `set autoreply.private on\|off` | `on` | Whether a test request sent to this repeater alone, off the channel, is answered. On since 2026-09-20: a private request is answered privately, and one that is never answered reads like a dead repeater. |
| `get autoreply` | — | Current state, in one line. |
| `get autoreply.channel` | — | The channels the node answers on. **Read-only** — they follow `autoreply.region` and, with legacy on, `mqtt.iata`. |
| `get autoreply.hops` | — | Read the hop limit back. |
| `get autoreply.direct.flood` | — | Read the direct-reply mode back. |
| `get autoreply.slot` | — | Read the slot back; `0` says it is derived from the key. |
| `get autoreply.window` | — | Read the window back. |
| `get autoreply.slots` | — | Read the slot count back. |
| `get autoreply.region` | — | Read the reply scope back. |
| `get autoreply.mode` | — | Read the standing mode back. |
| `get autoreply.private` | — | Read the private-request switch back. |

The trigger word is `test`, case-insensitive — `test`, `Test` and `TEST` all work, which
matters because phone keyboards like to capitalise the first letter. Override it at build
time with `-D AUTOREPLY_KEYWORD='"..."'`.

Remote control reaches all of these: `set autoreply` and `get autoreply` are on the allowlist
as families, so `set autoreply.slot 7` can be published to a node instead of typed into it —
which is how an operator hands out slots across a mesh without visiting it.

> **`autoreply.delay` is gone.** It multiplied a random wait, which spread the *average* while
> leaving every repeater in one shared window — on a mesh of fifteen that meant about twenty
> overlapping pairs in every storm. Slots replaced it. A node upgraded from a build that had the
> setting loads its config as before and simply stops using that byte, and the old commands now
> answer with an error rather than being silently ignored, so a provisioning note that still
> carries them fails on the first node instead of quietly doing nothing on all of them.
>
> The order rotates once a day, from each repeater's own clock, so it is the same all day and
> every repeater agrees on it without being told. A clock that has never synced uses day 0.

---

## Reply modes — asking for the answer you want

A bare `test` is answered the way the node is configured, and that is all most people need.
A request can also **name how it wants to be answered**, which is what the modes are for:

```
test                     answered the node's standing way
test A1B2C3D4            the same, with an id echoed back so you can match reply to request
test A1B2C3D4 F          answer on the channel, where everyone sees it
test A1B2C3D4 P          answer me privately
test A1B2C3D4 D          answer me privately, straight back down the path this came in on
test A1B2C3D4 S          do not answer at all
```

| Mode | What the repeater does | What it costs the mesh |
|---|---|---|
| **F — Flood** | Answers on `#test-<iata>`, where everyone in the region sees it. The default, and what every node did before modes existed. | The most: one flooded reply per repeater that heard you. |
| **P — Private** | Answers with a text message addressed to you alone, flood-routed so it finds you wherever you are. | One reply, but it still floods to find a path. |
| **D — Private Direct** | The same private answer, sent straight back down the path your request arrived on. | The least of the three that answer — no flood at all. The trade: the reverse path can fail where a flood would not, because this mesh is asymmetric. |
| **S — Silent** | Answers nothing. The node still *heard* you, and still reports the reception over its MQTT uplink. | Nothing on the air. |

**P and D need your public key**, appended to the request, because a channel message carries
no sender key and a repeater has no name-to-key table to look you up in. A `P` or `D` request
without one is answered as **F** rather than dropped — a probe is never left unanswered
because it asked for something the node could not do.

**S is per-request only.** There is no standing "silent" mode, because that is what
`set autoreply off` already is.

The standing mode is `set autoreply.mode flood|private|direct`. A request that names a mode
overrides it for that request only.

### Mode M — a test that never touches the channel

The modes above all *arrive* on `#test-<iata>`, in the open. **Mode M is the private
counterpart**: the request is sent to one repeater alone, off the channel entirely, and is
answered the same way. Nothing about the exchange appears on the test channel.

This sidesteps the key problem that P and D have, because the request packet carries the
sender's key by construction — there is nothing to append and nothing to get wrong.

It is **on by default** since 2026-09-20 (`set autoreply.private off` to stop it), and it is
the one switch here worth knowing about: unlike a channel request, it is an unauthenticated
packet sent to your node alone that makes it transmit. It was off, and a private request that
is never answered reads from the outside exactly like a dead repeater — the failure the flood
reply already exists to avoid. The guards that make the default reasonable are a cooldown
charged to the requester's *key* rather than a name — one answer per key per five minutes —
and a budget for the private path of its own, ten answers per five minutes, which bounds somebody
cycling through fresh keys. A request refused by either gets nothing back.

Full detail on all five in [`docs/autoreply.md`](autoreply.md).

---

## Why the channel is `#test-<iata>` and nothing else

You cannot choose the channel. It is always `#test-` followed by your node's region code, in
lower case — `#test-sto`, `#test-jkg`. That is a deliberate restriction, for three reasons.

**One badly chosen channel would spam the whole mesh.** Every repeater in range answers the
same message. Point that at `#public`, `#test` or `#bot` — channels everybody carries — and
one person typing `test` sets off a reply from every repeater that heard it, mesh-wide,
forever. A region code can never produce one of those names, so the mistake is impossible to
make rather than merely discouraged.

**A per-region channel keeps the traffic where it is useful.** Your coverage test is
interesting to people near you and noise to everyone else. Naming the channel after the
region keeps it out of other people's message lists.

**There is nothing to distribute.** The channel key is the first 16 bytes of
`sha256("#test-sto")`, so there is no PSK to generate, share or keep in sync. Anyone who
knows the region code can join by typing the name into their client — that is the whole
point, since the person testing coverage is usually a stranger to the repeater's owner.

Lower case is not a style choice: clients only accept lower-case channel names, and the key
is the hash of the name exactly as stored, so an upper-case name would hash to a channel
nobody could join.

## Why it will not flood your mesh

Every repeater in range answers the same message, which is exactly the shape of a broadcast
storm. Five mitigations keep it cheap:

**A direct reply you can make free.** If your request arrived directly, the repeater can
answer zero-hop: a single packet that no repeater will ever retransmit, costing the mesh one
transmission and nothing more. That is `set autoreply.direct.flood off`.

It is not the default, because hearing you is no promise you can hear the answer. A repeater
usually sits in far quieter radio noise than a handheld does, so it decodes signals that
never make it back the other way — the link is asymmetric even when the antennas are not. A
zero-hop reply gets one transmission, no acknowledgement and no alternative path, so where
that gap exists you simply see silence. Flooding lets a repeater you *can* hear carry the
answer back. Turn it off where airtime is tight, or where the people testing are known to be
in solid two-way range.

**A hop limit on what gets answered at all.** A request from several hops away can only be
answered by flooding, and *every* repeater that heard it floods its own reply — so one `test`
becomes one flood packet per repeater, each propagating as far as `flood.max` allows.
`set autoreply.hops` bounds this, and it is the setting that matters. `0` answers only direct
neighbours, and paired with `autoreply.direct.flood off` it puts no flood on the mesh at all.

**A per-sender cooldown.** One reply per sender per five minutes, with the last 16 senders
remembered. Someone hammering `test` gets one answer and then silence, and — because the
per-sender check runs *before* the shared limit — their retries cannot use up anyone else's
share. A group standing in a field testing together all get answers.

**A global rate limit.** Ten replies per repeater per five minutes, whatever the source.
Whatever else happens, that is the ceiling on what one repeater will put on the air.

**Random stagger.** Replies are delayed by a random interval, so neighbouring repeaters
answering the same message do not transmit on top of each other and corrupt each other's
packets.

If several of your repeaters cover the same area, consider enabling this on only one of them.

📖 Full reference, the multi-hop region-scope details and the test procedure:
**[docs/autoreply.md](autoreply.md)**

🛠️ Setting up a repeater on site, step by step — flashing, configuration, the command plane and
the checks: **[docs/quick-check-guide.md](quick-check-guide.md)**
