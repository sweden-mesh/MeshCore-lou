# Repeater auto-reply

> Feature `ar` (`WITH_AUTO_REPLY`): in the `ar` and `arrc` images on the Observer and in the
> `ar` images on core MeshCore ([fork.md](fork.md)). On core there is no MQTT, so no legacy
> `#test-<iata>` channel; everything else here applies.

A repeater can answer a keyword on one channel with a signal report, so anyone can check
coverage by sending a single message — no login, no contact setup, no administration.

```
you:    test
STO-1:  [louie] SNR 6.5 RSSI -92 2h A3,1B
STO-2:  [louie] SNR -4.0 RSSI -104 0h direct
```

The reply gives the SNR and RSSI the repeater heard you at, the hop count, and the hex
hashes of the repeaters your message travelled through.

**It is off by default, and it should stay off unless you have read this page.** Every
repeater in range answers the same trigger, so a request from more than one hop away becomes
one flood reply per repeater. `autoreply.hops` is what bounds that, and the reply carries
the requester's name in brackets so several arriving together can be told apart.

## Setup

The channel is `#test-<region>`, named by `autoreply.region` — the same name that bounds how
far a reply floods. The region must be in the node's region table first:

```
region put se-jkp
region save
set autoreply.region se-jkp
set autoreply on
```

`get autoreply.channel` then reports `#test-se-jkp + legacy #test-jkg` on a node whose
`mqtt.iata` is `JKG`. Add the channel in your client and send `test` to it. Every repeater in
direct range answers. Nothing else is needed for a range check.

**The legacy channel.** Releases before ar-12 answered on `#test-<iata>`, derived from
`set mqtt.iata`. While `autoreply.legacy` is on — the default, and the setting every upgraded
node comes up with — the node answers there too, with or without a region set, so an upgrade
never silences a node. A region moves its measurement to the new channel once, by switching
legacy off everywhere in one planned change.

A build without the Observer's MQTT bridge has no `mqtt.iata`, so it has no legacy channel at
all: it answers on `#test-<autoreply.region>` only, and stays silent until that is set.
`autoreply.legacy` is still stored, so a node flashed back to an Observer build finds it as it
was, and `get autoreply` shows it as `legacy on, inert: no MQTT`.

To also get answers from repeaters **more than one hop away**, the request has to carry a
region scope — see [How far the reply travels](#how-far-the-reply-travels) below.

To turn it back off:

```
set autoreply off
```

A node with neither channel — no `autoreply.region`, and legacy off or no `mqtt.iata` (or the
`XXX` placeholder) — has nothing to listen on and stays silent even with `set autoreply on`.
`get autoreply` says so.

**Rolling firmware back.** The settings live in the node's own `/autoreply` file, and every
release reads the files all earlier releases wrote, so upgrading keeps them. Downgrading does
not, unless both ends are new enough. Firmware older than file format version 5 reads nothing
from a newer file, so after a rollback to such a version the feature comes up **off** and has
to be switched on again with `set autoreply on`, and `hops`, `delay` and `region` re-entered.
From version 5 on the format is append-only: a newer file is read by the fields the older
firmware knows and the rest is ignored, so a rollback to any version from 5 onwards keeps
every setting that version understands. Format 8 (ar-12) appends `autoreply.legacy`; a
release before ar-12 keeps `autoreply.region` as the reply's scope alone and answers on
`#test-<iata>` as it always did.

## Commands

#### Switch it on or off

- `get autoreply`
- `set autoreply on|off`

**Default:** `off`

#### Read the channels the repeater listens on

- `get autoreply.channel`

**Read-only.** The channel is `#test-` plus `autoreply.region`, and while legacy is on also
`#test-` plus the node's `mqtt.iata` code folded to lower case. Change them with
`set autoreply.region` and `set autoreply.legacy`. Building the name rather than accepting
one is what keeps every repeater off the mesh-wide `#test`, where a reply from each of them
would be spam — a name that starts `#test-` can never be one of the shared channel names.

#### Keep answering on the legacy channel

- `get autoreply.legacy`
- `set autoreply.legacy on|off`

**Default:** `on`

While on and `mqtt.iata` is set, the node also answers on `#test-<iata>`, the channel every
release before ar-12 answered on. Each channel keeps its own rate limits, so a `test` sent on
both draws two answers from the node. A probe the node originates (`trigger test`) goes to the
legacy channel while it is answered and to the region's after, so the measurement moves
channel once, when legacy is switched off.

**Note:** the channel key is derived from the name — the first 16 bytes of `sha256("#name")`
— so there is no PSK to configure or share. Any client that adds a channel of the same name
gets the same key.

**Note:** the name is **lower case**. The key is the hash of the name exactly as stored, and
clients only accept lower-case channel names, so an upper-case name would produce a channel
nobody could join. `set autoreply.region SE-JKP` therefore stores `se-jkp` and gives
`#test-se-jkp`, and `set mqtt.iata STO` gives the legacy `#test-sto` — type those into your
client.

The trigger keyword is case-insensitive: `test`, `Test` and `TEST` all work. Many phone
keyboards capitalise the first letter, so this matters in practice.

The keyword may be followed by a correlation id: one space, then exactly eight hexadecimal
characters, as in `test a1b2c3d4`. The id is echoed back in the reply, so a requester can tie
an answer to the request that provoked it — which arrival time can no longer do once replies
are delayed by minutes. Either form may then name how it wants to be answered, with one letter
— see [Choose how a request is answered](#choose-how-a-request-is-answered). Anything else
after the keyword is ordinary chat and is ignored, so `test me` and `test 123` still cost
nobody any airtime.

A bare `test` keeps working and will continue to. Fleets are flashed slowly, and a firmware
that answered only the id form would drop every not-yet-updated node out of a survey.

#### Limit how far away a request can be

- `get autoreply.hops`
- `set autoreply.hops <value>`

**Parameters:**

- `value`: maximum hop count (0-63) of a request that will be answered. `0` answers only
  direct neighbours.

**Default:** `8`

#### Spread the replies out

Every repeater that hears a request answers it, so without a stagger their replies land on
top of each other. The window is cut into slots, and each node answers inside its own.

- `get autoreply.slot`
- `set autoreply.slot <n>`
- `get autoreply.window`
- `set autoreply.window <start> <end>`
- `get autoreply.slots`
- `set autoreply.slots <n>`

**Parameters:**

- `autoreply.slot`: this node's assigned slot, `0`–64. **`0` is the default and means
  unassigned**, in which case the node derives a slot from its own public key. Assigned slots
  are what make collisions impossible: two nodes in different slots cannot overlap, where two
  key-derived slots coincide at the birthday rate.
- `autoreply.window`: `start` and `end` in seconds after the request, default **10 to 120**.
  The start clears the request's own flood and the window in which nodes on older firmware
  answer. The end is bounded at 600 s, and must leave at least 4 s per slot.
- `autoreply.slots`: how many slots the window is cut into, `1`–64, default **16**.

The slot is rotated by the day, from the node's own clock, so the order is fixed between
midnights and every node agrees on it without any command being sent. A node whose clock has
never synced uses day 0, which is still a valid ordering. Inside its slot a reply waits a
random moment, with a guard at each edge so two nodes in adjacent slots cannot touch even
though they heard the request at slightly different times.

Measured on one mesh at 15 answering repeaters: the old scheme produced about 20 overlapping
pairs per storm, unassigned slots produce about 2, and assigned slots none
(`planning/firmware/slot-collisions-measured.md` in the Mesh-Health workspace).

**`autoreply.delay` was removed** when slots landed. It multiplied a random wait, which spread
the average while leaving every node in one shared window. The commands now answer with an
error rather than being silently ignored, so a provisioning script that still carries them
fails on the first node instead of quietly doing nothing on all of them.

**Default:** slot `0`, window `10 120`, slots `16`

Every repeater in range answers the same request, so their replies compete for the air. Field
measurement on 2026-08-30 found that a reply overlapping another transmission reached a median
of 2 relays, against 5 for one sent into clear air, and that 16 of 18 requests drawing two or
more replies contained an overlapping pair.

Raise this where several repeaters cover the same ground. For an automated survey, where
nobody is waiting for the answer, a much larger value costs only patience. The right number
depends on how many repeaters hear each other and cannot be read off one mesh, which is why it
is settable at runtime rather than compiled in.

#### Bound how far a reply travels

- `get autoreply.region`
- `set autoreply.region <name>`

**Parameters:**

- `name`: a region from the node's own region table, or empty to clear. Groups of `a-z` and
  `0-9` joined by single hyphens, 3–25 characters (`se-jkp`, `se-jkp-mul`); upper case is
  folded to lower. 25 is what a companion can add: `#test-` plus 25 fills its 32-byte
  channel name. A name not in the table is refused with the `region put` that fixes it.

**Default:** empty — no region channel, and the reply mirrors whatever scope the request
arrived under.

The same name is the test channel (`#test-<name>`, see above). With a region set, every
auto-reply -- on the channel, private, or to a private request -- and every probe this node
originates is scoped to it regardless of how the request arrived. This bounds the airtime a
survey costs the wider mesh while still letting a reply cross the whole region being measured.

Nothing else is. A login's answer, an ACK, a remote CLI reply and a path return follow
upstream's own rule, the scope the request arrived under, exactly as on a repeater without
auto-reply. Releases up to ar-13 scoped those too; from lou-14 the setting is auto-reply's
alone, so a node with a region set answers a login in the scope it was asked in.

Note this bounds propagation by a *stated* boundary rather than by hop count. A hop cap would
answer a different question — how much comes back to whoever asked — and would quietly hide
the far side of the mesh, which is the thing a connectivity survey exists to see.

#### Choose how a direct request is answered

- `get autoreply.direct.flood`
- `set autoreply.direct.flood on|off`

**Default:** `on`

With `on`, a request that reached this repeater without passing through another one is
answered the same way any other request is: a flood, kept inside the request's region scope
when it had one. With `off` it is answered by a single zero-hop packet that no repeater will
ever relay — the cheapest possible reply, and the behaviour of releases before this setting
existed.

Prefer `on` unless airtime is tight. A repeater generally sits in much quieter RF than a
handheld, so it hears requests that its own answers cannot get back to — the link is
asymmetric even when the antennas are not, and a zero-hop reply has no second chance and no
alternative path. `off` is the right choice on dense urban sites, or where requesters are
known to be in solid two-way range.

#### Choose how a request is answered

- `get autoreply.mode`
- `set autoreply.mode flood|private|direct`

**Default:** `flood`

The standing mode: how a request that names none is answered. `flood` is the channel reply
shown at the top of this page, the group text every repeater has always sent. `private` and
`direct` answer with a text message to the requester alone — see
[Private replies](#private-replies) for how the two travel, what they cost and what they
need from the requester. A standing `private` or `direct` is honoured only by a request that
carries a key, since that is where the reply is addressed; a request without one — every
bare `test` — is answered on the channel whatever the setting. `silent` is deliberately not a
standing mode: a node that should answer nobody is switched off, and silence is something a
request asks for one probe at a time.

A request names its own mode with one letter after the keyword, or after the id when it
carries one:

| Request | Answered |
|---|---|
| `test` | in the standing mode |
| `test a1b2c3d4` | in the standing mode, with the id echoed |
| `test F` · `test a1b2c3d4 F` | flooded on the channel, whatever the standing mode |
| `test P <64 hex>` · `test a1b2c3d4 P <64 hex>` | with a private text message to that key, flooded |
| `test D <64 hex>` · `test a1b2c3d4 D <64 hex>` | with a private text message to that key, sent back down the request's own path |
| `test S` · `test a1b2c3d4 S` | not at all — the observer's MQTT uplink still reports the reception |

The letter is case-insensitive, exactly one space separates the parts, and nothing may
follow. An id is always eight hex digits and a mode always one letter, so a lone `F` or `D`
is never read as a short id.

The key is the requester's public key as 64 hexadecimal characters, the same form
`set mqtt.cmd.pubkey` takes. A private reply has to be addressed to a key, because a group text
names its sender only by a display name anyone can type. A `P` or `D` that carries no key is
still a request, and is answered on the channel instead: a probe left unanswered for an
addressing gap would look exactly like a dead repeater. A key after `F` or `S` is chat, since
neither has anywhere to send one.

**Bare `test` keeps working, unchanged.** A repeater on firmware from before the modes
existed matches only the bare and id forms; to it a suffixed request is chat, and it stays
silent. Senders should stay bare until the fleet is updated — a suffix asks a question only
updated repeaters hear, and the ones that do not answer are exactly the ones a survey most
needs to hear from.

A probe originated over the signed MQTT control plane names a mode the same way:
`trigger test [<id>] [<F|P|D|S>]` — see [MQTT control](mqtt-control.md). The node appends
its own public key for `P` and `D`, since the probe's requester is itself; a key given in the
command is refused. A probe names no mode unless asked to, for the reason a request does not.

The requester side of a private request is the same control plane:
`trigger private <64 hex> [<id>]` makes the node send one to the repeater with that key. Here
the key names the *target*; the node's own key goes into the packet by construction. See
[A private request](#a-private-request).

#### Answer a private request

- `get autoreply.private`
- `set autoreply.private on|off`

**Default:** `on` (since 2026-09-20)

Whether a test request sent to this repeater alone, off the channel, is answered -- privately,
to the sender's key. A node that stored `off` keeps it. What the request is, how the answer
travels and what it costs is under [A private request](#a-private-request).

#### Show the current state

- `get autoreply`

```
> on, mode flood, private on, direct flood, 8 hops, region se-jkp (scope), legacy on: #test-se-jkp + legacy #test-jkg
```

The region, the scope the replies flood in, legacy, and every channel the node answers on,
so a site check sees all of them on one line. `(scope)` means the region is in the table and
replies flood in it; `(not in table: request scope)` means it is not, and replies take the
request's scope until `region put` adds it.

## How far the reply travels

A channel name does not limit propagation. Repeaters forward on the packet header alone —
route type, hop count against `flood.max`, transport code — and the channel lives in the
encrypted payload, which a repeater does not read. A message to `#test-sto` therefore costs
exactly the same airtime, over exactly the same hops, as one to `#test`. Naming the channel
per region keeps it out of other people's message lists; it does not keep it off their air.

What does limit propagation is the region transport code. So a channel reply goes out in
one of two ways, and the repeater stays silent if it can do neither (a private reply has its
own rules — [Private replies](#private-replies)):

| Request arrived | Reply |
|---|---|
| **0 hops**, `autoreply.direct.flood on` (default) | Flooded, scoped as below. Reaches you even where you cannot hear this repeater directly. |
| **0 hops**, `autoreply.direct.flood off` | Sent zero-hop. One packet, and no repeater will ever retransmit it. Costs the mesh nothing. |
| **1+ hops, region-scoped** | Flooded back inside that same scope only. |
| **1+ hops, unscoped** | Flooded. **This is the expensive case** — see below. |

**Why a direct request is flooded by default.** Hearing you is no promise you can hear the
answer. A repeater usually sits in far quieter RF than a handheld does, so it decodes
signals that never make it back the other way — the link is asymmetric even though the
antennas are not. A zero-hop reply gets exactly one transmission and no second chance, so
where that asymmetry exists the requester sees silence. Flooding lets a repeater you *can*
hear carry the answer back. Turn it off on dense sites where the extra packet is not worth
it, or where most requesters are known to be in solid two-way range.

**Understand the multi-hop cost before raising `autoreply.hops`.** A request that arrives
from several hops away can only be answered by flooding, and *every* repeater that heard it
answers. One `test` therefore becomes one flood packet per repeater in range, each
propagating as far as `flood.max` allows. On a busy mesh that is real airtime.

What bounds it:

* `autoreply.hops` — the single most effective control. `0` answers only direct neighbours.
  A small value such as `2` or `3` keeps replies regional.
* `autoreply.direct.flood off` — the only setting that produces no flood whatsoever, and
  only in combination with `autoreply.hops 0`. Either one alone still floods.
* The request itself. `S` draws no reply and `D` no flood — but that is the requester's
  choice per probe, not a setting on the node.
* The rate limits (below).
* Each repeater's own `flood.max` / `flood.max.unscoped`.

Scoping the request is still much cheaper, because the reply stays inside that scope.
Note a stock client has no per-channel scope setting — it applies a device-wide default
scope and sends unscoped when none is set (see the `// TODO: have per-channel send_scope`
in the companion firmware), so unscoped is what most meshes actually carry.

To use the cheaper scoped path, set `autoreply.region`: the channel and the reply's scope then
carry one name, and a client that scopes its request to that region keeps both ways inside it.

Region keys are derived from the name in the same way, so a region needs no key
distribution either. See [CLI commands](cli_commands.md) for the full `region` syntax.

## Private replies

A request that names `P` or `D` and carries a key is answered with a text message to that key
instead of a group text on the channel. The body is the same signal report, so the two layouts
are one layout; only the addressing changes. Nobody else on the channel sees it, and the reply
delay and both rate limits apply as they do to a channel reply. The two modes differ in how the
message travels:

| Mode | The reply |
|---|---|
| `P` | Flooded, scoped exactly as a channel reply is. Finds the requester wherever they are, through whichever repeaters can carry it. |
| `D`, request arrived over 1+ hops | Sent back down the path the request came in on, reversed. One transmission per hop, and no repeater off that path retransmits it. |
| `D`, request arrived direct | A single zero-hop packet. `autoreply.direct.flood` does not apply — the requester asked for the cheapest reply and gets it. |

**The reverse path.** A flood collects the hash of every repeater that carried it, appended in
order, so an inbound request holds the route from the requester to this node. Read backwards,
that is the route from here to the requester, and it is the only route a direct reply has. The
entries are reversed whole, at whatever hash size the request used, and the packet goes out
direct along them: each repeater on the way matches its own hash at the front of the path,
forwards, and removes itself, so the reply reaches the requester's neighbour and then the
requester without touching the rest of the mesh.

**Asymmetry is the trade.** The same links carried the request the other way, and this mesh is
asymmetric as a matter of course — the reason `autoreply.direct.flood` defaults to `on` for a
channel reply. A flood finds its own way round a link that only works one way; a direct reply
does not, and there is no fallback: a `D` that fails is silence. A survey that wants the
cheapest reply asks for `D` and accepts that; one that wants the reply to arrive asks for `P`.

**The requester has to know the repeater.** A companion decrypts a text message only from a
node it holds as a contact, so a private reply reaches a requester only if they have added the
repeater; otherwise it arrives at their radio as a packet they cannot read. That is MeshCore's
model, not a defect here, and it is why `flood` is the default and stays it: a channel reply
needs nothing but the channel, which is the property the feature was built for.

**Without a key there is no address.** A `P` or `D` that carries none is answered on the
channel, never with silence — see the fallback under
[Choose how a request is answered](#choose-how-a-request-is-answered).

### A private request

Everything above changes how a request on the channel is answered. A request can also be sent
to one repeater alone and never touch the channel at all: an anonymous request — the packet a
client uses to log in to a repeater, under a sub-type of its own — carrying `test` or
`test <8 hex>` as its body. The repeater answers with the report it would have sent on the
channel — name, requester, id, SNR, RSSI, hops, path — as a response to the key the request
came from, so a private measurement and a channel one compare like for like. The requester is
named in the brackets by the first four bytes of that key in hex, `[a1b2c3d4]`: a key is what
the packet carries, and nobody can type somebody else's. No group text is sent, nobody on the
channel sees anything, and no other repeater answers.

**The sub-type is `0xF0`.** Releases up to ar-13 used `0x04`; from lou-14 a node answers `0xF0`
and nothing else, a hard cut-off rather than a transition, so a node still on ar-11..13 is
re-flashed by hand and every requester sends `0xF0` from lou-14. `0xF0` is also the first byte
of a login password that starts with an emoji, so the sub-type alone does not make a request a
test: its body must be `test` or `test <8 hex>`, and anything else goes on to the login it may
be. A node built without auto-reply reads a test request as a login that fails, and stays silent.

A request may reach the repeater either way, and the answer travels accordingly:

| Request arrived | Reply |
|---|---|
| **Flooded** | Returned along the path the flood collected, carrying that path, exactly as a login is answered — so a requester that has no path to the repeater floods and gets one with the answer. |
| **Direct** | Flooded, scoped as a channel reply is. The body carries no reply path, so there is no other way home. |

**The switch.** `set autoreply.private off` turns it off; it is **on by default** since
2026-09-20 (operator: *"when someone messages the repeater in private the answer should be in
private"*). It was off, so a private request got nothing back — which reads from the outside
exactly like a dead repeater. A node that has already stored a config keeps whatever it stored,
so the new default reaches a node on a fresh flash or after an erase; a node upgrading from a
config older than v6, which has no field for it, takes the default. It still needs `autoreply on` and a channel
— the gate every reply shares, since a node with no channel has no auto-reply at all.
`autoreply.hops` does not apply: it bounds which of the requests every repeater hears this one
answers, and a private request was addressed to this node and nobody else, so distance is not
a reason to leave it unanswered — the hop count is reported, not judged.

**The slot applies here too.** It governs every reply this firmware sends, private or not.
One requester asking one node makes no storm, and for that case the delay buys nothing — but
the request does not have to arrive alone. Several observers can be told to probe the same
node, or a fleet of them told to probe at once, and without the stagger every answer would
leave on the same instant, which is the collision the setting exists to prevent. The cost of
being wrong in the other direction is nothing: nobody is waiting on a private test.

The four requests that share this code path — a login, a regions query, an owner query and a
clock query — are **not** staggered, and must never be: a person is watching a screen for
those, and a mesh-wide delay would read as a dead node. They keep the short fixed wait every
anonymous request has always had. A host test pins that separation across the whole sub-type
byte range, because a login carries a password in the same position.

**Charged to the key.** The cooldown is charged to the requester's key rather than to a name:
one answer per key per five minutes, in a ring of the last 16 keys, the same window and the
same rule as on the channel. The private path also has a budget of its own — 10 answers per
five minutes, separate from the channel's — and this is the guard that matters: a burst of
requests each under a fresh key passes every per-key check, and this cap is what bounds it.
Neither budget can be spent from the other side. A request refused by either gets nothing back;
there is no cheaper answer that is not still a transmission.

**No contact is needed, on either side.** The request carries the requester's key and the
repeater derives the secret it answers under from that, the way it does for a login from a
client it has never met. The contact caveat under `P` and `D` does not arise either, because
the measurement is not the reply's content. A stock companion has no button for this; the
requester side is our own observer nodes, over the signed MQTT control plane:
`trigger private <64 hex> [<id>]` makes an observer node send the request, flooded and scoped
exactly as a channel probe is so a target with no path from there still hears it. The key in
the command is the target's, the node's own goes into the packet by construction, and the
answer comes back addressed to that node — the observer feed reports it arriving, which is the
measurement, whether or not the node can read it. See [MQTT control](mqtt-control.md).

**A reply cannot become a request.** The repeater reads a test out of an anonymous request
only; a response is a different packet type and is never parsed as one — see
[A reply can never trigger a reply](#a-reply-can-never-trigger-a-reply).

## A reply can never trigger a reply

Every repeater in range answers the same trigger, so the one thing the feature must never
do is answer itself. Two repeaters that each took the other's reply for a request would
answer each other until the rate limit stopped them, every five minutes, for ever.

On the channel this holds by the shape of the text, not by any flag. A request is the
keyword at the start of the message — `test`, or `test` and an id, or those and a mode
letter — and a reply always begins with the node's name, then the bracketed requester, then
the measurements. Nothing a repeater sends starts with the keyword, however the tail is
parsed, and the host suite pins this with real reply bodies (`AReplyCanNeverTriggerAReply`
in `test/test_autoreply`), including a requester whose own node is named `test`.

A private reply is safer still, for a structural reason. It is a text message addressed to
one key, and a repeater acts on an incoming text message only from a node already in its
own access list as an admin — anything else is dropped before it is parsed, and a repeater
is never another repeater's admin. So a private reply that reaches a peer repeater is not
a request that fails to match; it is a packet that is never read as one. The answer to a
private request is a response, not a request, and the repeater looks for the keyword in
anonymous requests alone — the same property, held by packet type.

## What it costs

Be honest with yourself about the traffic before enabling this:

- One trigger produces **up to one flood reply per repeater in range**, each propagating
  across the configured scope.
- Two rate limits apply, both per repeater:
  - **Per sender and question** — one reply per sender per 5 minutes for the same question.
    Since 2026-09-20 a `test <id>` carrying a correlation id the sender has not used before
    is a *new* question and is answered inside the window (operator decision); a bare `test`
    and a repeat of the same id are unchanged, so the nightly probe — always bare — behaves
    exactly as it did. The last 16 (sender, question) pairs are remembered in a ring; the
    oldest is forgotten when a 17th appears. Senders are identified by the name prefix a
    group message carries, folded to lower case, so this is a courtesy limit rather than a
    security control — a name is trivially spoofed, and two people using the same name share
    a slot. **A sender cycling ids can churn the whole ring**, which costs other senders
    their cooldown; what it cannot do is raise how many replies leave.
  - **Global** — 10 replies per 5 minutes in total, and this is the limit that bounds a
    flood. It is a *sliding* window since 2026-09-20: no 5-minute span holds more than 10,
    wherever it starts. It was a fixed window, which refilled all at once on the boundary —
    tolerable only while the per-sender cooldown stopped one sender reaching it twice, and
    not tolerable once a fresh id bypasses that cooldown, since ten replies just before a
    boundary and ten just after would have been twenty in two seconds.
- Replies are staggered by a random delay, scaled by `f_txdelay`, so nearby repeaters do
  not transmit on top of each other. Setting `f_txdelay` to `0` removes that stagger.
- A request that names a mode changes the bill. `S` costs the mesh nothing beyond the
  request itself: no reply, from any repeater. `P` is still one flood per repeater in range,
  addressed to one node. `D` is one packet per hop back along the request's path, and a
  single packet when the request arrived direct. Private replies are charged against both
  rate limits like any other; a silent request is charged against neither, as nothing is sent.
- A private request is one packet to one node and one reply back — a single flood, or the
  path-return when the request was flooded — and no storm, since no other repeater answers.
  It is charged to the requester's key and to the private path's own 10-per-5-minute budget,
  not to the channel's.
- Only the keyword, alone or with its exact id and mode tail, triggers a reply, and the match
  is case-insensitive — so ordinary chat on the channel is ignored, and a reply can never
  trigger another reply.

If several repeaters you own cover the same area, consider enabling this on only one of
them. Do not enable it on a channel that another bot already answers.
