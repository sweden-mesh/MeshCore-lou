# Setting up a repeater: a step-by-step guide

For a visit to a repeater with a laptop and a USB cable. It covers a node already on an
Observer or auto-reply build of this firmware, and a node on stock MeshCore. Every check runs
on the node's own serial console; no other tool is needed on site.

**How to read this guide.** Type each command on the serial console, one per line. The node
prints its answer on the next line, shown here after `->`. The text after `->` is what the
code prints. `<...>` is a value you fill in. `<IATA>` is your region's three-letter code, in
upper case (for example `JKG`); `<iata>` is the same code in lower case.

**No setting is assumed to be on or off.** For each setting: read it with `get`, set it to the
value you want (also when it already has that value), and read it again.

Background: [`autoreply.md`](autoreply.md), [`mqtt-control.md`](mqtt-control.md),
[`ota.md`](ota.md).

**Which sections apply.** From lou-14 an image carries auto-reply (`ar`), the command plane
(`rc`) or both (`arrc`), and says which in its version: section 3 shows it
(`...-lou-14-arrc-...`; a version with `-ar-13-` or older is `arrc`). Do only the sections of the
features the node has ([`fork.md`](fork.md)):

| section | `arrc` | `ar` (Observer) | `rc` | `ar` (core MeshCore) |
|---|---|---|---|---|
| 0-4, 10 | yes | yes | yes | yes |
| 5 WiFi, region, time zone; 6 the observer slot | yes | yes | yes | -- (no MQTT) |
| 7 Auto-reply | yes | yes | -- (`get autoreply` is an unknown command) | yes, but `autoreply.region` is required: no IATA, no legacy channel |
| 8 The command plane | yes | -- | yes | -- |
| 9 Automatic updates | yes | yes | yes | -- (no pull OTA) |
| 11 On-site checks | all | auto-reply, MQTT counters, phone test | command plane, MQTT counters | auto-reply, phone test |

On core MeshCore the image is flashed as upstream's are (a `.uf2` or `.zip` for nRF52), not by
the Observer flasher.

---

## 0. What to bring

- The firmware images for the board, from the
  [releases page](https://github.com/sweden-mesh/MeshCore-lou/releases). Each release has
  two files per board:
  - `<board>_repeater_observer_mqtt-<chip>-<version>.bin`: the app image.
  - `<board>_repeater_observer_mqtt-<chip>-<version>-merged.bin`: the full image.

  For example `Heltec_v3_repeater_observer_mqtt-esp32s3-v1.17.1-ar-13-16a05810-merged.bin`.
- `esptool.py` (or `esptool`), and a USB data cable (not a charge-only cable).
- A serial terminal at **115200 baud** that sends CR or CRLF at the end of a line
  (`pio device monitor`, `screen`, `minicom`, PuTTY, the MeshCore web flasher's console).
- The site's WiFi name and password.
- Your command public key: 64 hex characters (`mccontrol key` prints it). This guide writes it
  as `<CMD_PUBKEY>`.
- A phone with the MeshCore app, for the test in step 11.
- Somewhere safe to keep the private key from step 1 (not a chat, not a photo).

Port name: `/dev/ttyACM0` or `/dev/ttyUSB0` on Linux, `COM<n>` on Windows (Device Manager).

## 1. Before you flash: write down what the node is

```
ver
get name
get public.key
get prv.key
get lat
get lon
get radio
get role
```

| command | reply shape |
|---|---|
| `ver` | `<version> (Build: <date>)` |
| `get name` | `> <name>` |
| `get public.key` | `> <64 hex>` |
| `get prv.key` | `> <128 hex>`. **Serial only. Copy it somewhere safe. This is the node's identity.** |
| `get lat` / `get lon` | `> <number>` |
| `get radio` | `> <freq>,<bw>,<sf>,<cr>`, e.g. `> 869.618,62.5,8,8` |
| `get role` | `> repeater` |

On an Observer build, also:

```
get mqtt.iata
get wifi.ssid
get mqtt1.preset
get mqtt2.preset
get mqtt3.preset
get mqtt4.preset
get mqtt5.preset
get mqtt6.preset
get mqtt.cmd.slot
get mqtt.presets
```

- `get mqtt.iata` -> `> <IATA>` (or empty after `> `).
- `get wifi.ssid` -> `> <ssid>`.
- `get mqttN.preset` -> `> <preset>` (`none`, `analyzer-us`, `analyzer-eu`, `meshat.se`,
  `mccontrol`, `custom`, ...). **This is what each slot holds.** A board without PSRAM runs
  slots 1-3 only; `mqtt4`-`mqtt6` there show what is stored, which does nothing.
- `get mqtt.cmd.slot` -> `> 0 (none)` or `> <N>`. If it is `> <N>`, also run
  `get mqtt<N>.server` and `get mqtt<N>.username` and write down the answers.
- `get mqtt.presets` lists the preset **names this build knows**, not what the slots hold. It
  answers in pages, without the `> `: `analyzer-us,analyzer-eu,nz-analyzer,...,<name>... next:<n>`,
  and `get mqtt.presets <n>` shows the next page. You only need it to confirm that your
  region's collector preset and `mccontrol` exist.

On stock MeshCore the `mqtt.*` and `wifi.*` commands do not exist. That is expected.

**Why `prv.key` matters:** if the flash is wiped, `set prv.key <hex>` puts the same identity
back. A new identity is a new node to the whole mesh: maps, history and contacts all lose the
old one.

## 2. Flash

Close the serial terminal first. esptool needs the port.

Pick the chip from the image file name: most boards are `esp32s3` (`--chip esp32s3`).
**T-Beam SX1262 and T-Beam SX1276 (classic T-Beam) are `esp32` (`--chip esp32`).** Use the
`*_repeater_observer_mqtt` image for your board.

### A. Node already on an Observer / auto-reply build: keep every setting

```
esptool.py --chip esp32s3 --port /dev/ttyACM0 --baud 460800 erase_region 0xe000 0x2000
esptool.py --chip esp32s3 --port /dev/ttyACM0 --baud 460800 write_flash 0x10000 <board>_repeater_observer_mqtt-esp32s3-<version>.bin
```

`erase_region 0xe000 0x2000` resets the OTA selector. Without it, a node that last booted
from the second slot (after an OTA update) boot-loops with `SHA-256 comparison failed`.
Settings and identity are in a separate area and stay.

### B. Node on stock MeshCore: full image

The partition layout may differ, so flash the whole image from 0x0:

```
esptool.py --chip esp32s3 --port /dev/ttyACM0 --baud 460800 write_flash 0x0 <board>_repeater_observer_mqtt-esp32s3-<version>-merged.bin
```

Then open the serial terminal and put the identity back, also if it looks unchanged:

```
get public.key                       -> > <64 hex>   (compare with step 1)
set prv.key <128 hex from step 1>    -> OK, reboot to apply! New pubkey: <64 hex>
reboot
get public.key                       -> > <64 hex>   must equal the value from step 1
```

`Error, bad key` means the hex was mistyped or cut off. Copy it again in one piece.

### If the flash fails

- `Failed to connect` / `No serial data received`: hold BOOT, press and release RESET (or
  plug in while holding BOOT), release BOOT, run the command again.
- Write errors on USB-CDC boards: repeat with `--baud 115200`.
- Optional check afterwards: the same command with `verify_flash` in place of `write_flash`.

## 3. Confirm the firmware

```
ver                    -> <...>-<version> (Build: <date>)
```

The answer **must contain the version you flashed**, e.g.
`esp32s3-v1.17.1-ar-13-16a05810 (Build: <date>)` (`esp32-...` on a T-Beam). Anything else:
flash again.

## 4. Name, position and radio

Compare each with step 1, then set it to the step-1 value even if it matches.

```
get name                       -> > <name>
set name <name from step 1>    -> OK
get name                       -> > <name from step 1>

get lat                        -> > <number>
set lat <lat from step 1>      -> OK
get lat                        -> > <lat from step 1>

get lon                        -> > <number>
set lon <lon from step 1>      -> OK
get lon                        -> > <lon from step 1>

get radio                      -> > <freq>,<bw>,<sf>,<cr>
set radio <freq>,<bw>,<sf>,<cr from step 1>   -> OK - reboot to apply
get radio                      -> > <the values you set>
```

`set radio` takes the four values with commas and no spaces, exactly as `get radio` printed
them in step 1. It takes effect at the reboot in step 10. `Error, bad chars` on `set name`
means the name has a character the node refuses.

## 5. WiFi, region and time zone

```
get wifi.ssid                  -> > <ssid or empty>
set wifi.ssid <site wifi>      -> OK
get wifi.ssid                  -> > <site wifi>

get wifi.pwd                   -> > <password>   (serial shows it in clear)
set wifi.pwd <site password>   -> OK
get wifi.pwd                   -> > <site password>

get mqtt.iata                  -> > <code or empty>
set mqtt.iata <IATA>           -> OK
get mqtt.iata                  -> > <IATA>

get timezone.offset            -> > <number>
set timezone.offset <hours>    -> OK
get timezone.offset            -> > <hours>
```

`timezone.offset` is the site's offset from UTC in whole hours, -12 to +14, including
daylight saving time if it is in effect (for example `2` for CEST, `1` for CET). Correct it
when the clocks change. The node uses it to keep automatic updates out of 00:00-06:00 local.

`Error: IATA code must be exactly 3 letters/digits (e.g. DEN)` means a typo.

## 6. The observer slot

Slot 1 is the observer's feed to your region's collector. Set it explicitly to that preset
(`meshat.se` in this example):

```
get mqtt1.preset               -> > <preset>
set mqtt1.preset meshat.se     -> OK - slot 1 preset: meshat.se
get mqtt1.preset               -> > meshat.se
```

A token-login preset needs nothing else. If the answer is
`Error: preset 'meshat.se' is already assigned to slot <N>`, free that slot first:
`set mqtt<N>.preset none` (-> `OK - slot <N> preset: none`), then repeat the three lines.

**Slot 2:** the command plane's slot rule (step 8) uses whatever slot 2 holds, so set slot 2
to the value you read, also if it is unchanged. **Skip this if step 1 showed
`get mqtt.cmd.slot` -> `> 2`**: slot 2 is then the plane's, the set is refused with
`Err - slot 2 is the command plane's: ...`, and step 8b handles slot 2.

```
get mqtt2.preset                       -> > <preset>
set mqtt2.preset <exactly what get showed>   -> OK - slot 2 preset: <preset>
get mqtt2.preset                       -> > <preset>
```

What happens to slot 2 in step 8:

- **Board without PSRAM** (runs two slots at once). Slot 1 is the observer's, slot 2 becomes
  the command plane's when it holds `none` or `analyzer-eu`. Any other preset there is a
  collector the owner chose. It is left alone, and `set mqtt.cmd on` is refused (see step 8)
  until it is turned off with `set mqtt2.preset none`.
- **Board with PSRAM.** Slot 2 is never taken. The plane goes to the first free slot of 3-6.

You do not need to know beforehand which kind of board it is. The reply in step 8 tells you.

The `set mqttN.preset` reply can end with ` (won't connect: 2-slot limit on this hardware)`.
On a board without PSRAM that is expected **until step 8**, while an old slot 3 is still set.
It must be gone after step 8.

## 7. Auto-reply

Set legacy first, so that the `set autoreply on` reply always names a channel.

```
get autoreply.legacy           -> > on | > off
set autoreply.legacy on        -> OK - legacy #test-<iata>
get autoreply.legacy           -> > on

get autoreply.mode             -> > <mode>
set autoreply.mode flood       -> OK
get autoreply.mode             -> > flood

get autoreply.hops             -> > <n>
set autoreply.hops 8           -> OK
get autoreply.hops             -> > 8

get autoreply.private          -> > on | > off
set autoreply.private on       -> OK
get autoreply.private          -> > on

get autoreply                  -> > <on|off>, mode flood, ...
set autoreply on               -> OK - legacy #test-<iata>
get autoreply                  -> > on, mode flood, private on, direct flood, 8 hops, region - (request scope), legacy on: legacy #test-<iata>
```

`autoreply.private on` is the firmware default: a `test` sent privately to this repeater gets
a private answer.

**Leave `autoreply.region` unset** until your region has agreed its region name and its
repeaters carry that scope. Setting it also scopes every reply to that region, so on a mesh
where few repeaters forward the scope, replies stop crossing the mesh.

Read the region without changing it:

```
get autoreply.region           -> > (none: request scope, no region channel)
```

On a node that already had a region, this shows the name, and the
`set autoreply.legacy on` / `set autoreply on` replies read
`OK - #test-<region> + legacy #test-<iata>`. `get autoreply` then shows
`region <name> (scope)` or `region <name> (not in table: request scope)`. Leave it, and write
it down.

Read back the reply timing. These are the defaults; leave them as they are:

```
get autoreply.slots            -> > 16
get autoreply.window           -> > 10 120
get autoreply.slot             -> > 0 (unassigned; the slot comes from this node's own key)
get autoreply.direct.flood     -> > on
```

Any other value was set on purpose by someone. Write it down; it can be changed over the
command plane later. `autoreply.delay` is gone: it answers
`Err - autoreply.delay is gone; use autoreply.window and autoreply.slots`.

**Moving a region to a region channel** is done for all its repeaters at once, over the
command plane rather than on site: `region put <region>`, `region save`,
`set autoreply.region <region>` and, once every node answers on `#test-<region>`,
`set autoreply.legacy off`.

## 8. The command plane (remote control with your key)

### 8a. The key

```
get mqtt.cmd.pubkey                 -> > <64 hex> | > (not set)
set mqtt.cmd.pubkey <CMD_PUBKEY>    -> OK
get mqtt.cmd.pubkey                 -> > <CMD_PUBKEY>
```

The **public** key only. `Err - use: set mqtt.cmd.pubkey <64 hex characters, the PUBLIC key>`
means a typo or the wrong length.

### 8b. The slot

Every node goes through the same four steps, so the plane always ends on the slot the
firmware's rule picks.

**1. Release the old slot, if any.** Read `get mqtt.cmd.slot` (step 1 noted it).

```
get mqtt.cmd.slot              -> > 0 (none) | > <N>
set mqtt.cmd.slot 0            -> OK - reboot to apply
get mqtt.cmd.slot              -> > 0 (none)
```

**2. Only if it was `<N>` (not 0):** turn off the old slot. This order is required: while the
plane holds slot N, `set mqtt<N>.preset none` is refused with
`Err - slot <N> is the command plane's: move it with set mqtt.cmd.slot first (not over the plane)`.

```
get mqtt<N>.preset             -> > custom | > mccontrol
set mqtt<N>.preset none        -> OK - slot <N> preset: none
get mqtt<N>.preset             -> > none
```

This removes a plane slot an older release set up by hand (`custom`), and it frees a
`mccontrol` slot that an older release put on slot 3 or above, so step 3 picks again.

**3. Turn the plane on.** With the slot at 0, `set mqtt.cmd on` chooses the slot, gives it the
built-in `mccontrol` preset (`mqtts://mqtt.louie.se:8883`, token login, packets off), and
enables the plane:

```
get mqtt.cmd                   -> > <on|off>, counter <n>, no slot
set mqtt.cmd on
```

The reply depends on the board and on slot 2:

| board | slot 2 held | reply |
|---|---|---|
| no PSRAM | `analyzer-eu` | `OK - slot 2 (was analyzer-eu, now off), mccontrol (mqtts://mqtt.louie.se:8883), packets off; reboot to apply` |
| no PSRAM | `none` | `OK - slot 2, mccontrol (mqtts://mqtt.louie.se:8883), packets off; reboot to apply` |
| no PSRAM | another collector | `Err - this board runs 2 slots at once and all are taken: turn one off (set mqtt2.preset none) and send 'set mqtt.cmd on' again` |
| PSRAM | anything | `OK - slot 3, mccontrol (mqtts://mqtt.louie.se:8883), packets off; reboot to apply` (the first free slot of 3-6) |
| PSRAM, 3-6 all used | anything | `Err - no free slot 3-6: set mqttN.preset none on one, or set mqtt.cmd.slot <n>` |

On a refusal, turn off the slot it names (with the owner's agreement if it is their
collector), read it back, and send `set mqtt.cmd on` again.

**4. Read it back.**

```
get mqtt.cmd.slot              -> > 2   (no PSRAM)  |  > 3   (PSRAM)
get mqtt<slot>.preset          -> > mccontrol
get mqtt.cmd                   -> > on, counter <n>, slot <slot> ...
```

Only `on` and the slot number count here. The rest of the line describes the MQTT session
started at the last boot and is read after the reboot in step 10.

After this, `set mqtt.analyzer.eu on` on a no-PSRAM board is refused with the same
`Err - slot 2 is the command plane's: ...` line. That is intended.

## 9. Automatic updates (`ota.auto`)

With `ota.auto on`, the node checks its release channel every 24 hours and installs a newer
signed image by itself, never between 00:00 and 06:00 local time. With `off` it installs
nothing unless told to. Choose `off` if you want each node to change version only when you
flash or command it.

```
get ota.auto                   -> > <on|off>, every 24 h
set ota.auto off               -> OK - automatic update off, checked every 24 h, never 00-06 local
get ota.auto                   -> > off, every 24 h
```

(with `on`: `OK - automatic update on, checked every 24 h, never 00-06 local`, then
`> on, every 24 h`.)

```
get ota                        -> > channel <release URL>, auto off/24h, last check (none yet), next -
```

A cable-flashed image is final: it is never rolled back. Rollback applies only to an image the
node installs itself by OTA: such an image is kept only after it has verified one signed
command (an image without remote command: once an MQTT slot has published and it has run ten
minutes). Until then, any reboot returns the node to the previous image.

## 10. Reboot

```
reboot
```

No reply. The node restarts. Give it about a minute for WiFi, the clock and both MQTT logins.

```
ver                            -> <...>-<version> (Build: <date>)
get public.key                 -> > <64 hex from step 1>
get wifi.status                -> > connected, IP: <ip>, RSSI: <n> dBm, uptime: <...>
get mqtt.status                -> > msgs: on, 1: meshat.se (ok), <slot>: mccontrol (ok), q:<n>
```

In `get mqtt.status`, `(wait)` means the slot is still waiting for WiFi or the clock: read
again in 30 s. `(disc)` or `(fail)`: see the symptom table. A board with PSRAM may list
`2: analyzer-eu (ok)` as well.

## 11. On-site checks

### The command plane, end to end

```
mqtt.cmd ping                  -> OK - ping sent, read 'get mqtt.cmd' for the pong
get mqtt.cmd                   -> > on, counter <n>, slot <slot> connected, /cmd subscribed, last command none yet, ping pong in <ms> ms
```

The four fields to check:

| field | good | otherwise |
|---|---|---|
| `slot <slot> ...` | `connected` | `not connected`: WiFi, clock, the slot (symptom table) |
| `/cmd ...` | `subscribed` | `not subscribed`: the broker refused or has not acknowledged the subscription |
| `last command ...` | `none yet` until a signed command arrives | |
| `ping ...` | `pong in <ms> ms` | `waiting`: read again in a few seconds; `no pong in 10 s`: /cmd subscription, or the broker does not answer pings; `publish refused` |

If the ping cannot go out, `mqtt.cmd ping` says so at once:
`Err - slot <slot> not connected`, `Err - publish refused`,
`Err - the command plane is off: set mqtt.cmd on`, or
`Err - a ping is already waiting: read 'get mqtt.cmd'`.

The ping proves the slot is connected, publishing and subscribed, and that the broker judges
this node's topics. The node keeps repeating while it waits.

### The MQTT counters, twice

```
get mqtt.stats
```

-> `> Free=<n> Max=<n> q:<n>/<n> Outbox=<n> drops=<n>/<n> | s1=<ok>/<err> jwt s<slot>=<ok>/<err> jwt`

Wait one minute, send `mqtt.cmd ping` once more, then:

```
get mqtt.stats
```

- One `s<N>=<ok>/<err> jwt` per running slot: `s1` (the observer) and the plane's slot. With
  token-login presets every slot ends in `jwt`. `pw` means a slot logs in with a password.
- `s1` ok climbs between the reads (packets heard on the radio).
- The plane's ok climbs by at least the ping. Its packets are off; it also publishes status
  every 5 min.
- `err` does not climb.

### Auto-reply

```
get autoreply                  -> > on, mode flood, private on, direct flood, 8 hops, region - (request scope), legacy on: legacy #test-<iata>
```

### A test from a phone next to the node

In the MeshCore app add the hashtag channel **`#test-<iata>`** (lower case, e.g. `#test-jkg`),
and send `test`. This repeater answers within **10-120 s** (its slot in the reply window), as:

```
<node name>: [<your name>] SNR <n> RSSI <n> 0h direct
```

`0h direct` because the phone is next to it. Other repeaters may answer too. The node answers
the same sender on the same channel at most once per 5 minutes, so wait 5 minutes before you
try again.

## 12. Afterwards, with mccontrol

From anywhere with a network connection:

```
mccontrol discover <IATA> --add   # the node should be listed
mccontrol send <node> ver         # <...>-<version> (Build: <date>)
mccontrol send <node> get autoreply
```

The `ver` reply must not carry `(unsigned)` or `BAD SIGNATURE`. A signed answer ends in
`[signed]`.

## If something is wrong

| symptom | what to do |
|---|---|
| esptool cannot connect | BOOT held while you reset; a data cable; the right port; `--baud 115200` |
| boot loop after flashing the app image | flash again with the `erase_region 0xe000 0x2000` line first |
| `ver` does not show the version you flashed | wrong file; flash again |
| `get public.key` differs from step 1 | `set prv.key <hex from step 1>`, `reboot`, read it again |
| `set autoreply on` says `OK - on, but no channel yet: set autoreply.region <name>` | `get mqtt.iata` is `> <IATA>`? `get autoreply.legacy` is `> on`? Fix those rather than setting a region |
| no reply to `test` | `get autoreply` starts `> on`; the phone's channel is `#test-<iata>`, lower case; the 5-min cooldown per sender; wait 120 s |
| `Error: preset '<preset>' is already assigned to slot <N>` | `set mqtt<N>.preset none`, then set slot 1 again |
| `Err - slot <N> is the command plane's: ...` | intended. Move the plane first: `set mqtt.cmd.slot 0` (serial only) |
| `set mqtt.cmd on` took slot 2 and `analyzer-eu` is gone | intended on a board without PSRAM: slot 2 is the plane's |
| `Err - this board runs 2 slots at once and all are taken: ...` | slot 2 holds a collector the owner chose; `set mqtt2.preset none` with their agreement, then `set mqtt.cmd on` |
| `Err - no free slot 3-6: ...` | `set mqttN.preset none` on one of 3-6, then `set mqtt.cmd on` |
| `get mqtt.status` shows `(wait)` | WiFi or clock not ready: `get wifi.status`, `get mqtt.ntp`; read again in 30 s |
| a slot `(disc)`/`(fail)`, or missing from `get mqtt.stats`, or its ok not climbing | `get wifi.status`; `get mqtt.ntp`; `get mqtt<N>.preset`; a `set mqttN.preset` reply with `(won't connect: 2-slot limit on this hardware)` means too many slots are on |
| `get wifi.status` shows `no_ssid` / `connect_failed` | `set wifi.ssid` / `set wifi.pwd` again, `reboot` |
| `get mqtt.cmd` shows `no slot` | step 8 not done, or `set mqtt.cmd.slot 0` was the last command: do 8b step 3 |
| `get mqtt.cmd` shows `not connected` | the plane's slot in `get mqtt.status`; WiFi; clock |
| `get mqtt.cmd` shows `not subscribed` or `ping no pong in 10 s` | read again after a minute; if it stays, the broker side needs a look; the node is still configured right |
| mccontrol gets no answer later | `mqtt.cmd ping` on the node first; then check `get mqtt.cmd.pubkey` is your key |
