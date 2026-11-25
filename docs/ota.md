# Pull OTA: a signed image, verified before it is trusted

> Not a feature: every Observer image of the fork carries it ([fork.md](fork.md)); core images
> have no pull OTA.

An observer node can fetch its own firmware: `ota check` reads a per-variant manifest from the
release channel it was built with and reports the build on offer; `ota update` downloads the
image into the inactive slot and reboots into it. From ar-11 (2026-10-08) that path is safe to
hand to a signed command, because three things hold that did not before.

## The image is signed by the release key

The manifest carries the image's `sha256` and `sig`, an Ed25519 signature by the **release key**
over `"<sha256>|<version>|<file>"` -- the manifest's own text, so a changed hash, version or
file name fails. The release key is held by whoever cuts releases and is never the command key:
a leaked command key must not become a firmware weapon. Its public half is baked into the
firmware as `OTA_RELEASE_PUBKEY` (`build.sh`); a build without one refuses every update, so a
locally built image never arms itself.

The node checks the signature **before it downloads a byte**, then streams the image through
SHA-256 into the inactive slot and compares the hash **before the slot is made bootable**; a
mismatch or a short download aborts the slot untouched (`OtaVerifyLogic.h`, host-tested in
`test_ota_verify`).

```
{ "version": "v1.17.1.3-ar-11-abc1234", "baseVersion": "v1.17.1", "build": 3,
  "file": "https://github.com/sweden-mesh/MeshCore-lou/releases/download/v1.17.1.3-ar-11/Heltec_v3_repeater_observer_mqtt-v1.17.1.3-ar-11-abc1234.bin",
  "sha256": "<64 hex of the image>",
  "sig": "<128 hex, Ed25519 by the release key over sha256|version|file>",
  "partSig": "<the partition signature of the build>" }
```

## One image for an Observer board, asked for by three names

From lou-14 an image asks its channel for `<env>-<features>.json`
(`Heltec_v3_repeater_observer_mqtt-arrc.json`), the manifest of its own board and combination
([fork.md](fork.md)). The manifest names both -- `"variant"` and `"features"` -- and carries a
second signature by the release key, `sig2`, over `"<sha256>|<version>|<file>|<variant>|<features>"`.
The node refuses a manifest whose `sig2` does not verify, or whose variant or features are not
its own (`otaManifestCombination`, `test_ota_verify`). There is no `<env>.json` alias for the
nodes on ar-11..13 (TODO 22a ruling 3): they are re-flashed by hand.

```
{ "version": "esp32s3-v1.17.1-lou-14-ar-1a2b3c4d", "baseVersion": "v1.17.1", "build": 0,
  "fileName": "Heltec_v3_repeater_observer_mqtt-esp32s3-v1.17.1-lou-14-ar-1a2b3c4d.bin",
  "file": "https://github.com/.../download/v1.17.1-lou-14/<fileName>",
  "sha256": "...", "partSig": "...", "variant": "Heltec_v3_repeater_observer_mqtt-ar",
  "features": "ar", "sig": "<128 hex>", "sig2": "<128 hex>" }
```

**From lou-21 an Observer board has one image, the full one (`arrc`)** (owner's ruling
2026-11-25). Up to lou-20 a board had three, and an `ar` node never took an `arrc` image. That
rule is reversed for Observer boards: the board's nodes on `ar` and `rc` reach the full image
by their ordinary update. Boards without Wi-Fi (`fork/core`) keep their three images and have
no pull OTA.

A node on `ar` still asks for `<env>-ar.json`, and a node on `rc` for `<env>-rc.json`. The
release answers both with an **alias manifest**: it carries the variant and features the
asking node compares with its own (`...-ar`, `ar`), and the version, file and hash of the
`arrc` image. `sig2` is signed over those, so an alias verifies only for the node it is
written for, and a copy of the `arrc` manifest under another name is refused as before.
`"aliasOf"` marks it for the tools; the node does not read that field.

```
{ "version": "esp32s3-v1.18.0-lou-21-arrc-1a2b3c4d", "baseVersion": "v1.18.0", "build": 0,
  "fileName": "Heltec_v3_repeater_observer_mqtt-esp32s3-v1.18.0-lou-21-arrc-1a2b3c4d.bin",
  "sha256": "...", "partSig": "...", "variant": "Heltec_v3_repeater_observer_mqtt-ar",
  "features": "ar", "aliasOf": "Heltec_v3_repeater_observer_mqtt-arrc",
  "file": "https://github.com/.../download/v1.18.0-lou-21/<fileName>",
  "sig": "<128 hex>", "sig2": "<128 hex>" }
```

After the update the node runs `arrc` and asks for `<env>-arrc.json` from then on.

**A feature the old image did not have starts switched off, once.** At the first start after
the update, a node that came from `ar` has remote command off, and a node that came from `rc`
has auto-reply off, whatever the feature's settings file says. That file was left by an
install before the old image, and the owner has chosen an image without the feature since.
Only "on" is changed: every other setting stays, the command key, the slot and the counter
among them. A node that came from `arrc` is not touched. The serial console says what was
done: `OTA: this node came from an ar image: remote command starts switched off`. Turn the
feature on with `set autoreply on`, or with `set cmd.pubkey <key>` (when none is set) and
`set cmd on` ([mqtt-control.md](mqtt-control.md), "Upgrading to lou-21").

The new image learns where it came from in one of two ways (`ForkArrival.h`, host-tested in
`test_fork_arrival`). An image from lou-21 on writes the marker `/ota_from`, holding its own
features, when it takes an update that has a feature it lacks. An image from lou-20 or older
writes none: there the new image, on its first start after the update, reads the old image's
update name (`<env>-<features>`) out of the other slot. With neither, nothing is switched: a
cable flash, a later start, a new node. Whichever image starts next removes the marker, so
after a rollback the old image finds its own features in it and switches nothing.

`scripts/manifest.py unsigned` writes a manifest without `file`, `sig` and `sig2` where the
images are built (`build-matrix.sh`, CI), and `scripts/manifest.py alias` writes the two
aliases from an `arrc` image's unsigned manifest. `scripts/manifest.py sign` adds the
signatures on the release host, after checking that the image is the one described and that
the version, variant and features agree. `test/data/manifest-lou-14-example.json`,
`manifest-lou-21-example-arrc.json` and `manifest-lou-21-example-alias-ar.json`, signed by
`manifest.py` with a test key, are verified by the node's own code in `test_ota_verify`.

## The new image must prove itself, or the old one returns

The ESP32 bootloader's rollback is on in this core (`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`), and
the Arduino core would mark a new image valid at boot. This firmware says `verifyRollbackLater()`
and marks the running image valid only once it has proved itself. Until then any reboot
(watchdog, power) returns to the previous image. A bad release therefore costs one boot, not a
visit. What counts as proof depends on the image's features ([fork.md](fork.md)):

| image | proof |
|---|---|
| with remote command (`rc`) | it has **verified one signed command**: the radio came up, WiFi and the bridge reached the broker, and the owner can still reach the node -- and the control plane comes back with the old image if not |
| without it, or with it while the plane cannot take a command (`cmd` off, no slot or no command key) | **some MQTT slot has published since boot, and it has run ten minutes**: the radio, WiFi, TLS and a broker all work, and it has outlived the watchdog and the reconnect ladder |

Either proof shows WiFi and the broker, not LoRa. From lou-19 the image is also kept only once
the radio has worked: it came up at boot and has received or sent at least one packet since.
The two may come in either order. An image whose radio driver is broken stays pending, and
the next reboot returns to the previous one.

A node that arrived from `ar` has `cmd` off, so its new image is proved the second way. Left
on, the plane would wait for a signed command that an `ar` node's owner may never send, and
the next restart would return to the old image.

Pull OTA is in every Observer image of this fork, because an image that pulled from another
channel would replace itself with one that has none of its features.

## What "newer" means

The fork's revision in the version string decides. From lou-14 a version reads
`<mcu>-v1.17.1-lou-<nn>-<features>-<hash>` (`esp32s3-v1.17.1-lou-14-arrc-1a2b3c4d`); up to
ar-13 it read `...-ar-<nn>-<hash>`. The two are one counter -- lou-14 follows ar-13 -- and
`-lou-` is read first, because an image with auto-reply alone carries `-ar-` after its revision
(`...-lou-14-ar-1a2b3c4d`). A manifest offering a higher revision is an update; a lower one never
is -- a channel cannot roll a node back by mistake. Within the same revision the build number
(the fourth version component, set by `FIRMWARE_BUILD_NUMBER` at build time) decides, and
without build numbers the commit hash, as upstream does. `ota check` says which:
`update available: ... (rev 13 -> 14)`, `... (2 behind)`, or
`up to date: the channel offers an older build`.

## Automatic, but paced

```
set ota.auto on            # default off
set ota.check.hours 24     # 1-168
get ota                    # channel, auto, last check's result, whether an update is scheduled
```

The two settings live in their own file, `/ota`, which every Observer image reads. Up to
ar-13 they were the last two bytes of the command plane's `/mqttcontrol`; a node with no `/ota`
yet reads them from there, and that file is never written for them, so an image that rolls back
to ar-13 still finds what it had.

With `ota.auto on` the node checks the channel at the interval and, when a newer signed build is
on offer, updates -- after a hold-off of 0-60 minutes drawn from its own key, so a region's
nodes spread across the hour rather than flash in the same minute, and never between 00:00 and
06:00 node-local (`set timezone.offset`), when the mesh is being measured. The update then
takes the same path as `ota update`: bridge paused, image verified, reboot, and the old image
back if the new one never proves itself. The schedule is `OtaAutoLogic.h`, host-tested in
`test_ota_auto`. `set ota.auto on` is a setting and travels over the control plane, and from
lou-19 so does `ota update`, to one node at a time.

## The channel

`OTA_MANIFEST_BASE` is baked in by `build.sh` (`OTA_MANIFEST_BASE_URL`), so a node only ever
takes updates from the channel it was flashed from. From lou-14 the channel is the GitHub
releases of `sweden-mesh/MeshCore-lou`
(`https://github.com/sweden-mesh/MeshCore-lou/releases/latest/download/<variant>.json`);
GitHub redirects `latest/download` to the asset, and the node follows it over TLS. ar-11..13
images ask `the-louie/MeshCore-observer` and are never moved (TODO 22a ruling 3).

From lou-21 a release image carries a second address, the release tagged `beta`
(`https://github.com/sweden-mesh/MeshCore-lou/releases/download/beta/<variant>.json`), so a
few nodes can take a build before every node is offered it. `ota branch beta` points a node
at it and answers `channel set to beta, base <url>; run ota update to switch`;
`ota branch prod` puts it back on the latest release, and a bare `ota branch` says which is
in use. `build-matrix.sh` bakes both addresses in (`OTA_MANIFEST_BASE_URL`,
`OTA_MANIFEST_BASE_STABLE_URL` and `OTA_MANIFEST_BASE_DEV_URL` in the environment win) and
reads each Observer image back with `scripts/verify_ota_channel.py --expect prod --no-compat
<image>`: an image without two different addresses fails the build. Up to lou-20 the two
addresses were the same.

## Cutting a release that nodes will take

From lou-14 (TODO 22a rulings 15, 16, 25):

1. **Build, in GitHub Actions.** Run `.github/workflows/fork-matrix.yml` by hand with the two
   refs, the revision (`lou-21`) and the release key's *public* half
   (`scripts/manifest.py --pubkey ~/.config/mccontrol/release.key`). It builds the 33 Observer
   images (`arrc`) and every combination for every core board, and leaves one artifact,
   `candidate-lou-21`: the images, each Observer image's unsigned manifest with its two
   aliases (`<env>-ar.unsigned.json`, `<env>-rc.unsigned.json`), and `SHA256SUMS`.
2. **Sign, on the release host.** Download and unpack the artifact, then
   `scripts/release-candidate.sh -c <candidate> -t v1.18.0-lou-21`. It refuses a set that
   does not hold together -- a hash that does not match, an image without its manifest or a manifest
   without its image, a manifest not named for its variant, an `arrc` image that leaves the
   board's `ar` or `rc` nodes without a manifest (`scripts/manifest.py candidate <dir>`),
   another revision, an image without this key's public half -- then signs every manifest
   (`sig` and `sig2`), verifies each back, writes and verifies the signed
   `firmware-index.json` (one row for every image, [fork.md](fork.md)), and checks the asset
   count against GitHub's limit of 1 000 per release.
3. **Upload as a draft.** Add `RELEASE_NOTES.md` to the assembled directory and rerun with `-p`,
   or run the `gh release create ... --draft` it prints. Nobody sees a draft and no node
   fetches one.
4. **Publish.** `gh release edit <tag> --repo sweden-mesh/MeshCore-lou --draft=false`. The
   release must be the repository's *latest*: the nodes' channel is
   `releases/latest/download/`, and every node with `ota.auto on` takes it from that moment.

### Testing a candidate before it is released

A release candidate has a revision that ends in `rc` or `rcN` (`lou-21rc`,
`-t v1.18.0-lou-21rc`). `release-candidate.sh` creates it as a pre-release, signed by the
release key as a release is. GitHub's `latest` skips a pre-release, so no node in the field
is offered it.

- **For lou-21 itself**, whose predecessors have no beta address: publish the candidate as a
  pre-release, and flash the bench board by cable with images built from the lou-20 source as
  `ar` and as `rc`, with
  `OTA_MANIFEST_BASE_URL=https://github.com/sweden-mesh/MeshCore-lou/releases/download/<the pre-release tag>`
  and the release key's public half. Their `ota update` then fetches the candidate's alias
  manifests. Each must reach the `arrc` image, keep on what it had on, have the other feature
  off (`get autoreply`, `get cmd`), and ask for `<env>-arrc.json` at the next check.
- **From lou-21 on**, on a released image: `ota branch beta`, `ota update`, and
  `ota branch prod` afterwards. This needs a pre-release tagged `beta` that holds the
  candidate's manifests. `release-candidate.sh` does not make one: its tag must end in
  `lou-<nn>` or `lou-<nn>rc[<n>]`.

The release key is made once (`scripts/manifest.py --keygen ~/.config/mccontrol/release.key`,
mode 600) and is read by `release-candidate.sh` alone; it is never in a repository, a CI secret
or an artifact. A node whose baked-in key differs from the one that signed the manifest refuses
the update -- rotating the release key means flashing once by cable.
