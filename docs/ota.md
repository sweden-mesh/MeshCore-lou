# Pull OTA: a signed image, verified before it is trusted

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
  "file": "https://github.com/the-louie/MeshCore-observer/releases/download/v1.17.1.3-ar-11/Heltec_v3_repeater_observer_mqtt-v1.17.1.3-ar-11-abc1234.bin",
  "sha256": "<64 hex of the image>",
  "sig": "<128 hex, Ed25519 by the release key over sha256|version|file>",
  "partSig": "<the partition signature of the build>" }
```

## The new image must prove itself, or the old one returns

The ESP32 bootloader's rollback is on in this core (`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`), and
the Arduino core would mark a new image valid at boot. This firmware says `verifyRollbackLater()`
and marks the running image valid **only after it has verified one signed command** -- which
means the radio came up, WiFi and the bridge reached the broker, and the owner can still reach
the node. Until then any reboot (watchdog, power) returns to the previous image, and the
control plane comes back with it. A bad release therefore costs one boot, not a visit.

## Automatic, but paced

```
set ota.auto on            # default off
set ota.check.hours 24     # 1-168
get ota                    # channel, auto, last check's result, whether an update is scheduled
```

With `ota.auto on` the node checks the channel at the interval and, when a newer signed build is
on offer, updates -- after a hold-off of 0-60 minutes drawn from its own key, so a region's
nodes spread across the hour rather than flash in the same minute, and never between 00:00 and
06:00 node-local (`set timezone.offset`), when the mesh is being measured. The update then
takes the same path as `ota update`: bridge paused, image verified, reboot, and the old image
back if the new one never verifies a command. The schedule is `OtaAutoLogic.h`, host-tested in
`test_ota_auto`. `set ota.auto on` is a setting and travels over the control plane; `ota update`
itself does not.

## The channel

`OTA_MANIFEST_BASE` is baked in by `build.sh` (`OTA_MANIFEST_BASE_URL`), so a node only ever
takes updates from the channel it was flashed from. The ar-11 channel is the GitHub releases of
`the-louie/MeshCore-observer`
(`https://github.com/the-louie/MeshCore-observer/releases/latest/download/<variant>.json`);
GitHub redirects `latest/download` to the asset, and the node follows it over TLS.

## Cutting a release that nodes will take

```
scripts/sign_manifest.py --keygen ~/.config/mccontrol/release.key     # once; mode 600; never in a repo
OTA_RELEASE_KEY_FILE=~/.config/mccontrol/release.key VARIANT_TAG=ar-11 bash build-all.sh
scripts/release.sh                                                    # tags, pushes, uploads images + manifests
```

`build-all.sh` bakes the key's public half into every image and writes a signed
`<variant>.json` beside each; `publish-release.sh` uploads both. Without the key file the
images build but say so, and refuse every update. A node on a build whose baked-in key
differs from the one that signed the manifest refuses too -- rotating the release key means
flashing once by cable.
