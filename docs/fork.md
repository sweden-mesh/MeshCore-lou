# The fork's features and how they combine

This fork adds three features to the Observer repeater. Each is chosen when an image is
built, and any combination of them builds from the same tree:

| code | switch | feature | docs |
|---|---|---|---|
| `as` | `WITH_AUTO_SCOPE` | auto-scope (reserved: no code yet, the switch stops the build) | |
| `ar` | `WITH_AUTO_REPLY` | auto-reply: the regional test channel, private tests, `trigger test` | [autoreply.md](autoreply.md) |
| `rc` | `WITH_MQTT_COMMAND` | remote command: signed commands and results over MQTT | [mqtt-control.md](mqtt-control.md) |

| base | `ar` | `rc` | `arrc` | with `as` (reserved) |
|---|---|---|---|---|
| Observer (`fork/observer`), 17 repeater boards | built | built | built | `as`, `asar`, `asrc`, `asarrc`: not yet |
| core MeshCore (`fork/core`), 12 curated boards (`scripts/boards-core.txt`) | built | -- (needs the Observer bridge) | -- | `as`, `asar`: not yet |

Every Observer image also carries signed pull OTA; a core image has none. Room-server and
companion images are not built (TODO 22a rulings 14, 23).

An image says which combination it is in its version, which `ver` reports and every status
publish carries: `<mcu>-v1.17.1-lou-<nn>-<features>-<hash>`, for example
`esp32s3-v1.17.1-lou-14-arrc-1a2b3c4d` -- the image file's name; inside an Observer image
`build.sh` adds the base's own `-observer` before the hash (`forkFeaturesOfVersion` reads
either). The revision
`lou-<nn>` continues the `ar-<nn>` counter of the releases before the split.

A combination is named by its codes run together in that fixed order: `ar`, `rc`, `arrc`,
and later `as`, `asar`, `asrc`, `asarrc`. `rc` needs the Observer's MQTT bridge; asking for
it without `WITH_MQTT_BRIDGE` stops the build (`include/ForkFeatures.h`).

Signed pull OTA ([ota.md](ota.md)) is not a feature: every Observer image of this fork
carries it, because an image that pulled from another channel would replace itself with one
that has none of its features.

## Building one combination

The switches are passed by the build script, never written into a variant's
`platformio.ini`, so every board builds every combination unchanged.
`scripts/build-matrix.sh` builds every combination for every board of the base it runs on
(`ar rc arrc` × the 17 Observer boards on `fork/observer`, `ar` × `scripts/boards-core.txt` on
`fork/core`), or the ones named with `-c` and `-b`:

```sh
scripts/build-matrix.sh -c arrc -b Heltec_v3_repeater_observer_mqtt    # one image
scripts/build-matrix.sh -n                                             # the plan, nothing built
```

Each image is `<env>-<mcu>-v1.17.1-lou-<nn>-<features>-<hash>.bin` and asks its channel for the
manifest `<env>-<features>.json` (`OTA_VARIANT`), so it can only be offered its own combination.
`scripts/check-build-matrix.sh` compares the plan with `test/data/build-matrix-<base>.txt`.
The whole matrix runs in GitHub Actions, `.github/workflows/fork-matrix.yml`, started by hand
with the two refs and the revision: the host suites per combination, then one job per image
(63 at lou-14), then one artifact, `candidate-<revision>`, with every image, every Observer
image's unsigned manifest and `SHA256SUMS`. It signs nothing and publishes nothing; the
release step on the release host does both. Every pull request and push to either branch runs
`.github/workflows/fork-pr.yml`: each combination of the base on one ESP32 and one nRF52 board
(`scripts/ci-pr-plan.sh`), and on `fork/observer` the XIAO S3 WIO image built as a release
builds it, checked free of debug lines by `scripts/check-quiet-image.sh`.
Without any switch the image is the Observer repeater plus the fork's OTA channel.

## Tests per combination

`pio test -e native` runs every suite as an image with no feature switched on; `native_ar`,
`native_rc` and `native_arrc` run the features' suites and `test_fork_seams` with that
combination's switches on, so the
seams -- the feature token, which commands the plane admits -- are checked in the shape each
image has. `native_v2` and `native_kiss_modem` are as before. The glue in
`examples/simple_repeater/` is not host-tested; a target compile of each combination is its
gate.

## Settings across combinations

Each feature keeps its settings in its own file, and a build without the feature neither
reads nor writes it:

| file | owner |
|---|---|
| `/autoreply` | auto-reply |
| `/mqttcontrol` | remote command |
| `/ota` | pull OTA, in every Observer image; read from `/mqttcontrol` until it is first written |

A node flashed from one combination to another therefore keeps every setting of a feature
it loses, and finds them again when it gets the feature back.

## Where the features attach

All feature code lives in files of its own; the repeater's `MyMesh` holds one `Fork` object
(`examples/simple_repeater/Fork.{h,cpp}`) and calls it from a few lines:

| hook | where in `MyMesh` | what the features do there |
|---|---|---|
| H1, H2 | `MyMesh.h`: `#include "Fork.h"`, `friend class Fork; Fork fork { *this };` | the object, with access to the mesh's own state |
| H3 | `MyMesh.h`: `searchChannelsByHash` and `onGroupDataRecv` forward to `fork` | auto-reply's channels and its answer to a test; without it, Mesh's defaults (no channel) |
| H4 | `begin()`, after the ACL is loaded: `fork.begin(_fs)` | each feature reads its settings file |
| H5 | `loop()`, after the radio: `fork.loop()` | the command queue, the ping, the automatic OTA check, the proof that marks a new image good |
| H6 | `handleCommand()`, after upstream's verbs: `else if (!fork.handleCommand(...))` | the features' CLI, before the common CLI |
| H7 | `begin()`, before `bridge->begin()`: `fork.attachBridge(bridge)` | with remote command: the control topics and the per-slot client ids |
| H8 | `onAnonDataRecv()`, first line of the anonymous-request branch: `if (fork.onAnonRequest(...)) return;` | the private test request (sub-type `0xF0`), answered on auto-reply's own path and slot |
| H9a (reserved) | `onControlDataRecv()`, first line: `if (fork.onControlData(packet)) return;` | auto-scope's request and reply (`as`); not written until auto-scope has code |
| H9b (reserved) | `createSelfAdvert()`, beside the advert data: `fork.decorateAdvert(...)` | auto-scope's fingerprint in `ADV_FEAT2`; not written until auto-scope has code |

H9 is reserved, not added: a hook line that calls nothing would be dead code in every image.
When auto-scope's repeater half is written (its plan, `meshcore-auto-scope/AUTO-SCOPE.md`,
A-03), the two lines go in on both branches with `Fork::onControlData` and
`Fork::decorateAdvert` -- inline no-ops without `WITH_AUTO_SCOPE`, as the channel hooks are
without auto-reply -- and its code in `AutoScopeHooks.cpp`; its declaration in its own
`/autoscope` file, read in `Fork::begin`, and `region client-default` through
`Fork::handleCommand`, ahead of the common CLI's `region` parser (TODO 22a rulings 1, 19).

## Two bases, one copy of the feature code

The Observer images build from `fork/observer` (the Observer's `observer-firmware` plus the
fork) and the core images from `fork/core` (upstream's release tag `repeater-v1.17.1` plus the
fork). Every file the fork owns -- listed in `scripts/fork-files.txt` -- is identical on both;
only the hook lines in each base's own files differ. Develop on `fork/observer`, then
`git checkout fork/core && scripts/fork-sync.sh fork/observer`, commit, and
`scripts/fork-check.sh` (also run by `.github/workflows/fork-files.yml` on every push) says
whether the two agree. On core the command plane and OTA compile to nothing and their suites
are ignored: they need Observer headers that base does not have.

### Auto-reply on core

A core image has no MQTT and so no `mqtt.iata`: no legacy `#test-<iata>` channel, and the node
stays silent until `autoreply.region` is set; `get autoreply` shows `legacy on, inert: no MQTT`.
Its replies are measured by the Observer nodes that hear them. Cost, measured on `fork/core`
(static RAM / flash, `ar` against the same board with no feature):

| board | RAM | flash |
|---|---|---|
| RAK_4631_repeater (nRF52840) | 33 784 → 34 576 (+792 B) | 469 620 → 484 612 (+14 992 B of 815 104) |
| Heltec_t114_repeater (nRF52840) | 31 904 → 32 696 (+792 B) | 427 604 → 442 596 (+14 992 B) |

## The index a web page reads

Every release carries `firmware-index.json` (TODO 22a ruling 25): one row per image file --
board, base, features, MCU, version, file, URL, SHA-256, the form (`bin`, `merged`, `uf2`,
`zip`) and how to flash it, and for Observer images the manifest it asks for -- and `sig`, the
release key's Ed25519 signature over the rest as canonical JSON (keys sorted, no spaces,
ASCII). A page reads that one file and never parses an image name;
`scripts/manifest.py verify-index` checks it. `release-candidate.sh` writes it.
