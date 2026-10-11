# The fork's features and how they combine

This fork adds three features to the Observer repeater. Each is chosen when an image is
built, and any combination of them builds from the same tree:

| code | switch | feature | docs |
|---|---|---|---|
| `as` | `WITH_AUTO_SCOPE` | auto-scope (reserved: no code yet, the switch stops the build) | |
| `ar` | `WITH_AUTO_REPLY` | auto-reply: the regional test channel, private tests, `trigger test` | [autoreply.md](autoreply.md) |
| `rc` | `WITH_MQTT_COMMAND` | remote command: signed commands and results over MQTT | [mqtt-control.md](mqtt-control.md) |

A combination is named by its codes run together in that fixed order: `ar`, `rc`, `arrc`,
and later `as`, `asar`, `asrc`, `asarrc`. `rc` needs the Observer's MQTT bridge; asking for
it without `WITH_MQTT_BRIDGE` stops the build (`include/ForkFeatures.h`).

Signed pull OTA ([ota.md](ota.md)) is not a feature: every Observer image of this fork
carries it, because an image that pulled from another channel would replace itself with one
that has none of its features.

## Building one combination

The switches are passed by the build script, never written into a variant's
`platformio.ini`, so every board builds every combination unchanged:

```sh
PLATFORMIO_BUILD_FLAGS="-DWITH_AUTO_REPLY=1 -DWITH_MQTT_COMMAND=1" \
  bash build.sh build-firmware Heltec_v3_repeater_observer_mqtt      # arrc
```

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

## Two bases, one copy of the feature code

The Observer images build from `fork/observer` (the Observer's `observer-firmware` plus the
fork) and the core images from `fork/core` (upstream's release tag `repeater-v1.17.1` plus the
fork). Every file the fork owns -- listed in `scripts/fork-files.txt` -- is identical on both;
only the hook lines in each base's own files differ. Develop on `fork/observer`, then
`git checkout fork/core && scripts/fork-sync.sh fork/observer`, commit, and
`scripts/fork-check.sh` (also run by `.github/workflows/fork-files.yml` on every push) says
whether the two agree. On core the command plane and OTA compile to nothing and their suites
are ignored: they need Observer headers that base does not have.
