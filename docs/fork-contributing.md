# Working on the fork

This repository is a fork with two long-lived branches: `fork/observer`, the
[MeshCore Observer](https://github.com/agessaman/MeshCore) firmware's `observer-firmware` plus the
fork, and `fork/core`, upstream MeshCore's release tag `repeater-v1.17.1` plus the fork. The fork
adds three features that an image carries in any combination -- auto-reply (`ar`), remote
control over MQTT (`rc`) and, reserved, auto-scope (`as`) -- and signed pull OTA in every Observer
image. [`fork.md`](fork.md) says how they combine and are built; [`fork-overview.md`](fork-overview.md)
what they do.

## 1. Releases are batches

A release is a rare, expensive event: flashing is a manual, physical job that takes weeks for
some nodes and longer for others, and the fleet runs several versions at once for months. So
changes go out as a tested batch at most once a month, every change must degrade gracefully
next to older versions, and anything tunable is a runtime setting rather than a constant. How a
release is built and signed is in [`ota.md`](ota.md), "Cutting a release".

## 2. Definition of done

Every change, however small:

1. **Host tests pass**, and new logic has new tests.
2. **Every combination it touches compiles** on at least one board --
   `scripts/build-matrix.sh -c <combination> -b <env>`.
3. **Docs updated** — `docs/`, and the command tables in [`fork-overview.md`](fork-overview.md)
   if you added a command.
4. Committed with a message that says *why*, not *what*.

### Green is not proof

The convention here is stricter than "the suite passes": after adding a test, **mutate the
logic it covers** — flip a `<` to `<=`, delete a branch, invert a condition — confirm the
suite goes red, then restore. A test that passes against broken code is worse than no test,
because it is believed. Every decision on this branch has been through this.

## 3. Building and testing

```bash
# the host suites, per combination; about 2 min on fork/observer, 1 458 cases at lou-14
pio test -e native -e native_kiss_modem -e native_v2 -e native_ar -e native_rc -e native_arrc
pio test -e native -e native_kiss_modem -e native_ar      # on fork/core
scripts/build-matrix.sh -c arrc -b Heltec_v3_repeater_observer_mqtt   # one target, one combination
scripts/build-matrix.sh -n                                # every build this base would make
```

Three traps, each of which has cost real time here:

- **`bash build.sh`, never `sh build.sh`.** The script uses bash arrays; `/bin/sh` is dash on
  most of these machines and dies with `Syntax error: "(" unexpected`. `sh build.sh list`
  appears to work only because dash exits before it parses that far.
- **One `pio` invocation per checkout at a time — tests included.** `.pio/build` is shared, so
  a `pio test` started beside a running environment build clears the build directory under it
  and produces failures that look like code errors and are not. If you need the suite while a
  build runs, use a second checkout.
- **`.pio/libdeps` can be owned by another user** on a shared machine, and PlatformIO will
  fail with a `PermissionError` that does not name the cause. Work around it per-user:
  `export PLATFORMIO_LIBDEPS_DIR=.pio/libdeps-yourname`.

CI runs the host suites (`.github/workflows/run-unit-tests.yml`), a compile of every
combination on one ESP32 and one nRF52 board for every pull request (`fork-pr.yml`), and the
full matrix by hand for a release (`fork-matrix.yml`).

## 4. Where code goes — keep the fork rebasable

This fork tracks an upstream that is actively developed and will probably never be
upstreamed itself, so **every change has to stay easy to re-apply onto a new upstream.**

- **Put new code in new files, behind its feature's switch.** Edits to upstream-owned files are
  the hook lines into the `Fork` object (`examples/simple_repeater/Fork.h`, [fork.md](fork.md))
  and nothing more; a feature's code is a file wrapped whole in `#ifdef WITH_<FEATURE>`.
- **Never add fields to `NodePrefs` or `CommonCLI.{h,cpp}`.** Upstream edits those constantly.
  Use a feature-local config file and the repeater's own `handleCommand()` — `AutoReply.{h,cpp}`
  is the worked example, with its own `/autoreply` flash file and its own CLI clause.
- **Pure logic goes in a header** under `src/helpers/` — `static inline` free functions, a
  feature-name prefix, only `<stddef.h>`/`<stdint.h>`/`<string.h>`-level includes, state passed
  in by the caller. `AutoReplyLogic.h` and `MqttControlLogic.h` are the pattern. This is what
  makes the logic host-testable without a radio, and it needs no `platformio.ini` wiring: the
  `native` env already has `-I src`.
- **New docs are new pages under `docs/`**, not edits to `docs/cli_commands.md`. `mkdocs.yml`
  has no explicit `nav`, so new pages are picked up automatically.
- New `.cpp` files under `examples/<app>/` need no `platformio.ini` change — every variant
  uses the directory form of `build_src_filter`.
- **The fork's own files are identical on `fork/observer` and `fork/core`.** Develop on
  `fork/observer`; `scripts/fork-sync.sh fork/observer` on `fork/core` brings them over and
  `scripts/fork-check.sh` (also CI) compares them. `scripts/fork-files.txt` lists them.

The config files are **append-only from version 5 onward**: a reader that meets a higher
version than its own reads the fields it knows. Add a field at the end and bump the version;
do not reorder or reuse.

## 5. House style — match the file you are in

Read the surrounding code and match it. Concretely, the things reviewers here remove:

- **Comments that narrate syntax.** `i += 1 // increment index`. Comment *why*, never *what*.
- **Comments about the edit rather than the code** — "fixed as requested", "updated function",
  or anything referring to the change's own history. State the invariant; the history belongs
  in the commit message.
- **Placeholder comments.** `// ... existing code ...`. Never.
- **Defensive checks the call sites make impossible.** House style is direct: `ClientACL::load`
  assigns `_fs = fs;` then calls `_fs->exists(...)` with no null check. *Exception:* the pure
  headers in `src/helpers/` are effectively fuzz targets and do guard null, zero-length and
  degenerate input — their tests assert it.
- **Hand-rolled standard library.** `strcasecmp` (`<strings.h>`), `tolower` (`<ctype.h>`) and
  Arduino's `min()` are all already in use here.

Do not over-correct either: uniformity this codebase does not have is its own kind of wrong.
Comment capitalisation in `examples/simple_repeater/MyMesh.cpp` is genuinely mixed, and
pointer placement in that file is split almost evenly. Leave both alone.

## 6. Commits

- One logical change per commit; the message explains **why**, and the diff shows what.
- **No AI-assistant attribution** — no `Co-Authored-By` trailer, no "generated with" line,
  nothing of the kind in code, comments or docs.
- **Commit and push only when asked.** Same for releasing and flashing.
- **Nothing but code belongs in this repo.** Notes, plans, analyses, backlogs, scratch scripts,
  logs and build output all live outside it. Build and release artifacts belong in the parent
  build folder; planning lives in a separate repository.

## 7. Two constraints that are not negotiable

Both were found in this tree and both are load-bearing for security:

- **`sender_timestamp == 0` is a privilege signal**, not merely a clock. It gates
  `set prv.key`, `erase` and `set mqtt.cmd.pubkey`. **A remote path must never pass 0**, and must
  additionally be bounded by the deny list over admitted verbs (`mqttCtrlCommandDenied`),
  so that either gate alone keeps the privileged commands unreachable.
- **The rate limit applies to validly signed commands.** A compromised signing key must not
  become a mesh-flood weapon. Do not add a path that bypasses it "because the signature
  checked out" — that is precisely the case it exists for.

And one invariant with a test pinning it, which any change to request parsing must keep:
**a reply can never trigger a reply.** See `AReplyCanNeverTriggerAReply` in
`test/test_autoreply/`.

## 8. Airtime is a real, shared resource

This firmware runs on a live mesh other people depend on. A flood costs every node in range
airtime and battery. When you change anything that transmits, work out what it costs before
you change it, and say so in the commit message. Measured on this mesh at SF8/BW62.5/CR4:8: a
probe is ~0.54 s of time-on-air and provokes a reply storm of several seconds across the mesh.

Delays are cheap and airtime is not. A repeater waiting minutes to answer a test costs nothing
but patience, and spreading replies out in time is the main tool against the collisions that
cause most of the losses we can measure.

---

Fuller detail — the release process, the flashing notes, the design documents behind the reply
modes, and the per-sprint history — lives in the project's planning repository. Ask for access
rather than reconstructing it from the diff.
