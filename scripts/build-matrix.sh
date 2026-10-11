#!/bin/bash
# Build every combination of the fork's features for every board of this branch's base,
# named so a web page and an OTA channel can find the right image (TODO 22a, rulings 8, 9).
#
#   scripts/build-matrix.sh [-c "ar rc arrc"] [-b "env ..."] [-r lou-14] [-o DIR] [-n]
#
#   -c  combinations, the codes as/ar/rc run together in that order. Default: ar rc arrc on
#       fork/observer, ar on fork/core.
#   -b  boards (env names). Default: every *_repeater_observer_mqtt env on fork/observer,
#       scripts/boards-core.txt on fork/core.
#   -r  the revision, lou-<nn> (default: $REVISION, else lou-14).
#   -o  where the images go (default: .pio/matrix/, which git ignores).
#   -n  dry run: print what each build would be given, one line per build, and build nothing.
#
# Per board and combination: the feature switches as -D flags (never an ini edit),
#   FIRMWARE_VERSION = <mcu>-<base version>-<revision>-<features>   (build.sh adds -<hash>)
#   OTA_VARIANT      = <env>-<features>     the manifest this image asks its channel for
# and build.sh build-firmware. The images keep build.sh's names,
# <env>-<mcu>-v1.17.1-lou-14-<features>-<hash>.bin. Core images have no pull OTA, and their
# OTA_VARIANT goes unused.
#
# A failed build is retried once -- on the small host a link killed for memory is the usual
# cause -- and a second failure is listed at the end and makes the exit status 1; the
# board is then left to CI.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

COMBOS="" BOARDS="" REV="${REVISION:-lou-14}" OUT=".pio/matrix" DRY=0
while getopts "c:b:r:o:n" opt; do
  case "$opt" in
    c) COMBOS="$OPTARG" ;;
    b) BOARDS="$OPTARG" ;;
    r) REV="$OPTARG" ;;
    o) OUT="$OPTARG" ;;
    n) DRY=1 ;;
    *) sed -n '2,/^set /p' "$0" | sed '$d' >&2; exit 2 ;;
  esac
done

if [ -f src/helpers/bridges/MQTTBridge.h ]; then BASE=observer; else BASE=core; fi
if [ -z "$COMBOS" ]; then
  [ "$BASE" = observer ] && COMBOS="ar rc arrc" || COMBOS="ar"
fi
if [ -z "$BOARDS" ]; then
  if [ "$BASE" = observer ]; then
    BOARDS=$(bash build.sh list | awk '{print $1}' | grep '_repeater_observer_mqtt$')
  else
    BOARDS=$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' scripts/boards-core.txt | grep -v '^$')
  fi
fi
case "$REV" in lou-[0-9]*) ;; *) echo "revision must be lou-<nn>, not '$REV'" >&2; exit 2 ;; esac
BASE_VERSION=$(grep -m1 -oE 'FIRMWARE_VERSION +"v[0-9.]+"' examples/simple_repeater/MyMesh.h | grep -oE 'v[0-9.]+')

# The -D flags for a combination; the codes must be known and in the fixed order, so one
# combination never has two names.
flags_for() {
  local combo="$1" rest="$1" flags=""
  while [ -n "$rest" ]; do
    case "${rest:0:2}" in
      as) flags="$flags -DWITH_AUTO_SCOPE=1" ;;
      ar) flags="$flags -DWITH_AUTO_REPLY=1" ;;
      rc) flags="$flags -DWITH_MQTT_COMMAND=1" ;;
      *) return 1 ;;
    esac
    rest="${rest:2}"
  done
  case "$combo" in as|ar|rc|asar|asrc|arrc|asarrc) ;; *) return 1 ;; esac
  [ "$BASE" = core ] && [[ "$combo" == *rc* ]] && return 1
  echo "${flags# }"
}

# Boards whose Observer variant ships with debug logging on are built quiet: DISABLE_DEBUG=1
# undefines MESH_DEBUG and the rest, and -UMQTT_DEBUG the Observer's own (ruling 21).
QUIET_ENVS="${QUIET_ENVS:-Xiao_S3_WIO_repeater_observer_mqtt}"

for combo in $COMBOS; do
  flags_for "$combo" >/dev/null || { echo "not a combination for $BASE: '$combo'" >&2; exit 2; }
done

mkdir -p "$OUT"
LOGS="$OUT/logs"
mkdir -p "$LOGS"
failed=""
n=0
total=$(( $(echo $COMBOS | wc -w) * $(echo $BOARDS | wc -w) ))
for combo in $COMBOS; do
  flags=$(flags_for "$combo")
  for env in $BOARDS; do
    n=$((n + 1))
    variant="$env-$combo"
    quiet=""
    case " $QUIET_ENVS " in *" $env "*) quiet=1 ;; esac
    extra="${quiet:+ -UMQTT_DEBUG}"
    if [ $DRY -eq 1 ]; then
      echo "$env $combo flags='$flags$extra' version=<mcu>-$BASE_VERSION-$REV-$combo variant=$variant${quiet:+ quiet}"
      continue
    fi
    # `|| true` is load-bearing under pipefail: no match must reach the check below.
    mcu=$(PLATFORMIO_BUILD_FLAGS="$flags" pio run -e "$env" -t envdump 2>"$LOGS/$variant.log" \
          | grep -oE "'BOARD_MCU': '[^']+'" | head -1 | cut -d"'" -f4 || true)
    if [ -z "$mcu" ]; then
      echo "[$n/$total] $variant - SKIPPED, could not read BOARD_MCU (see $LOGS/$variant.log)"
      failed="$failed $variant"
      continue
    fi
    version="$mcu-$BASE_VERSION-$REV-$combo"
    ok=0
    for attempt in 1 2; do
      echo "[$n/$total] $variant ($mcu)${quiet:+, debug off}$([ $attempt -eq 2 ] && echo ", retry")"
      if DISABLE_DEBUG="${quiet:-${DISABLE_DEBUG:-}}" PLATFORMIO_BUILD_FLAGS="$flags$extra" \
         FIRMWARE_VERSION="$version" OTA_VARIANT="$variant" \
         bash build.sh build-firmware "$env" > "$LOGS/$variant.log" 2>&1; then
        ok=1; break
      fi
    done
    if [ $ok -eq 0 ]; then
      echo "         FAILED twice, left to CI: $LOGS/$variant.log"
      failed="$failed $variant"
      continue
    fi
    cp out/"$env"-*.bin out/"$env"-*.uf2 out/"$env"-*.zip out/"$env"-*.hex "$OUT"/ 2>/dev/null || true
  done
done

[ $DRY -eq 1 ] && exit 0
echo
if [ -n "$failed" ]; then
  echo "FAILED:$failed"
  exit 1
fi
echo "all $total builds in $OUT/"
