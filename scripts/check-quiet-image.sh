#!/bin/bash
# Is a built image free of debug logging? MESH_DEBUG and MQTT_DEBUG lines write to the
# Serial the CLI reads commands from; a board built quiet (build-matrix.sh QUIET_ENVS,
# TODO 22a ruling 21) must carry none of their format strings.
#
#   scripts/check-quiet-image.sh <image.bin> ...      exit 1 naming each string found
set -uo pipefail
# One line each that only those macros print: MQTT_DEBUG_PRINTLN in MQTTBridge.cpp,
# MESH_DEBUG_PRINTLN in the repeater and in auto-reply.
DEBUG_STRINGS=("MQTT%d connected" "MQTT%d disconnected" "Login success" "AutoReply: sending %s reply")
bad=0
for img in "$@"; do
  # Read whole, not piped into grep -q: under pipefail the early exit would SIGPIPE
  # strings and read as "not found".
  text=$(strings "$img")
  for s in "${DEBUG_STRINGS[@]}"; do
    if grep -qF -- "$s" <<< "$text"; then
      echo "$img: carries the debug line '$s'"
      bad=1
    fi
  done
  [ $bad -eq 0 ] && echo "$img: quiet"
done
exit $bad
