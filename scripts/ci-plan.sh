#!/bin/bash
# The build matrix as GitHub Actions takes it: one JSON object per image, from the dry run
# of build-matrix.sh in a checkout of each base.
#
#   scripts/ci-plan.sh <observer-checkout> <core-checkout>
#   BOARDS=all scripts/ci-plan.sh ...   every repeater board of both bases (the sweep)
#   -> [{"base":"observer","env":"Heltec_v3_repeater_observer_mqtt","combo":"arrc"}, ...]
set -euo pipefail
OBS="${1:?observer checkout}"
CORE="${2:?core checkout}"
B=()
[ -n "${BOARDS:-}" ] && B=(-b "$BOARDS")
{
  (cd "$OBS" && bash scripts/build-matrix.sh -n "${B[@]}") | awk '{print "observer", $1, $2}'
  (cd "$CORE" && bash scripts/build-matrix.sh -n "${B[@]}") | awk '{print "core", $1, $2}'
} | python3 -c '
import json, sys
rows = [dict(zip(("base", "env", "combo"), line.split())) for line in sys.stdin if line.strip()]
if not rows:
    sys.exit("no builds planned")
print(json.dumps(rows, separators=(",", ":")))
'
