#!/bin/bash
# The build matrix as GitHub Actions takes it, from the dry run of build-matrix.sh in a
# checkout of each base: one job per Observer image, and one job per core board that builds
# all of that board's combinations in turn -- one job per core image would pass GitHub's
# limit of 256 jobs in a matrix. "name" is what the job's artifacts are called by.
#
#   scripts/ci-plan.sh <observer-checkout> <core-checkout>
#   scripts/ci-plan.sh --from <observer-plan> <core-plan>   from saved dry runs instead
#   BOARDS=all scripts/ci-plan.sh ...   every repeater board of both bases (the sweep)
#   -> [{"base":"observer","env":"Heltec_v3_repeater_observer_mqtt","combo":"arrc",
#        "name":"Heltec_v3_repeater_observer_mqtt-arrc"}, ...,
#       {"base":"core","env":"RAK_4631_repeater","combo":"ar rc arrc",
#        "name":"RAK_4631_repeater-ar-rc-arrc"}, ...]
# The number of jobs goes to stderr; more than 256 is an error.
set -euo pipefail
FROM=0
[ "${1:-}" = --from ] && { FROM=1; shift; }
OBS="${1:?observer checkout}"
CORE="${2:?core checkout}"
B=()
[ -n "${BOARDS:-}" ] && B=(-b "$BOARDS")
plan() {
  if [ $FROM -eq 1 ]; then cat "$1"; else (cd "$1" && bash scripts/build-matrix.sh -n "${B[@]}"); fi
}
{
  plan "$OBS" | awk '{print "observer", $1, $2}'
  plan "$CORE" | awk '{print "core", $1, $2}'
} | python3 -c '
import json, sys
jobs = {}
for line in sys.stdin:
    if not line.strip():
        continue
    base, env, combo = line.split()
    key = (base, env) if base == "core" else (base, env, combo)
    jobs.setdefault(key, {"base": base, "env": env, "combo": []})["combo"].append(combo)
if not jobs:
    sys.exit("no builds planned")
rows = []
for j in jobs.values():
    rows.append(dict(j, combo=" ".join(j["combo"]), name=j["env"] + "-" + "-".join(j["combo"])))
print(f"{len(rows)} jobs of the 256 GitHub allows", file=sys.stderr)
if len(rows) > 256:
    sys.exit("more jobs than a matrix may hold")
print(json.dumps(rows, separators=(",", ":")))
'
