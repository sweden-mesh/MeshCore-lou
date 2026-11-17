#!/bin/bash
# The build matrix as GitHub Actions takes it, from the dry run of build-matrix.sh in a
# checkout of each base: one job per Observer image, and one job per core board that builds
# all of that board's combinations in turn -- one job per core image would pass GitHub's
# limit of 256 jobs in a matrix. "name" is what the job's artifacts are called by.
#
#   scripts/ci-plan.sh <observer-checkout> <core-checkout>
#   scripts/ci-plan.sh --from <observer-plan> <core-plan>   from saved dry runs instead
#   BOARDS=all scripts/ci-plan.sh ...   every repeater board of both bases (the sweep)
#   BOARDS="env ..." scripts/ci-plan.sh ...   those boards, each in the base that has it
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
# A named list of boards is cut, per base, to the boards that base builds (its BOARDS=all,
# from build.sh list; or the boards of a saved dry run), so a trial naming one board of each
# base builds each in its own base only.
plan() {
  local src="$1" base="$2" b=() have keep="" skip="" e
  if [ -n "${BOARDS:-}" ] && [ "$BOARDS" != all ]; then
    if [ $FROM -eq 1 ]; then have=$(awk '{print $1}' "$src"); else have=$(cd "$src" && bash scripts/build-matrix.sh -n -c ar -b all | awk '{print $1}'); fi
    for e in $BOARDS; do
      if grep -qxF -- "$e" <<< "$have"; then keep="$keep $e"; else skip="$skip $e"; fi
    done
    [ -n "$skip" ] && echo "$base: skipped$skip, not a board of this base" >&2
    [ -z "$keep" ] && return 0
    b=(-b "${keep# }")
  elif [ -n "${BOARDS:-}" ]; then
    b=(-b "$BOARDS")
  fi
  if [ $FROM -eq 1 ]; then
    awk -v keep="$keep" 'BEGIN { n = split(keep, k); for (i = 1; i <= n; i++) want[k[i]] = 1 }
                         n == 0 || ($1 in want)' "$src"
  else
    (cd "$src" && bash scripts/build-matrix.sh -n "${b[@]}")
  fi
}
{
  plan "$OBS" observer | awk '{print "observer", $1, $2}'
  plan "$CORE" core | awk '{print "core", $1, $2}'
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
