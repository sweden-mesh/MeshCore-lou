#!/bin/bash
# Does build-matrix.sh still plan the builds it planned? Its dry run for this branch's base
# -- every board and combination, with the flags, version and OTA variant each would be
# given -- against test/data/build-matrix-<base>.txt. Exit 1 with the difference. Then the
# Actions plan of both bases' expected files (scripts/ci-plan.sh): at most 256 jobs, and
# every board and combination built by exactly one of them.
#
#   scripts/check-build-matrix.sh            compare
#   scripts/check-build-matrix.sh --update   rewrite the expected file after a deliberate change
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f src/helpers/bridges/MQTTBridge.h ]; then BASE=observer; else BASE=core; fi
EXPECTED=test/data/build-matrix-$BASE.txt
if [ "${1:-}" = "--update" ]; then
  REVISION=lou-14 bash scripts/build-matrix.sh -n > "$EXPECTED"
  echo "wrote $EXPECTED"
  exit 0
fi
if diff -u "$EXPECTED" <(REVISION=lou-14 bash scripts/build-matrix.sh -n); then
  echo "build-matrix.sh plans $(wc -l < "$EXPECTED") builds for $BASE, as expected"
else
  exit 1
fi
OBS_PLAN=test/data/build-matrix-observer.txt CORE_PLAN=test/data/build-matrix-core.txt
bash scripts/ci-plan.sh --from "$OBS_PLAN" "$CORE_PLAN" | python3 -c '
import json, sys
want = sorted((b, *l.split()[:2]) for b, f in (("observer", sys.argv[1]), ("core", sys.argv[2]))
              for l in open(f) if l.strip())
jobs = json.load(sys.stdin)
got = sorted((j["base"], j["env"], c) for j in jobs for c in j["combo"].split())
if got != want:
    sys.exit("the Actions plan does not build every board and combination exactly once")
print(f"the Actions plan builds all {len(got)} images in {len(jobs)} jobs")
' "$OBS_PLAN" "$CORE_PLAN"
