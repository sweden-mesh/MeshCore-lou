#!/bin/bash
# Does build-matrix.sh still plan the builds it planned? Its dry run for this branch's base
# -- every board and combination, with the flags, version and OTA variant each would be
# given -- against test/data/build-matrix-<base>.txt. Exit 1 with the difference.
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
