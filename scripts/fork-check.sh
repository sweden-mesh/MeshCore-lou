#!/bin/bash
# Are the fork's own files (scripts/fork-files.txt) the same on both branches?
#
#   scripts/fork-check.sh [observer-ref] [core-ref]     default fork/observer fork/core
#
# The list is read from each ref, and the two lists must agree too, so a file added on one
# branch and not the other is a difference like any other. Exit 0 when identical, 1 with
# the differing paths when not, 2 when a ref is missing.
set -euo pipefail
OBS="${1:-fork/observer}"
CORE="${2:-fork/core}"
LIST=scripts/fork-files.txt

for ref in "$OBS" "$CORE"; do
  git rev-parse -q --verify "$ref^{commit}" >/dev/null || { echo "no such ref: $ref" >&2; exit 2; }
done

paths() { git show "$1:$LIST" 2>/dev/null | sed -e 's/#.*//' -e 's/[[:space:]]*$//' | grep -v '^$'; }

if ! diff <(paths "$OBS") <(paths "$CORE") >/dev/null; then
  echo "$LIST differs between $OBS and $CORE:"
  diff <(paths "$OBS") <(paths "$CORE") | sed 's/^/  /'
  exit 1
fi

bad=0
while read -r path; do
  a=$(git rev-parse -q --verify "$OBS:$path" || echo missing)
  b=$(git rev-parse -q --verify "$CORE:$path" || echo missing)
  if [ "$a" != "$b" ]; then
    echo "differs: $path ($OBS ${a:0:8}, $CORE ${b:0:8})"
    bad=1
  fi
done < <(paths "$OBS")
[ $bad -eq 0 ] && echo "the fork's $(paths "$OBS" | wc -l) files are identical on $OBS and $CORE"
exit $bad
