#!/bin/bash
# Bring the fork's own files (scripts/fork-files.txt, as the source branch lists them) onto
# the branch checked out here, from another branch -- the one they were developed on.
#
#   git checkout fork/core && scripts/fork-sync.sh fork/observer
#
# Stages the files and stops; review and commit like any other change. Files are copied
# whole, so the source branch is the authority: a fix made on the wrong branch is lost.
# A file the source no longer lists is left alone here; remove it by hand.
set -euo pipefail
SRC="${1:?usage: scripts/fork-sync.sh <source-branch>}"
LIST=scripts/fork-files.txt

git rev-parse -q --verify "$SRC^{commit}" >/dev/null || { echo "no such ref: $SRC" >&2; exit 2; }
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "the working tree has changes: commit or stash them first" >&2
  exit 2
fi

mapfile -t files < <(git show "$SRC:$LIST" | sed -e 's/#.*//' -e 's/[[:space:]]*$//' | grep -v '^$')
git checkout "$SRC" -- "${files[@]}"
git status --short -- "${files[@]}"
echo "${#files[@]} files from $SRC staged; scripts/fork-check.sh $SRC $(git rev-parse --abbrev-ref HEAD) after committing"
