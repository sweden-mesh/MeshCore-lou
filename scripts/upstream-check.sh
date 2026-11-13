#!/bin/bash
# Is there a new upstream for one of the fork's bases, and does it merge? (UPSTREAM-1)
#
#   scripts/upstream-check.sh core|observer [<base-ref>]
#
#   core      upstream = the newest stock repeater release tag, repeater-v<x.y.z>, of
#             meshcore-dev/MeshCore; base = fork/core
#   observer  upstream = the head of agessaman/MeshCore's observer-firmware branch;
#             base = fork/observer
#   base-ref  what to merge into (default origin/<base>); a test can pass an older commit
#
# "New" means: not already an ancestor of the base. When it is new, a branch
# upstream/<kind>-<name> is made from the base and the upstream merged into it with a merge
# commit. Nothing is pushed here; the workflow pushes and opens the pull request.
#
# Prints key=value lines (for $GITHUB_OUTPUT): status (up-to-date | merged | conflict),
# upstream (the tag or short sha), branch, and for a conflict the files, space-separated.
# Exit status 0 in all three cases; anything else is an error in the script itself.
set -euo pipefail

kind="${1:?usage: scripts/upstream-check.sh core|observer [<base-ref>]}"
case "$kind" in
  core)
    url=https://github.com/meshcore-dev/MeshCore.git
    base="${2:-origin/fork/core}"
    # Release tags only; a pre-release (repeater-v1.19.0-rc1) is not merged on its own.
    tag=$(git ls-remote --tags --refs "$url" 'repeater-v*' | awk '{print $2}' | sed 's#refs/tags/##' \
          | grep -E '^repeater-v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1)
    [ -n "$tag" ] || { echo "no repeater-v* tag at $url" >&2; exit 2; }
    git fetch -q --no-tags "$url" "refs/tags/$tag:refs/tags/$tag"
    ref="$tag"; name="$tag"
    message="Merge $tag: stock MeshCore ${tag#repeater-v} under the fork"
    ;;
  observer)
    url=https://github.com/agessaman/MeshCore.git
    base="${2:-origin/fork/observer}"
    git fetch -q --no-tags "$url" observer-firmware
    ref=$(git rev-parse FETCH_HEAD)
    name=$(git rev-parse --short=8 "$ref")
    message="Merge observer-firmware $name: the Observer as of $(git log -1 --format=%cs "$ref")"
    ;;
  *) echo "unknown kind: $kind" >&2; exit 2 ;;
esac

echo "upstream=$name"
if git merge-base --is-ancestor "$ref" "$base"; then
  echo "status=up-to-date"
  exit 0
fi

branch="upstream/$kind-$name"
echo "branch=$branch"
git checkout -q -B "$branch" "$base"
if git -c user.name="${GIT_AUTHOR_NAME:-The Louie}" -c user.email="${GIT_AUTHOR_EMAIL:-github@louie.se}" \
     merge -q --no-ff --no-edit -m "$message" "$ref" >/dev/null 2>&1; then
  echo "status=merged"
else
  files=$(git diff --name-only --diff-filter=U | tr '\n' ' ')
  git merge --abort
  echo "status=conflict"
  echo "files=${files% }"
fi
