#!/bin/bash
# Turn a CI candidate into one signed release, on the release host (TODO 22a rulings 15, 25).
#
#   scripts/release-candidate.sh -c <candidate-dir> -t <tag> [-k key-file] [-r owner/repo]
#                                [-o out-dir] [-p]
#
#   -c  the unpacked candidate-<revision> artifact of fork-matrix.yml (images, unsigned
#       manifests, SHA256SUMS)
#   -t  the release tag, v1.17.1-lou-<nn>; every image must be of that revision
#   -k  the release key (default ~/.config/mccontrol/release.key); read here and nowhere else
#   -r  the repository the release lives in (default sweden-mesh/MeshCore-lou)
#   -o  where the release's files are assembled (default: release-<tag>/ beside the candidate)
#   -p  publish: create the GitHub release with gh. Without it the gh command is printed.
#
# Refuses, before signing anything, a set that does not hold together: a file that is not
# what SHA256SUMS says, an Observer image without its manifest or a manifest without its
# image, two images for one variant, an image of another revision, or an Observer image
# that does not carry this key's public half (it could never verify what is signed here).
# Then signs every manifest (scripts/manifest.py sign), verifies each signature back, writes
# and verifies the signed index the web page reads (firmware-index.json), and counts the
# assets against GitHub's limit.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python3}"
CAND="" TAG="" KEY="$HOME/.config/mccontrol/release.key" REPO="sweden-mesh/MeshCore-lou" OUT="" PUBLISH=0
while getopts "c:t:k:r:o:p" opt; do
  case "$opt" in
    c) CAND="$OPTARG" ;; t) TAG="$OPTARG" ;; k) KEY="$OPTARG" ;; r) REPO="$OPTARG" ;;
    o) OUT="$OPTARG" ;; p) PUBLISH=1 ;;
    *) sed -n '2,/^set /p' "$0" | sed '$d' >&2; exit 2 ;;
  esac
done
[ -n "$CAND" ] && [ -n "$TAG" ] || { sed -n '2,/^set /p' "$0" | sed '$d' >&2; exit 2; }
REV=$(echo "$TAG" | grep -oE 'lou-[0-9]+$' || true)
[ -n "$REV" ] || { echo "the tag must end in lou-<nn>: $TAG" >&2; exit 2; }
[ -f "$KEY" ] || { echo "no release key at $KEY" >&2; exit 2; }
OUT="${OUT:-$(dirname "$CAND")/release-$TAG}"
MAX_ASSETS=1000
fail() { echo "REFUSED: $*" >&2; exit 1; }

cd "$CAND"
[ -f SHA256SUMS ] || fail "no SHA256SUMS in $CAND"
sha256sum --quiet -c SHA256SUMS || fail "a file is not what SHA256SUMS says"
listed=$(awk '{print $2}' SHA256SUMS | sed 's/^\*//' | sort)
present=$(ls | grep -v '^SHA256SUMS$' | sort)
[ "$listed" = "$present" ] || fail "the candidate holds files SHA256SUMS does not list, or the reverse"

PUB=$("$PY" "$ROOT/scripts/manifest.py" --pubkey "$KEY")
images=$(ls | grep -E '\.(bin|uf2|zip|hex)$' | grep -v -- '-merged\.bin$')
for img in $images; do
  case "$img" in *-"$REV"-*) ;; *) fail "$img is not $REV" ;; esac
done
for img in $(echo "$images" | grep '_observer_mqtt-.*\.bin$' || true); do
  m=$(grep -l "\"fileName\": \"$img\"" *.unsigned.json 2>/dev/null || true)
  [ "$(echo "$m" | grep -c .)" -eq 1 ] || fail "$img has $(echo "$m" | grep -c .) manifests, not one"
  grep -qa "$PUB" "$img" || fail "$img does not carry the public key of $KEY"
done
for m in *.unsigned.json; do
  [ -e "$m" ] || continue
  f=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["fileName"])' "$m")
  [ -f "$f" ] || fail "$m describes $f, which is not in the candidate"
done
dups=$(ls *.unsigned.json 2>/dev/null | sed 's/\.unsigned\.json$//' | sort | uniq -d)
[ -z "$dups" ] || fail "two manifests for $dups"

rm -rf "$OUT"
mkdir -p "$OUT"
cp $images $(ls | grep -- '-merged\.bin$' || true) "$OUT"/
base_url="https://github.com/$REPO/releases/download/$TAG"
for m in *.unsigned.json; do
  [ -e "$m" ] || continue
  variant="${m%.unsigned.json}"
  f=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["fileName"])' "$m")
  "$PY" "$ROOT/scripts/manifest.py" sign "$m" "$f" "$base_url/$f" "$KEY" "$OUT/$variant.json" >/dev/null
  "$PY" "$ROOT/scripts/manifest.py" verify "$OUT/$variant.json" "$PUB" >/dev/null \
    || fail "$variant.json did not verify after signing"
done

"$PY" "$ROOT/scripts/manifest.py" index "$OUT" "$TAG" "$base_url" "$KEY" >/dev/null
"$PY" "$ROOT/scripts/manifest.py" verify-index "$OUT/firmware-index.json" "$PUB" >/dev/null \
  || fail "firmware-index.json did not verify after signing"
rows=$("$PY" -c 'import json,sys; print(" ".join(sorted(r["file"] for r in json.load(open(sys.argv[1]))["images"])))' "$OUT/firmware-index.json")
files=$(cd "$OUT" && ls | grep -E '\.(bin|uf2|zip|hex)$' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')
[ "$rows" = "$files" ] || fail "firmware-index.json does not list exactly the release's images"

cd "$OUT"
sha256sum * > SHA256SUMS
count=$(ls | wc -l)
[ "$count" -le "$MAX_ASSETS" ] || fail "$count assets, over GitHub's $MAX_ASSETS per release"
echo "release $TAG: $count assets in $OUT ($(ls "$CAND"/*.unsigned.json 2>/dev/null | wc -l) signed manifests, firmware-index.json), key ${PUB:0:12}..."
cmd=(gh release create "$TAG" --repo "$REPO" --title "$TAG" --notes-file RELEASE_NOTES.md --prerelease)
if [ "$PUBLISH" -eq 1 ]; then
  [ -f RELEASE_NOTES.md ] || fail "no RELEASE_NOTES.md in $OUT"
  "${cmd[@]}" ./*
else
  echo "to publish: (cd $OUT && ${cmd[*]} ./*)   -- or rerun with -p"
fi
