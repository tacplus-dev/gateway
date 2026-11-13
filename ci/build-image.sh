#!/usr/bin/env bash
# Runs a command in the build image a checkout pins (tacplus.lock's build_image, by digest), as the build
# pipeline's gates job does: the tree at /workspace, as root, its tacplus the exact release the lock names.
#
# Usage:  ci/build-image.sh DIR CMD [ARG...]
#
# A tree that predates the pin (v0.1.0; tacplus.lock arrived in #28) takes this repository's tacplus.lock, the
# one beside this script, copied into DIR untracked, and says so. Tested by tests/release.rs.
set -euo pipefail

dir="$(cd "$1" && pwd)"
shift
ours="$(cd "$(dirname "$0")/.." && pwd)/tacplus.lock"
lock="$dir/tacplus.lock"
if [[ ! -f "$lock" ]]; then
  echo "build-image.sh: $dir has no tacplus.lock: it predates the pin, so it builds with $ours:" >&2
  cat "$ours" >&2
  cp "$ours" "$lock"
fi
image="$(sed -n -E 's/^build_image:[[:space:]]*"?([^"[:space:]]+)"?.*$/\1/p' "$lock" | head -1)"
[[ "$image" == *@sha256:* ]] || { echo "build-image.sh: $lock names no build_image by digest" >&2; exit 1; }

# The tree is the caller's, the container root: git refuses a tree it does not own unless told it is safe,
# and what the command writes is given back to the caller.
docker run --rm -v "$dir:/workspace" -w /workspace -e OWNER="$(id -u):$(id -g)" \
  -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/workspace \
  "$image" bash -c '"$@"; rc=$?; chown -R "$OWNER" /workspace; exit $rc' bash "$@"
