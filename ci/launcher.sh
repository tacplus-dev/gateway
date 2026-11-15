#!/usr/bin/env bash
# The launcher the image runs under (Dockerfile): one architecture's binary from the tacplus-dev/launcher
# release ci/launcher.lock pins, checked against the sha256 the lock records (the release's checksums.txt), so
# every release image of a line runs the launcher the lock names and nothing a moving ref resolves to
# (tacplus-dev/roadmap decisions/deterministic-builds-2026-10-27.md; tacplus-dev/kernel#22 asks the same).
#
# Usage:  ci/launcher.sh ARCH DEST [LOCK]
#
# Writes DEST/launcher-linux-ARCH. LOCK is ci/launcher.lock unless given. LAUNCHER_DOWNLOAD_URL replaces the
# release download base (the tests point it at a directory). A mismatch leaves nothing behind. Tested by
# tests/release.rs.
set -euo pipefail

arch="$1"
dest="$2"
lock="${3:-$(cd "$(dirname "$0")" && pwd)/launcher.lock}"
base="${LAUNCHER_DOWNLOAD_URL:-https://github.com/tacplus-dev/launcher/releases/download}"

name="launcher-linux-$arch"
version="$(sed -n -E 's/^version:[[:space:]]*"?(v[0-9]+\.[0-9]+\.[0-9]+)"?[[:space:]]*$/\1/p' "$lock" | head -1)"
want="$(sed -n -E "s/^$name:[[:space:]]*\"?([0-9a-f]{64})\"?[[:space:]]*$/\1/p" "$lock" | head -1)"
[[ -n "$version" ]] || { echo "launcher.sh: $lock names no release version" >&2; exit 1; }
[[ -n "$want" ]] || { echo "launcher.sh: $lock has no sha256 for $name" >&2; exit 1; }

mkdir -p "$dest"
tmp="$(mktemp "$dest/.$name.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
curl -fsSL --retry 5 --retry-delay 2 -o "$tmp" "$base/$version/$name"
got="$(sha256sum "$tmp" | cut -c1-64)"
if [[ "$got" != "$want" ]]; then
  echo "launcher.sh: $name of $version: sha256 $got, $lock says $want" >&2
  exit 1
fi
chmod 755 "$tmp"
mv "$tmp" "$dest/$name"
trap - EXIT
echo "$dest/$name: tacplus-dev/launcher $version, sha256 $got"
