#!/usr/bin/env bash
# How the GitHub release of a tag is marked (.github/workflows/release.yml): the flag for `gh release create`.
#
# Usage:  ci/release-latest.sh vX.Y.Z[-pre]
#
# Run in the checkout with its tags fetched. The tag must exist: a release is only ever made of a tag already
# pushed, never one this makes or moves. Prints --latest when it is the highest release by version,
# --latest=false otherwise (a patch on an older line, or v0.1.0 published after v0.1.1), and --prerelease for
# vX.Y.Z-rc.N. Tested by tests/release.rs.
set -euo pipefail

ref="$1"
if [[ ! "${ref#v}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "release-latest.sh: $ref is not vMAJOR.MINOR.PATCH" >&2
  exit 1
fi
git rev-parse -q --verify "refs/tags/$ref" >/dev/null || { echo "release-latest.sh: no tag $ref" >&2; exit 1; }
if [[ "$ref" == *-* ]]; then
  echo --prerelease
  exit 0
fi
highest="$(git tag -l 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -t. -k1.2,1n -k2,2n -k3,3n | tail -1)"
if [[ "$highest" == "$ref" ]]; then echo --latest; else echo --latest=false; fi
