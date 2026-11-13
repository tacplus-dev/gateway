#!/usr/bin/env bash
# Builds the release image of one architecture (.github/workflows/release.yml), on a runner of that
# architecture, from a checkout of the tag whose gates have run (ci/build-image.sh DIR just gates: they build
# target/release/gateway).
#
# Usage:  ci/release-image.sh DIR ARCH VERSION [IMAGE]
#
# In the build image DIR pins, it builds the web console into webapp-dist/ (webapp/, generated against the
# registry's contracts, as the gateway's ROUTES are) and the launcher from target/launcher-src (the workflow
# checks it out at the commit it pins) into target/launcher/. Then it stages the Dockerfile's context: the
# gateway, webapp-dist/, the launcher, and web-dist/ and clients/ empty (a customer app and client binaries
# are a fleet's, tacplus-dev/roadmap decisions/gateway-per-fleet-2026-10-27.md), and builds it labelled with
# VERSION (no v), the commit and its time. With IMAGE it is pushed by digest, written to
# DIR/target/image/ARCH.digest; without, nothing is pushed: the dry run.
set -euo pipefail

dir="$(cd "$1" && pwd)"
arch="$2"
version="$3"
image="${4:-}"
ci="$(cd "$(dirname "$0")" && pwd)"

case "$arch/$(uname -m)" in
  amd64/x86_64 | arm64/aarch64) ;;
  *) echo "release-image.sh: $arch is built on its own architecture, not on $(uname -m)" >&2; exit 1 ;;
esac
[[ -x "$dir/target/release/gateway" ]] || { echo "release-image.sh: no $dir/target/release/gateway: run the gates first" >&2; exit 1; }

# The web console's tacplus.yaml makes webapp/ a project of its own to tacplus, which runs only the release a
# lock pins: the repository's.
cp "$dir/tacplus.lock" "$dir/webapp/tacplus.lock"
"$ci/build-image.sh" "$dir" bash -c 'cd webapp && tacplus build && npm ci && npm run build && rm -rf ../webapp-dist && cp -R dist ../webapp-dist'
"$ci/build-image.sh" "$dir" bash -c "cd target/launcher-src && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -buildvcs=false -trimpath -ldflags='-s -w' -o ../launcher/launcher-linux-$arch ."

ctx="$dir/target/image/$arch"
rm -rf "$ctx"
mkdir -p "$ctx/target/release" "$ctx/web-dist" "$ctx/clients"
cp "$dir/Dockerfile" "$ctx/"
cp "$dir/target/release/gateway" "$ctx/target/release/gateway"
cp -R "$dir/webapp-dist" "$ctx/webapp-dist"
cp "$dir/target/launcher/launcher-linux-$arch" "$ctx/"

revision="$(git -C "$dir" rev-parse HEAD)"
created="$(TZ=UTC git -C "$dir" show -s --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ HEAD)"
output="type=cacheonly"
[[ -n "$image" ]] && output="type=image,name=$image,push-by-digest=true,name-canonical=true,push=true"
docker buildx build --platform "linux/$arch" \
  --build-arg "VERSION=$version" --build-arg "VCS_REF=$revision" --build-arg "BUILD_DATE=$created" \
  --label "org.opencontainers.image.source=https://github.com/tacplus-dev/gateway" \
  --output "$output" --metadata-file "$ctx.json" "$ctx"
if [[ -n "$image" ]]; then
  digest="$(jq -r '."containerimage.digest"' "$ctx.json")"
  echo "linux/$arch: $image@$digest"
  echo "$image@$digest" > "$dir/target/image/$arch.digest"
fi
