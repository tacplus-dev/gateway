# Local development builds only — not used in CI/CD.

TACPLUS := env_var_or_default("TACPLUS_BIN", "tacplus")

default: generate

generate:
  #!/usr/bin/env bash
  set -euo pipefail
  {{TACPLUS}} build --tag latest

verify:
  {{TACPLUS}} verify

# What every change must pass: regenerate with the floor's compiler (generated
# code lives only in target/, so generation touching any file git sees is a
# failure), then build and test the gateway and webapp-login. The release
# build is the binary the image ships (target/release/gateway), and the only
# build that trips main.rs's compile_error! should dev-bypass ever be on.
gates:
  #!/usr/bin/env bash
  set -euo pipefail
  before="$(git status --porcelain)"
  {{TACPLUS}} build --tag latest
  if [[ "$(git status --porcelain)" != "$before" ]]; then
    echo "gates: generation changed files outside target/:" >&2
    git status --porcelain >&2
    exit 1
  fi
  cargo build --locked --all-targets
  cargo build --locked --release
  cargo test --locked
  cd webapp-login && npm ci && npm test

clean:
  rm -rf target

# Stage a built customer web app (its vite dist/) as web-dist/, which the image
# serves from /opt/tacplus/web, e.g. `just stage-web ../web/dist`.
stage-web dist:
  #!/usr/bin/env bash
  set -euo pipefail
  test -f "{{dist}}/index.html" || { echo "{{dist}}/index.html not found — build the web app first" >&2; exit 1; }
  rm -rf web-dist
  mkdir -p web-dist
  cp -R "{{dist}}/." web-dist/

# The gateway's own web console (webapp/, a tacplus TypeScript client) into
# webapp-dist/, which the image serves from /opt/tacplus/webapp. FLEET_PROTO
# is the fleet's merged tree the model generates against.
webapp fleet_proto:
  cd webapp && tacplus build --src "{{fleet_proto}}" && npm ci && npm run build
  rm -rf webapp-dist && cp -R webapp/dist webapp-dist

# The release image, as the fleet builder builds it (see Dockerfile): twice,
# from scratch, at the last commit's SOURCE_DATE_EPOCH with rewritten
# timestamps, failing unless both digests are the same. Needs the Dockerfile's
# inputs beside it (target/release/gateway, webapp-dist/, web-dist/, clients/,
# launcher-linux-<arch>).
image:
  #!/usr/bin/env bash
  set -euo pipefail
  export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
  out="$(mktemp -d)"
  for i in 1 2; do
    docker buildx build --no-cache --build-arg SOURCE_DATE_EPOCH \
      --output "type=oci,dest=$out/image-$i.tar,rewrite-timestamp=true" \
      --metadata-file "$out/meta-$i.json" .
  done
  a="$(jq -r '."containerimage.digest"' "$out/meta-1.json")"
  b="$(jq -r '."containerimage.digest"' "$out/meta-2.json")"
  [[ "$a" == "$b" ]] || { echo "image: not reproducible: $a vs $b" >&2; exit 1; }
  echo "image: $a ($out/image-1.tar)"
