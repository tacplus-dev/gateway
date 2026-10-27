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
# failure), then build and test the gateway and webapp-login.
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
  cargo test --locked
  cd webapp-login && npm ci && npm test

clean:
  rm -rf target

# Stage a built customer web app (its vite dist/) as web-dist/, which the image
# serves from /opt/schematic/web, e.g. `just stage-web ../web/dist`.
stage-web dist:
  #!/usr/bin/env bash
  set -euo pipefail
  test -f "{{dist}}/index.html" || { echo "{{dist}}/index.html not found — build the web app first" >&2; exit 1; }
  rm -rf web-dist
  mkdir -p web-dist
  cp -R "{{dist}}/." web-dist/

# The gateway's own web console (webapp/, a tacplus TypeScript client) into
# webapp-dist/, which the image serves from /opt/schematic/webapp. FLEET_PROTO
# is the fleet's merged tree the model generates against.
webapp fleet_proto:
  cd webapp && tacplus build --src "{{fleet_proto}}" && npm ci && npm run build
  rm -rf webapp-dist && cp -R webapp/dist webapp-dist
