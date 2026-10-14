# Local development builds only — not used in CI/CD.

TACPLUS := env_var_or_default("TACPLUS_BIN", "tacplus")

default: generate

generate:
  #!/usr/bin/env bash
  set -euo pipefail
  {{TACPLUS}} build --tag latest

verify:
  {{TACPLUS}} verify

clean:
  rm -rf target

# Stage a built customer web app (its vite dist/) as web-dist/, which the image
# serves from /opt/schematic/web, e.g. `just stage-web ../../../../sonar/clients/web/dist`.
stage-web dist:
  #!/usr/bin/env bash
  set -euo pipefail
  test -f "{{dist}}/index.html" || { echo "{{dist}}/index.html not found — build the web app first" >&2; exit 1; }
  rm -rf web-dist
  mkdir -p web-dist
  cp -R "{{dist}}/." web-dist/
