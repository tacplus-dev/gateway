# Local development builds only — not used in CI/CD.

registry := "registry.gitlab.com/secondstarcavalier/controlplane/services/gateway"

default: binary container

binary:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ -d "../proto" ]; then
    tacplus build --src ../proto
  else
    tacplus build
  fi
  cargo build --release

container: binary
  #!/usr/bin/env bash
  set -euo pipefail
  tag=$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')
  major=$(echo "$tag" | cut -d. -f1)
  minor=$(echo "$tag" | cut -d. -f2)
  image="{{registry}}/gateway-${major}-${minor}:latest"
  docker build -t "$image" .
  echo "Built: $image"
