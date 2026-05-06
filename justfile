# Local development builds only — not used in CI/CD.

mount_flag := if path_exists("../../utils") == "true" { "--mount ../../utils:/utils" } else { "" }

proto-sync:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ -L proto ]; then
    : # symlink — user-managed, skip sync
  elif [ -d proto ]; then
    git -C proto fetch --quiet
    git -C proto reset --hard --quiet origin/HEAD
  else
    git clone --quiet https://gitlab.com/secondstarcavalier/schematic/platform/cavalier.git proto
  fi

default: proto-sync
  tacplus build --src proto {{mount_flag}}

verify:
  tacplus verify

clean:
  rm -rf target
