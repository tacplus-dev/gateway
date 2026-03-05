webapp_dir := "../webapp"
dist_dir := webapp_dir / "dist"
webapp_repo := "git@gitlab.com:secondstarcavalier/controlplane/services/webapp.git"

build:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ ! -d "{{webapp_dir}}" ]; then
    echo "Cloning webapp..."
    git clone {{webapp_repo}} {{webapp_dir}}
  fi
  if [ ! -d "{{dist_dir}}" ]; then
    echo "Building webapp..."
    cd {{webapp_dir}} && just
  fi
  rm -rf dist
  cp -r {{dist_dir}} dist
  tacplus build
  go build -ldflags="-s -w" ./...
  docker build --secret id=netrc,src=$HOME/.netrc -t $(basename $PWD) .
