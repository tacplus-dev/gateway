# Gateway Release Image
# Layers the pre-built gateway binary onto a minimal runtime image.
# The webapp, the fleet's contributed modules and the clients are installed
# from disk (not embedded in the binary).
#
# Reproducible: every input is pinned (base images by digest, never a tag;
# Debian's updates by a dated snapshot), the upgrade drops what would date it,
# and adding the 65532 user dates what it writes by SOURCE_DATE_EPOCH (shadow's
# useradd reads it for /etc/shadow's last change), so the image's digest
# depends only on its inputs. Build it with a fixed SOURCE_DATE_EPOCH and rewritten timestamps,
# as the fleet's `tacplus fleet gateway` does (and its --check, twice, comparing
# digests; `just image`):
#
#   docker buildx build --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
#     --output type=image,name=<name>,rewrite-timestamp=true .

FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0

# The image's creation time and every file's mtime (with rewrite-timestamp=true).
ARG SOURCE_DATE_EPOCH
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.authors="Jody Scott <jody@thescottsweb.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="tacplus.dev" \
      org.opencontainers.image.title="Gateway" \
      org.opencontainers.image.description="The edge gateway of a tacplus fleet"

# The base tag lags Debian's fixes by weeks (13.7's, built 2026-11-04, ships
# zlib1g 1+b1, CVE-2026-85091, and libc6 2.41-12+deb13u4): upgrade it from
# trixie, trixie-updates and trixie-security as snapshot.debian.org dated them,
# so every build installs the same packages (13.8's), fail the build below the
# fixed versions (#38), and drop what apt and dpkg write that would date the
# image (lists, caches, logs). Move the digest once the tag carries them.
RUN printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/%s/20261122T120000Z/ %s main\n' \
      debian trixie debian trixie-updates debian-security trixie-security > /tmp/snapshot.list \
 && apt="apt-get -qq -o Dir::Etc::SourceList=/tmp/snapshot.list -o Dir::Etc::SourceParts=/nonexistent -o Acquire::Retries=3" \
 && $apt update \
 && DEBIAN_FRONTEND=noninteractive $apt upgrade -y --no-install-recommends \
 && for floor in zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1 libc6=2.41-12+deb13u5; do \
      have="$(dpkg-query -W -f='${Version}' "${floor%%=*}")"; \
      dpkg --compare-versions "$have" ge "${floor#*=}" \
        || { echo "${floor%%=*} $have is older than ${floor#*=} (#38)" >&2; exit 1; }; \
    done \
 && $apt clean \
 && rm -rf /tmp/snapshot.list /var/lib/apt/lists/* /var/cache/apt/*.bin /var/log/apt/* /var/log/dpkg.log \
      /var/log/alternatives.log /var/cache/ldconfig/aux-cache /var/cache/debconf/*-old /var/lib/dpkg/*-old

COPY --from=ghcr.io/grpc-ecosystem/grpc-health-probe:v0.4.63@sha256:1d6cc5716f1c80cbcf97d5bc7eef3cd5bd4c7a7b942c0dc4f533dea70dcb5173 \
     --chmod=0755 /ko-app/grpc-health-probe /usr/local/bin/grpc_health_probe
COPY --chmod=0755 target/release/gateway /usr/local/bin/gateway

# The fleet's merged webapp, served from disk via WEB_ROOT (not embedded in the
# binary): the gateway's own at its root, each contributed module under
# -/apps/<service>/ and their index at -/apps.json (#21).
COPY webapp-dist/ /opt/tacplus/webapp/
ENV WEB_ROOT=/opt/tacplus/webapp

# Customer web app, served on the hostnames gateway Config.web_bundles maps to
# /opt/tacplus/web. Any other hostname keeps getting the webapp above.
COPY web-dist/ /opt/tacplus/web/

# Client binaries for authenticated download: the gateway's own via
# /client/:os/:arch (gateway-<os>-<arch>[.exe]), each contributed one via
# /-/clients/<service>/<client>/<os>/<arch> (<service>/<client>/<client>-<os>-<arch>[.exe]).
COPY clients/ /opt/tacplus/clients/

# Every service runs under the launcher (github.com/tacplus-dev/launcher): PID 1
# that forwards signals, propagates the exit code, and kills a deadlocked child
# on gRPC health. The fleet's image pipeline puts the binary beside the Dockerfile.
ARG TARGETARCH
COPY --chmod=0755 launcher-linux-${TARGETARCH} /usr/local/bin/launcher
ENV LAUNCH_CMD="gateway" HEALTH_PORT=8443
# The gateway needs no root: it binds 8443 and 8080 and only reads from disk.
# It runs as a fixed UID/GID, not a useradd default, so the operator's
# securityContext (runAsUser/runAsGroup 65532) can name it (#29).
RUN groupadd --system --gid 65532 gateway \
 && useradd --system --no-create-home --uid 65532 --gid 65532 --home-dir /nonexistent --shell /usr/sbin/nologin gateway

USER 65532:65532
ENTRYPOINT ["launcher"]
