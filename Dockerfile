# Gateway Release Image
# Layers the pre-built gateway binary onto a minimal runtime image.
# The webapp, the fleet's contributed modules and the clients are installed
# from disk (not embedded in the binary).
#
# Reproducible: every input is pinned (base images by digest, never a tag) and
# nothing here runs a command, so the image's digest depends only on the files
# it copies. Build it with a fixed SOURCE_DATE_EPOCH and rewritten timestamps,
# as the fleet's `tacplus fleet gateway` does (and its --check, twice, comparing
# digests; `just image`):
#
#   docker buildx build --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
#     --output type=image,name=<name>,rewrite-timestamp=true .

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

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

COPY --from=ghcr.io/grpc-ecosystem/grpc-health-probe:v0.4.60@sha256:2d433b978644e40eb2b2887dbd0af3a19e470514a2176a97cad1971f13bdb171 \
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
ENTRYPOINT ["launcher"]
