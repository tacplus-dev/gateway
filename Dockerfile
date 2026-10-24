# Gateway Release Image
# Layers the pre-built gateway binary onto a minimal runtime image.
# Webapp and schematic clients are installed from disk (not embedded in the binary).

FROM debian:trixie-slim

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Seabeam LLC <cloudctlplane@seabeam.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Seabeam LLC" \
      org.opencontainers.image.title="Gateway" \
      org.opencontainers.image.description="API gateway for Schematic control plane services"

COPY --from=ghcr.io/grpc-ecosystem/grpc-health-probe:v0.4.48 /ko-app/grpc-health-probe /usr/local/bin/grpc_health_probe
RUN chmod +x /usr/local/bin/grpc_health_probe
COPY target/release/gateway /usr/local/bin/gateway
RUN chmod +x /usr/local/bin/gateway

# Webapp served from disk via WEB_ROOT (not embedded in the binary).
COPY webapp-dist/ /opt/schematic/webapp/
ENV WEB_ROOT=/opt/schematic/webapp

# Customer web app, served on the hostnames gateway Config.web_bundles maps to
# /opt/schematic/web. Any other hostname keeps getting the webapp above.
COPY web-dist/ /opt/schematic/web/

# Schematic client binaries for authenticated download via /client/:os/:arch
COPY clients/ /opt/schematic/clients/

# Every service runs under the launcher (github.com/tacplus-dev/launcher): PID 1
# that forwards signals, propagates the exit code, and kills a deadlocked child
# on gRPC health. The fleet's image pipeline puts the binary beside the Dockerfile.
ARG TARGETARCH
COPY launcher-linux-${TARGETARCH} /usr/local/bin/launcher
ENV LAUNCH_CMD="gateway" HEALTH_PORT=8443
ENTRYPOINT ["launcher"]
