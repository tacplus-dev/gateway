# Gateway Release Image
# Layers the pre-built gateway binary onto a minimal runtime image.
# Webapp and cavalier clients are installed from disk (not embedded in the binary).

FROM debian:trixie-slim

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="Second Star Cavalier LLC <cloudctlplane@secondstarcavalier.com>" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="Second Star Cavalier LLC" \
      org.opencontainers.image.title="Gateway" \
      org.opencontainers.image.description="API gateway for Cavalier control plane services"

COPY --from=ghcr.io/grpc-ecosystem/grpc-health-probe:v0.4.48 /ko-app/grpc-health-probe /usr/local/bin/grpc_health_probe
RUN chmod +x /usr/local/bin/grpc_health_probe
COPY target/release/gateway /usr/local/bin/gateway
RUN chmod +x /usr/local/bin/gateway

# Webapp served from disk via WEB_ROOT (not embedded in the binary).
COPY webapp-dist/ /opt/cavalier/webapp/
ENV WEB_ROOT=/opt/cavalier/webapp

# Cavalier client binaries for authenticated download via /api/v1/client/:os/:arch
COPY clients/ /opt/cavalier/clients/

ENTRYPOINT ["gateway"]
