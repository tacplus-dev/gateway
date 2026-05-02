# Gateway Release Image
# Layers the pre-built gateway binary onto a minimal runtime image.

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

ARG GRPC_HEALTH_PROBE_VERSION=0.4.48
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    curl -fsSL -o /usr/local/bin/grpc_health_probe \
      "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/v${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-${TARGETARCH}" && \
    chmod +x /usr/local/bin/grpc_health_probe && \
    apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
COPY target/release/gateway /usr/local/bin/gateway
RUN chmod +x /usr/local/bin/gateway

ENTRYPOINT ["gateway"]
