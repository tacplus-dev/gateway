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

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/*
COPY target/release/gateway /usr/local/bin/gateway
RUN chmod +x /usr/local/bin/gateway

ENTRYPOINT ["gateway"]
