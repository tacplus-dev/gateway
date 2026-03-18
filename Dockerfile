FROM rust:1.88-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/gateway /usr/bin/gateway
ENTRYPOINT ["gateway"]
