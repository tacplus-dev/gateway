FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S gateway && adduser -S gateway -G gateway

WORKDIR /app

ARG TARGETARCH
COPY bin/gateway-${TARGETARCH} /app/gateway
COPY dist/ /app/dist/

USER gateway

ENTRYPOINT ["/app/gateway"]
