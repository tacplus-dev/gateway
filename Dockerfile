# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

ENV GOPRIVATE=gitlab.com/secondstarcavalier/*

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=secret,id=netrc,dst=/root/.netrc go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /gateway .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S gateway && adduser -S gateway -G gateway

WORKDIR /app

COPY --from=builder /gateway /app/gateway

USER gateway

ENTRYPOINT ["/app/gateway"]
