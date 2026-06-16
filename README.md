# Gateway

Gateway is the edge proxy for the Cavalier control plane. All external traffic
enters the cluster through gateway, which routes REST and gRPC requests to
backend services, serves OIDC discovery and JWKS endpoints, handles token
minting delegation to kernel, and provides SPIFFE-based workload routing.

## Architecture

```
                          ┌──────────────────────────────────────────┐
                          │               gateway                    │
                          │                                          │
  clients ──► HTTPS ──►   │  axum server (HTTP/1.1 + HTTP/2 + H3)   │
                          │    ├── REST handler (/api/v1/...)        │
                          │    │     ├── ROUTES table dispatch       │
                          │    │     ├── SPIFFE path routing         │
                          │    │     └── Mint (OIDC, JWKS, tokens)   │
                          │    ├── gRPC proxy (application/grpc)     │
                          │    │     ├── service_id lookup           │
                          │    │     └── SPIFFE fallback             │
                          │    └── SPA / static file serving         │
                          │                                          │
                          │  HealthWatcher (kernel WatchInstances)   │
                          │    ├── service_id → endpoints            │
                          │    └── spiffe_path → endpoints           │
                          │                                          │
                          │  Resolver (round-robin channel dial)     │
                          └──────────────────────────────────────────┘
```

Gateway watches `ServiceHealthState.instances` from kernel to maintain a live
map of healthy service endpoints. Incoming requests are routed by matching
the gRPC method path or REST path against the tacplus-generated `ROUTES` table.
Requests not in the table fall back to SPIFFE path routing.

## Routing

**REST**: Requests to `/api/v1/{service}/{Method}` are matched against the
proto-generated `ROUTES` table. The handler deserializes JSON, dispatches via
gRPC to the backend service, and returns JSON. Server-streaming RPCs are
supported via `dispatch_stream`.

**gRPC proxy**: Requests with `content-type: application/grpc` are forwarded
as raw HTTP/2 frames without deserializing the protobuf body. The target
service is extracted from the gRPC method path (`/package.Service/Method`).

**SPIFFE path routing**: For paths not in the ROUTES table, gateway strips the
REST prefix and uses the remaining path as a SPIFFE service path for endpoint
resolution. Exact match only — no hierarchical fallback.

## RPCs

### gateway.Mint

| RPC | Description |
|-----|-------------|
| `GetOpenIdConfig` | OIDC discovery document (served locally) |
| `ListJwks` | JSON Web Key Set (served locally from kernel-watched keys) |
| `TokenMint` | Proxied to kernel's MintService |
| `X509Mint` | Proxied to kernel's MintService |

## Configuration

| Field | Default | Description |
|-------|---------|-------------|
| `health_poll_interval_seconds` | 5 | Interval for health endpoint polling |
| `enable_http` | true | Enable HTTP/1.1 + HTTP/2 listener |
| `enable_http3` | true | Enable QUIC/HTTP3 listener |
| `enable_grpc` | true | Enable gRPC proxy |
| `tcp_listener` | 0.0.0.0:8443 | TCP bind address |
| `quic_listener` | 0.0.0.0:8443 | QUIC bind address |

## Key Files

- `src/main.rs` — Server startup, TLS config, axum router assembly
- `src/rest.rs` — REST-to-gRPC dispatch handler and auth middleware
- `src/grpc_proxy.rs` — Raw gRPC byte-level proxy
- `src/health.rs` — HealthWatcher (kernel WatchInstances stream consumer)
- `src/resolver.rs` — Service endpoint resolution and channel dialing
- `src/spa.rs` — Single-page application static file serving
- `src/registry.rs` — Registry.json serving

## Build

```bash
just        # generate + compile
just clean  # remove build artifacts
```

## Proto

[`services/gateway.proto`](../../proto/services/gateway.proto)
