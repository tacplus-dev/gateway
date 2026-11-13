# Gateway

Gateway is the edge proxy for the Schematic control plane. All external traffic
enters the cluster through gateway, which routes REST and gRPC requests to
backend services, serves OIDC discovery and JWKS endpoints, handles token
minting delegation to kernel, and provides SPIFFE-based workload routing.

## Architecture

```
                          ┌──────────────────────────────────────────┐
                          │               gateway                    │
                          │                                          │
  clients ──► HTTPS ──►   │  axum server (HTTP/1.1 + HTTP/2 + H3)   │
                          │    ├── REST handler (/{pkg}/{Svc}/{Rpc}) │
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

**REST**: Requests to `/{package}/{Service}/{Method}` are matched against the
proto-generated `ROUTES` table; each generated path is registered as an exact
route at the origin root. The handler deserializes JSON, dispatches via
gRPC to the backend service, and returns JSON. Server-streaming RPCs are
supported via `dispatch_stream`.

**gRPC proxy**: Requests with `content-type: application/grpc` are forwarded
as raw HTTP/2 frames without deserializing the protobuf body. The target
service is extracted from the gRPC method path (`/package.Service/Method`).

**SPIFFE path routing**: For paths not in the ROUTES table, gateway strips the
leading `/` and uses the remaining path as a SPIFFE service path for endpoint
resolution. Exact match only — no hierarchical fallback. Paths that match no
SPIFFE service either serve the SPA (`GET`/`HEAD`) or return a JSON 404.

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
just gates  # generate (checks it writes only target/), build (debug and release), test
just clean  # remove build artifacts
```

## Releasing

Releases are tags `vMAJOR.MINOR.PATCH` on main (on a `release/MAJOR.MINOR` branch for a patch to an older
line). The project stays on `0.x` until SeaBeam's launch; on `0.x` a minor may break and a patch never does.
A fix merged to main is released as a patch, a feature as a minor. Fleets pin the release line
`MAJOR.MINOR` (tacplus-dev/tacplus#180).

To cut a release, push an annotated tag on a green commit:

```bash
git tag -a v0.1.2 -m "gateway 0.1.2: <what changed>" <commit>
git push origin v0.1.2
```

The tag starts `.github/workflows/release.yml`, which:

1. runs `just gates` on the tag, in the build image `tacplus.lock` pins (`ci/build-image.sh`);
2. builds the image from the `Dockerfile` (`ci/release-image.sh`): the gates' release binary, the web
   console (`webapp/`, generated from the registry's contracts), the launcher, and empty `web-dist/` and
   `clients/`. A customer app and client binaries belong to a fleet, not to this image;
3. pushes `ghcr.io/tacplus-dev/gateway:X.Y.Z`, and moves the line tag `X.Y` only when this is the line's
   highest release (`ci/release-tags.sh`), so a line never moves backwards and a patch never moves another
   line. The image is built for linux/arm64. amd64 is off, as it is in the fleets: set `PLATFORMS` in the
   workflow to `arm64 amd64` to build both;
4. creates the GitHub release, with the commits since the previous release as its notes
   (`ci/release-notes.sh`). The release is marked Latest only when it is the highest release
   (`ci/release-latest.sh`).

A tag pushed without the workflow (v0.1.0, say) is built by running the workflow by hand on `main`:
`gh workflow run release.yml -f version=v0.1.0 -f publish=true`. Without `publish` it is a dry run: it runs
the gates and builds the image, prints the tags and notes the release would get, and publishes nothing. Neither
mode makes or moves a tag. A tag that predates `tacplus.lock` builds with main's lock. The rules are tested
by `tests/release.rs`.

## Proto

[`services/gateway.proto`](../../proto/services/gateway.proto)
