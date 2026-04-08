# Gateway Architecture

This document defines the target architecture for the Cavalier gateway. It supersedes the current implementation described in `README.md`.

## Design Principles

1. **Every message is validated and authenticated.** The gateway deserializes every protobuf message (unary and streaming) into its typed form, runs validation, and checks auth. Corrupted types are rejected at the edge. Expired tokens are rejected immediately.
2. **No redundant auth layers.** Auth and validation happen in exactly one place: `proxy_grpc`. The REST translation layer does zero auth — it converts the format and hands off to `proxy_grpc`.
3. **No redundant serialization.** After validation, the gateway forwards the original bytes held in the receive buffer. It does not re-serialize the validated message.
4. **Two logical services, one process.** `proxy_grpc` and `rest_translation` are conceptually separate services co-located in one binary to avoid an extra network hop.

## Logical Layers

```
  REST clients ────┐
                   ├────► gateway :8443 (TLS, HTTP/2 + HTTP/1.1)
  gRPC clients ────┘
                          │
                          ▼
         ┌────────────────────────────────────────────────────────────┐
         │                        axum router                         │
         │                                                            │
         │   content-type: application/grpc ────────────► proxy_grpc  │
         │   /gateway.Mint/* ───────────────► tonic (native Mint)     │
         │   /api/v1/* ─────────────────────► rest_translation        │
         │   /* ────────────────────────────► SPA                     │
         │                                                            │
         └──────────────┬───────────────────────────┬─────────────────┘
                        │                           │
                        ▼                           ▼
  ┌──────────────────────────────┐   ┌──────────────────────────────────┐
  │       rest_translation       │   │           proxy_grpc             │
  │                              │   │                                  │
  │   match route                │   │   extract gRPC frame             │
  │   JSON → proto (*_from_json) │   │   deserialize (*_from_bytes)     │
  │   frame as gRPC              ├──►│   validate type                  │
  │                              │   │   authenticate (every message)   │
  │   (no auth)                  │   │   extract trace_id               │
  │   (no validation)            │   │   forward original bytes ────────┼──► backend
  │                              │   │                                  │   services
  │   response:                  │   │   response:                      │
  │   proto → JSON (*_to_json)   │◄──┤   return response proto bytes    │◄── backend
  │   return to REST client      │   │                                  │   services
  │                              │   │                                  │
  └──────────────────────────────┘   └──────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────┐
  │                          infrastructure                              │
  │                                                                      │
  │   HealthWatcher ──── Resolver ──── TLS ──── GatewayAuth              │
  │                                                                      │
  └──────────────────────────────────────────────────────────────────────┘
```

### proxy_grpc

Handles all gRPC traffic, both from native gRPC clients and from `rest_translation`.

**Per-message processing (unary and streaming):**

1. **Extract gRPC frame** — Read the 5-byte gRPC header (1 byte compressed flag + 4 bytes big-endian message length), then read the protobuf payload bytes.
2. **Deserialize into typed message** — Using the tacplus-generated `*_from_bytes()` function for the RPC's request type (looked up from the ROUTES table via the gRPC method path).
3. **Validate** — Run proto validation on the typed message. Reject with `INVALID_ARGUMENT` if validation fails.
4. **Authenticate** — Extract the bearer token from the initial HEADERS `authorization` metadata. On every message, check:
   - Token signature (via JWK cache)
   - Token expiry (`exp` claim)
   - Audience matches target service
   - Entitlements (for `Entitled` policy routes)

   If the token has expired, return `UNAUTHENTICATED` and close the stream. The client must reconnect with a fresh token. This is the standard gRPC behavior — auth metadata is sent once in the initial HEADERS frame and cannot be updated mid-stream.
5. **Extract trace_id** — If proto field 200 (`trace_id`) is non-empty, publish a `TraceEvent` for the gateway hop.
6. **Forward original bytes** — Write the original gRPC frame bytes (not re-serialized) to the resolved backend channel. The deserialized message from step 2 is discarded after validation.

**Streaming RPCs:**

For server-streaming and bidirectional-streaming RPCs, steps 1-6 are applied to **each message frame** as it arrives. The gateway does not buffer the entire stream — it processes frames one at a time as they are received from the client.

On the response path, frames from the backend are forwarded to the client without deserialization (the gateway trusts backend services).

**Service resolution:**

The target service is identified from the gRPC method path (e.g., `/sentinel.Dashboard/GetDashboard` -> service_id `sentinel`). The Resolver provides a tonic Channel to a healthy instance via round-robin selection from the HealthWatcher's endpoint map. SPIFFE path routing is used as a fallback when the service_id has no direct matches.

### rest_translation

Converts REST HTTP requests into gRPC messages, then delegates to `proxy_grpc`.

**Processing:**

**Request path:**

1. **Match route** — Look up the REST path in the tacplus-generated ROUTES table to find the corresponding gRPC method path and request type.
2. **Read HTTP body** — Buffer the JSON request body (or `{}` for GET requests).
3. **Convert JSON to proto** — Using the tacplus-generated `*_from_json()` function for the RPC's request type.
4. **Frame as gRPC** — Wrap the serialized proto bytes in a gRPC frame (5-byte header + payload).
5. **Delegate to proxy_grpc** — Pass the gRPC-framed request to `proxy_grpc` for validation, auth, and forwarding. The `authorization` header from the REST request is passed through as gRPC metadata.

**Response path:**

6. **Receive response bytes** — `proxy_grpc` returns the response protobuf message bytes from the backend.
7. **Convert proto to JSON** — Using the tacplus-generated `*_to_json()` function for the RPC's response type. No hand-written JSON — always use the generated typed helpers.
8. **Return JSON** — Send the JSON response to the REST client.

**No auth at this layer.** The REST layer does not validate tokens, check entitlements, or verify message types. All of that happens in `proxy_grpc`. This eliminates duplicated auth logic and ensures a single code path for all security enforcement.

**Server-streaming REST (SSE):** For server-streaming RPCs accessed via REST, `rest_translation` returns a Server-Sent Events (SSE) stream. Each response frame from `proxy_grpc` is converted to JSON using the generated `*_to_json()` helper and sent as an SSE `data:` event. This is how the current `rest_dispatch::dispatch_stream()` works — it must be preserved in the new architecture.

> **TODO:** Implement SSE streaming in `rest_translation` for server-streaming RPCs. The current `rest_dispatch::dispatch_stream()` already does this (axum SSE with `Event::default().data(json)`) — the new implementation must follow the same pattern but route through `proxy_grpc` instead of making a direct client call.

**Bidirectional-streaming REST (WebSocket):** For bidi-streaming RPCs accessed via REST, `rest_translation` upgrades the HTTP connection to a WebSocket. Each client message is JSON, converted to proto via `*_from_json()`, framed as gRPC, and sent through `proxy_grpc`. Each response frame from `proxy_grpc` is converted back to JSON via `*_to_json()` and sent as a WebSocket text message.

> **TODO:** Implement WebSocket transport in `rest_translation` for bidirectional-streaming RPCs (e.g., Session, WatchTrace). This enables REST clients (browsers, curl) to use bidi RPCs that are currently only accessible via native gRPC.

### Mint (gateway-native service)

The `gateway.Mint` service remains a native tonic service, not proxied. It handles:

- `OpenIdConfig` — OIDC discovery (served locally)
- `Jwks` — JWK set (served locally from kernel-watched keys)
- `TokenMint` — Proxied to kernel's MintService
- `X509Mint` — Proxied to kernel's MintService

Mint is routed before `proxy_grpc` in the axum layer stack (tonic routes take priority).

## Auth Model

### Token Lifecycle on Streams

gRPC sends auth metadata in the initial HEADERS frame only. There is no mechanism to refresh credentials mid-stream. The gateway handles this as follows:

- The bearer token from the initial HEADERS is cached for the lifetime of the stream.
- On **every message frame**, the gateway re-checks the token's `exp` claim against the current time.
- When the token expires, the gateway closes the stream with `UNAUTHENTICATED` (gRPC status code 16).
- The client obtains a fresh token and reconnects. This is standard gRPC client behavior — `CallCredentials` / per-RPC credentials handle this automatically.

### Auth Policies

Auth policy is determined per-RPC from the tacplus-generated ROUTES table:

| Policy | Behavior |
|--------|----------|
| `NoAuth` | No token required. Message is still validated. |
| `AnyUser` | Token must be valid, not expired, audience matches target service, not a refresh token. |
| `Entitled` | `AnyUser` + entitlement check against the target service's profile cache. |

For routes not in the ROUTES table, the default policy is `Entitled` (most restrictive).

### Auth Target

The gateway checks `aud` (audience) against the **target service**, not "gateway". A token scoped to `sentinel` is valid for `/sentinel.Dashboard/GetDashboard` but not for `/eventbus.Trace/WatchTrace`. This is correct because the gateway is a transparent proxy — the client's intent is to call the backend service.

## Trace Pipeline

Every message flowing through `proxy_grpc` is checked for `trace_id` (proto field 200). When present:

1. Gateway publishes a `TraceEvent` with the `trace_id`, current `TraceRound`, and gRPC method path.
2. The trace publisher sends events to EventBus via a direct bidi stream (`PublishTraceEventBusTraceEvents`).
3. EventBus dispatches to Kafka, which feeds `WatchTrace` subscribers.

This works for both unary and streaming RPCs because `proxy_grpc` inspects every message frame.

## Request Flow

### gRPC Client -> Backend Service

```
1. Client sends HTTP/2 request with content-type: application/grpc
2. axum detects gRPC content-type via middleware
3. Mint routes checked first (tonic router)
4. Non-Mint gRPC -> proxy_grpc
5. proxy_grpc: extract frame -> deserialize -> validate -> auth -> trace -> forward bytes
6. Backend response frames forwarded to client (no deserialization)
```

### REST Client -> Backend Service

```
1. Client sends HTTP/1.1 or HTTP/2 request to /api/v1/{service}/{Method}
2. rest_translation: match route -> read JSON body -> *_from_json() -> frame as gRPC
3. Delegate to proxy_grpc (same path as native gRPC)
4. proxy_grpc: extract frame -> deserialize -> validate -> auth -> trace -> forward bytes
5. proxy_grpc returns response proto bytes
6. rest_translation: *_to_json() -> return JSON to REST client
```

## Infrastructure

### HealthWatcher

Watches `ServiceHealthState.instances` from kernel via a streaming RPC. Maintains two in-memory indexes:

- `service_id -> [endpoints]` — for proto-defined service routing
- `spiffe_path -> [endpoints]` — for workload identity routing

### Resolver

Provides tonic `Channel` objects to healthy backends. Uses round-robin selection across healthy endpoints. All backend connections use mTLS with cluster CAs (bootstrap + dynamic from kernel CaState).

### TLS

- **Frontend**: Publicly-signed cert from kernel's `GatewayTlsState`, hot-reloaded on change.
- **Backend**: mTLS using bootstrap CAs + dynamic CAs from kernel's `CaState`. All service certs have `SAN DNS:kernel` (from X509Mint).

## File Map (Target)

| File | Responsibility |
|------|---------------|
| `src/main.rs` | Server startup, TLS, router assembly |
| `src/proxy_grpc.rs` | gRPC proxy: frame extraction, typed deserialization, validation, auth, forwarding |
| `src/rest_translation.rs` | REST-to-gRPC conversion, delegates to proxy_grpc |
| `src/auth.rs` | Token verification, entitlement checks (used by proxy_grpc) |
| `src/health.rs` | HealthWatcher (kernel WatchInstances stream) |
| `src/resolver.rs` | Service endpoint resolution, channel dialing |
| `src/mint.rs` | gateway.Mint native tonic service |
| `src/spa.rs` | SPA static file serving |
| `src/registry.rs` | Registry.json serving |
| `src/tls.rs` | TLS config building |

## Changes from Current Implementation

| Current | Target |
|---------|--------|
| `grpc_proxy.rs` forwards raw bytes without deserialization | `proxy_grpc.rs` deserializes every frame for validation and auth |
| REST handler (`rest.rs`) has its own auth middleware | `rest_translation.rs` does no auth — delegates entirely to proxy_grpc |
| Streaming RPCs skip body processing | Streaming RPCs are processed frame-by-frame |
| `to_bytes()` buffers entire body for unary RPCs | Frame-by-frame extraction (works for both unary and streaming) |
| Auth checked once per request | Auth checked on every message frame (catches token expiry) |
| Trace extraction only for non-streaming unary RPCs | Trace extraction on every message frame |
| Duplicate auth code in rest.rs and grpc_proxy.rs | Single auth path in proxy_grpc |
