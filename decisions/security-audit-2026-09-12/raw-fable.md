Audit complete. Findings below, ranked by severity. Everything listed was traced through the code and, where it depended on generated code, confirmed against `target/generated-sources` (REST root is `/api/v1`, the JSON dispatcher rejects unknown paths, and eight client-streaming routes exist, seven of them `Entitled`).

## High

1. **WebSocket path forwards a token the gateway never verified.** `src/rest_translation.rs:717` only checks that an authorization string is *present*. That string comes from the `start` frame or the HTTP header, neither of which is validated on this path because the upgrade at `:207` runs before `authorize_then_read_body`, and `handle_prevalidated_stream` (`src/proxy_grpc.rs:384`) skips the header-time check. Per-frame validation at `:996` uses each frame's own `authorization` field, so the token that passes entitlement checks is not the token sent to the backend at `:733`. Scenario: an unauthenticated caller opens a WS on any client-streaming route, sends `{"type":"start","authorization":"x"}`, and the gateway dials the backend and opens a gRPC stream carrying `authorization: x`. With zero data frames nothing is ever verified. The backend's own interceptor is the only remaining defense, which contradicts the invariant the tests at `:1331` and `src/proxy_grpc.rs:730` exist to protect.

2. **Path traversal in disk-served SPA mode.** `src/spa.rs:74-76` does `root.join(path)` on the raw request path with no `..` rejection or canonicalization. With `WEB_ROOT` set, `GET /../../etc/passwd` (sent with a client that does not normalize, or over HTTP/2 where `:path` is arbitrary) reads any file the process can read. The env var is honored in release builds, so this is one misconfigured container away from live.

3. **Panic on attacker-controlled input in the gRPC error path.** `src/proxy_grpc.rs:638-644` builds `grpc-message` from the error text and `.unwrap()`s the builder. Error text includes the unverified `kid` (`src/auth.rs:368`) and the parser's own message (`:354`). A JWT whose header is `{"kid":"a\nb"}` parses fine (serde_json, `token.rs:149`), fails lookup, and the newline makes the header value invalid, so the builder errors and the unwrap panics. That kills the connection task and every in-flight HTTP/2 stream on it. tonic percent-encodes this header for exactly this reason; the hand-rolled version does not.

## Medium

4. **Registry endpoint always returns 404.** `src/spa.rs:145` strips `"/registry/"` but the path is `/api/v1/registry/<file>`, so nothing is stripped and the match falls through to `NOT_FOUND`. `registry.json`, `registry.schema.json` and `AGENT.md` are unreachable.

5. **SPIFFE-path REST branch reads the body unauthenticated and can never succeed.** `src/rest_translation.rs:182` buffers up to the JSON limit before any token check, then `:186` calls `dispatch_via_proxy` with the *HTTP* path. The generated `request_json_to_proto` returns `unknown gRPC path` for anything not in its table (`proxy_dispatch/mod.rs:2385`), so the result is always 400. Dead code that also breaks the "no work before auth" rule.

6. **SPIFFE index is keyed on an obsolete ID shape, so the fallback routing is dead.** `src/health.rs:245-256` assumes `spiffe://<org>/<cluster>/<service>` and strips three segments. The chassis emits `spiffe://<td>/system/<loc>/services/<svc>` and `/tenants/<tenant>/services/<svc>` (`spiffe.rs:303`). Keys become `us-east/services/docmanager`, so `dial_spiffe(service_id)` at `src/proxy_grpc.rs:569` and the fallback in `src/resolver.rs:96` never match and always hit the `[::1]:1` placeholder.

7. **Backend trust store is never refreshed after CA rotation.** The SPIFFE verifier (`src/main.rs:194-196`) and the IDP connector (`:294`) are built once from the initial CA bundle. `spawn_ca_cert_watcher` (`:200`) only updates the store that `ListPublicCa` serves. If the kernel rotates its CA, every backend dial fails until the pod restarts. This is the same class of bug the long comment at `:158-170` describes for the external cert.

8. **IDP proxy: header injection and unbounded body.** `src/idp_proxy.rs:128-141` copies every client header, then *appends* `X-Forwarded-Host/Proto/Port`. A client-supplied `X-Forwarded-Host: evil` arrives first and Keycloak builds redirect and issuer URLs from it. `:91` collects the whole body with no cap, because the body limit layer sits inside the intercept (`src/main.rs:344-350`). The comment at `:16` says Keycloak was removed, but `registry.json` still names it, so treat this as live-if-deployed.

9. **A new TLS connection per proxied request.** `src/proxy_grpc.rs:566-573` calls `dial_ready_any` on every request. `src/resolver.rs:107-126` does a TCP probe (dropped immediately, producing resets on the backend) plus a full TLS handshake and a fresh HTTP/2 connection each time, with no channel cache. Probes are sequential with a 500 ms timeout each, so one stale health entry adds 500 ms to every request for that service.

10. **Lost-wakeup race in `wait_ready`.** `src/health.rs:59-62` checks the flag, then registers on `Notify`. If `process_entries` runs between those two steps, `notify_waiters` (`:224`) stores no permit and the waiter hangs until the 30 s timeout in `src/main.rs:184`. `notify_one` or `Notify::enable` would close the window.

11. **`ListPublicCa` gives different answers per transport.** gRPC (`src/mint.rs:106`) returns `cfg.root_ca`; REST (`src/rest_translation.rs:1222-1228`) returns the kernel `CaState` certs. A client picks up a different trust set depending on which door it uses.

12. **Streaming auth failures reach the client as opaque transport errors.** In `validated_streaming_body` a per-frame `PermissionDenied` is injected as an `io::Error` into the *request* body (`src/proxy_grpc.rs:278-284`). The backend sees a stream reset and the client sees whatever the backend or tonic emits, never the gateway's status or message. The `RequestHeader` check at `:385` covers the first message only in the sense that it verifies the token, not the namespace field.

13. **Oversize unary gRPC bodies return `INTERNAL`.** `src/proxy_grpc.rs:440-447` maps any `to_bytes` failure, including exceeding the 10 MB cap, to `Status::internal`. REST callers get a 500 for a client error. The streaming path returns `resource_exhausted` for the same condition.

## Low / pattern drift

14. **Hand-rolled state clients and manual Bearer headers.** `src/main.rs:389-397`, `:526-534`, `:596-604`, `:638-646` and `src/health.rs:125-135` construct raw tonic clients and format `Bearer` metadata by hand. `spawn_cert_chain_reloader` (`src/main.rs:463-467`) shows the codebase's own convention: the generated state client with `on_change`. This is the exact duplication the tacplus rule in your CLAUDE.md forbids. Side effect: a failed token fetch is silently skipped and the watch is sent unauthenticated.

15. **SSE dispatch drops `x-request-id`.** `src/rest_translation.rs:584-592` never forwards it, while the sibling at `:473-479` documents that accounting records are empty without it.

16. **JWT verified three or four times per REST call.** `authorize_then_read_body` → `handle_inner` header check → `validate_c2s_with_target_namespace` → `caller_tenant`. Each is a full signature verification of the same token.

17. **`status_code_to_tonic` maps every unlisted HTTP code to `Unauthenticated`.** `src/proxy_grpc.rs:130`. A future 500 from the auth layer would be reported to callers as a bad token.

The three High items are where I would start. Items 1 and 3 are reachable by an anonymous caller today; item 2 depends on `WEB_ROOT` being set.
