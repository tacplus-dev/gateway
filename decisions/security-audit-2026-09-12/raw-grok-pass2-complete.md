## Security review

| # | Severity | File | Lines | Vulnerability | Confidence |
|---|----------|------|-------|---------------|------------|
| 1 | 🔴 CRITICAL | rest_dispatch ROUTES + `proxy_grpc.rs` | 236–277 / 400–416 | Unauthenticated C2S proxy of kernel mint RPCs | 9/10 |
| 2 | 🔴 CRITICAL | rest_dispatch ROUTES + `proxy_grpc.rs` | 421–430 / 400–416 | Unauthenticated C2S proxy of `kmaker.Kmaker/MintKernelCert` | 9/10 |
| 3 | 🟠 HIGH | `mint.rs` + `rest_translation.rs` | 84–108 / 1138–1188 | NoAuth `MintX509Cert`/`MintToken` confused deputy via SM | 8/10 |
| 4 | 🟠 HIGH | `rest_translation.rs` | 1219–1236 | NoAuth `ListPublicCa` REST serves **internal** CaState CAs | 9/10 |
| 5 | 🟠 HIGH | `auth.rs` | 129–138, 390–456 | Documented S2S-token reject is not implemented | 8/10 |
| 6 | 🟠 HIGH | `idp_proxy.rs` + `main.rs` | 42–50 / 384–392 | Unauthenticated reverse-proxy of `/admin/*` and `/realms/*` | 8/10 |
| 7 | 🟠 HIGH | rest_dispatch ROUTES | 126–138 | `SubscribeTrace` is NoAuth C2S | 8/10 |
| 8 | 🟠 HIGH | `spa.rs` | 55–71 | `WEB_ROOT` path traversal | 9/10 |
| 9 | 🟡 MEDIUM | `idp_proxy.rs` | 178–212 | IDP TLS accepts any kernel-CA cert (no name bind) | 8/10 |
| 10 | 🟡 MEDIUM | `idp_proxy.rs` | 114–141 | Client `Host`/`X-Forwarded-*` copied into IDP request | 8/10 |
| 11 | 🟡 MEDIUM | `rest_translation.rs` | 165–195 | SPIFFE fallback skips auth-before-body | 9/10 |
| 12 | 🟡 MEDIUM | `rest_translation.rs` | 206–216, 655–666 | Authenticated WS upgrade before any token | 8/10 |
| 13 | 🟡 MEDIUM | `health.rs` | 268–282 | SPIFFE path parser does not match current IDs | 9/10 |
| 14 | 🟡 MEDIUM | `idp_proxy.rs` | 74–78 | `split(':')` host parse breaks IPv6 | 9/10 |
| 15 | 🟡 MEDIUM | `main.rs` | 563–565 | `/healthz` and `/readyz` always 200 | 9/10 |
| 16 | 🟡 MEDIUM | `proxy_grpc.rs` | 638–658 | `tonic_status_to_response` can panic on bad `grpc-message` | 8/10 |
| 17 | ⚪ LOW | `proxy_grpc.rs` | 126–129 | Unknown HTTP status mapped to Unauthenticated | 9/10 |
| 18 | ⚪ LOW | `limits.rs` | 48–51, 139–156 | Edge RPS/concurrency is global, not per-client | 9/10 |

---

### 1. 🔴 CRITICAL — `proxy_grpc.rs:400-416` + generated ROUTES
Gateway admits a path iff it is in `ROUTES`. These entries are **NoAuth** with empty `http_path` (REST-hidden, **gRPC-live**): `/kernel.Mint/MintServiceToken`, `MintToken`, `MintClientToken`, `MintX509Cert`. External `content-type: application/grpc` POST to those paths is forwarded to kernel with no token. Same class as the closed `CreatePersonalPrincipal` hole.

### 2. 🔴 CRITICAL — `proxy_grpc.rs:400-416` + ROUTES `kmaker`
`/kmaker.Kmaker/MintKernelCert` is NoAuth in `ROUTES`. Same unauthenticated gRPC proxy to an internal cert-mint service.

### 3. 🟠 HIGH — `mint.rs:84-108`, `rest_translation.rs:1138-1188`
`gateway.Mint` TokenMint/X509Mint are NoAuth. Native tonic and REST `handle_mint` call `sm.s2s().kernel().mint_client()` — **gateway’s S2S identity**, attacker-controlled body. Kernel sees a trusted service, not an anonymous edge caller.

### 4. 🟠 HIGH — `rest_translation.rs:1219-1236` vs `mint.rs:110-116`
REST `ListPublicCa` dumps `ca_certs` from kernel **CaState** (cluster signing CAs). gRPC Mint serves `cfg.root_ca` (external TLS CA). Unauthenticated GET `/api/v1/gateway/Mint/ListPublicCa` leaks internal CAs.

### 5. 🟠 HIGH — `auth.rs:129-138` vs `authenticate` (~390-456)
Comment: reject S2S tokens. Code only rejects `token_use`/`typ` == `refresh`. An S2S JWT with `aud` = target service, same JWKS, passes `AnyUser` (e.g. `MintAssertion`, `BrokerCliAuth`, client download).

### 6. 🟠 HIGH — `idp_proxy.rs:42-50`, `main.rs:384-392`
Any HTTP request under `/realms` or `/admin` is proxied to Keycloak with **no C2S auth**. `/admin` is the admin console if that backend is still registered.

### 7. 🟠 HIGH — ROUTES `SubscribeTrace`
`/eventbus.TraceSession/SubscribeTrace` is NoAuth C2S (REST + gRPC). Gateway will open a server-stream to eventbus with no caller identity.

### 8. 🟠 HIGH — `spa.rs:55-71`
`serve_from_disk` does `root.join(uri_path)` with no `..` / canonicalize check. With `WEB_ROOT` set, `GET /../../etc/passwd` reads host files (then SPA fallback only if read fails).

### 9. 🟡 MEDIUM — `idp_proxy.rs:178-212`
`NotValidForName` is treated as success. Any cert chained to the kernel CA (any service) is accepted for the IDP TLS hop if the TCP path is intercepted.

### 10. 🟡 MEDIUM — `idp_proxy.rs:114-141`
Forwards caller headers; sets `X-Forwarded-Host` from `Host`; does not strip client `X-Forwarded-*`. Keycloak can mint redirects/cookies for an attacker-chosen host.

### 11. 🟡 MEDIUM — `rest_translation.rs:165-195`
Unknown `/api/v1/...` that matches a health SPIFFE path **skips** `authorize_then_read_body`, buffers 10MB, then `dispatch_via_proxy` with the REST path as `grpc_path` (usually 404 in `proxy_grpc`). Violates auth-first; unauthenticated CPU/RAM.

### 12. 🟡 MEDIUM — `rest_translation.rs:206-216`
Bidi routes upgrade to WebSocket **before** token checks. Auth is only on later frames. Unauthenticated callers can pin WS tasks (10s first-message wait).

### 13. 🟡 MEDIUM — `health.rs:268-282`
Parser assumes `spiffe://<org>/<cluster>/<service>/...`. Current IDs are `spiffe://<td>/tenants|system/.../services/<svc>`. `dial_spiffe` / REST SPIFFE index keys are wrong → misroute or fail-open to empty/wrong endpoints.

### 14. 🟡 MEDIUM — `idp_proxy.rs:74-78`
`ep.split(':').next()` + `:9443` breaks IPv6 health addresses; IDP proxy aims at a truncated host.

### 15. 🟡 MEDIUM — `main.rs:563-565`
Both `/healthz` and `/readyz` return 200 unconditionally, so k8s can send public traffic before backends/JWKs are ready (fail-closed auth still 401, but IDP/NoAuth/Mint are live).

### 16. 🟡 MEDIUM — `proxy_grpc.rs:638-658`
`.header("grpc-message", message).body(...).unwrap()`. Invalid `HeaderValue` (CR/LF in validation/auth text) panics the worker on attacker-influenced status text.

### 17. ⚪ LOW — `proxy_grpc.rs:126-129`
Non-mapped HTTP errors become gRPC `Unauthenticated`, so 5xx/404-ish proxy failures look like auth failures.

### 18. ⚪ LOW — `limits.rs:48-51`
One client can consume the process-wide 2000 rps / 1024 in-flight budget and 503 everyone else.

---

**Pattern drift (concrete):** (4) REST vs gRPC `ListPublicCa`; (5) S2S reject comment vs code; (11) SPIFFE path skips the auth-first rule used by unary REST/gRPC; ARCHITECTURE.md still says unknown routes default to `Entitled` — code correctly **rejects** them.

**Not a finding:** unknown gRPC methods are deny-by-default; `dev-bypass` cannot ship in release; unary/stream auth-before-body on the main path is real; tenant-owned NoAuth callers are rejected; `CreatePersonalPrincipal` is not in `ROUTES`.

---

Follow-up (reply with a number):
1. Fix highest severity issues
2. Fix all issues
3. Commit a summary of findings

