# gateway Security & Quality Audit — Consolidated Report
2026-09-12 — multimodal review: Fable 5.1 (Claude), Codex CLI (GPT), Grok 4.6 (via GitHub Copilot CLI)
Scope: `src/` (16 Rust files). `target/`, `dist/`, `webapp-dist/`, `clients/` excluded.

Gateway is the platform's front door — the only service directly reachable from outside the mesh.
Items marked **[VERIFIED]** were personally re-checked against source; items marked
**[OVERSTATED — corrected]** were tool-reported claims I checked and found to be wrong or
significantly overclaiming impact — don't act on those as originally stated.

---

## Corrected claims — read this before anything else in this report

**Grok reported two CRITICAL + one HIGH finding claiming kernel's Mint RPCs
(`MintServiceToken`/`MintToken`/`MintClientToken`/`MintX509Cert`) are proxied with zero
authentication, allowing anyone to mint tokens/certs for free. I checked this in depth and it is
[OVERSTATED].** The gateway's `AuthPolicy::NoAuth` for these routes is real (confirmed in the
generated `ROUTES` table), but it's intentional — these RPCs are "self-authenticating": kernel's
own handler independently verifies a real cryptographic credential supplied in the request body,
regardless of gateway's policy or the mTLS peer identity. I read `mintServiceToken`'s full
implementation: it requires exactly one of `input_token` / `cloud_proof` / `kubernetes_token`,
verifies whichever is present (K8s token against the API server, `input_token` via the same
signature+expiry-checked path used everywhere else), and never trusts the `Caller` parameter for
this decision. `doX509Mint` (audited separately under kernel) does the identical thing. An
external caller with no valid credential gets rejected, not a free token.

**The real, narrower issue underneath — and it's the same thing schematic flagged in its own
inbox this morning, independently, hours before this audit:** these self-authenticating bootstrap
RPCs have no legitimate external caller (they're meant for in-mesh service bootstrap), and gateway
currently proxies them externally anyway with no network-boundary defense — the *only* thing
stopping misuse is each RPC's own internal credential check. That's real hardening debt (defense
in depth is missing), not an active bypass. Treat as Medium, sequence behind the confirmed items
below, and note it connects to the standing "should tacplus grow a do-not-proxy-externally
mechanism" question already sitting in schematic's inbox.

---

## Confirmed real, personally verified

### 1. WebSocket streams dial the backend before verifying any token [VERIFIED]
**File:** `src/rest_translation.rs`, `handle_websocket_stream` (~655-730), reached via the
`client_streaming` branch in `rest_handler` (~205-215) which bypasses `authorize_then_read_body`
entirely for these routes.
I read the full flow: the WS upgrade happens unconditionally for any `client_streaming` route
before the normal auth-check call site (line 237) is ever reached. `handle_websocket_stream` then
only checks `backend_auth_header.is_none()` — whether *some* non-empty string was supplied, not
whether it's valid — before opening a real backend gRPC stream and forwarding that unverified
string as the `authorization` header. Actual signature verification happens later, per data-frame.
**Impact is bounded by the backend's own auth enforcement** (which, per the tacplus/kernel audits,
is generally real and fail-closed) — but the gateway itself provides zero defense-in-depth here,
which contradicts its role everywhere else in the codebase.

### 2. Path traversal in dev-mode static file serving [VERIFIED, currently dormant]
**File:** `src/spa.rs`, `serve_from_disk` (~72-76)
`root.join(path)` on the raw request path, no `..` rejection, no canonicalization-and-verify-under-
root check. Confirmed no defense exists in the function. **Checked deployment configs and the live
`gateway` deployment — `WEB_ROOT` is not set anywhere**, so this is real but not currently
reachable. `WEB_ROOT` is explicitly a local-dev convenience per its own doc comment; worth fixing
so it can never become live-exploitable by an accidental future config change, not urgent.

---

## Not personally verified — real per 2-3 tool agreement, but I ran out of verification budget

These all have multiple independent tool agreement (noted per-item) and look plausible given the
codebase's general patterns, but I have not traced them myself. Treat with the confidence noted,
not as certain.

- **REST `ListPublicCa` may leak internal cluster CAs** (Grok 9/10, unverified) — claim is that the
  REST path returns kernel's internal `CaState` signing CAs while the native gRPC path returns only
  the external public root CA; if true, an unauthenticated GET exposes internal trust material.
  **Worth checking before anything else in this section — cheapest to verify, highest impact if real.**
- **Documented S2S-token rejection isn't actually implemented** (Grok 8/10) — `auth.rs` only
  rejects `token_use == refresh`, not other S2S-only token classes the comment says are rejected.
- **`/realms/*` and `/admin/*` proxied to Keycloak with no gateway-level auth** (Grok 8/10) —
  worth checking whether an admin console is actually still registered behind this (Fable separately
  noted a comment claiming Keycloak was removed, but `registry.json` still names it — inconsistent
  state worth resolving either way).
- **`SubscribeTrace` (eventbus) is a NoAuth route** (Grok 8/10) — opens a server-stream with no
  caller identity if true.
- **IDP TLS proxy accepts any cert chaining to the kernel CA, no service-identity binding** (Codex
  9/10, Fable + Grok corroborate) — the ordinary gRPC resolver pins to an expected SPIFFE label;
  this path allegedly doesn't.
- **IDP proxy forwards/trusts client-supplied `Host`/`X-Forwarded-*` headers** (Fable + Grok
  cross-confirmed) — could let a caller influence Keycloak-generated redirect/issuer URLs.
- **SPIFFE ID parser uses an obsolete path shape**, so a fallback routing/health-index path never
  matches current IDs (Fable + Grok cross-confirmed, `health.rs`).
- **`/healthz`/`/readyz` always return 200** regardless of actual backend/JWKS readiness (Grok
  9/10) — k8s could route traffic before the gateway is actually ready.
- **A crafted `grpc-message`/status text can panic the connection-handling task** (Fable + Grok
  cross-confirmed, `proxy_grpc.rs` ~638) — unescaped header value into a builder that `.unwrap()`s.
- **New TLS connection + full handshake per proxied request, no connection pooling** (Fable) — a
  latency/DoS-surface issue more than a security bug per se.
- Assorted Medium/Low: registry endpoint always 404s (dead code, `spa.rs`), a lost-wakeup race in
  health-readiness waiting, per-client rate limiting is actually process-wide (one client can 503
  everyone), oversized gRPC bodies return the wrong status class to REST callers, JWT verified
  redundantly 3-4x per REST call (performance, not security), unlisted HTTP codes mapped to
  `Unauthenticated` (misleading error surface).

## Pattern drift
- Hand-rolled state clients + manually-formatted Bearer headers in several places in `main.rs`,
  duplicating what the codebase's own generated state-client-with-`on_change` convention already
  does elsewhere in the same file — the exact kind of duplication the tacplus rule in CLAUDE.md is
  meant to prevent, and a failed-token-fetch here is silently skipped rather than failing loud.
- `ARCHITECTURE.md` documentation states unknown routes default to `Entitled`; the actual code
  correctly denies them by default — docs are stale, not the code.

---

## Recommended next step
Fix #1 and #2 above now (both confirmed, both cheap). Before touching anything else, spend five
minutes confirming or refuting the `ListPublicCa` internal-CA-leak claim — cheapest check, highest
payoff if real. The self-authenticating-RPC external-exposure question should get folded into
whatever decision comes out of the standing tacplus inbox question about a do-not-proxy-externally
mechanism, rather than treated as a new, separate ask.

## Raw per-tool output
- Codex: `codex.out.md` (8 findings)
- Fable 5.1: `fable.out.md` (17 findings)
- Grok 4.6: `grok.out.md` (first pass, cut short with zero findings written — internal timeout) +
  `grok2.out.md` (completed continuation, 18 findings — includes the corrected mint-RPC claims,
  read the correction note above before trusting items 1-3 of this file)
