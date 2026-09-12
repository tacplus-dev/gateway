# WebSocket streams authenticate before dialing; static serving stays in its root; ListPublicCa answers once

2026-09-12. Fixes the two personally-verified findings of
`decisions/security-audit-2026-09-12/CONSOLIDATED_REPORT.md`, plus the one item that report
flagged as cheapest-to-check/highest-payoff and left unverified — which turned out to be real.
Code-only change in `src/rest_translation.rs`, `src/spa.rs`, `src/mint.rs` and the `RestState`
wiring in `src/main.rs`, plus tests. No config, proto, or deploy change.

## 1. WebSocket streams dialed the backend before verifying any token

**Report finding #1 [VERIFIED].** `rest_handler` upgrades any `client_streaming` route to a
WebSocket at `src/rest_translation.rs:206-217`, before the `authorize_then_read_body` call site
that guards every other REST path. `handle_websocket_stream` then checked only
`backend_auth_header.is_none()` — whether *some* non-empty string had been supplied, not whether
it was a token — and opened a real backend gRPC stream forwarding that unverified string as the
`authorization` header. `"Bearer "` plus any junk satisfied it. Real verification only happened
later, per data frame, in `ws_frame_to_proto`.

Impact was bounded by the backend's own fail-closed auth, which is why this was the narrower
"gateway provides no defense in depth" finding rather than an open door. The gateway is the
platform's front door and enforces on every other path; it should enforce here too.

### The fix

`authorize_ws_stream` (`src/rest_translation.rs`) runs the header-only half of exactly the check
`authorize_then_read_body` runs on the unary path — `GatewayAuth::validate_c2s` over
`proxy_grpc::route_identity(route)` — and `handle_websocket_stream` returns on its error without
ever building the backend request. The namespace-aware half still runs per data frame in
`ws_frame_to_proto`, unchanged, exactly as on the unary path where it runs in `proxy_grpc`.

**Why the gate is not in `rest_handler` ahead of the upgrade,** which is where the report
suggested putting it: W2S streams are message-tokened by design, not header-tokened
(`ARCHITECTURE.md` §"Token Lifecycle on Streams" — the socket may stay open across token
rotations, so each frame carries a current token and the first token may legitimately arrive in
the `start` frame rather than in an HTTP header a browser cannot set). Rejecting a missing header
before the upgrade would break that documented contract. `authorize_ws_stream` is called at the
first point where the token that will actually be forwarded is known, which is still before the
dial — the property the finding is about. The pre-existing missing-token message and its
behaviour are preserved verbatim; validity checking is added on top.

Backend-side auth is untouched. This is additive.

## 2. Path traversal in dev-mode static file serving

**Report finding #2 [VERIFIED, dormant].** `serve_from_disk` did `root.join(path)` on the raw
request path with no `..` rejection and no canonicalize-and-verify-under-root check, so
`GET /../../etc/passwd` served any file the gateway process could read. Dormant because `WEB_ROOT`
is set in no deployment config; fixed so a future config change cannot make it live.

### The fix

`resolve_under_root` (`src/spa.rs`) resolves a request path against the root and returns one of
three states — `UnderRoot`, `Missing`, `Escaped`. Two checks, because neither alone suffices:

- a component scan rejecting anything that is not `Component::Normal`/`CurDir`, which catches
  `..` and absolute paths as written;
- `canonicalize` on both root and result plus a `starts_with` comparison, which catches an escape
  that only appears once a symlink *inside* the root is followed.

`Escaped` returns 400 outright. `Missing` keeps the existing SPA fallback to `index.html`, because
a path that is inside the root and simply does not exist is client-side routing, not an attack.

Nothing percent-decodes the path on the way in (`spa_handler` takes `uri.path()` verbatim), so an
encoded `%2e%2e` stays a literal file name and cannot smuggle a `..` past the component scan.

## 3. `ListPublicCa` did leak kernel's internal cluster CAs over REST

The report listed this under "not personally verified" with a note to check it first. **It is
real.** Traced both paths:

| Path | Source | What that is |
|------|--------|--------------|
| gRPC `GatewayMintService::list_public_ca` (`src/mint.rs`) | `cfg.root_ca` | the CA that signed gateway's **external TLS cert** |
| REST `/gateway.Mint/ListPublicCa` (`src/rest_translation.rs`) | `state.ca_certs` → `ca_certs_store` → `wait_for_ca_certs()` | kernel's **`CaState` internal cluster signing CAs**, the runtime CAs that sign per-service intermediate CAs via `X509Mint` (`src/main.rs:189-200`) |

The route is `AuthPolicy::NoAuth` with `GET` allowed
(`target/generated-sources/model/s2sm/rest_dispatch/mod.rs:220-231`), matching
`RPC_FLAG_PUBLIC_NO_AUTH` in `proto/services/gateway.proto:126-130`. That NoAuth is correct for
what the proto says the RPC returns — "the cluster root CA certificate(s)… clients (e.g.
schematicctl) use these to verify TLS connections to the gateway" — and wrong for what REST was
actually returning.

Two problems, not one. The disclosure is the milder half (these are certificates, not private
keys). The worse half is that REST was answering a different question than gRPC: a client that
followed the proto's own instructions and built its gateway TLS trust store from the REST
response would end up trusting the **internal cluster CA** as gateway's external identity — a CA
that signs a cert for every service in the mesh.

### The fix

`mint::public_ca_response(root_ca)` is now the single source of the answer, called by both the
native gRPC handler and `rest_translation::list_public_ca_response`. `RestState::ca_certs` is
replaced by `RestState::root_ca: Vec<X509Cert>`, fed from `cfg.root_ca` in `main.rs` — the same
value `GatewayMintService::new` already receives. The REST JSON shape (`{"certs":[{"id","base64"}]}`)
is unchanged.

The internal `CaState` store is now structurally unreachable from the REST path: the field no
longer exists on `RestState`, so the compiler, not a test, prevents the regression.

## What was NOT changed

- The three mint-RPC findings the report marks **[OVERSTATED — corrected]**. Kernel's handlers
  self-authenticate those RPCs; the real narrower item (no network-boundary defense on
  bootstrap RPCs with no legitimate external caller) belongs with the standing tacplus
  "do-not-proxy-externally" inbox question, per the report.
- Everything in the report's "not personally verified" list other than `ListPublicCa`, and the
  pattern-drift notes. Out of scope for this batch, still open.
- `ca_certs_store` and `spawn_ca_cert_watcher` in `main.rs`. With the REST leak closed, nothing
  reads that store — the backend TLS trust bundle is built once at startup from `initial_cas`
  directly (`build_ca_pem_bundle`, `main.rs:193`), not from the store, so the watcher now
  refreshes a value with no reader. **Flagged, not deleted.** Either the watcher should feed a
  rebuilt backend TLS verifier (which is presumably what it was for) or both it and the store
  should go; that is a separate decision. The stale comment that said the store existed "so the
  Mint service can serve them via ListPublicCa" — the bug, written down — is corrected in place.

## Verification

New tests, all in-tree:

`src/rest_translation.rs` — `websocket_stream_rejects_a_token_that_is_not_a_token` (the reported
bypass: any non-empty string passed the old presence check),
`websocket_stream_rejects_a_token_signed_by_an_untrusted_key` (well-formed, unexpired,
correctly-audienced token signed by a key the `JwkCache` does not hold — real ECDSA, real
`GatewayAuth`), `websocket_stream_rejects_a_missing_token`,
`websocket_stream_accepts_a_valid_token` (the defense-in-depth gate is not a new wall),
`a_noauth_websocket_stream_still_opens_without_a_token`. Routes are picked out of the generated
`ROUTES` table by shape, so the tests follow regeneration rather than pinning paths.

`src/spa.rs` — `a_path_that_escapes_the_web_root_is_rejected` (`../secret.txt`,
`../../etc/passwd`, `assets/../../secret.txt`, `/etc/passwd`: 400, and the secret's bytes never
appear in the body), `a_symlink_out_of_the_web_root_is_rejected` (the case the component scan
alone misses), `a_normal_in_root_path_is_still_served`,
`a_missing_in_root_path_still_falls_back_to_index`.

`src/rest_translation.rs` — `rest_and_grpc_list_public_ca_return_the_same_cert_set`: the REST
JSON's `(id, base64)` pairs equal `mint::public_ca_response`'s certs for the same `root_ca`.

**Negative controls**, both run:

- Reverting `authorize_ws_stream`'s body to the old presence-only check:
  `websocket_stream_rejects_a_token_that_is_not_a_token` and
  `websocket_stream_rejects_a_token_signed_by_an_untrusted_key` fail
  ("an unverifiable string must not open a backend stream"). The other three still pass, which is
  the point — the old check was not wrong, just insufficient.
- Reverting `resolve_under_root` to `Resolved::UnderRoot(root.join(path))`:
  `a_path_that_escapes_the_web_root_is_rejected` and `a_symlink_out_of_the_web_root_is_rejected`
  fail with `left: 200, right: 400` — i.e. the traversal succeeded and served the file.

`cargo build`: clean. One warning, pre-existing and unrelated (`unused import:
tracing_subscriber::EnvFilter`, `main.rs:48`).

`cargo test`: **41 passed, 3 failed** — all 17 gateway-owned `rest_translation::tests` and
`spa::tests` (10 of them new here) pass. The 3 failures are
`auth::tests::flat_grants_accept_{exact_catalog_token,generated_package_wildcard,object_wrapper_shape}`,
all asserting `flat_grants_allow(…, "echo", "/echo.Echo/Ping")`. **Pre-existing:** verified by
reverting all four changed files to HEAD and re-running — identical 3 failures. `src/auth.rs` is
not touched by this change. The generated entitlement catalog no longer carries the `echo`
service those tests assert on.

### Blocker: `cargo test` does not compile at HEAD

Unrelated to this change, and it gates the whole suite, since a bin crate's tests are one binary.
At HEAD, on a clean tree, `cargo test` fails with **32 errors, all in `src/e2e_entitlement.rs`**,
from generated-source drift: `stratum_pb::record_query_{client,server}` no longer exist,
`*TaskActivity*` was renamed `*WorkActivity*`, and the whole `DelegationProbe` family is gone
from `types::vservices::query`. Evidence:

```
error[E0432]: unresolved import `stratum_pb::record_query_client`
error[E0425]: cannot find type `SampleTaskActivityRequest` in module `stratum_pb`
              help: a struct with a similar name exists: `SampleWorkActivityRequest`
error[E0425]: cannot find type `DelegationProbeWatchEvent` in module `stratum_pb`
              (no suggestion — the type is gone)
error: could not compile `gateway` (bin "gateway" test) due to 32 previous errors
```

`src/e2e_entitlement.rs` has a history of mechanical "follow tacplus's rename" repairs
(`8e6d2b1 gateway: follow tacplus's s2s RecordMap verb rename`). This round is not purely
mechanical — `DelegationProbe` is a removed service, not a rename, so its fixture backend needs
rewriting rather than renaming. Out of scope for this batch and left untouched.

To produce the counts above, `mod e2e_entitlement;` (`main.rs:28`) was commented out for the test
runs only, and **restored**; it is uncommented in the delivered tree. Verify with
`grep -n e2e_entitlement src/main.rs`. Reproduce the counts with the same one-line comment-out.
