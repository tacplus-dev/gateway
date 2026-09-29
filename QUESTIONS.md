# Gateway Questions

## 2. `cargo test` does not compile: stale generated model (2026-09-29)

The test build fails before any test runs. `src/e2e_entitlement.rs`
(`#[cfg(test)]`, `main.rs:30`) uses `stratum_pb::record_query_client`,
`record_query_server`, `OpenTaskActivityQueryRequest`, `*DelegationProbe*` and
more, and none of them exist in `target/generated-sources/model` (generated
2026-09-28). There are 32 errors, all in that file. `dist/` is also missing, so
`#[derive(rust_embed::Embed)] #[folder = "dist/"]` in `spa.rs` does not derive
`get`.

With that module switched off and an empty `dist/`, in a scratch copy and not in
this repo, the suite runs: 58 passed and 8 failed. The same 8 fail without the
blob_proxy change: `auth::tests::flat_grants_accept_{exact_catalog_token,
object_wrapper_shape,generated_package_wildcard}`, all four
`e2e_tenant_routing::*`, and
`registry::tests::the_embedded_registry_marks_no_service_tenant_owned_today`.
`blob_proxy::tests::a_bucket_refills_over_time` also fails now and then
(1 run in 3). It expects two back-to-back `allow` calls less than 1ms apart at
1000/s.

**Default taken:** did not regenerate (`just generate` / `tacplus build`) or
touch those tests. They are outside the blob-proxy task. A regen against current
tacplus and protos is the likely fix.

## 3. Upload 503 covers every failed hop, not only "pod dead" (2026-09-29)

`blob_proxy::forward` now answers **503** for any `proxy_streaming` error on
`PUT /upload/*`: connect refused, reset mid-body, closed before a response.
Reads (`/b/*`) keep **502**. This follows the decision's R1 ("if a pod is down,
uploads fail (503)").

A client that drops its own connection mid-upload also takes this path. It
gets the 503 on a connection it has already abandoned, so nothing sees it.

**Default taken:** did not add a `Retry-After` header. Is one wanted?

---

# ANSWERED

## 1. SM needs to expose grpc_health reporter for services that bypass `run()` — RESOLVED

**Answered/verified:** 2026-08-16 (fix itself landed 2026-08-06).

The report was correct. Gateway builds the ServiceManager with `new()` but never calls
`run()`, because it serves external TLS (LetsEncrypt / CertChain) rather than the SM's
auto-TLS. The SM sets its gRPC health handle to NOT_SERVING in `new()` and only flipped
it to SERVING inside `run()` — so the plaintext health listener on 8444 stayed
NOT_SERVING forever for any service that bootstraps itself.

**Fixed in tacplus** (`07223a0c`,
`pkg/templates/rust/types/service_manager.rs.tmpl:853`): the SM now exposes

```rust
pub async fn set_serving(&self, serving: bool)
```

which drives the *same* `grpc_health` handle that backs both the plaintext 8444 probe
and the main-server health service. Services that call `run()` are unaffected —
bootstrap still flips to SERVING automatically after health publish and TLS setup. The
doc comment states the contract explicitly: do not call it until your own bootstrap is
complete, or the readiness probe becomes a lie.

**Wired up in gateway** (`8036781`, `src/main.rs:313`): `sm.set_serving(true).await` is
called after identity, state clients, TLS material and the full router are built, and
immediately before the TLS listener starts accepting — the earliest point at which
SERVING is truthful.

**Verified live, not assumed:** port-forwarded 8444 on the running `gateway0` pod and
queried the probe directly:

```
$ grpcurl -plaintext -proto health.proto -d '{}' localhost:18444 grpc.health.v1.Health/Check
{
  "status": "SERVING"
}
```

Fleet gates re-run alongside the verification and all green: tacplus `test` /
`current-generation` / `determinism` / `soundness` all pass; `control/verify-live.sh`
PASS 9 / FAIL 0; `testapp/verify-tasks.sh` PASS 11 / FAIL 0;
`testapp/verify-tasks-web.sh` PASS 8 / FAIL 0.
