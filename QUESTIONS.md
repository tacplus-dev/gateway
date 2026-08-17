# Gateway Questions

_No open questions._

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
