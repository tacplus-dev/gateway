# State: gateway

Overwritten to stay current (loopers and agents). Last updated: 2026-11-15 by the looper (#3).

- **Version / line:** unreleased (Cargo 1.2.0); tacplus floor 2.6, pinned to 2.6.1 and its build image by digest in tacplus.lock (#28)
- **Works:** REST and gRPC routing to backends; a call to a tenant-owned service is routed by its request's target-tenant field (`(spec.rpc).route_field`, a tid; a stream by its first message) to that tenant's `<svc>-<tid>` instance, never by the caller's token, and a call naming no valid tid is refused, INVALID_ARGUMENT (#3); OIDC discovery and JWKS, Mint proxied to kernel, SPIFFE path fallback, the sign-in webapp. External TLS is the config's `cert_chain` only (letsencrypt mode and the ACME challenge proxy are retired, #25): hot-swapped on every config change with no restart or dropped connection, and an expired certificate or a key that is not its own is refused at startup and on reload, keeping the current one.
- **Released / deployed:** not released; a gateway config still naming `EXTERNAL_TLS_MODE_LETSENCRYPT` (or relying on `acme_backend`) no longer starts: deployments supply the pipeline's certificate as `external_cert_pem`/`external_key_pem` (tacplus-dev/roadmap:decisions/certificates-by-pipeline-2026-11-03.md).
- **Known gaps:** see ROADMAP.md Next and PROPOSALS.md.
- **Blocked on:** nothing for TLS. Landing #3's tenant routing waits on #34 (the build image's node rejects webapp-login's test flag, so every land's gates fail).
