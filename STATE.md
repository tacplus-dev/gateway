# State: gateway

Overwritten to stay current (loopers and agents). Last updated: 2026-11-11 by the looper (#30).

- **Version / line:** v0.1.2 (patch: rustix 1.1.6 for RUSTSEC-2026-0486, #30) on main (Cargo 1.2.0); tacplus floor 2.6, pinned to 2.6.1 and its build image by digest in tacplus.lock (#28)
- **Security floor:** the build scan's cargo-deny can't run here (its `cargo metadata` can't resolve the generated path crates in the checkout), so RustSec advisories reach us only through OSV until tacplus-dev/looper#126 is fixed
- **Works:** REST and gRPC routing to backends, OIDC discovery and JWKS, Mint proxied to kernel, SPIFFE path fallback, the sign-in webapp. External TLS is the config's `cert_chain` only (letsencrypt mode and the ACME challenge proxy are retired, #25): hot-swapped on every config change with no restart or dropped connection, and an expired certificate or a key that is not its own is refused at startup and on reload, keeping the current one.
- **Released / deployed:** not released; a gateway config still naming `EXTERNAL_TLS_MODE_LETSENCRYPT` (or relying on `acme_backend`) no longer starts: deployments supply the pipeline's certificate as `external_cert_pem`/`external_key_pem` (tacplus-dev/roadmap:decisions/certificates-by-pipeline-2026-11-03.md).
- **Known gaps:** see ROADMAP.md Next and PROPOSALS.md.
- **Blocked on:** nothing for TLS.
