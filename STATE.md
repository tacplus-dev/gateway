# State: gateway

Overwritten to stay current (loopers and agents). Last updated: 2026-11-13 by the looper (#6).

- **Version / line:** 0.1 (v0.1.0, v0.1.1 tagged; Cargo 1.2.0); tacplus floor 2.6, pinned to 2.6.1 and its build image by digest in tacplus.lock (#28)
- **Works:** REST and gRPC routing to backends, OIDC discovery and JWKS, Mint proxied to kernel, SPIFFE path fallback, the sign-in webapp. External TLS is the config's `cert_chain` only (letsencrypt mode and the ACME challenge proxy are retired, #25): hot-swapped on every config change with no restart or dropped connection, and an expired certificate or a key that is not its own is refused at startup and on reload, keeping the current one.
- **Released / deployed:** a tag `vX.Y.Z` publishes `ghcr.io/tacplus-dev/gateway:X.Y.Z` and the line tag `X.Y` (linux/arm64; amd64 off) and creates the GitHub release (`.github/workflows/release.yml`, README Releasing, #6). The image's routes and web console come from the registry's contracts at its tacplus.lock, and its `web-dist/` and `clients/` are empty. Not deployed; a gateway config still naming `EXTERNAL_TLS_MODE_LETSENCRYPT` (or relying on `acme_backend`) no longer starts: deployments supply the pipeline's certificate as `external_cert_pem`/`external_key_pem` (tacplus-dev/roadmap:decisions/certificates-by-pipeline-2026-11-03.md).
- **Known gaps:** see ROADMAP.md Next and PROPOSALS.md.
- **Blocked on:** nothing for TLS.
