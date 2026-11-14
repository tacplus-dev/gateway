# State: gateway

Overwritten to stay current (loopers and agents). Last updated: 2026-11-13 by the looper (#35, with #34 and #29).

- **Version / line:** source tags v0.1.0, v0.1.1, v0.1.2 (#35, #34, #29) on main (Cargo 1.2.0); tacplus floor 2.6, pinned to 2.6.1 and its build image by digest in tacplus.lock (#28)
- **Works:** REST and gRPC routing to backends, OIDC discovery and JWKS, Mint proxied to kernel, SPIFFE path fallback, the sign-in webapp. External TLS is the config's `cert_chain` only (letsencrypt mode and the ACME challenge proxy are retired, #25): hot-swapped on every config change with no restart or dropped connection, and an expired certificate or a key that is not its own is refused at startup and on reload, keeping the current one.
- **Released / deployed:** not released; a gateway config still naming `EXTERNAL_TLS_MODE_LETSENCRYPT` (or relying on `acme_backend`) no longer starts: deployments supply the pipeline's certificate as `external_cert_pem`/`external_key_pem` (tacplus-dev/roadmap:decisions/certificates-by-pipeline-2026-11-03.md).
- **Known gaps:** see ROADMAP.md Next and PROPOSALS.md.
- **Blocked on:** nothing for TLS. `just gates` runs on the pinned build image (webapp-login's tests under its node 26 with no flag, as erasable TypeScript, #34), the release images run as 65532:65532 (#29), and the security checks' clippy run is clean (#35).
