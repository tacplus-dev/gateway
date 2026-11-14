# State: gateway

Overwritten to stay current (loopers and agents). Last updated: 2026-11-14 by the looper (#31).

- **Version / line:** unreleased (Cargo 1.2.0); tacplus floor 2.6, pinned to 2.6.1 and its build image by digest in tacplus.lock (#28)
- **Works:** REST and gRPC routing to backends, OIDC discovery and JWKS, Mint proxied to kernel, SPIFFE path fallback, the sign-in webapp. External TLS is the config's `cert_chain` only (letsencrypt mode and the ACME challenge proxy are retired, #25): hot-swapped on every config change with no restart or dropped connection, and an expired certificate or a key that is not its own is refused at startup and on reload, keeping the current one.
- **Released / deployed:** not released; a gateway config still naming `EXTERNAL_TLS_MODE_LETSENCRYPT` (or relying on `acme_backend`) no longer starts: deployments supply the pipeline's certificate as `external_cert_pem`/`external_key_pem` (tacplus-dev/roadmap:decisions/certificates-by-pipeline-2026-11-03.md).
- **Security checks:** `security-exceptions.yaml` accepts, until 2027-02-11, the test-only `ws://` semgrep finding and four unmaintained crates the generated chassis and axum-server lock (backoff, instant, unsafe-libyaml, rustls-pemfile; tacplus-dev/tacplus#308, #319, #320); the gateway's own code no longer uses rustls-pemfile and pin-utils is gone (#31). v0.1.2 is #31's patch.
- **Known gaps:** see ROADMAP.md Next and PROPOSALS.md.
- **Blocked on:** nothing for TLS.
