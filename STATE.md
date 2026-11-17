# State: gateway

Overwritten to stay current (loopers and agents). Last updated: 2026-11-17 by the looper (#26).

- **Version / line:** unreleased (Cargo 1.2.0); tacplus floor 2.6, pinned to 2.6.1 and its build image by digest in tacplus.lock (#28)
- **Works:** REST and gRPC routing to backends, OIDC discovery and JWKS, Mint proxied to kernel, SPIFFE path fallback, the sign-in webapp. External TLS is the config's `cert_chain` only (letsencrypt mode and the ACME challenge proxy are retired, #25): hot-swapped on every config change with no restart or dropped connection, and an expired certificate or a key that is not its own is refused at startup and on reload, keeping the current one. Rotating streams (#26, tacplus#322's `<Svc>Rotating` sibling): a rotated leg goes to the backend instance that issued its session, admitted only for the opening token's subject (another subject `PERMISSION_DENIED`, an unknown session `UNAUTHENTICATED`, a leg ended at its token's `exp`), envelopes validated as the plain method's frames; proved against a stand-in backend, since no generated C2S server serves the sibling until tacplus-dev/tacplus#323.
- **Released / deployed:** not released; a gateway config still naming `EXTERNAL_TLS_MODE_LETSENCRYPT` (or relying on `acme_backend`) no longer starts: deployments supply the pipeline's certificate as `external_cert_pem`/`external_key_pem` (tacplus-dev/roadmap:decisions/certificates-by-pipeline-2026-11-03.md).
- **Known gaps:** see ROADMAP.md Next and PROPOSALS.md.
- **Blocked on:** a green `just gates`: the build image's node rejects webapp-login's `--experimental-transform-types` (#34), so no build of gateway passes yet; the Rust gates (build, release build, tests) pass.
