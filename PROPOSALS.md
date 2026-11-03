# Proposals: gateway

Written by loopers. Each proposal: what, why, links. Jody promotes accepted ones into ROADMAP.md (via an agent);
the looper then marks it `promoted` or `declined` here with the date.

## Open
- **<title>** (<date>, <issue/run link>): <what and why>
- **webapp-login: forget an add that never left** (2026-10-29, #17): `SignIn.startAdding` sets `tp-login-adding` (and the step-up tenant) in sessionStorage before the redirect, and nothing clears it if the redirect fails. Since #17 the page stays put with an inline error after a failed redirect. If the person then signs out and signs in again in the same tab, `complete()` treats that fresh sign-in as an add. Fix: in `startAdding`, clear both keys when `start` throws (bug-sized; flow.ts).
- **Unmaintained crates `cargo audit` still warns about** (2026-10-30, #20): after the aws-lc-rs relock there are no vulnerabilities, but four unmaintained warnings remain: `backoff` 0.4 and its `instant` (RUSTSEC-2025-0012, RUSTSEC-2024-0384; via the generated `httpclient` chassis), `serde_yaml` 0.9's `unsafe-libyaml` (RUSTSEC-2024-0449; via the generated types crate) and `rustls-pemfile` 2 (RUSTSEC-2025-0134; via `axum-server`, the generated model and the gateway itself). The first two belong upstream in tacplus' Rust chassis; `rustls-pemfile` the gateway can drop by parsing PEM with `rustls-pki-types`' `PemObject`.
- **Unused `EnvFilter` import in main.rs** (2026-10-30, #20): every build warns `unused import: tracing_subscriber::EnvFilter` (src/main.rs:50). Remove it.
- **One shared harness for the end-to-end tests** (2026-11-03, #23): `e2e_user_mint.rs`, `e2e_form_post.rs` and `e2e_mint_trace.rs` each carry their own copy of `unused_verifier()`, the plaintext `ProxyState` wiring and a "serve this stand-in on a real port" helper. A `#[cfg(test)] mod e2e_harness` holding them would cut ~40 lines a file and make the next stand-in (each trace-propagation test needs one, looper#51) a few lines. Not done in #23 so as not to collide with #24, which reworks `e2e_user_mint.rs`'s harness.

## Promoted / declined
