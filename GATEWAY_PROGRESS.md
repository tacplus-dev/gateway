# Gateway Progress

## 2026-06-13

- Added authorization support for flat `service_entitlements.grants` arrays.
- Kept rollout compatibility with legacy `{"grants":[{"token":"..."}]}` and
  pre-flat per-service entitlement maps.
- Added tests for legacy wildcard grants, generated package wildcard grants,
  object-wrapper compatibility, and exact grant token derivation.
- Verification passed: `cargo test`.
