# Gateway Progress

## 2026-06-13

- Added authorization support for flat `service_entitlements.grants` arrays.
- Kept rollout compatibility with legacy `{"grants":[{"token":"..."}]}` and
  pre-flat per-service entitlement maps.
- Added tests for legacy wildcard grants, generated package wildcard grants,
  object-wrapper compatibility, and exact grant token derivation.
- Verification passed: `cargo test`.

## 2026-06-16

- Aligned gateway with the governed proto contract:
  - mint implementation now uses generated `MintToken` and `MintX509Cert`.
  - service manager trace publishing is wired through the generated trace
    publisher alias.
  - REST translation docs/source references were updated to the renamed RPCs.
- Local verification passed:
  - regenerated gateway model with source-built tacplus.
  - `cargo check`.
- Push is pending the tacplus `v1.2.206` tag pipeline so proto fanout can use
  the corrected generator build.
