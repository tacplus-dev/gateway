# State: gateway

Overwritten to stay current (loopers and agents). Last updated: 2026-11-07 by the looper (#15).

- **Version / line:** unreleased (Cargo 1.2.0); tacplus floor 2.5
- **Works:** REST and gRPC routing to backends, OIDC discovery and JWKS, Mint proxied to kernel, SPIFFE path fallback, the sign-in webapp. External TLS is the config's `cert_chain` only (letsencrypt mode and the ACME challenge proxy are retired, #25): hot-swapped on every config change with no restart or dropped connection, and an expired certificate or a key that is not its own is refused at startup and on reload, keeping the current one. A tenant-owned service is routed to the instance of the caller token's tenant; on its MCP session carrier (`Broker<Service>McpSession`) every `McpRequest` frame is stamped with that tenant, and a frame naming another tenant is refused and not forwarded (#15).
- **Released / deployed:** not released; a gateway config still naming `EXTERNAL_TLS_MODE_LETSENCRYPT` (or relying on `acme_backend`) no longer starts: deployments supply the pipeline's certificate as `external_cert_pem`/`external_key_pem` (tacplus-dev/roadmap:decisions/certificates-by-pipeline-2026-11-03.md).
- **Known gaps:** see ROADMAP.md Next and PROPOSALS.md.
- **Blocked on:** nothing for TLS.
