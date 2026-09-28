Audited all 16 `src/*.rs` files read-only. I found 8 issues that meet the requested confidence threshold.

## High

1. [src/auth.rs:387](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/gateway/src/auth.rs:387) — Gateway authentication rejects refresh tokens but accepts `bootstrap`, `locality`, and `external` token classes, unlike the generated chassis authorizer.

   Failure scenario: a valid kernel-signed bootstrap/locality token—or an external token intended exclusively for an upstream provider—has a matching service audience and entitlements; the gateway accepts it as a normal C2S credential and forwards the request internally. The generated authorizer explicitly rejects all three classes because they must not be usable for API access.

2. [src/rest_translation.rs:685](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/gateway/src/rest_translation.rs:685) — A WebSocket stream can authenticate its backend connection with one token while authorizing individual messages with different tokens.

   Failure scenario: the start frame supplies token A, which becomes the forwarded backend credential and determines tenant routing, while later message frames supply token B and are validated against B at lines 988–1000. A message authorized for B is consequently sent on a backend stream authenticated and routed as A, breaking caller and tenant identity binding.

3. [src/idp_proxy.rs:164](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/gateway/src/idp_proxy.rs:164) — The IDP TLS verifier accepts any certificate chaining to a configured kernel CA and deliberately performs no Keycloak/SPIFFE identity check.

   Failure scenario: a health entry points `keycloak` at another internal workload possessing any kernel-issued certificate; the TLS handshake succeeds and that workload receives IDP requests, credentials, cookies, and authorization codes. The ordinary gRPC resolver instead pins the certificate to an expected SPIFFE service label.

4. [src/resolver.rs:207](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/gateway/src/resolver.rs:207) — Tenant-owned backend TLS is pinned only to the bare service label, not the selected tenant namespace.

   Failure scenario: the health table for `documents-tenantA` contains an endpoint serving a valid `documents` certificate for tenant B; routing selects the endpoint under tenant A’s key, but TLS accepts tenant B’s certificate because only `documents` is compared, causing cross-tenant misrouting.

## Medium

5. [src/idp_proxy.rs:90](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/gateway/src/idp_proxy.rs:90) — IDP request bodies are collected without a size bound.

   Failure scenario: an unauthenticated caller sends a very large or indefinitely streamed body to `/realms/*` or `/admin/*`; the IDP interceptor consumes it before reaching the REST body-limit layer, tying up memory and one of the gateway’s concurrency slots until exhaustion.

6. [src/idp_proxy.rs:121](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/gateway/src/idp_proxy.rs:121) — The proxy trusts the external `Host` header and preserves caller-supplied `X-Forwarded-*` headers before adding its own copies.

   Failure scenario: a caller submits an attacker-controlled `Host` and/or existing `X-Forwarded-Host`; Keycloak receives attacker-selected or ambiguous forwarded-host values and may generate redirects, issuer URLs, or password-reset links for that host. No configured `external_hostnames` validation occurs on this path.

7. [src/spa.rs:73](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/gateway/src/spa.rs:73) — Disk-backed SPA serving joins the raw URI path to `WEB_ROOT` without rejecting `..` components or verifying the resulting path remains beneath the root.

   Failure scenario: when `WEB_ROOT` is enabled, a request containing accepted parent-directory segments makes `root.join(path)` resolve outside the web root; any readable file at that resolved path is returned publicly. Impact depends on the HTTP stack or upstream proxy preserving such segments.

8. [src/main.rs:570](/Users/jody/workspace/gitlab/seabeam/schematic/platform/services/gateway/src/main.rs:570) — CA-state updates only modify the public certificate store; the resolver and IDP TLS verifiers retain the startup trust store permanently.

   Failure scenario: kernel rotates to a new service CA and backends begin presenting certificates under it; `ca_certs_store` updates, but the verifier created at lines 193–196 and the IDP connector created at lines 293–295 continue using the old roots, so backend traffic fails until gateway restart. Conversely, removal of a compromised CA does not remove it from the active trust decision.

I excluded several suspicious-looking areas where the generated route allowlist or downstream kernel validation prevented a demonstrable exploit. No files were modified.
