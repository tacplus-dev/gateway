# Roadmap: gateway

Owned by Jody; changed only by an agent at Jody's request. Loopers propose in PROPOSALS.md.

## Now
The edge proxy (Rust): routes REST and gRPC to backend services, serves OIDC discovery and JWKS, proxies mint calls to kernel, falls back to SPIFFE path routing.
Also serves the sign-in webapp. Unreleased; tacplus floor 2.5 (#18).

## Next
- Sign-in page: providers, Custom with remembered icon, link-your-personal prompt, binding confirmation (#19)
- Login page: "Signing in with <provider>…" once a button is clicked (#17)
- Gates: the e2e_user_mint kernel stand-in lacks UserMint.RevokeDeviceCredential, build fails on main (#14)
- Release by tag (v0.1.0) with notes, no deployable image: the gateway is built per fleet by the fleet builder with the merged webapp (#6; tacplus-dev/roadmap:decisions/gateway-per-fleet-2026-10-27.md; after tacplus-dev/looper#17 and #12)

## Later
- Image: grpc-health-probe v0.4.48 to v0.4.60 (#11; blocked on #14)
- Update h2, quinn-proto, rustls, rustls-webpki, webpki-roots (#9; blocked on #14)
- crypto-bigint 0.5.5 and rsa 0.9.10 advisories via generated chassis crates (#10; blocked on tacplus-dev/tacplus#186)
- Port SeaBeam gateway f3002b7..d0b7ad44 (#7; blocked on #6)
- Route tenant-owned calls by the request's target-tenant field (#3; blocked on tacplus-dev/tacplus#170)
- Identity step 4 in the console: linked accounts, sign out everywhere, delete account, tenant step-up (#2; blocked on tacplus-dev/fleet-seatrials#1)
- Keep the Let's Encrypt certificate across a kernel restart (tacplus-dev/roadmap:decisions/tacplus-dev-stable-gate-2026-10-25.md)
- Tenant placement resolver behind the resolve-a-target seam, tabled (tacplus-dev/roadmap:decisions/deployments-per-cluster-2026-10-26.md)
- Version-aware routing for canary, design needed (tacplus-dev/roadmap:decisions/fleets-and-canary-huddle-2026-10-22.md)

## Not doing
- Nothing recorded yet.
