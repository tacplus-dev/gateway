# Provenance

Copied **wholesale** on 2026-10-23 from `gitlab.com/seabeam/schematic/platform/services/gateway` at commit
`f3002b7` (its own nested git repository; history carried over), with `proto/services/gateway.proto` and
`proto/dependencies.yaml` from `platform/proto` at `ca7c322` on branch `big8-p1-messaging`. Build outputs not copied.

Jody, 2026-10-23: *"We will copy kernel over to its github home and only make changes to it. we will
keep these as ships in the night for now. For the new stuff we want to do it the right way."* and
*"the following will also need to be ported over to tacplus-dev ... blobstore gateway kmaker letsencrypt
eventbus oauth"*. The private copy runs the launch fleet unchanged; new-design changes land here.

Divergences: headers in tacplus.yaml (Jody Scott, Apache-2.0; LICENSE added); `src: proto` (this repo
holds the service's own proto); `proto/registry.yaml` is a lock of github.com/tacplus-dev/registry.

2026-10-23, later: removed two test modules and one test that depended on things outside this fleet:
`e2e_personalauth_registration` (personalauth is dead — boneyard), `e2e_entitlement` (drives Scotty's
TaskActivity/AgentEvent records through stratum's query plane; product records, not platform), and the
proxy_grpc test asserting personalauth's NoAuth routes. Trace publishing to agentsensor's topic removed
(agentsensor is dead). The Mint front proxies MintToken/MintX509Cert to the sys minter (minter.Minter).

2026-10-27, no SeaBeam (#8): tacplus-dev works by itself, so nothing outside this note and dated records
names SeaBeam. The gateway's proto is this repository's own (`proto/services/gateway.proto`), not vendored or
fetched: its contract in the registry lock is `github.com/tacplus-dev/gateway`, and its dependencies come from
their tacplus-dev homes through the registry. `pkg` is `com.github.tacplusdev.gateway` (the Rust crate is
still `gateway-model`). Removed: `.gitlab-ci.yml` (SeaBeam's GitLab pipeline and registry; release CI is
#6) and the GitLab package `registry:` block of `proto/dependencies.yaml`. The proto header, image labels
and the privacy-page contact now name Jody Scott and tacplus.dev; tests use example.com hostnames and
neutral names instead of SeaBeam's hosts and products.
