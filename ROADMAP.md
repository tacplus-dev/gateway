# Roadmap: tacplus

Owned by Jody; changed only by an agent at Jody's request. Loopers propose in PROPOSALS.md.

## Now
tacplus compiles annotated proto definitions into complete services (Go, Rust, Java) and clients (TypeScript, Python, Swift, C#).
Latest release: v2.4.1 (2026-10-27). 2.4 is the line with the global registry and the version floor (#161).
Release lines with branches: 2.0 through 2.4.

## Next
- Move CI, images, releases and nightlies from GitHub Actions to the GitLab build pipeline (#194, after looper#17)
- No tacplus image: `build:X.Y` per line with a `tacplus` script that fetches and verifies the newest binary; verify (Kani, JBMC) and fuzzing run there; Go not formally verified (#193)
- Fetch layer: authenticate GitHub clones with GH_TOKEN, only to github.com (#191)
- Images: bump moby/go-archive to 0.3.0 (CVE-2026-17106) and patch the release lines (#190)
- Generated Rust chassis: rsa and crypto-bigint advisories (#186)
- Fleets pin services by release line (MAJOR.MINOR to latest patch), not commit (#180)
- JWK verification: infer a missing alg from the token within the key's family (#179)
- Route tenant-owned RPCs by a declared target-tenant field (#170)
- Records: generated write surface, entry/map locks, durability levels, Watch, for 2.5 (#163) (needs Jody's decision)
- diskstore archive: public wiring helper for hand-opened RedoLogs (#145) (needs Jody's decision)
- Make the three well-known platform names proto-declared instead of baked into the generator (#1) (needs Jody's decision)

## Later
- Fleet builder gathers service webapp pieces and clients, builds the merged webapp and the fleet's gateway (#195, after #180; contract needs Jody's OK)
- Split the build image by language (build-go, build-rust, build-java, …), each with its toolchain and verifier (tacplus-dev/roadmap:decisions/tacplus-images-2026-10-27.md)
- Retire the linked claim from the generated namespace backstop (#171), blocked on #170 and tacplus-dev/kernel#4
- diskstore archive: stable member id across restarts (#143), blocked on #163
- diskstore archive: retention of old segments and checkpoints (#144), blocked on #163

## Not doing
- Nothing recorded yet.
