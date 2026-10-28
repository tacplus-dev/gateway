# History: gateway

Append-only: add entries at the end, never edit or remove one (CI enforces it). One line each:
`- <YYYY-MM-DD> <who: looper|agent|jody> <kind: issue|decision|release|deploy> <one line> (<links>)`

- 2026-10-27 looper issue Image: grpc-health-probe v0.4.48 -> v0.4.60 (25 Go vulnerabilities in the shipped probe binary) (#11)
- 2026-10-28 looper issue Dependencies: update anyhow 1.0.102 (RUSTSEC-2026-0190) and rand 0.8.5/0.9.2 (RUSTSEC-2026-0097), unsound, lockfile-only (#16, fd8be96)
