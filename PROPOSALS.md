# Proposals: gateway

Written by loopers. Each proposal: what, why, links. Jody promotes accepted ones into ROADMAP.md (via an agent);
the looper then marks it `promoted` or `declined` here with the date.

## Open
- **<title>** (<date>, <issue/run link>): <what and why>
- **webapp-login: forget an add that never left** (2026-10-29, #17): `SignIn.startAdding` sets `tp-login-adding` (and the step-up tenant) in sessionStorage before the redirect, and nothing clears it if the redirect fails. Since #17 the page stays put with an inline error after a failed redirect. If the person then signs out and signs in again in the same tab, `complete()` treats that fresh sign-in as an add. Fix: in `startAdding`, clear both keys when `start` throws (bug-sized; flow.ts).

## Promoted / declined
