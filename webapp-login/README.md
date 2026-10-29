# @tacplus-dev/webapp-login

Sign-in for a tacplus fleet's web app, as a library. Two layers:

- `SignIn` (flow.ts): the oauth flow — providers, start, complete the provider's return,
  current identity, sign out — over two small interfaces the consumer implements with its
  own generated W2S clients (`LoginAuth` over `oauth.Auth`, `SessionTokens` over the
  generated `MintTokenProvider`). The library imports no generated package, so every app's
  model stays its own.
- Tenants: a session credential's proofs vouch for tenants (an org sign-in the fleet routed
  vouches for the org and `people`, a personal one for `people`). `SignIn` keeps the tenant
  access tokens are minted for across refreshes and reloads, starting with the sign-in's first
  access token's (the org's, when it was routed to one), lists the vouched tenants
  (`tenants()`), and switches (`switchTenant`). A tenant kernel refuses is `StepUpNeeded`:
  signing in with that tenant's provider (`startAdding(i, tenant)`) adds it and finishes the
  switch.
- Sign-ins per provider: `providerStates()` says, for each provider the fleet offers, whether
  the session holds a sign-in with it (matched by name to the proof's `idp_id`). With a
  `ProofRevoker` (over `kernel.UserMint.RevokeCredentialProof`), `signOutOf(idpId)` drops that
  provider's sign-ins and keeps the session in the tenant kernel's new access token is for;
  signing out of the last one is `signOut()`, which ends the session. The page offers "Sign out
  of <provider>" for a held provider, "Add <provider>" for the others, and "Sign out of all".
- `mountSignIn` (page.ts): a page that renders the flow into a container under a `Brand`
  (title, subtitle, logo, accent, labels, footer, and what to do once signed in). A clicked
  provider button says "Signing in with <provider>…" (`providerPendingLabel`), or "Adding
  <provider>…", until the browser leaves for the provider, and its fellow buttons are disabled;
  a redirect that fails puts them back, with the error. An app that wants its own markup uses
  `SignIn` and skips this.

The gateway's own console (`../webapp`) is the first consumer, with the default brand;
a company's web app brings its own `Brand` and its own clients.

`npm test` type-checks and runs the tests (node's runner, no browser).

Anyone the fleet's providers vouch for can sign in; what they may then do is their
entitlements, which the fleet decides by tenant membership. Signing in grants nothing.
