# @tacplus-dev/webapp-login

Sign-in for a tacplus fleet's web app, as a library. Two layers:

- `SignIn` (flow.ts): the oauth flow — providers, start, complete the provider's return,
  current identity, sign out — over two small interfaces the consumer implements with its
  own generated W2S clients (`LoginAuth` over `oauth.Auth`, `SessionTokens` over the
  generated `MintTokenProvider`). The library imports no generated package, so every app's
  model stays its own.
- `mountSignIn` (page.ts): a page that renders the flow into a container under a `Brand`
  (title, subtitle, logo, accent, labels, footer, and what to do once signed in). An app
  that wants its own markup uses `SignIn` and skips this.

The gateway's own console (`../webapp`) is the first consumer, with the default brand;
a company's web app brings its own `Brand` and its own clients.

Anyone the fleet's providers vouch for can sign in; what they may then do is their
entitlements, which the fleet decides by tenant membership. Signing in grants nothing.
