// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

// The sign-in flow of a tacplus fleet, independent of any one generated
// model. A consumer (the gateway's console, a company's web app) generates its
// own W2S clients for oauth.Auth and gateway.Mint and hands them here through
// the two small interfaces below, so this library never imports a generated
// package and every app's model stays its own.
//
// The flow is oauth's: list providers → authorize with the page as the
// callback → the provider sends the browser back with code+state → exchange
// them for tokens → the refresh token is the session; per-service tokens are
// minted from it on demand.
//
// The session token is the kernel's session credential: a set of proofs, one
// per sign-in. Adding a sign-in runs the same provider flow again and then asks
// kernel to make the two credentials one person (UserMint.MergePeople).

export interface Provider {
  name: string;
  providerIndex: number;
}

/** The oauth.Auth calls sign-in needs, as plain values. */
export interface LoginAuth {
  listProviders(): Promise<Provider[]>;
  /** Starts the provider's flow; returns the URL to send the browser to. */
  authorize(providerIndex: number, callbackUrl: string): Promise<string>;
  /** Exchanges the provider's return for tokens; returns the refresh token. */
  mintCallbackTokens(code: string, state: string): Promise<string>;
  revokeSession(postLogoutRedirectUrl: string): Promise<void>;
}

/** The session: the refresh token's home and the mint of tokens from it. The
 * generated w2sm MintTokenProvider satisfies it. */
export interface SessionTokens {
  getRefreshToken(): string | null;
  setRefreshToken(token: string): void;
  clear(): void;
  /** A token for `service` ('' for the access token), minted from the session.
   * The generated TokenProvider's shape: a value or a promise of one. */
  provider(service?: string): string | undefined | Promise<string | undefined>;
}

/** Joins the session's credential with a fresh sign-in's (kernel.UserMint.MergePeople).
 * Returns the joined credential; throws ConfirmNeeded when kernel's warning path
 * applies (the fresh sign-in already belongs to an existing account). */
export interface AccountMerger {
  mergePeople(current: string, added: string, confirm: boolean): Promise<string>;
}

/** Kernel's warning path: the added sign-in belongs to an account with its own history. */
export class ConfirmNeeded extends Error {}

/** One sign-in the session holds, as the credential's proofs record it. */
export interface SignedInWith {
  idpId: string;
  email?: string;
}

/** The proofs a session credential carries; empty for any other token. */
export function signedInWith(credential: string | null): SignedInWith[] {
  if (!credential) return [];
  try {
    const parts = credential.split('.');
    const claims = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>;
    const proofs = Array.isArray(claims.proofs) ? (claims.proofs as Array<Record<string, unknown>>) : [];
    return proofs.map((p) => {
      const c = (p.claims ?? {}) as Record<string, unknown>;
      return { idpId: String(p.idp_id ?? ''), email: typeof c.email === 'string' ? c.email : undefined };
    });
  } catch {
    return [];
  }
}

const ADDING_KEY = 'tp-login-adding';

/** Who is signed in, as the access token says. */
export interface Identity {
  subject: string;
  email?: string;
  tenant: string;
}

/** Reads an Identity from an access token's base64url payload. No signature
 * check: the token came from the fleet's own mint over TLS, and nothing here
 * grants on it; the fleet checks it on every call. */
export function identityFromToken(token: string): Identity {
  const parts = token.split('.');
  if (parts.length < 2) throw new Error('not a JWT');
  const json = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
  const claims = JSON.parse(json) as Record<string, unknown>;
  const str = (k: string) => (typeof claims[k] === 'string' ? (claims[k] as string) : undefined);
  return { subject: str('sub') ?? '', email: str('email'), tenant: str('namespace') ?? '' };
}

/** True when the page was loaded as the provider's redirect back to it. */
export function isCallback(search: string): boolean {
  const params = new URLSearchParams(search);
  return params.has('error') || (params.has('code') && params.has('state'));
}

export class SignIn {
  constructor(
    private readonly auth: LoginAuth,
    private readonly tokens: SessionTokens,
    /** This page's URL, which the provider returns to; must be one the fleet's
     * oauth config allows (allowed_redirect_uri_prefixes). */
    private readonly callbackUrl: string,
    /** Present when the app lets a person add sign-ins to their session. */
    private readonly merger?: AccountMerger,
  ) {}

  /** A fresh sign-in waiting for the person to confirm the merge. */
  private pendingAdded: string | null = null;

  /** Whether this app can add a sign-in to the session. */
  canAdd(): boolean {
    return this.merger !== undefined;
  }

  /** The sign-ins the current session holds. */
  signedInWith(): SignedInWith[] {
    return signedInWith(this.tokens.getRefreshToken());
  }

  /** Sends the browser to a provider to ADD a sign-in to this session. */
  async startAdding(providerIndex: number): Promise<void> {
    sessionStorage.setItem(ADDING_KEY, '1');
    await this.start(providerIndex);
  }

  /** Completes a merge the person confirmed after ConfirmNeeded. */
  async confirmAdding(): Promise<void> {
    const current = this.tokens.getRefreshToken();
    const added = this.pendingAdded;
    this.pendingAdded = null;
    if (!this.merger || !current || !added) throw new Error('Nothing is waiting to be added.');
    this.tokens.setRefreshToken(await this.merger.mergePeople(current, added, true));
  }

  /** Drops a fresh sign-in the person chose not to merge. */
  cancelAdding(): void {
    this.pendingAdded = null;
  }

  providers(): Promise<Provider[]> {
    return this.auth.listProviders();
  }

  /** Sends the browser to the provider. Does not return on success. */
  async start(providerIndex: number): Promise<void> {
    window.location.assign(await this.auth.authorize(providerIndex, this.callbackUrl));
  }

  /** Finishes the provider's return: stores the session and cleans the URL. */
  async complete(search: string): Promise<void> {
    const params = new URLSearchParams(search);
    const error = params.get('error');
    if (error) throw new Error(`Sign-in did not finish (${error}).`);
    const adding = sessionStorage.getItem(ADDING_KEY) !== null;
    sessionStorage.removeItem(ADDING_KEY);
    const refresh = await this.auth.mintCallbackTokens(params.get('code') ?? '', params.get('state') ?? '');
    history.replaceState(null, '', window.location.pathname);
    const current = this.tokens.getRefreshToken();
    if (!adding || !this.merger || !current) {
      this.tokens.setRefreshToken(refresh);
      return;
    }
    // Adding: the session (still the current credential, which is also what
    // authenticates the call) and the fresh sign-in become one person.
    try {
      this.tokens.setRefreshToken(await this.merger.mergePeople(current, refresh, false));
    } catch (err) {
      if (err instanceof ConfirmNeeded) this.pendingAdded = refresh;
      throw err;
    }
  }

  /** The signed-in identity, or null when there is no usable session. */
  async current(): Promise<Identity | null> {
    if (!this.tokens.getRefreshToken()) return null;
    try {
      const token = await Promise.resolve(this.tokens.provider(''));
      return token ? identityFromToken(token) : null;
    } catch {
      return null;
    }
  }

  /** Ends the session on the fleet and forgets it here, whatever the fleet said. */
  async signOut(): Promise<void> {
    try {
      await this.auth.revokeSession(this.callbackUrl);
    } finally {
      this.tokens.clear();
    }
  }
}
