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
//
// Each proof vouches for the tenants its login was routed to (an org login
// [org, people], a personal one [people]). An access token is minted for one
// of them (Mint.MintToken with tenant_namespace); the page keeps that tenant
// across refreshes and reloads, starting from the first access token's (the
// org's when the login routed to one), and lets the person switch. A tenant no
// live proof vouches for is refused PERMISSION_DENIED: the step-up, signing in
// with that tenant's identity provider.

export interface Provider {
  name: string;
  providerIndex: number;
}

/** The oauth.Auth calls sign-in needs, as plain values. */
export interface LoginAuth {
  listProviders(): Promise<Provider[]>;
  /** Starts the provider's flow; returns the URL to send the browser to. */
  authorize(providerIndex: number, callbackUrl: string): Promise<string>;
  /** Exchanges the provider's return for the session's tokens. */
  mintCallbackTokens(code: string, state: string): Promise<CallbackTokens>;
  revokeSession(postLogoutRedirectUrl: string): Promise<void>;
}

/** What a provider's return mints (oauth.CallbackResponse). */
export interface CallbackTokens {
  /** The session credential. */
  refreshToken: string;
  /** The first access token, in the tenant the login was routed to. */
  accessToken: string;
}

/** The session: the refresh token's home and the mint of tokens from it. The
 * generated w2sm MintTokenProvider satisfies it. */
export interface SessionTokens {
  getRefreshToken(): string | null;
  setRefreshToken(token: string): void;
  clear(): void;
  /** The tenant the refresh -> access mint asks for (tenant_namespace); null for none. */
  setTenantNamespace(ns: string | null): void;
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

/** Kernel refused a tenant no live proof vouches for: sign in with that tenant's
 * identity provider (startAdding with the tenant) and the switch completes. */
export class StepUpNeeded extends Error {
  constructor(readonly tenant: string, message: string) {
    super(message);
  }
}

/** One sign-in the session holds, as the credential's proofs record it. */
export interface SignedInWith {
  idpId: string;
  email?: string;
}

/** The proofs a session credential carries; empty for any other token. */
function proofsOf(credential: string | null): Array<Record<string, unknown>> {
  if (!credential) return [];
  try {
    const parts = credential.split('.');
    const claims = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>;
    return Array.isArray(claims.proofs) ? (claims.proofs as Array<Record<string, unknown>>) : [];
  } catch {
    return [];
  }
}

/** The sign-ins a session credential holds; empty for any other token. */
export function signedInWith(credential: string | null): SignedInWith[] {
  return proofsOf(credential).map((p) => {
    const c = (p.claims ?? {}) as Record<string, unknown>;
    return { idpId: String(p.idp_id ?? ''), email: typeof c.email === 'string' ? c.email : undefined };
  });
}

/** The tenants a session credential's proofs vouch for, each once, in proof order. */
export function vouchedTenants(credential: string | null): string[] {
  const tenants = proofsOf(credential).flatMap((p) =>
    Array.isArray(p.tenants) ? p.tenants.filter((t): t is string => typeof t === 'string') : []);
  return [...new Set(tenants)];
}

const ADDING_KEY = 'tp-login-adding';
/** The tenant an adding sign-in is the step-up for. */
const STEP_UP_KEY = 'tp-login-step-up';
/** The tenant the session's access tokens are minted for; kept across reloads. */
const TENANT_KEY = 'tp-login-tenant';
/** The gRPC status kernel refuses an unvouched tenant with, as W2SError.code carries it. */
const PERMISSION_DENIED = 7;

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

  /** The tenants the current session vouches for. */
  tenants(): string[] {
    return vouchedTenants(this.tokens.getRefreshToken());
  }

  /** The tenant the session's access tokens are minted for; null before any sign-in. */
  activeTenant(): string | null {
    return localStorage.getItem(TENANT_KEY);
  }

  private setActiveTenant(tenant: string): void {
    localStorage.setItem(TENANT_KEY, tenant);
    this.mintFor(tenant);
  }

  /** Has the session's mint name `tenant`. Only a session credential is
   * exchanged per tenant: kernel refuses a legacy refresh token (a tenant IdP's
   * login) that names one, and mints it for its own tenant without. */
  private mintFor(tenant: string | null): void {
    this.tokens.setTenantNamespace(proofsOf(this.tokens.getRefreshToken()).length > 0 ? tenant : null);
  }

  /** Mints an access token for `tenant` and makes it the active one. Throws
   * StepUpNeeded, leaving the active tenant as it was, when kernel refuses it. */
  async switchTenant(tenant: string): Promise<Identity> {
    this.mintFor(tenant);
    let token: string | undefined;
    try {
      token = await Promise.resolve(this.tokens.provider(''));
    } catch (err) {
      this.mintFor(this.activeTenant());
      if ((err as { code?: unknown }).code === PERMISSION_DENIED) {
        throw new StepUpNeeded(tenant, `This session has no sign-in for ${tenant}. Sign in with that tenant's identity provider.`);
      }
      throw err;
    }
    if (!token) {
      this.mintFor(this.activeTenant());
      throw new Error(`No access token for ${tenant}.`);
    }
    this.setActiveTenant(tenant);
    return identityFromToken(token);
  }

  /** Sends the browser to a provider to ADD a sign-in to this session; with
   * `forTenant`, the sign-in is the step-up for it and the switch completes on return. */
  async startAdding(providerIndex: number, forTenant?: string): Promise<void> {
    sessionStorage.setItem(ADDING_KEY, '1');
    if (forTenant) sessionStorage.setItem(STEP_UP_KEY, forTenant);
    else sessionStorage.removeItem(STEP_UP_KEY);
    await this.start(providerIndex);
  }

  /** Completes a merge the person confirmed after ConfirmNeeded. */
  async confirmAdding(): Promise<void> {
    const current = this.tokens.getRefreshToken();
    const added = this.pendingAdded;
    this.pendingAdded = null;
    if (!this.merger || !current || !added) throw new Error('Nothing is waiting to be added.');
    this.tokens.setRefreshToken(await this.merger.mergePeople(current, added, true));
    await this.finishStepUp();
  }

  /** Drops a fresh sign-in the person chose not to merge. */
  cancelAdding(): void {
    this.pendingAdded = null;
    sessionStorage.removeItem(STEP_UP_KEY);
  }

  /** Completes the switch an added sign-in was the step-up for. */
  private async finishStepUp(): Promise<void> {
    const tenant = sessionStorage.getItem(STEP_UP_KEY);
    sessionStorage.removeItem(STEP_UP_KEY);
    if (tenant) await this.switchTenant(tenant);
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
    const minted = await this.auth.mintCallbackTokens(params.get('code') ?? '', params.get('state') ?? '');
    const refresh = minted.refreshToken;
    history.replaceState(null, '', window.location.pathname);
    const current = this.tokens.getRefreshToken();
    if (!adding || !this.merger || !current) {
      sessionStorage.removeItem(STEP_UP_KEY);
      this.tokens.setRefreshToken(refresh);
      // A new session starts in the tenant its first access token is for.
      this.setActiveTenant(identityFromToken(minted.accessToken).tenant);
      return;
    }
    // Adding: the session (still the current credential, which is also what
    // authenticates the call) and the fresh sign-in become one person. The
    // active tenant stays, unless the sign-in was a step-up for another.
    try {
      this.tokens.setRefreshToken(await this.merger.mergePeople(current, refresh, false));
      await this.finishStepUp();
    } catch (err) {
      if (err instanceof ConfirmNeeded) this.pendingAdded = refresh;
      throw err;
    }
  }

  /** The signed-in identity, or null when there is no usable session. */
  async current(): Promise<Identity | null> {
    if (!this.tokens.getRefreshToken()) return null;
    this.mintFor(this.activeTenant());
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
      localStorage.removeItem(TENANT_KEY);
      this.tokens.setTenantNamespace(null);
    }
  }
}
