// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

// SignIn's tenant handling against a fake fleet: the session credential's
// proofs say which tenants it vouches for, and the fake mint refuses any other
// with PERMISSION_DENIED, as kernel does (the step-up).
import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import { SignIn, StepUpNeeded, providerStates, signedInWith, vouchedTenants, type LoginAuth, type SessionTokens } from '../src/flow.ts';

const ALPHA = '/tenants/alpha';
const PEOPLE = '/tenants/people';
const BETA = '/tenants/beta';

class MemoryStorage {
  private readonly m = new Map<string, string>();
  getItem(k: string) { return this.m.get(k) ?? null; }
  setItem(k: string, v: string) { this.m.set(k, v); }
  removeItem(k: string) { this.m.delete(k); }
}

const jwt = (claims: Record<string, unknown>) =>
  `e30.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.sig`;

const credential = (...tenants: string[]) => jwt({
  sub: '/users/x1', namespace: PEOPLE, xid_gen: 1,
  proofs: [{ idp_id: 'google', sub: 'g1', tenants, claims: { email: 'p@example.com' } }],
});

const accessToken = (tenant: string) => jwt({ sub: '/users/x1', email: 'p@example.com', namespace: tenant });

/** The generated MintTokenProvider's part SignIn uses, minting as kernel would. */
class FakeTokens implements SessionTokens {
  /** tenant_namespace of every refresh → access mint, '' for none. */
  readonly requests: string[] = [];
  private tenant: string | null = null;
  constructor(private readonly storage: MemoryStorage) {}
  getRefreshToken() { return this.storage.getItem('w2sm.refresh_token'); }
  setRefreshToken(t: string) { this.storage.setItem('w2sm.refresh_token', t); }
  clear() { this.storage.removeItem('w2sm.refresh_token'); }
  setTenantNamespace(ns: string | null) { this.tenant = ns || null; }
  async provider(): Promise<string> {
    const ns = this.tenant ?? '';
    this.requests.push(ns);
    const refresh = this.getRefreshToken() ?? '';
    if (signedInWith(refresh).length === 0) {
      // A legacy refresh token: refused INVALID_ARGUMENT with a tenant, else its own.
      if (ns) throw Object.assign(new Error('tenant_namespace on a legacy refresh token'), { code: 3 });
      return accessToken(JSON.parse(Buffer.from(refresh.split('.')[1], 'base64url').toString()).namespace);
    }
    const want = ns || PEOPLE;
    if (!vouchedTenants(this.getRefreshToken()).includes(want)) {
      throw Object.assign(new Error(`no live proof vouches for ${want}`), { code: 7 });
    }
    return accessToken(want);
  }
}

/** A provider return carrying `cred` and the first AT, in `firstTenant`. */
const authReturning = (cred: string, firstTenant: string): LoginAuth => ({
  async listProviders() { return [{ name: 'Google', providerIndex: 0 }]; },
  async authorize() { return 'https://idp.example/authorize'; },
  async mintCallbackTokens() { return { refreshToken: cred, accessToken: accessToken(firstTenant) }; },
  async revokeSession() {},
});

let local: MemoryStorage;

beforeEach(() => {
  local = new MemoryStorage();
  Object.assign(globalThis, {
    localStorage: local,
    sessionStorage: new MemoryStorage(),
    history: { replaceState() {} },
    window: { location: { pathname: '/', assign() {} } },
  });
});

/** Signs in through a provider return; returns the page's SignIn and its tokens. */
async function signedIn(cred: string, firstTenant: string) {
  const tokens = new FakeTokens(local);
  const signIn = new SignIn(authReturning(cred, firstTenant), tokens, 'https://fleet.example/');
  await signIn.complete('?code=c&state=s');
  return { signIn, tokens };
}

/** The same browser, page reloaded: a fresh SignIn and provider over the same storage. */
function reloaded(cred: string, firstTenant: string) {
  const tokens = new FakeTokens(local);
  return { signIn: new SignIn(authReturning(cred, firstTenant), tokens, 'https://fleet.example/'), tokens };
}

test('an org sign-in is active in the org, and a refresh names it', async () => {
  const cred = credential(ALPHA, PEOPLE);
  const { signIn, tokens } = await signedIn(cred, ALPHA);
  assert.equal(signIn.activeTenant(), ALPHA);
  assert.equal((await signIn.current())?.tenant, ALPHA);
  assert.deepEqual(tokens.requests, [ALPHA]);
});

test('the org tenant survives a page reload', async () => {
  const cred = credential(ALPHA, PEOPLE);
  await signedIn(cred, ALPHA);
  const { signIn, tokens } = reloaded(cred, ALPHA);
  assert.equal((await signIn.current())?.tenant, ALPHA);
  assert.deepEqual(tokens.requests, [ALPHA]);
});

test('the page lists the tenants the credential vouches for', async () => {
  const { signIn } = await signedIn(credential(ALPHA, PEOPLE), ALPHA);
  assert.deepEqual(signIn.tenants(), [ALPHA, PEOPLE]);
});

test('switching to people and back', async () => {
  const cred = credential(ALPHA, PEOPLE);
  const { signIn, tokens } = await signedIn(cred, ALPHA);
  assert.equal((await signIn.switchTenant(PEOPLE)).tenant, PEOPLE);
  assert.equal(signIn.activeTenant(), PEOPLE);
  assert.equal((await signIn.current())?.tenant, PEOPLE);
  assert.equal(tokens.requests[tokens.requests.length - 1], PEOPLE);

  const again = reloaded(cred, ALPHA);
  assert.equal((await again.signIn.current())?.tenant, PEOPLE, 'the switch survives a reload');

  assert.equal((await again.signIn.switchTenant(ALPHA)).tenant, ALPHA);
  assert.equal((await again.signIn.current())?.tenant, ALPHA);
  assert.equal(again.tokens.requests[again.tokens.requests.length - 1], ALPHA);
});

test('a personal-only sign-in shows only people', async () => {
  const { signIn, tokens } = await signedIn(credential(PEOPLE), PEOPLE);
  assert.deepEqual(signIn.tenants(), [PEOPLE]);
  assert.equal((await signIn.current())?.tenant, PEOPLE);
  assert.deepEqual(tokens.requests, [PEOPLE]);
});

test('a tenant no proof vouches for asks for step-up and keeps the active tenant', async () => {
  const { signIn } = await signedIn(credential(ALPHA, PEOPLE), ALPHA);
  await assert.rejects(signIn.switchTenant(BETA), (e: unknown) => e instanceof StepUpNeeded && e.tenant === BETA);
  assert.equal(signIn.activeTenant(), ALPHA);
  assert.equal((await signIn.current())?.tenant, ALPHA);
});

test('a stepped-up sign-in finishes the switch it was for', async () => {
  const tokens = new FakeTokens(local);
  const merged = credential(ALPHA, PEOPLE, BETA);
  const merger = { async mergePeople() { return merged; } };
  const signIn = new SignIn(authReturning(credential(ALPHA, PEOPLE), ALPHA), tokens, 'https://fleet.example/', merger);
  await signIn.complete('?code=c&state=s');
  await assert.rejects(signIn.switchTenant(BETA), StepUpNeeded);

  // The step-up is adding the tenant's sign-in; the provider returns to a reloaded page.
  await signIn.startAdding(0, BETA);
  const back = new SignIn(authReturning(credential(BETA, PEOPLE), BETA), new FakeTokens(local), 'https://fleet.example/', merger);
  await back.complete('?code=c&state=s');
  assert.equal(back.activeTenant(), BETA);
  assert.equal((await back.current())?.tenant, BETA);
});

test('a legacy refresh token (a tenant IdP login) never names a tenant', async () => {
  const legacy = jwt({ sub: 'u1', namespace: ALPHA });
  const tokens = new FakeTokens(local);
  const signIn = new SignIn(authReturning(legacy, ALPHA), tokens, 'https://fleet.example/');
  await signIn.complete('?code=c&state=s');
  assert.equal((await signIn.current())?.tenant, ALPHA);
  assert.deepEqual(tokens.requests, ['']);
  assert.deepEqual(signIn.tenants(), []);
});

test('signing out forgets the tenant', async () => {
  const { signIn } = await signedIn(credential(ALPHA, PEOPLE), ALPHA);
  await signIn.signOut();
  assert.equal(signIn.activeTenant(), null);
});

// Signing out of one provider: kernel.UserMint.RevokeCredentialProof drops that
// provider's proofs and answers the remaining credential and an access token,
// in the bearer's tenant when a remaining proof vouches it, else people's.

const GOOGLE_P = { name: 'Google', providerIndex: 0 };
const APPLE_P = { name: 'Apple', providerIndex: 1 };

/** A session credential with one proof per [idp_id, ...tenants]. */
const credentialOf = (...proofs: Array<[string, ...string[]]>) => jwt({
  sub: '/users/x1', namespace: PEOPLE, xid_gen: 1,
  proofs: proofs.map(([idp, ...tenants]) => ({ idp_id: idp, sub: `${idp}-1`, tenants, claims: { email: `p@${idp}.example` } })),
});

/** Revokes as kernel does: NOT_FOUND for a provider the credential has no proof of, null for the last. */
class FakeRevoker {
  readonly calls: string[] = [];
  async revokeProof(current: string, idpId: string) {
    this.calls.push(idpId);
    const proofs = JSON.parse(Buffer.from(current.split('.')[1], 'base64url').toString()).proofs as Array<{ idp_id: string; tenants: string[] }>;
    const kept = proofs.filter((p) => p.idp_id !== idpId);
    if (kept.length === proofs.length) throw Object.assign(new Error('no such proof'), { code: 5 });
    if (kept.length === 0) return null;
    const credential = credentialOf(...kept.map((p): [string, ...string[]] => [p.idp_id, ...p.tenants]));
    const active = localStorage.getItem('tp-login-tenant') ?? PEOPLE;
    return { credential, accessToken: accessToken(vouchedTenants(credential).includes(active) ? active : PEOPLE) };
  }
}

/** Signed in with `cred`, the fleet offering Google and Apple, signing out of one allowed. */
async function signedInWithProviders(cred: string, firstTenant: string) {
  const revoked: string[] = [];
  const auth: LoginAuth = {
    ...authReturning(cred, firstTenant),
    async listProviders() { return [GOOGLE_P, APPLE_P]; },
    async revokeSession() { revoked.push('session'); },
  };
  const tokens = new FakeTokens(local);
  const revoker = new FakeRevoker();
  const merger = { async mergePeople() { return cred; } };
  const signIn = new SignIn(auth, tokens, 'https://fleet.example/', merger, revoker);
  await signIn.complete('?code=c&state=s');
  return { signIn, tokens, revoker, revoked };
}

const states = (s: Array<{ provider: { name: string }; held?: string }>) => s.map((p) => [p.provider.name, p.held ?? null]);

test('providerStates: no sign-in held, every provider is one to add', () => {
  assert.deepEqual(states(providerStates([GOOGLE_P, APPLE_P], [])), [['Google', null], ['Apple', null]]);
});

test('the page states each provider: one held', async () => {
  const { signIn } = await signedInWithProviders(credentialOf(['google', ALPHA, PEOPLE]), ALPHA);
  assert.deepEqual(states(await signIn.providerStates()), [['Google', 'google'], ['Apple', null]]);
});

test('the page states each provider: all held', async () => {
  const { signIn } = await signedInWithProviders(credentialOf(['google', ALPHA, PEOPLE], ['apple', PEOPLE]), ALPHA);
  assert.deepEqual(states(await signIn.providerStates()), [['Google', 'google'], ['Apple', 'apple']]);
});

test('the page states each provider: none held (a legacy refresh token)', async () => {
  const { signIn } = await signedInWithProviders(jwt({ sub: 'u1', namespace: ALPHA }), ALPHA);
  assert.deepEqual(states(await signIn.providerStates()), [['Google', null], ['Apple', null]]);
});

test('signing out of one provider keeps the others and the session', async () => {
  const { signIn, revoker, revoked } = await signedInWithProviders(credentialOf(['google', ALPHA, PEOPLE], ['apple', PEOPLE]), ALPHA);
  await signIn.signOutOf('google');
  assert.deepEqual(revoker.calls, ['google']);
  assert.deepEqual(revoked, [], 'the session is not ended');
  assert.deepEqual(signIn.signedInWith().map((s) => s.idpId), ['apple']);
  assert.deepEqual(states(await signIn.providerStates()), [['Google', null], ['Apple', 'apple']]);
  // alpha was vouched only by the Google proof: the session is people's now.
  assert.equal(signIn.activeTenant(), PEOPLE);
  assert.deepEqual(signIn.tenants(), [PEOPLE]);
  assert.equal((await signIn.current())?.tenant, PEOPLE, 'the page is still usable');
});

test('signing out of one provider keeps the tenant a remaining sign-in vouches', async () => {
  const { signIn } = await signedInWithProviders(credentialOf(['google', PEOPLE], ['apple', ALPHA, PEOPLE]), ALPHA);
  await signIn.signOutOf('google');
  assert.equal(signIn.activeTenant(), ALPHA);
  assert.equal((await signIn.current())?.tenant, ALPHA);
});

test('signing out of the last provider is signing out of all', async () => {
  const { signIn, revoker, revoked } = await signedInWithProviders(credentialOf(['google', ALPHA, PEOPLE]), ALPHA);
  await signIn.signOutOf('google');
  assert.deepEqual(revoker.calls, [], 'the session is ended, not trimmed');
  assert.deepEqual(revoked, ['session']);
  assert.equal(await signIn.current(), null);
  assert.equal(signIn.activeTenant(), null);
});

test('a session kernel ends while signing out of one is signed out of all', async () => {
  const { signIn, revoker, revoked } = await signedInWithProviders(credentialOf(['google', PEOPLE], ['apple', PEOPLE]), PEOPLE);
  revoker.revokeProof = async () => null;
  await signIn.signOutOf('google');
  assert.deepEqual(revoked, ['session']);
  assert.equal(await signIn.current(), null);
});
