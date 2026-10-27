// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

// SignIn's tenant handling against a fake fleet: the session credential's
// proofs say which tenants it vouches for, and the fake mint refuses any other
// with PERMISSION_DENIED, as kernel does (the step-up).
import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import { SignIn, StepUpNeeded, signedInWith, vouchedTenants, type LoginAuth, type SessionTokens } from '../src/flow.ts';

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
