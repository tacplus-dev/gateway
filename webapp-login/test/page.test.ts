// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

// The page against a fake DOM: just enough of one for mountSignIn's markup
// (elements carrying data-tp, their attributes and inner HTML) and a SignIn
// stub whose redirect the test resolves or fails.
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { beforeEach, test } from 'node:test';
import type { Brand } from '../src/page.ts';
import type { Identity, Provider, ProviderState, SignIn, SignedInWith } from '../src/flow.ts';

// page.ts imports './flow.js', as its consumers' bundlers resolve it; node
// finds the .ts source.
registerHooks({
  resolve: (specifier, context, next) =>
    next(specifier.startsWith('./') ? specifier.replace(/\.js$/, '.ts') : specifier, context),
});
const { mountSignIn } = await import('../src/page.ts');

class FakeElement {
  disabled = false;
  innerHTML: string;
  readonly dataset: Record<string, string> = {};
  private readonly listeners: (() => void)[] = [];
  constructor(readonly tag: string, attrs: string, inner: string) {
    this.innerHTML = inner;
    this.disabled = /\sdisabled(\s|=|$)/.test(attrs);
    for (const [, k, v] of attrs.matchAll(/data-([a-z]+)="([^"]*)"/g)) this.dataset[k] = v;
  }
  get textContent() { return this.innerHTML.replace(/<[^>]*>/g, ''); }
  set textContent(s: string) { this.innerHTML = s; }
  addEventListener(_: string, f: () => void) { this.listeners.push(f); }
  click() { if (!this.disabled) for (const f of this.listeners) f(); }
}

class FakeContainer {
  readonly classList = { add() {} };
  readonly style = { setProperty() {} };
  private html = '';
  private elements: FakeElement[] = [];
  get innerHTML() { return this.html; }
  set innerHTML(html: string) {
    this.html = html;
    this.elements = [...html.matchAll(/<(button|p)(\s[^>]*data-tp="[^"]*"[^>]*)>(.*?)<\/\1>/gs)]
      .map(([, tag, attrs, inner]) => new FakeElement(tag, attrs, inner));
  }
  querySelectorAll(sel: string): FakeElement[] {
    const m = /^(\w+)?\[data-tp="([^"]*)"\]$/.exec(sel);
    if (!m) throw new Error(`fake DOM: unsupported selector ${sel}`);
    return this.elements.filter((e) => (!m[1] || e.tag === m[1]) && e.dataset.tp === m[2]);
  }
  querySelector(sel: string): FakeElement | null {
    return this.querySelectorAll(sel)[0] ?? null;
  }
}

const g = globalThis as Record<string, unknown>;
const pageListeners = new Map<string, ((e: { persisted: boolean }) => void)[]>();
beforeEach(() => {
  pageListeners.clear();
  g.document = { getElementById: () => ({}), head: { appendChild() {} }, createElement: () => ({}) };
  g.window = {
    location: { host: 'app.example.com', search: '', pathname: '/' },
    addEventListener: (type: string, f: (e: { persisted: boolean }) => void) =>
      pageListeners.set(type, [...(pageListeners.get(type) ?? []), f]),
  };
  g.history = { replaceState() {} };
});

const GOOGLE: Provider = { name: 'Google', providerIndex: 0 };
const APPLE: Provider = { name: 'Apple', providerIndex: 1 };

/** A redirect the test settles: start/startAdding wait on it. */
class Redirect {
  calls: number[] = [];
  private settle: { resolve: () => void; reject: (e: Error) => void } | null = null;
  begin(i: number): Promise<void> {
    this.calls.push(i);
    return new Promise((resolve, reject) => { this.settle = { resolve, reject }; });
  }
  fail(message: string) { this.settle?.reject(new Error(message)); }
}

const stub = (redirect: Redirect, me: Identity | null = null, held: SignedInWith[] = []) => ({
  providers: async () => [GOOGLE, APPLE],
  current: async () => me,
  start: (i: number) => redirect.begin(i),
  startAdding: (i: number) => redirect.begin(i),
  tenants: () => [],
  signedInWith: () => held,
  providerStates: async (): Promise<ProviderState[]> =>
    [GOOGLE, APPLE].map((provider) => ({ provider, held: held.find((s) => s.idpId === provider.name.toLowerCase())?.idpId })),
  canAdd: () => true,
  canSignOutOfOne: () => false,
}) as unknown as SignIn;

const settled = () => new Promise((r) => setTimeout(r, 0));

const mount = async (signIn: SignIn, brand: Brand = { title: 'Seatrials' }) => {
  const c = new FakeContainer();
  mountSignIn(c as unknown as HTMLElement, signIn, brand);
  await settled();
  return c;
};

const labels = (c: FakeContainer, kind: string) => c.querySelectorAll(`button[data-tp="${kind}"]`).map((b) => b.textContent);
const disabled = (c: FakeContainer, kind: string) => c.querySelectorAll(`button[data-tp="${kind}"]`).map((b) => b.disabled);
const error = (c: FakeContainer) => c.querySelector('[data-tp="error"]')?.textContent ?? '';

test('clicking a provider shows it signing in and disables every provider button', async () => {
  const redirect = new Redirect();
  const c = await mount(stub(redirect));
  assert.deepEqual(labels(c, 'p'), ['Continue with Google', 'Continue with Apple']);
  assert.deepEqual(disabled(c, 'p'), [false, false]);

  c.querySelectorAll('button[data-tp="p"]')[0].click();
  assert.deepEqual(labels(c, 'p'), ['Signing in with Google…', 'Continue with Apple']);
  assert.deepEqual(disabled(c, 'p'), [true, true]);

  // A second click starts no second flow.
  for (const b of c.querySelectorAll('button[data-tp="p"]')) b.click();
  assert.deepEqual(redirect.calls, [0]);
});

test('a failed redirect returns the providers to normal, with the error', async () => {
  const redirect = new Redirect();
  const c = await mount(stub(redirect));
  c.querySelectorAll('button[data-tp="p"]')[1].click();
  redirect.fail('oauth unavailable');
  await settled();
  assert.deepEqual(labels(c, 'p'), ['Continue with Google', 'Continue with Apple']);
  assert.deepEqual(disabled(c, 'p'), [false, false]);
  assert.equal(error(c), 'oauth unavailable');

  // And a provider can be tried again, which clears the error.
  c.querySelectorAll('button[data-tp="p"]')[0].click();
  assert.deepEqual(redirect.calls, [1, 0]);
  assert.equal(error(c), '');
});

test('the brand labels both the idle and the pending button', async () => {
  const redirect = new Redirect();
  const c = await mount(stub(redirect), {
    title: 'Seatrials',
    providerLabel: (p) => `Sign in with ${p.name}`,
    providerPendingLabel: (p) => `Opening ${p.name}…`,
  });
  assert.deepEqual(labels(c, 'p'), ['Sign in with Google', 'Sign in with Apple']);
  c.querySelectorAll('button[data-tp="p"]')[0].click();
  assert.deepEqual(labels(c, 'p'), ['Opening Google…', 'Sign in with Apple']);
});

test('the brand idle label alone keeps the default pending label', async () => {
  const redirect = new Redirect();
  const c = await mount(stub(redirect), { title: 'Seatrials', providerLabel: (p) => `Sign in with ${p.name}` });
  c.querySelectorAll('button[data-tp="p"]')[0].click();
  assert.deepEqual(labels(c, 'p'), ['Signing in with Google…', 'Sign in with Apple']);
});

test('adding a provider shows it adding and disables the add buttons', async () => {
  const redirect = new Redirect();
  const me = { subject: '/users/x1', email: 'p@example.com', tenant: '/tenants/people' };
  const c = await mount(stub(redirect, me, [{ idpId: 'microsoft', email: 'p@example.com' }]));
  assert.deepEqual(labels(c, 'add'), ['Add Google', 'Add Apple']);
  c.querySelectorAll('button[data-tp="add"]')[1].click();
  assert.deepEqual(labels(c, 'add'), ['Add Google', 'Adding Apple…']);
  assert.deepEqual(disabled(c, 'add'), [true, true]);

  redirect.fail('no route');
  await settled();
  assert.deepEqual(labels(c, 'add'), ['Add Google', 'Add Apple']);
  assert.deepEqual(disabled(c, 'add'), [false, false]);
  assert.equal(error(c), 'no route');
});

test('coming back to the page from the cache shows it afresh, not still signing in', async () => {
  const redirect = new Redirect();
  const c = await mount(stub(redirect));
  c.querySelectorAll('button[data-tp="p"]')[0].click();
  for (const f of pageListeners.get('pageshow') ?? []) f({ persisted: true });
  await settled();
  assert.deepEqual(labels(c, 'p'), ['Continue with Google', 'Continue with Apple']);
  assert.deepEqual(disabled(c, 'p'), [false, false]);
});
