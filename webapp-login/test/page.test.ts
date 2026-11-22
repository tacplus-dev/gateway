// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

// The page in a DOM (happy-dom's: parsed markup, selectors, events, a
// disabled button taking no click, as a browser's) and a SignIn stub whose
// redirect the test resolves or fails.
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { afterEach, beforeEach, test } from 'node:test';
import { Window } from 'happy-dom';
import type { Brand } from '../src/page.ts';
import type { Identity, Provider, ProviderState, SignIn, SignedInWith } from '../src/flow.ts';

// page.ts imports './flow.js', as its consumers' bundlers resolve it; node
// finds the .ts source.
registerHooks({
  resolve: (specifier, context, next) =>
    next(specifier.startsWith('./') ? specifier.replace(/\.js$/, '.ts') : specifier, context),
});
const { mountSignIn } = await import('../src/page.ts');

// A window of its own per test, its document, window and history the globals
// page.ts uses.
let win: Window;
const g = globalThis as Record<string, unknown>;
beforeEach(() => {
  win = new Window({ url: 'https://app.example.com/' });
  g.document = win.document;
  g.window = win;
  g.history = win.history;
});
afterEach(async () => {
  await win.happyDOM.close();
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
  const c = win.document.body.appendChild(win.document.createElement('div')) as unknown as HTMLElement;
  mountSignIn(c, signIn, brand);
  await settled();
  return c;
};

const buttons = (c: HTMLElement, kind: string) => [...c.querySelectorAll<HTMLButtonElement>(`button[data-tp="${kind}"]`)];
const labels = (c: HTMLElement, kind: string) => buttons(c, kind).map((b) => b.textContent);
const disabled = (c: HTMLElement, kind: string) => buttons(c, kind).map((b) => b.disabled);
const error = (c: HTMLElement) => c.querySelector('[data-tp="error"]')?.textContent ?? '';

test('clicking a provider shows it signing in and disables every provider button', async () => {
  const redirect = new Redirect();
  const c = await mount(stub(redirect));
  assert.deepEqual(labels(c, 'p'), ['Continue with Google', 'Continue with Apple']);
  assert.deepEqual(disabled(c, 'p'), [false, false]);

  buttons(c, 'p')[0].click();
  assert.deepEqual(labels(c, 'p'), ['Signing in with Google…', 'Continue with Apple']);
  assert.deepEqual(disabled(c, 'p'), [true, true]);

  // A second click starts no second flow.
  for (const b of buttons(c, 'p')) b.click();
  assert.deepEqual(redirect.calls, [0]);
});

test('a failed redirect returns the providers to normal, with the error', async () => {
  const redirect = new Redirect();
  const c = await mount(stub(redirect));
  buttons(c, 'p')[1].click();
  redirect.fail('oauth unavailable');
  await settled();
  assert.deepEqual(labels(c, 'p'), ['Continue with Google', 'Continue with Apple']);
  assert.deepEqual(disabled(c, 'p'), [false, false]);
  assert.equal(error(c), 'oauth unavailable');

  // And a provider can be tried again, which clears the error.
  buttons(c, 'p')[0].click();
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
  buttons(c, 'p')[0].click();
  assert.deepEqual(labels(c, 'p'), ['Opening Google…', 'Sign in with Apple']);
});

test('the brand idle label alone keeps the default pending label', async () => {
  const redirect = new Redirect();
  const c = await mount(stub(redirect), { title: 'Seatrials', providerLabel: (p) => `Sign in with ${p.name}` });
  buttons(c, 'p')[0].click();
  assert.deepEqual(labels(c, 'p'), ['Signing in with Google…', 'Sign in with Apple']);
});

test('adding a provider shows it adding and disables the add buttons', async () => {
  const redirect = new Redirect();
  const me = { subject: '/users/x1', email: 'p@example.com', tenant: '/tenants/people' };
  const c = await mount(stub(redirect, me, [{ idpId: 'microsoft', email: 'p@example.com' }]));
  assert.deepEqual(labels(c, 'add'), ['Add Google', 'Add Apple']);
  buttons(c, 'add')[1].click();
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
  buttons(c, 'p')[0].click();
  win.dispatchEvent(Object.assign(new win.Event('pageshow'), { persisted: true }));
  await settled();
  assert.deepEqual(labels(c, 'p'), ['Continue with Google', 'Continue with Apple']);
  assert.deepEqual(disabled(c, 'p'), [false, false]);
});
