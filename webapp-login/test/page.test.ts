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
import type { AccountSignIn, Identity, Membership, Provider, ProviderState, SignIn, SignedInWith } from '../src/flow.ts';
const { ConfirmNeeded, StepUpNeeded } = await import('../src/flow.ts');

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
  canManageAccount: () => false,
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

const ME = { subject: '/users/x1', email: 'p@example.com', tenant: '/tenants/people' };

test('the signed-in page lists the fleet\'s modules', async () => {
  const c = await mount(stub(new Redirect(), ME), {
    title: 'Seatrials',
    apps: async () => [
      { service: 'pager', title: 'Pager <beta>', version: '0.3.1', path: '/-/apps/pager/' },
      { service: 'tenantecho', title: 'Echo', version: '1.2.0', path: '/-/apps/tenantecho/' },
    ],
  });
  assert.match(c.innerHTML, /<h2>Apps<\/h2>/);
  const links = [...c.innerHTML.matchAll(/<a href="([^"]*)"[^>]*>(.*?)<\/a>/g)].map(([, href, text]) => [href, text]);
  assert.deepEqual(links, [['/-/apps/pager/', 'Pager &lt;beta&gt;'], ['/-/apps/tenantecho/', 'Echo']]);
  assert.match(c.innerHTML, /Subject/);
});

test('without modules, or when they cannot be read, the page has no apps list', async () => {
  for (const apps of [undefined, async () => [], async () => { throw new Error('502'); }]) {
    const c = await mount(stub(new Redirect(), ME), { title: 'Seatrials', apps });
    assert.doesNotMatch(c.innerHTML, /Apps/);
    assert.match(c.innerHTML, /Subject/);
    assert.match(c.innerHTML, /Sign out of all/);
  }
});

// The account screens, over a SignIn that records what the page asks of it.

class Account {
  calls: string[] = [];
  signedIn = true;
  signIns: AccountSignIn[] = [
    { idpId: 'google', subject: 'g-1', addedAtMs: Date.UTC(2026, 9, 1), inSession: true },
    { idpId: 'apple', subject: 'a-<1>', addedAtMs: Date.UTC(2026, 9, 2), inSession: false },
  ];
  memberships: Membership[] = [{ tenant: '/tenants/beta', joinedAtMs: 1, revokedAtMs: 0 }];
}

const withAccount = (account: Account, redirect = new Redirect()) => Object.assign(
  stub(redirect, ME, [{ idpId: 'google', subject: 'g-1', email: 'p@example.com' }]) as unknown as Record<string, unknown>, {
    current: async () => (account.signedIn ? ME : null),
    tenants: () => ['/tenants/people'],
    canManageAccount: () => true,
    linkedAccounts: async () => ({ signIns: account.signIns, memberships: account.memberships }),
    removeSignIn: async (idpId: string, subject: string) => {
      account.calls.push(`remove ${idpId} ${subject}`);
      account.signIns = account.signIns.filter((s) => s.subject !== subject);
    },
    signOutEverywhere: async () => { account.calls.push('everywhere'); account.signedIn = false; },
    deleteAccount: async (confirm: boolean) => {
      account.calls.push(`delete ${confirm}`);
      if (!confirm) throw new ConfirmNeeded('deleting this account removes its 2 sign-in(s); it cannot be undone');
      account.signedIn = false;
    },
    switchTenant: async (tenant: string) => {
      account.calls.push(`switch ${tenant}`);
      throw new StepUpNeeded(tenant, `This session has no sign-in for ${tenant}.`);
    },
    startAdding: (i: number, tenant?: string) => { account.calls.push(`add ${i} for ${tenant}`); return redirect.begin(i); },
    cancelAdding: () => {},
  }) as unknown as SignIn;

test('linked accounts list every sign-in, with Remove on those the session does not hold', async () => {
  const account = new Account();
  const c = await mount(withAccount(account));
  const rows = [...c.querySelectorAll('ul.tp-linked li')].map((li) => li.textContent?.replace(/\s+/g, ' ').trim());
  assert.deepEqual(rows, ['Google g-1 added 2026-10-01 this session', 'Apple a-<1> added 2026-10-02 Remove']);
  assert.deepEqual(buttons(c, 'unlink').map((b) => b.dataset.sub), ['a-<1>']);

  buttons(c, 'unlink')[0].click();
  await settled();
  assert.deepEqual(account.calls, ['remove apple a-<1>']);
  assert.equal(c.querySelectorAll('ul.tp-linked li').length, 1, 'the list is read again');
});

test('sign out everywhere ends the session and shows the providers', async () => {
  const account = new Account();
  const c = await mount(withAccount(account));
  buttons(c, 'everywhere')[0].click();
  await settled();
  assert.deepEqual(account.calls, ['everywhere']);
  assert.deepEqual(labels(c, 'p'), ['Continue with Google', 'Continue with Apple']);
});

test('delete account shows kernel\'s warning and deletes only on the second click', async () => {
  const account = new Account();
  const c = await mount(withAccount(account));
  buttons(c, 'delete')[0].click();
  await settled();
  assert.deepEqual(account.calls, ['delete false']);
  assert.match(c.textContent ?? '', /deleting this account removes its 2 sign-in\(s\); it cannot be undone/);
  assert.equal(buttons(c, 'merge').length, 0, 'not the merge confirmation');

  buttons(c, 'delete-confirm')[0].click();
  await settled();
  assert.deepEqual(account.calls, ['delete false', 'delete true']);
  assert.deepEqual(labels(c, 'p'), ['Continue with Google', 'Continue with Apple']);
});

test('cancelling the delete keeps the account', async () => {
  const account = new Account();
  const c = await mount(withAccount(account));
  buttons(c, 'delete')[0].click();
  await settled();
  buttons(c, 'cancel')[0].click();
  await settled();
  assert.deepEqual(account.calls, ['delete false']);
  assert.match(c.innerHTML, /Subject/);
});

test('a membership the session has no sign-in for can be asked for, and asks for the step-up', async () => {
  const account = new Account();
  const c = await mount(withAccount(account));
  assert.deepEqual(buttons(c, 'switch').map((b) => b.dataset.t), ['/tenants/beta']);
  buttons(c, 'switch')[0].click();
  await settled();
  assert.deepEqual(account.calls, ['switch /tenants/beta']);
  assert.match(c.textContent ?? '', /no sign-in for \/tenants\/beta/);
  assert.deepEqual(labels(c, 'step-up'), ['Sign in with Google', 'Sign in with Apple']);
  buttons(c, 'step-up')[1].click();
  assert.deepEqual(account.calls, ['switch /tenants/beta', 'add 1 for /tenants/beta']);
});

test('without an account manager the page offers no account screens', async () => {
  const c = await mount(stub(new Redirect(), ME));
  for (const kind of ['unlink', 'everywhere', 'delete']) assert.equal(buttons(c, kind).length, 0, kind);
  assert.doesNotMatch(c.innerHTML, /Linked accounts/);
});
