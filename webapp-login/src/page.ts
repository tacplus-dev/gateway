// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

// The sign-in page: one function that owns a container element and renders
// the flow into it under the consumer's brand. A consumer that wants its own
// markup uses SignIn (flow.ts) directly and never calls this.
import { SignIn, ConfirmNeeded, StepUpNeeded, isCallback, type Identity, type Provider } from './flow.js';

export interface Brand {
  /** The heading, e.g. the product name. */
  title: string;
  /** Under the heading; defaults to the page's hostname. */
  subtitle?: string;
  /** Inline SVG or an <img> tag, rendered above the heading. */
  logoHtml?: string;
  /** Button and link color; any CSS color. */
  accent?: string;
  /** The button label for a provider; defaults to "Continue with <name>". */
  providerLabel?: (p: Provider) => string;
  /** The label a provider's button takes once clicked, until the browser has
   * left for the provider; defaults to "Signing in with <name>…". */
  providerPendingLabel?: (p: Provider) => string;
  /** The mark shown on a provider's button; defaults to providerIcon(p.name). */
  providerIconHtml?: (p: Provider) => string;
  /** Rendered under the providers (terms, help). */
  footerHtml?: string;
  /** Called once someone is signed in; defaults to showing the identity, the
   * tenants the session vouches for with a switch to each, the sign-ins it
   * holds with a sign-out of each provider, buttons to add a provider it does
   * not hold, and sign out of all. */
  onSignedIn?: (identity: Identity, signOut: () => Promise<void>) => void;
}

// The providers' own marks, as each publishes them for sign-in buttons.
const GOOGLE = `<svg viewBox="0 0 48 48" aria-hidden="true"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>`;
const APPLE = `<svg viewBox="0 0 814 1000" aria-hidden="true"><path fill="currentColor" d="M788.1 340.9c-5.8 4.5-108.2 62.2-108.2 190.5 0 148.4 130.3 200.9 134.2 202.2-.6 3.2-20.7 71.9-68.7 141.9-42.8 61.6-87.5 123.1-155.5 123.1s-85.5-39.5-164-39.5c-76.5 0-103.7 40.8-165.9 40.8s-105.6-57-155.5-127C46.7 790.7 0 663 0 541.8c0-194.4 126.4-297.5 250.8-297.5 66.1 0 121.2 43.4 162.7 43.4 39.5 0 101.1-46 176.3-46 28.5 0 130.9 2.6 198.3 99.2zm-234-181.5c31.1-36.9 53.1-88.1 53.1-139.3 0-7.1-.6-14.3-1.9-20.1-50.6 1.9-110.8 33.7-147.1 75.8-28.5 32.4-55.1 83.6-55.1 135.5 0 7.8 1.3 15.6 1.9 18.1 3.2.6 8.4 1.3 13.6 1.3 45.4 0 102.5-30.4 135.5-71.3z"/></svg>`;
const MICROSOFT = `<svg viewBox="0 0 21 21" aria-hidden="true"><rect x="1" y="1" width="9" height="9" fill="#f25022"/><rect x="11" y="1" width="9" height="9" fill="#7fba00"/><rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg>`;

/** The mark for a provider by its configured name or kernel idp_id ("Google",
 * "apple", "Microsoft"...); empty for a provider without a known mark. */
export function providerIcon(name: string): string {
  const n = name.toLowerCase();
  if (n.includes('google')) return GOOGLE;
  if (n.includes('apple')) return APPLE;
  if (n.includes('microsoft')) return MICROSOFT;
  return '';
}

const STYLE = `
.tp-login { font-family: system-ui, sans-serif; width: min(28rem, 92vw); margin: 0 auto; }
.tp-login h1 { font-size: 1.4rem; margin: 0.5rem 0 0.25rem; }
.tp-login h2 { font-size: 1rem; margin: 1.5rem 0 0.5rem; }
.tp-login .tp-sub { opacity: 0.7; font-size: 0.9rem; margin: 0 0 1.5rem; }
.tp-login button { display: block; width: 100%; padding: 0.75rem; margin: 0.5rem 0; font: inherit; cursor: pointer;
  border: 1px solid var(--tp-accent, #333); background: var(--tp-accent, #333); color: #fff; border-radius: 6px; }
.tp-login button.tp-secondary { background: transparent; color: var(--tp-accent, #333); }
.tp-login button.tp-provider { display: flex; align-items: center; justify-content: center; gap: 0.75rem;
  background: #fff; color: #1f1f1f; border-color: #747775; }
.tp-login .tp-icon { display: inline-flex; width: 1.25rem; height: 1.25rem; flex: none; }
.tp-login .tp-icon svg { width: 100%; height: 100%; }
.tp-login ul.tp-signins { list-style: none; padding: 0; margin: 0; }
.tp-login ul.tp-signins li { display: flex; align-items: center; gap: 0.75rem; padding: 0.35rem 0; }
.tp-login ul.tp-signins .tp-who { flex: 1; word-break: break-all; }
.tp-login ul.tp-signins button { display: inline-block; width: auto; margin: 0; padding: 0.35rem 0.75rem; }
.tp-login ul.tp-tenants { list-style: none; padding: 0; margin: 0; }
.tp-login ul.tp-tenants li { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; padding: 0.35rem 0; word-break: break-all; }
.tp-login ul.tp-tenants button { display: inline-block; width: auto; margin: 0; padding: 0.35rem 0.75rem; }
.tp-login .tp-error { color: #b00020; }
.tp-login .tp-error:empty { display: none; }
.tp-login dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1rem; }
.tp-login dt { opacity: 0.7; } .tp-login dd { margin: 0; word-break: break-all; }
.tp-login .tp-footer { opacity: 0.7; font-size: 0.85rem; margin-top: 1.5rem; }
`;

function escape(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c] as string);
}

/** Renders the sign-in flow into `container` and runs it. */
export function mountSignIn(container: HTMLElement, signIn: SignIn, brand: Brand): void {
  if (!document.getElementById('tp-login-style')) {
    const style = document.createElement('style');
    style.id = 'tp-login-style';
    style.textContent = STYLE;
    document.head.appendChild(style);
  }
  container.classList.add('tp-login');
  if (brand.accent) container.style.setProperty('--tp-accent', brand.accent);

  const header = `${brand.logoHtml ?? ''}<h1>${escape(brand.title)}</h1><p class="tp-sub">${escape(brand.subtitle ?? window.location.host)}</p>`;
  const footer = brand.footerHtml ? `<div class="tp-footer">${brand.footerHtml}</div>` : '';
  const render = (body: string) => { container.innerHTML = header + body + footer; };
  const icon = (p: Provider) => (brand.providerIconHtml ?? ((q: Provider) => providerIcon(q.name)))(p);
  const providerButtons = (providers: Provider[], label: (p: Provider) => string, kind: string) =>
    providers.map((p) =>
      `<button class="tp-provider" data-tp="${kind}" data-i="${p.providerIndex}"><span class="tp-icon">${icon(p)}</span>${escape(label(p))}</button>`,
    ).join('');
  // Where a failed redirect says why, beside the buttons it put back.
  const errorLine = '<p class="tp-error" data-tp="error" role="alert"></p>';
  const message = (err: unknown) => (err instanceof Error ? err.message : String(err));
  // A provider button, once clicked, says so until the browser has left for
  // the provider, and every button of its kind is disabled so a second click
  // starts no second flow. A redirect that fails puts them back, with why.
  const onProvider = (providers: Provider[], kind: string, pending: (p: Provider) => string, go: (i: number) => Promise<void>) => {
    const buttons = [...container.querySelectorAll<HTMLButtonElement>(`button[data-tp="${kind}"]`)];
    const error = container.querySelector<HTMLElement>('[data-tp="error"]');
    for (const b of buttons) {
      b.addEventListener('click', () => {
        const i = Number(b.dataset.i);
        const p = providers.find((q) => q.providerIndex === i);
        const idle = b.innerHTML;
        for (const x of buttons) x.disabled = true;
        if (p) b.innerHTML = `<span class="tp-icon">${icon(p)}</span>${escape(pending(p))}`;
        if (error) error.textContent = '';
        go(i).catch((err) => {
          for (const x of buttons) x.disabled = false;
          b.innerHTML = idle;
          if (err instanceof ConfirmNeeded || err instanceof StepUpNeeded || !error) fail(err);
          else error.textContent = message(err);
        });
      });
    }
  };

  const showIdentity = async (me: Identity) => {
    if (brand.onSignedIn) {
      brand.onSignedIn(me, () => signIn.signOut().then(run));
      return;
    }
    const tenants = signIn.tenants().map((t) => t === me.tenant
      ? `<li><strong>${escape(t)}</strong><span>active</span></li>`
      : `<li>${escape(t)}<button class="tp-secondary" data-tp="switch" data-t="${escape(t)}">Switch</button></li>`).join('');
    // Per provider: one the session holds is signed out of (every sign-in with
    // it), one it does not is added.
    const states = await signIn.providerStates();
    const held = new Map<string, string[]>();
    for (const s of signIn.signedInWith()) held.set(s.idpId, [...(held.get(s.idpId) ?? []), s.email ?? s.idpId]);
    const signins = [...held].map(([idpId, who]) => {
      const name = states.find((p) => p.held === idpId)?.provider.name ?? idpId;
      const out = signIn.canSignOutOfOne()
        ? `<button class="tp-secondary" data-tp="out-of" data-idp="${escape(idpId)}">Sign out of ${escape(name)}</button>`
        : '';
      return `<li><span class="tp-icon">${providerIcon(idpId)}</span><span class="tp-who">${escape(who.join(', '))}</span>${out}</li>`;
    }).join('');
    const addable = states.filter((p) => !p.held).map((p) => p.provider);
    const adding = signIn.canAdd() && addable.length > 0
      ? `<h2>Add another sign-in</h2>${providerButtons(addable, (p) => `Add ${p.name}`, 'add')}`
      : '';
    render(`<dl><dt>Subject</dt><dd>${escape(me.subject)}</dd><dt>Email</dt><dd>${escape(me.email ?? '')}</dd><dt>Tenant</dt><dd>${escape(me.tenant)}</dd></dl>
      ${tenants ? `<h2>Tenants</h2><ul class="tp-tenants">${tenants}</ul>` : ''}
      ${signins ? `<h2>Signed in with</h2><ul class="tp-signins">${signins}</ul>` : ''}
      ${adding}${adding ? errorLine : ''}
      <button class="tp-secondary" data-tp="out">Sign out of all</button>`);
    container.querySelector('[data-tp="out"]')?.addEventListener('click', () => signIn.signOut().then(run));
    for (const b of container.querySelectorAll<HTMLButtonElement>('button[data-tp="out-of"]')) {
      b.addEventListener('click', () => signIn.signOutOf(b.dataset.idp ?? '').then(run, fail));
    }
    onProvider(addable, 'add', (p) => `Adding ${p.name}…`, (i) => signIn.startAdding(i));
    for (const b of container.querySelectorAll<HTMLButtonElement>('button[data-tp="switch"]')) {
      b.addEventListener('click', () => signIn.switchTenant(b.dataset.t ?? '').then(run, fail));
    }
  };

  const showProviders = async () => {
    const providers = await signIn.providers();
    if (providers.length === 0) {
      render('<p>No sign-in provider is configured for this fleet.</p>');
      return;
    }
    render(providerButtons(providers, brand.providerLabel ?? ((p: Provider) => `Continue with ${p.name}`), 'p') + errorLine);
    onProvider(providers, 'p', brand.providerPendingLabel ?? ((p: Provider) => `Signing in with ${p.name}…`), (i) => signIn.start(i));
  };

  // Kernel's warning path: the added sign-in already belongs to an account.
  const showConfirm = (message: string) => {
    render(`<p>${escape(message)}</p>
      <button data-tp="merge">Merge the accounts</button>
      <button class="tp-secondary" data-tp="cancel">Cancel</button>`);
    container.querySelector('[data-tp="merge"]')?.addEventListener('click', () =>
      signIn.confirmAdding().then(run, fail));
    container.querySelector('[data-tp="cancel"]')?.addEventListener('click', () => {
      signIn.cancelAdding();
      run();
    });
  };

  // Kernel's step-up: no sign-in in the session vouches for the tenant asked
  // for. Signing in with that tenant's provider adds it and finishes the switch.
  const showStepUp = async (err: StepUpNeeded) => {
    const providers = signIn.canAdd() ? await signIn.providers() : [];
    const buttons = providers.length > 0
      ? providerButtons(providers, (p) => `Sign in with ${p.name}`, 'step-up') + errorLine
      : '';
    render(`<p>${escape(err.message)}</p>${buttons}
      <button class="tp-secondary" data-tp="cancel">Cancel</button>`);
    onProvider(providers, 'step-up', (p) => `Signing in with ${p.name}…`, (i) => signIn.startAdding(i, err.tenant));
    container.querySelector('[data-tp="cancel"]')?.addEventListener('click', () => {
      signIn.cancelAdding();
      run();
    });
  };

  const fail = (err: unknown) => {
    if (err instanceof ConfirmNeeded) {
      showConfirm(err.message);
      return;
    }
    if (err instanceof StepUpNeeded) {
      showStepUp(err).catch(fail);
      return;
    }
    render(`<p class="tp-error">${escape(message(err))}</p><button class="tp-secondary" data-tp="retry">Try again</button>`);
    container.querySelector('[data-tp="retry"]')?.addEventListener('click', () => {
      history.replaceState(null, '', window.location.pathname);
      run();
    });
  };

  const run = () => {
    (async () => {
      render('<p>Loading…</p>');
      if (isCallback(window.location.search)) await signIn.complete(window.location.search);
      const me = await signIn.current();
      if (me) await showIdentity(me);
      else await showProviders();
    })().catch(fail);
  };

  run();
  // Back from the provider's page, a browser may restore this one as it was
  // left, still signing in: show it afresh.
  window.addEventListener('pageshow', (e) => { if (e.persisted) run(); });
}
