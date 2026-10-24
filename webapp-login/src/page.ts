// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

// The sign-in page: one function that owns a container element and renders
// the flow into it under the consumer's brand. A consumer that wants its own
// markup uses SignIn (flow.ts) directly and never calls this.
import { SignIn, isCallback, type Identity, type Provider } from './flow.js';

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
  /** Rendered under the providers (terms, help). */
  footerHtml?: string;
  /** Called once someone is signed in; defaults to showing the identity with a sign-out button. */
  onSignedIn?: (identity: Identity, signOut: () => Promise<void>) => void;
}

const STYLE = `
.tp-login { font-family: system-ui, sans-serif; width: min(28rem, 92vw); margin: 0 auto; }
.tp-login h1 { font-size: 1.4rem; margin: 0.5rem 0 0.25rem; }
.tp-login .tp-sub { opacity: 0.7; font-size: 0.9rem; margin: 0 0 1.5rem; }
.tp-login button { display: block; width: 100%; padding: 0.75rem; margin: 0.5rem 0; font: inherit; cursor: pointer;
  border: 1px solid var(--tp-accent, #333); background: var(--tp-accent, #333); color: #fff; border-radius: 6px; }
.tp-login button.tp-secondary { background: transparent; color: var(--tp-accent, #333); }
.tp-login .tp-error { color: #b00020; }
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

  const showIdentity = (me: Identity) => {
    if (brand.onSignedIn) {
      brand.onSignedIn(me, () => signIn.signOut().then(run));
      return;
    }
    render(`<dl><dt>Subject</dt><dd>${escape(me.subject)}</dd><dt>Email</dt><dd>${escape(me.email ?? '')}</dd><dt>Tenant</dt><dd>${escape(me.tenant)}</dd></dl>
      <button class="tp-secondary" data-tp="out">Sign out</button>`);
    container.querySelector('[data-tp="out"]')?.addEventListener('click', () => signIn.signOut().then(run));
  };

  const showProviders = async () => {
    const providers = await signIn.providers();
    if (providers.length === 0) {
      render('<p>No sign-in provider is configured for this fleet.</p>');
      return;
    }
    const label = brand.providerLabel ?? ((p: Provider) => `Continue with ${p.name}`);
    render(providers.map((p) => `<button data-tp="p" data-i="${p.providerIndex}">${escape(label(p))}</button>`).join(''));
    for (const b of container.querySelectorAll<HTMLButtonElement>('button[data-tp="p"]')) {
      b.addEventListener('click', () => signIn.start(Number(b.dataset.i)).catch(fail));
    }
  };

  const fail = (err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    render(`<p class="tp-error">${escape(msg)}</p><button class="tp-secondary" data-tp="retry">Try again</button>`);
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
      if (me) showIdentity(me);
      else await showProviders();
    })().catch(fail);
  };

  run();
}
