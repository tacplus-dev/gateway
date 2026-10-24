// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

// The gateway's web console, today the sign-in page. Everything it does goes
// through the generated W2S clients (model/w2sm): oauth.Auth for the sign-in
// itself and gateway.Mint for per-service tokens. The flow is oauth's:
// ListProviders → Authorize(provider, this page as the callback) → the
// provider sends the browser back here with code+state → MintCallbackTokens →
// the refresh token is kept in localStorage by the generated MintTokenProvider,
// which mints every later per-service token from it.
import { create } from '@bufbuild/protobuf';
import { MintTokenProvider, ServiceManager } from '../model/w2sm/index.js';
import {
  AuthorizeRequestSchema,
  CallbackRequestSchema,
  LogoutRequestSchema,
} from '../model/types/services/oauth/services/index.js';
import { TraceRequestSchema } from '../model/types/sys/trace/index.js';
import { TokenWrapper } from '../model/chassis/token/index.js';

// Same origin: the gateway serves this page and every route it calls.
const sm = new ServiceManager({ gatewayUrl: '' });
const auth = sm.grpc().oauth().auth_client();
const tokens = new MintTokenProvider(sm.grpc().gateway().mint_client(), localStorage);

const app = document.getElementById('app') as HTMLElement;
const callbackUrl = `${window.location.origin}/`;

function render(html: string): void {
  app.innerHTML = `<h1>Sign in</h1><p class="host">${window.location.host}</p>${html}`;
}

function escape(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c] as string);
}

function fail(err: unknown): void {
  const msg = err instanceof Error ? err.message : String(err);
  render(`<p class="error">${escape(msg)}</p><button id="retry">Try again</button>`);
  document.getElementById('retry')?.addEventListener('click', () => {
    history.replaceState(null, '', '/');
    void main();
  });
}

/** Who the current session is, from a token minted for this very page. */
async function whoAmI(): Promise<TokenWrapper | null> {
  if (!tokens.getRefreshToken()) return null;
  try {
    const token = await tokens.provider('');
    return token ? TokenWrapper.parse(token) : null;
  } catch {
    return null;
  }
}

function showSignedIn(tw: TokenWrapper): void {
  const email = tw.getCustomField('email') ?? '';
  render(`
    <dl>
      <dt>Subject</dt><dd>${escape(tw.getSubject())}</dd>
      <dt>Email</dt><dd>${escape(email)}</dd>
      <dt>Tenant</dt><dd>${escape(tw.getNamespace())}</dd>
    </dl>
    <button id="out">Sign out</button>`);
  document.getElementById('out')?.addEventListener('click', async () => {
    try {
      await auth.revokeSession(create(LogoutRequestSchema, { postLogoutRedirectUrl: callbackUrl }));
    } finally {
      tokens.clear();
      void main();
    }
  });
}

async function showProviders(): Promise<void> {
  const resp = await auth.listProviders(create(TraceRequestSchema, {}));
  if (resp.providers.length === 0) {
    render('<p>No sign-in provider is configured for this fleet.</p>');
    return;
  }
  render(resp.providers
    .map((p) => `<button data-provider="${p.providerIndex}">Continue with ${escape(p.name)}</button>`)
    .join(''));
  for (const button of app.querySelectorAll<HTMLButtonElement>('button[data-provider]')) {
    button.addEventListener('click', async () => {
      try {
        const index = Number(button.dataset.provider);
        const r = await auth.authorize(create(AuthorizeRequestSchema, { providerIndex: index, callbackUrl }));
        window.location.assign(r.redirectUrl);
      } catch (err) {
        fail(err);
      }
    });
  }
}

async function completeCallback(params: URLSearchParams): Promise<void> {
  const error = params.get('error');
  if (error) throw new Error(`Sign-in did not finish (${error}).`);
  const resp = await auth.mintCallbackTokens(create(CallbackRequestSchema, {
    code: params.get('code') ?? '',
    state: params.get('state') ?? '',
  }));
  tokens.setRefreshToken(resp.refreshToken);
  history.replaceState(null, '', '/');
}

async function main(): Promise<void> {
  try {
    const params = new URLSearchParams(window.location.search);
    if (params.has('error') || (params.has('code') && params.has('state'))) {
      await completeCallback(params);
    }
    const me = await whoAmI();
    if (me) showSignedIn(me);
    else await showProviders();
  } catch (err) {
    fail(err);
  }
}

void main();
