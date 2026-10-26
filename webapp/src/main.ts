// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

// The gateway's web console: the first consumer of @tacplus-dev/webapp-login,
// under the default brand. It generates its own W2S clients (model/w2sm:
// oauth.Auth, gateway.Mint and kernel.UserMint, declared in
// proto/clients/webapp.proto) and
// hands them to the library through its two small interfaces; the library
// itself imports no generated code.
import { create } from '@bufbuild/protobuf';
import { ConfirmNeeded, SignIn, mountSignIn, type AccountMerger, type LoginAuth } from '@tacplus-dev/webapp-login';
import { MintTokenProvider, ServiceManager, W2SError } from '../model/w2sm/index.js';
import { MergePeopleRequestSchema } from '../model/types/services/kernel/services/index.js';
import {
  AuthorizeRequestSchema,
  CallbackRequestSchema,
  LogoutRequestSchema,
} from '../model/types/services/oauth/services/index.js';
import { TraceRequestSchema } from '../model/types/sys/trace/index.js';

// Same origin: the gateway serves this page and every route it calls.
const sm = new ServiceManager({ gatewayUrl: '' });
const authClient = sm.grpc().oauth().auth_client();
const tokens = new MintTokenProvider(sm.grpc().gateway().mint_client(), localStorage);
// Calls made as the signed-in person carry tokens minted from the session.
const authed = new ServiceManager({ gatewayUrl: '' }, tokens.provider);
const userMint = authed.grpc().kernel().user_mint_client();

// The generated oauth.Auth client, as the library's LoginAuth.
const auth: LoginAuth = {
  async listProviders() {
    const resp = await authClient.listProviders(create(TraceRequestSchema, {}));
    return resp.providers.map((p) => ({ name: p.name, providerIndex: p.providerIndex }));
  },
  async authorize(providerIndex, callbackUrl) {
    return (await authClient.authorize(create(AuthorizeRequestSchema, { providerIndex, callbackUrl }))).redirectUrl;
  },
  async mintCallbackTokens(code, state) {
    return (await authClient.mintCallbackTokens(create(CallbackRequestSchema, { code, state }))).refreshToken;
  },
  async revokeSession(postLogoutRedirectUrl) {
    await authClient.revokeSession(create(LogoutRequestSchema, { postLogoutRedirectUrl }));
  },
};

// kernel.UserMint.MergePeople, as the library's AccountMerger. FAILED_PRECONDITION
// is kernel's warning path: the added sign-in belongs to an existing account.
const FAILED_PRECONDITION = 9;
const merger: AccountMerger = {
  async mergePeople(current, added, confirm) {
    try {
      const resp = await userMint.mergePeople(create(MergePeopleRequestSchema, {
        credentialA: current, credentialB: added, confirm,
      }));
      return resp.credential?.base64 ?? '';
    } catch (e) {
      if (e instanceof W2SError && e.code === FAILED_PRECONDITION) {
        throw new ConfirmNeeded('That sign-in already belongs to another account. '
          + 'Merging moves that account, and everything in it, into this one.');
      }
      throw e;
    }
  },
};

const signIn = new SignIn(auth, tokens, `${window.location.origin}/`, merger);
mountSignIn(document.getElementById('app') as HTMLElement, signIn, { title: 'Sign in' });
