// Copyright (c) 2026 Jody Scott
// SPDX-License-Identifier: Apache-2.0

// The gateway's web console: the first consumer of @tacplus-dev/webapp-login,
// under the default brand. It generates its own W2S clients (model/w2sm:
// oauth.Auth and gateway.Mint, declared in proto/clients/webapp.proto) and
// hands them to the library through its two small interfaces; the library
// itself imports no generated code.
import { create } from '@bufbuild/protobuf';
import { SignIn, mountSignIn, type LoginAuth } from '@tacplus-dev/webapp-login';
import { MintTokenProvider, ServiceManager } from '../model/w2sm/index.js';
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

const signIn = new SignIn(auth, tokens, `${window.location.origin}/`);
mountSignIn(document.getElementById('app') as HTMLElement, signIn, { title: 'Sign in' });
