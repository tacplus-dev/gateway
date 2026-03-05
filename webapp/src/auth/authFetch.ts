import { create } from '@bufbuild/protobuf';
import {
  getStoredToken,
  getStoredRefreshToken,
  getServiceToken,
  storeServiceToken,
  storeTokens,
  isExpired,
  serviceFromPath,
} from './tokenUtils';
import { IronMaidenServiceRestClient } from '../../tacplus/wrappers/restclients/rest_clients';
import {
  RefreshTokenRequestSchema,
  ExchangeTokenRequestSchema,
} from '../../tacplus/types/services/ironmaiden/ironmaiden_pb.ts';

// The authFetch transport uses raw fetch (no auth), because the REST client
// is used internally by authFetch to get/exchange tokens — we can't use
// authFetch to implement authFetch.
const rawTransport = {
  async getJson(url: string): Promise<unknown> {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },
  async postJson(url: string, body: unknown): Promise<unknown> {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      let detail = '';
      try { const j = await res.json(); detail = j?.message || JSON.stringify(j); } catch { /* ignore */ }
      const msg = detail ? `HTTP ${res.status}: ${detail}` : `HTTP ${res.status}`;
      console.error(`[authFetch] ${res.url} → ${msg}`);
      if (res.status === 401) throw Object.assign(new Error(msg), { status: 401 });
      throw new Error(msg);
    }
    return res.json();
  },
  async putJson(url: string, body: unknown): Promise<unknown> {
    const res = await fetch(url, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },
  async patchJson(url: string, body: unknown): Promise<unknown> {
    const res = await fetch(url, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },
  async deleteJson(url: string, body?: unknown): Promise<unknown> {
    const res = await fetch(url, { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  },
};

const ironmaiden = new IronMaidenServiceRestClient(rawTransport, '');

// In-flight refresh promises keyed by audience, to avoid duplicate requests.
const inflightRefresh = new Map<string, Promise<string>>();

// In-flight generic token refresh promise.
let inflightGenericRefresh: Promise<void> | null = null;

/**
 * Refresh the generic access token using the stored refresh token.
 */
async function refreshGenericToken(): Promise<void> {
  if (inflightGenericRefresh) return inflightGenericRefresh;

  const refreshToken = getStoredRefreshToken();
  if (!refreshToken) throw new Error('No refresh token available');

  inflightGenericRefresh = ironmaiden
    .refreshToken(create(RefreshTokenRequestSchema, { refreshToken }))
    .then((data) => {
      const token = data.accessToken;
      if (!token) throw new Error('No access_token in refresh response');
      storeTokens(token);
    })
    .catch((err) => {
      if (err?.status === 401 || err?.message?.includes('401')) {
        // Don't clear tokens here — let the caller decide how to handle
        // session expiry. Aggressively clearing tokens causes race conditions
        // where parallel requests all trigger clearTokens() simultaneously.
        throw new Error('Session expired');
      }
      throw err;
    })
    .finally(() => {
      inflightGenericRefresh = null;
    });

  return inflightGenericRefresh;
}

/**
 * Exchange a generic access token for a service-specific access token.
 */
async function refreshServiceToken(audience: string): Promise<string> {
  const existing = inflightRefresh.get(audience);
  if (existing) return existing;

  const promise = (async () => {
    // Ensure we have a valid generic access token first.
    let accessToken = getStoredToken();
    if (!accessToken || isExpired(accessToken)) {
      await refreshGenericToken();
      accessToken = getStoredToken();
    }
    if (!accessToken) throw new Error('No access token available');

    try {
      const data = await ironmaiden.exchangeToken(
        create(ExchangeTokenRequestSchema, { accessToken, audience }),
      );
      const token = data.accessToken;
      if (!token) throw new Error('No access_token in exchange response');
      storeServiceToken(audience, token);
      return token;
    } catch (err: any) {
      if (err?.status === 401 || err?.message?.includes('401')) {
        // Generic token may have been invalidated — try refreshing once.
        await refreshGenericToken();
        const retryToken = getStoredToken();
        if (!retryToken) throw new Error('No access token after refresh');

        const retryData = await ironmaiden.exchangeToken(
          create(ExchangeTokenRequestSchema, { accessToken: retryToken, audience }),
        );
        const token = retryData.accessToken;
        if (!token) throw new Error('No access_token in exchange response');
        storeServiceToken(audience, token);
        return token;
      }
      throw err;
    }
  })().finally(() => {
    inflightRefresh.delete(audience);
  });

  inflightRefresh.set(audience, promise);
  return promise;
}

/**
 * Fetch wrapper that automatically attaches the correct Bearer token.
 */
export async function authFetch(url: string, opts?: RequestInit): Promise<Response> {
  const headers = new Headers(opts?.headers);
  if (!headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const service = serviceFromPath(url);

  if (service) {
    // Get a service-specific token (with correct `aud` claim)
    let token = getServiceToken(service);
    if (!token || isExpired(token)) {
      try {
        token = await refreshServiceToken(service);
      } catch (err) {
        console.error(`Failed to get ${service} token:`, err);
      }
    }
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }
  } else {
    // Use default access token for non-API routes
    let token = getStoredToken();
    if (token && isExpired(token)) {
      try {
        await refreshGenericToken();
        token = getStoredToken();
      } catch (err) {
        console.error('Failed to refresh generic token:', err);
      }
    }
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }
  }

  return fetch(url, { ...opts, headers });
}
