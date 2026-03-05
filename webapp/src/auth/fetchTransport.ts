import type { RestTransport } from '../../tacplus/wrappers/restclients/rest_clients';
import { authFetch } from './authFetch';

async function jsonOrThrow(res: Response): Promise<unknown> {
  if (!res.ok) {
    let detail = '';
    try { const j = await res.json(); detail = j?.message || JSON.stringify(j); } catch { /* ignore */ }
    const msg = detail ? `HTTP ${res.status}: ${detail}` : `HTTP ${res.status}`;
    console.error(`[fetchTransport] ${res.url} → ${msg}`);
    throw new Error(msg);
  }
  return res.json();
}

/**
 * Browser implementation of RestTransport using authFetch.
 * Automatically handles service-specific bearer tokens via authFetch.
 */
export const fetchTransport: RestTransport = {
  async getJson(url: string): Promise<unknown> {
    return jsonOrThrow(await authFetch(url));
  },
  async postJson(url: string, body: unknown): Promise<unknown> {
    return jsonOrThrow(await authFetch(url, {
      method: 'POST',
      body: JSON.stringify(body),
    }));
  },
  async putJson(url: string, body: unknown): Promise<unknown> {
    return jsonOrThrow(await authFetch(url, {
      method: 'PUT',
      body: JSON.stringify(body),
    }));
  },
  async patchJson(url: string, body: unknown): Promise<unknown> {
    return jsonOrThrow(await authFetch(url, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }));
  },
  async deleteJson(url: string, body?: unknown): Promise<unknown> {
    return jsonOrThrow(await authFetch(url, {
      method: 'DELETE',
      body: body ? JSON.stringify(body) : undefined,
    }));
  },
  async getStream(url: string, opts?: { signal?: AbortSignal }): Promise<Response> {
    const res = await authFetch(url, { signal: opts?.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res;
  },
  async postStream(url: string, body: unknown, opts?: { signal?: AbortSignal }): Promise<Response> {
    const res = await authFetch(url, { method: 'POST', body: JSON.stringify(body), signal: opts?.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res;
  },
};

/**
 * Unauthenticated transport for pre-login endpoints (e.g., ListProviders, Authorize, Callback).
 */
export const publicTransport: RestTransport = {
  async getJson(url: string): Promise<unknown> {
    return jsonOrThrow(await fetch(url));
  },
  async postJson(url: string, body: unknown): Promise<unknown> {
    return jsonOrThrow(await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }));
  },
  async putJson(url: string, body: unknown): Promise<unknown> {
    return jsonOrThrow(await fetch(url, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }));
  },
  async patchJson(url: string, body: unknown): Promise<unknown> {
    return jsonOrThrow(await fetch(url, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }));
  },
  async deleteJson(url: string, body?: unknown): Promise<unknown> {
    return jsonOrThrow(await fetch(url, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    }));
  },
  async getStream(url: string, opts?: { signal?: AbortSignal }): Promise<Response> {
    const res = await fetch(url, { signal: opts?.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res;
  },
  async postStream(url: string, body: unknown, opts?: { signal?: AbortSignal }): Promise<Response> {
    const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: opts?.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res;
  },
};
