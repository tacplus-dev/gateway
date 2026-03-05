const ACCESS_TOKEN_KEY = 'access_token';
const REFRESH_TOKEN_KEY = 'refresh_token';
const SERVICE_TOKEN_PREFIX = 'service_token_';

export interface JwtPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  email?: string;
  name?: string;
  [key: string]: unknown;
}

export function parseJwt(token: string): JwtPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

export function isExpired(token: string): boolean {
  const payload = parseJwt(token);
  if (!payload?.exp) return true;
  // 30 second buffer
  return Date.now() / 1000 > payload.exp - 30;
}

export function getStoredToken(): string | null {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getStoredRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function storeTokens(accessToken: string, refreshToken?: string): void {
  localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
  if (refreshToken) {
    localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
  }
}

export function getServiceToken(audience: string): string | null {
  return localStorage.getItem(SERVICE_TOKEN_PREFIX + audience);
}

export function storeServiceToken(audience: string, token: string): void {
  localStorage.setItem(SERVICE_TOKEN_PREFIX + audience, token);
}

export function clearTokens(): void {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  // Clear all service tokens
  const keys = Object.keys(localStorage);
  for (const key of keys) {
    if (key.startsWith(SERVICE_TOKEN_PREFIX)) {
      localStorage.removeItem(key);
    }
  }
}

/** Extract the service name from an API path like /api/fleetwood/v1/dashboard */
export function serviceFromPath(path: string): string | null {
  const match = path.match(/^\/api\/([^/]+)\//);
  return match ? match[1] : null;
}
