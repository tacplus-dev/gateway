import { createContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import { create } from '@bufbuild/protobuf';
import {
  getStoredToken,
  getStoredRefreshToken,
  isExpired,
  clearTokens,
  storeTokens,
  storeServiceToken,
  parseJwt,
  type JwtPayload,
} from './tokenUtils';
import { authFetch } from './authFetch';
import { publicTransport } from './fetchTransport';
import { IronMaidenServiceRestClient } from '../../tacplus/wrappers/restclients/rest_clients';
import { CallbackRequestSchema, RefreshTokenRequestSchema } from '../../tacplus/types/services/ironmaiden/ironmaiden_pb.ts';

const ironmaiden = new IronMaidenServiceRestClient(publicTransport, '');

export interface AuthState {
  isAuthenticated: boolean;
  user: JwtPayload | null;
  accessToken: string | null;
  loading: boolean;
  login: () => void;
  logout: () => void;
  authFetch: typeof authFetch;
  setTokens: (accessToken: string, refreshToken?: string) => void;
  /** Get a service-specific access token using the refresh token. */
  getServiceToken: (audience: string) => Promise<string>;
}

export const AuthContext = createContext<AuthState>({
  isAuthenticated: false,
  user: null,
  accessToken: null,
  loading: true,
  login: () => {},
  logout: () => {},
  authFetch,
  setTokens: () => {},
  getServiceToken: () => Promise.reject(new Error('not initialized')),
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [user, setUser] = useState<JwtPayload | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');

    if (code && state) {
      // OAuth callback — exchange code for tokens
      ironmaiden.callback(create(CallbackRequestSchema, { code, state }))
        .then((data) => {
          const at = data.accessToken;
          const rt = data.refreshToken;
          if (at) {
            storeTokens(at, rt);
            setAccessToken(at);
            setUser(parseJwt(at));
          }
          window.history.replaceState({}, '', window.location.pathname);
        })
        .catch((err) => {
          console.error('OAuth callback failed:', err);
          window.history.replaceState({}, '', window.location.pathname);
        })
        .finally(() => setLoading(false));
      return;
    }

    const token = getStoredToken();
    if (token && !isExpired(token)) {
      setAccessToken(token);
      setUser(parseJwt(token));
    }
    setLoading(false);
  }, []);

  const login = useCallback(() => {
    window.location.href = '/login';
  }, []);

  const logout = useCallback(() => {
    clearTokens();
    setAccessToken(null);
    setUser(null);
    window.location.href = '/login';
  }, []);

  const handleSetTokens = useCallback((access: string, refresh?: string) => {
    storeTokens(access, refresh);
    setAccessToken(access);
    setUser(parseJwt(access));
  }, []);

  const getServiceTokenFn = useCallback(async (audience: string): Promise<string> => {
    const refreshToken = getStoredRefreshToken();
    if (!refreshToken) throw new Error('No refresh token');

    const data = await ironmaiden.refreshToken(
      create(RefreshTokenRequestSchema, { refreshToken, audience }),
    );
    const token = data.accessToken;
    if (!token) throw new Error('No access_token in response');

    storeServiceToken(audience, token);
    return token;
  }, []);

  const isAuthenticated = !!accessToken && !isExpired(accessToken);

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        user,
        accessToken,
        loading,
        login,
        logout,
        authFetch,
        setTokens: handleSetTokens,
        getServiceToken: getServiceTokenFn,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
