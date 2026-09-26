import { createContext, useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api, onUnauthorized, tokenStore } from '@/lib/api';
import type { AuthResponse, AuthUser, MfaChallenge, UserRole } from '@/lib/types';

export interface AuthContextValue {
  user: AuthUser | null;
  ready: boolean;
  /** Devuelve el reto MFA si la cuenta exige el segundo paso; si no, inicia la sesión. */
  login: (email: string, password: string) => Promise<MfaChallenge | null>;
  /** Segundo paso del login: canjea el token intermedio con el código TOTP o de recuperación. */
  loginMfa: (mfaToken: string, code: string) => Promise<void>;
  logout: () => void;
  /** Guarda la sesión devuelta por la API (p. ej. tras cambiar la contraseña). */
  applySession: (res: AuthResponse) => void;
  /** true si el usuario puede registrar activos, lanzar escaneos y revisar hallazgos. */
  canEdit: boolean;
  hasRole: (...roles: UserRole[]) => boolean;
}

// eslint-disable-next-line react-refresh/only-export-components
export const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(() => (tokenStore.get() ? tokenStore.getUser() : null));
  const [ready, setReady] = useState(false);

  // Al cargar, valida el token guardado contra la API y refresca el usuario.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (tokenStore.get()) {
        try {
          const me = await api<AuthUser>('/auth/me');
          if (!cancelled) {
            tokenStore.setUser(me);
            setUser(me);
          }
        } catch {
          if (!cancelled) setUser(null);
        }
      }
      if (!cancelled) setReady(true);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const off = onUnauthorized(() => setUser(null));
    return () => {
      off();
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const res = await api<AuthResponse | MfaChallenge>('/auth/login', { method: 'POST', json: { email, password } });
    if ('mfaRequired' in res) return res;
    tokenStore.set(res.accessToken);
    tokenStore.setUser(res.user);
    setUser(res.user);
    return null;
  }, []);

  const loginMfa = useCallback(async (mfaToken: string, code: string) => {
    const res = await api<AuthResponse>('/auth/login/mfa', { method: 'POST', json: { mfaToken, code } });
    tokenStore.set(res.accessToken);
    tokenStore.setUser(res.user);
    setUser(res.user);
  }, []);

  const applySession = useCallback((res: AuthResponse) => {
    tokenStore.set(res.accessToken);
    tokenStore.setUser(res.user);
    setUser(res.user);
  }, []);

  const logout = useCallback(() => {
    tokenStore.clear();
    setUser(null);
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      ready,
      login,
      loginMfa,
      logout,
      applySession,
      canEdit: user?.role === 'ADMIN' || user?.role === 'ANALYST',
      hasRole: (...roles) => (user ? roles.includes(user.role) : false),
    }),
    [user, ready, login, loginMfa, logout, applySession],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
