import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { api, setUnauthenticatedHandler } from './api.js';

const AuthContext = createContext(null);
const ConfigContext = createContext(null);

export function AppProviders({ children }) {
  const [me, setMe] = useState({ status: 'loading', user: null, entitlement: null });
  const [config, setConfig] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const r = await api.get('/auth/me');
      setMe({ status: 'signed_in', user: r.user, entitlement: r.entitlement });
      return r;
    } catch (e) {
      setMe({ status: e.status === 401 ? 'signed_out' : 'error', user: null, entitlement: null, error: e });
      return null;
    }
  }, []);

  useEffect(() => {
    setUnauthenticatedHandler(() => setMe({ status: 'signed_out', user: null, entitlement: null }));
    refresh();
    api.get('/config').then(setConfig).catch(() => setConfig({ unavailable: true }));
  }, [refresh]);

  const value = useMemo(
    () => ({
      ...me,
      refresh,
      async login(email, password) {
        await api.post('/auth/login', { email, password });
        return refresh();
      },
      async register(email, password, displayName) {
        await api.post('/auth/register', { email, password, displayName: displayName || undefined });
        return refresh();
      },
      async logout() {
        try {
          await api.post('/auth/logout', {});
        } finally {
          setMe({ status: 'signed_out', user: null, entitlement: null });
        }
      },
    }),
    [me, refresh]
  );
  return (
    <ConfigContext.Provider value={config}>
      <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
    </ConfigContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
export const useConfig = () => useContext(ConfigContext);

export function RequireAuth({ children }) {
  const auth = useAuth();
  const loc = useLocation();
  if (auth.status === 'loading') return <div className="boot" role="status">Loading FootprintX…</div>;
  if (auth.status === 'error') {
    return (
      <div className="boot" role="alert">
        <p>{auth.error?.message || 'FootprintX is unavailable right now.'}</p>
        <button className="btn" onClick={auth.refresh}>Try again</button>
      </div>
    );
  }
  if (auth.status !== 'signed_in') return <Navigate to={`/login?next=${encodeURIComponent(loc.pathname + loc.search)}`} replace />;
  return children;
}
