import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { api } from './api';

const AuthCtx = createContext(null);
export const useAuth = () => useContext(AuthCtx);

const RANK = { viewer: 1, analyst: 2, admin: 3 };

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try { setUser(await api.get('/auth/me')); }
    catch { setUser(null); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const login = async (username, password) => {
    const u = await api.post('/auth/login', { username, password });
    setUser(u);
    return u;
  };
  const logout = async () => { try { await api.post('/auth/logout'); } finally { setUser(null); } };

  const can = (minRole) => user && RANK[user.role] >= RANK[minRole];

  return <AuthCtx.Provider value={{ user, loading, login, logout, refresh, can }}>{children}</AuthCtx.Provider>;
}
