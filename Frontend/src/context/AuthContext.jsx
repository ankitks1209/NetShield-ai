import { useCallback, useEffect, useState } from 'react';
import { AuthContext } from './auth';
import { apiFetch } from '../services/api';

export const AuthProvider = ({ children }) => {
  const [session, setSession] = useState(() => ({ token: localStorage.getItem('token'), user: null, verified: false }));
  const logout = useCallback(() => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_avatar');
    setSession({ token: null, user: null, verified: false });
  }, []);

  useEffect(() => {
    window.addEventListener('netshield:unauthorized', logout);
    return () => window.removeEventListener('netshield:unauthorized', logout);
  }, [logout]);

  useEffect(() => {
    if (!session.token || session.verified) return;
    const controller = new AbortController();
    apiFetch('/api/auth/me', { signal: controller.signal })
      .then(response => response.json())
      .then(data => {
        if (!controller.signal.aborted) {
          setSession(previous => ({ ...previous, user: data.user, verified: true }));
        }
      })
      .catch(error => {
        if (error.name !== 'AbortError') logout();
      });
    return () => controller.abort();
  }, [session.token, session.verified, logout]);

  const login = (token, user) => {
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(user));
    setSession({ token, user, verified: true });
  };
  return <AuthContext.Provider value={{ ...session, login, logout }}>{children}</AuthContext.Provider>;
};
