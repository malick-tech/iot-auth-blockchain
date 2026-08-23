import { useCallback, useEffect, useState } from "react";
import { api, setAuthToken, setUnauthorizedHandler } from "./api/client";
import { AuthContext } from "./auth-context";
const SESSION_KEY = "iot-auth-admin-session";

function readSession() {
  try {
    return JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
  } catch {
    return null;
  }
}

export function AuthProvider({ children }) {
  const [username, setUsername] = useState(() => readSession()?.username ?? null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const logout = useCallback(async () => {
    // Bug 15 fix : invalider le token côté serveur avant de nettoyer la session locale.
    // L'appel est best-effort : si le réseau est down ou le token déjà expiré,
    // on nettoie quand même la session locale.
    try {
      await api.logout();
    } catch {
      // ignoré intentionnellement
    }
    setAuthToken(null);
    setUsername(null);
    localStorage.removeItem(SESSION_KEY);
  }, []);

  useEffect(() => {
    const session = readSession();
    if (session?.token) {
      setAuthToken(session.token);
    }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      logout();
    });
  }, [logout]);

  async function login(user, password) {
    setLoading(true);
    setError(null);
    try {
      const data = await api.login(user, password);
      setAuthToken(data.token);
      setUsername(data.username);
      localStorage.setItem(SESSION_KEY, JSON.stringify({
        token: data.token,
        username: data.username,
      }));
    } catch (e) {
      setError(e.message);
      throw e;
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthContext.Provider value={{ username, login, logout, loading, error }}>
      {children}
    </AuthContext.Provider>
  );
}

