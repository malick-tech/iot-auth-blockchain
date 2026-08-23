import { useCallback, useEffect, useRef, useState } from "react";
import { api, setAuthToken, setUnauthorizedHandler } from "./api/client";
import { AuthContext } from "./auth-context";
const SESSION_KEY = "iot-auth-admin-session";
const IDLE_TIMEOUT_MS = 20 * 60 * 1000;

function readSession() {
  try {
    return JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
  } catch {
    return null;
  }
}

function getTokenExpiration(token) {
  try {
    const payload = token.split(".")[1];
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(window.atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="))).exp;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }) {
  const [username, setUsername] = useState(() => readSession()?.username ?? null);
  const [fullName, setFullName] = useState(() => readSession()?.fullName ?? null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const loggingOutRef = useRef(false);

  const logout = useCallback(async () => {
    if (loggingOutRef.current) return;
    loggingOutRef.current = true;
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
    loggingOutRef.current = false;
  }, []);

  useEffect(() => {
    const session = readSession();
    if (session?.token) {
      setAuthToken(session.token);
    }
  }, []);

  useEffect(() => {
    const session = readSession();
    if (!session?.token) return undefined;

    const expiresAt = getTokenExpiration(session.token);
    if (!expiresAt) return undefined;

    let timeout;
    let retryTimeout;
    const refreshToken = async () => {
      try {
        const data = await api.refreshAdminToken();
        setAuthToken(data.token);
        setUsername(data.username || session.username);
        setFullName(data.fullName || session.fullName || data.username || session.username);
        localStorage.setItem(SESSION_KEY, JSON.stringify({
          token: data.token,
          username: data.username || session.username,
          fullName: data.fullName || session.fullName || data.username || session.username,
        }));
      } catch {
        const remainingMs = expiresAt * 1000 - Date.now();
        if (remainingMs > 0) {
          retryTimeout = window.setTimeout(refreshToken, Math.min(30_000, remainingMs));
        } else {
          logout();
        }
      }
    };

    timeout = window.setTimeout(
      refreshToken,
      Math.max(1_000, expiresAt * 1000 - Date.now() - 60_000)
    );

    return () => {
      window.clearTimeout(timeout);
      window.clearTimeout(retryTimeout);
    };
  }, [username, logout]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      logout();
    });
  }, [logout]);

  useEffect(() => {
    if (!username) return undefined;

    let idleTimeout;
    const resetIdleTimeout = () => {
      window.clearTimeout(idleTimeout);
      idleTimeout = window.setTimeout(() => {
        logout();
      }, IDLE_TIMEOUT_MS);
    };
    const activityEvents = ["click", "keydown", "mousemove", "scroll", "touchstart"];

    activityEvents.forEach((eventName) => {
      window.addEventListener(eventName, resetIdleTimeout, { passive: true });
    });
    resetIdleTimeout();

    return () => {
      window.clearTimeout(idleTimeout);
      activityEvents.forEach((eventName) => {
        window.removeEventListener(eventName, resetIdleTimeout);
      });
    };
  }, [username, logout]);

  async function login(user, password) {
    setLoading(true);
    setError(null);
    try {
      const data = await api.login(user, password);
      setAuthToken(data.token);
      setUsername(data.username);
      setFullName(data.fullName || data.username);
      localStorage.setItem(SESSION_KEY, JSON.stringify({
        token: data.token,
        username: data.username,
        fullName: data.fullName || data.username,
      }));
    } catch (e) {
      setError(e.message);
      throw e;
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthContext.Provider value={{ username, fullName, login, logout, loading, error }}>
      {children}
    </AuthContext.Provider>
  );
}

