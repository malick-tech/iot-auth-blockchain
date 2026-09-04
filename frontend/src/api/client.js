const BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8083").replace(/\/$/, "");

let authToken = null;
let onUnauthorized = () => {};

export function setAuthToken(token) {
  authToken = token;
}

export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn;
}

async function request(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }

  const response = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
  });

  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { message: text };
    }
  }

  // Bug 16 fix : n'appeler onUnauthorized (logout automatique) que si on n'est PAS
  // sur l'endpoint de login. Un 401 sur /login est un mauvais mot de passe — pas une
  // session expirée — et ne doit pas déclencher un logout sur une session existante.
  if (response.status === 401 && !path.includes("/auth/login")) {
    onUnauthorized();
  }

  if (!response.ok && !options.returnErrorData) {
    const message = data?.message || data?.error || `Erreur HTTP ${response.status}`;
    throw new Error(message);
  }

  return data;
}

export const api = {
  health: () => request("/actuator/health", { returnErrorData: true }),

  login: (username, password) =>
    request("/api/v1/admin/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  refreshAdminToken: () =>
    request("/api/v1/admin/auth/refresh", { method: "POST" }),

  listDevices: () => request("/api/v1/admin/devices"),

  getDeviceByDid: (did) => request(`/api/v1/admin/devices/did/${encodeURIComponent(did)}`),

  searchLogs: ({ eventType, eventTypes, did, adminUsername, success, page = 0, size = 20 } = {}) => {
    const params = new URLSearchParams();
    if (eventType) params.set("eventType", eventType);
    eventTypes?.forEach((type) => params.append("eventTypes", type));
    if (did) params.set("did", did);
    if (adminUsername) params.set("adminUsername", adminUsername);
    if (success !== undefined && success !== null && success !== "") params.set("success", success);
    params.set("page", page);
    params.set("size", size);
    return request(`/api/v1/admin/logs?${params.toString()}`);
  },
  registerDevice: (payload) =>
    request("/api/v1/admin/devices", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  suspendDevice: (did, reason) =>
    request(`/api/v1/admin/devices/${encodeURIComponent(did)}/suspend`, {
      method: "PATCH",
      body: JSON.stringify({ reason }),
    }),

  reactivateDevice: (did) =>
    request(`/api/v1/admin/devices/${encodeURIComponent(did)}/reactivate`, {
      method: "PATCH",
    }),

  revokeDevice: (did, reason) =>
    request(`/api/v1/admin/devices/${encodeURIComponent(did)}/revoke`, {
      method: "PATCH",
      body: JSON.stringify({ reason }),
    }),

  logout: () =>
    request("/api/v1/admin/auth/logout", { method: "POST" }).catch(() => {
      // Logout côté serveur best-effort : même si l'appel échoue (réseau, token déjà expiré),
      // on nettoie la session locale dans tous les cas.
    }),
};
