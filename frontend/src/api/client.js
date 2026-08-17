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

  if (response.status === 401) {
    onUnauthorized();
  }

  if (!response.ok) {
    const message = data?.message || data?.error || `Erreur HTTP ${response.status}`;
    throw new Error(message);
  }

  return data;
}

export const api = {
  health: () => request("/actuator/health"),

  login: (username, password) =>
    request("/api/admin/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  listDevices: () => request("/api/admin/devices"),

  getDeviceByDid: (did) => request(`/api/admin/devices/did/${encodeURIComponent(did)}`),

  searchLogs: ({ eventType, did, adminUsername, success, page = 0, size = 20 } = {}) => {
    const params = new URLSearchParams();
    if (eventType) params.set("eventType", eventType);
    if (did) params.set("did", did);
    if (adminUsername) params.set("adminUsername", adminUsername);
    if (success !== undefined && success !== null && success !== "") params.set("success", success);
    params.set("page", page);
    params.set("size", size);
    return request(`/api/admin/logs?${params.toString()}`);
  },
  registerDevice: (payload) =>
    request("/api/admin/devices", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  suspendDevice: (did, reason) =>
    request(`/api/admin/devices/${encodeURIComponent(did)}/suspend`, {
      method: "PATCH",
      body: JSON.stringify({ reason }),
    }),

  reactivateDevice: (did) =>
    request(`/api/admin/devices/${encodeURIComponent(did)}/reactivate`, {
      method: "PATCH",
    }),

  revokeDevice: (did, reason) =>
    request(`/api/admin/devices/${encodeURIComponent(did)}/revoke`, {
      method: "PATCH",
      body: JSON.stringify({ reason }),
    }),
};
