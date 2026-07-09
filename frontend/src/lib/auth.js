/**
 * Centralized auth helpers. Single source of truth for the JWT token key.
 *
 * All frontend components MUST use these helpers instead of touching
 * localStorage directly. This prevents key drift bugs (e.g. `nivx.token`
 * vs `nivx_token`) across the codebase.
 */
const TOKEN_KEY = "nivx_token";

export function getToken() {
  try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
}

export function setToken(token) {
  try { localStorage.setItem(TOKEN_KEY, token); } catch { /* quota */ }
}

export function clearToken() {
  try { localStorage.removeItem(TOKEN_KEY); } catch { /* noop */ }
}

/** Returns `{ Authorization: 'Bearer …' }` if a token exists, else `{}`. */
export function authHeaders() {
  const t = getToken();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

/** For test / debug only. */
export const _TOKEN_KEY = TOKEN_KEY;
