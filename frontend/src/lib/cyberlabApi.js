/**
 * CyberLab API client.
 * All calls hit /api/cyberlab/* on the backend.
 */
const API = process.env.REACT_APP_BACKEND_URL;

async function req(path, opts = {}) {
  const res = await fetch(`${API}/api/cyberlab${path}`, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(opts.headers || {}),
    },
  });
  if (!res.ok) {
    const err = await res.text().catch(() => `${res.status}`);
    throw new Error(err || `HTTP ${res.status}`);
  }
  return res.json();
}

export const listPlugins = () => req("/plugins");
export const listRules = () => req("/rules");

export const runRecipe = (input, recipe) =>
  req("/run", { method: "POST", body: JSON.stringify({ input, recipe }) });

export const autoDecode = (input, opts = {}) =>
  req("/auto-decode", {
    method: "POST",
    body: JSON.stringify({
      input,
      max_depth: opts.max_depth ?? 10,
      include_analysis: opts.include_analysis ?? true,
    }),
  });

export const analyze = (input, autoDecodeFirst = true) =>
  req("/analyze", {
    method: "POST",
    body: JSON.stringify({ input, auto_decode: autoDecodeFirst }),
  });

export const extractIocs = (input) =>
  req("/extract-iocs", { method: "POST", body: JSON.stringify({ input }) });
