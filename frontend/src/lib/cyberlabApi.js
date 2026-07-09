const API = process.env.REACT_APP_BACKEND_URL;

/** Persistent session-id used for session-scoped custom rules. */
function getSessionId() {
  try {
    let sid = localStorage.getItem("nivx.cyberlab.sid");
    if (!sid) {
      sid = (crypto.randomUUID?.() || Math.random().toString(36).slice(2)).replace(/-/g, "").slice(0, 12);
      localStorage.setItem("nivx.cyberlab.sid", sid);
    }
    return sid;
  } catch { return "anon"; }
}

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
export const listRules = (sessionId) => req(sessionId ? `/rules?session_id=${sessionId}` : "/rules");

export const runRecipe = (input, recipe) =>
  req("/run", { method: "POST", body: JSON.stringify({ input, recipe }) });

export const autoDecode = (input, opts = {}) => {
  const sid = getSessionId();
  return req(`/auto-decode?session_id=${sid}`, {
    method: "POST",
    body: JSON.stringify({
      input,
      max_depth: opts.max_depth ?? 10,
      include_analysis: opts.include_analysis ?? true,
    }),
  });
};

export const analyze = (input, autoDecodeFirst = true) => {
  const sid = getSessionId();
  return req(`/analyze?session_id=${sid}`, {
    method: "POST",
    body: JSON.stringify({ input, auto_decode: autoDecodeFirst }),
  });
};

export const extractIocs = (input) =>
  req("/extract-iocs", { method: "POST", body: JSON.stringify({ input }) });

// Phase 4
export const runAiAnalysis = (payload) =>
  req("/ai-analysis", { method: "POST", body: JSON.stringify(payload) });

export const createShare = (payload) =>
  req("/share", { method: "POST", body: JSON.stringify(payload) });

export const fetchShare = (id) => req(`/share/${id}`);

export const exportPdf = async (payload) => {
  const res = await fetch(`${API}/api/cyberlab/export/pdf`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`PDF export failed: ${res.status}`);
  return res.blob();
};

export const exportMarkdown = async (payload) => {
  const res = await fetch(`${API}/api/cyberlab/export/markdown`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Markdown export failed: ${res.status}`);
  return res.text();
};

export const listSessionRules = () => {
  const sid = getSessionId();
  return req(`/session-rules?session_id=${sid}`);
};

export const addSessionRule = (rule) => {
  const sid = getSessionId();
  return req(`/session-rules?session_id=${sid}`, {
    method: "POST",
    body: JSON.stringify(rule),
  });
};

export const deleteSessionRule = (id) => {
  const sid = getSessionId();
  return req(`/session-rules/${id}?session_id=${sid}`, { method: "DELETE" });
};

export { getSessionId };
