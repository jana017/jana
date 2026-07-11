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

/** Refine — deterministic, offline-safe input repair (no LLM). */
export const refinePayload = (input) =>
  req("/refine", { method: "POST", body: JSON.stringify({ input }) });
/** Diagnose — dry-run report of every repair Troubleshoot could apply. */
export const diagnosePayload = (input) =>
  req("/diagnose", { method: "POST", body: JSON.stringify({ input }) });
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

export const detectFormat = (input) =>
  req("/detect-format", { method: "POST", body: JSON.stringify({ input }) });

export const autoInvestigate = (input, opts = {}) => {
  const sid = getSessionId();
  return req(`/auto-investigate?session_id=${sid}`, {
    method: "POST",
    body: JSON.stringify({
      input,
      max_depth: opts.max_depth ?? 10,
      include_ai: opts.include_ai ?? true,
      format_hint: opts.format_hint ?? null,
    }),
  });
};

export const processTree = (input, format) =>
  req("/process-tree", { method: "POST", body: JSON.stringify({ input, format: format ?? null }) });

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

// CyberLab in-page OSINT enrichment (bulk) — 20 IOC cap, depth = free|comprehensive|ai.
export const enrichIocs = (values, depth = "comprehensive") =>
  req("/enrich-iocs", { method: "POST", body: JSON.stringify({ values, depth }) });

// One-click report download in any format. Server generates the file; we save
// it to disk via a blob-URL anchor click.
export const downloadReport = async (format, payload) => {
  const paths = {
    pdf: "/export/pdf",
    csv: "/export/csv",
    json: "/export/json",
    markdown: "/export/markdown",
  };
  const path = paths[format];
  if (!path) throw new Error(`Unsupported format: ${format}`);
  const res = await fetch(`${API}/api/cyberlab${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`${format.toUpperCase()} export failed: ${res.status}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const ext = format === "markdown" ? "md" : format;
  const a = document.createElement("a");
  a.href = url;
  a.download = `nivx-cyberlab-report-${ts}.${ext}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
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
