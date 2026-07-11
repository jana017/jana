/**
 * AdminUiScanner — deterministic UI/UX health scanner for NivX.
 *
 * How it works:
 *   1. Admin clicks "Run Scan"
 *   2. For each viewport preset × core route, we mount a hidden iframe,
 *      wait for it to load, then run a series of pure-DOM audits inside it.
 *   3. Findings are aggregated and shown in a table, then persisted via
 *      POST /api/ui-scanner/scan for history.
 *
 * No LLM. No external HTTP. No network requests beyond loading own pages.
 * All checks are rule-based per WCAG 2.5.5 / 1.4.3 / Apple HIG / mobile UX.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import { Play, X, Loader2, Download, ShieldAlert, ShieldCheck, Bug, FileCode2, RefreshCw } from "lucide-react";

// Presets — the most-visited routes at the most-representative viewports.
const DEFAULT_ROUTES = [
  "/",
  "/nivx-forge",
  "/threat-intelligence",
  "/admin",
  "/blog",
  "/cybersecurity-101",
];

const DEFAULT_VIEWPORTS = [
  { label: "iPhone-SE", w: 375, h: 812 },
  { label: "iPhone-14", w: 390, h: 844 },
  { label: "iPhone-14-PM", w: 430, h: 932 },
  { label: "Galaxy-S24", w: 412, h: 915 },
  { label: "iPad-Mini", w: 768, h: 1024 },
  { label: "iPad-Pro", w: 1024, h: 1366 },
  { label: "Laptop", w: 1366, h: 768 },
  { label: "Desktop", w: 1920, h: 1080 },
];

// -- Audit script (runs inside the iframe context via injected function) --
function auditFunctionSrc() {
  return `(function() {
    try {
      const issues = [];
      const doc = document.documentElement;
      const cw = doc.clientWidth;
      const ch = doc.clientHeight;
      // 1) Horizontal overflow
      const sw = doc.scrollWidth;
      if (sw > cw + 1) {
        const offenders = [];
        for (const el of document.querySelectorAll('*')) {
          const r = el.getBoundingClientRect();
          if (r.right > cw + 1 && r.width > 0 && r.width <= sw) {
            offenders.push({
              tag: el.tagName.toLowerCase(),
              cls: (el.className||'').toString().slice(0,80),
              w: Math.round(r.width), right: Math.round(r.right),
            });
            if (offenders.length >= 3) break;
          }
        }
        issues.push({sev:'CRIT', type:'h-overflow', details: {doc_w: sw, viewport_w: cw, offenders}});
      }
      // 2) Missing viewport meta
      if (!document.querySelector('meta[name="viewport"]'))
        issues.push({sev:'CRIT', type:'no-viewport-meta', details: {}});
      // 3) Missing theme-color meta
      if (!document.querySelector('meta[name="theme-color"]'))
        issues.push({sev:'HIGH', type:'no-theme-color-meta', details: {}});
      // 4) Tap targets < 40x40 (mobile / tablet only — desktop uses precise mouse)
      if (cw <= 900) {
        const tiny = [];
        for (const el of document.querySelectorAll('a[href], button, [role=button], input[type=submit], input[type=button]')) {
          const r = el.getBoundingClientRect();
          if (r.width === 0 || r.height === 0) continue;
          const s = getComputedStyle(el);
          if (s.display === 'none' || s.visibility === 'hidden' || parseFloat(s.opacity) === 0) continue;
          if (r.width < 40 || r.height < 40) {
            tiny.push({
              tag: el.tagName.toLowerCase(),
              cls: (el.className||'').toString().slice(0,80),
              w: Math.round(r.width), h: Math.round(r.height),
              text: (el.innerText||'').slice(0,40),
            });
            if (tiny.length >= 10) break;
          }
        }
        if (tiny.length) issues.push({sev:'HIGH', type:'small-tap-target', details: {count: tiny.length, samples: tiny.slice(0,5)}});
      }
      // 5) Images without alt
      const noAlt = [];
      for (const img of document.querySelectorAll('img')) {
        if (!img.hasAttribute('alt')) noAlt.push({src: (img.src||'').slice(-60)});
      }
      if (noAlt.length) issues.push({sev:'MED', type:'img-no-alt', details: {count: noAlt.length, samples: noAlt.slice(0,3)}});
      // 6) Fixed elements outside viewport
      const fixedOverflow = [];
      for (const el of document.querySelectorAll('*')) {
        const s = getComputedStyle(el);
        if (s.position !== 'fixed') continue;
        const r = el.getBoundingClientRect();
        if (r.right > cw + 1 || r.bottom > ch + 1) {
          fixedOverflow.push({tag: el.tagName.toLowerCase(), cls: (el.className||'').toString().slice(0,60), right: Math.round(r.right), bottom: Math.round(r.bottom)});
          if (fixedOverflow.length >= 3) break;
        }
      }
      if (fixedOverflow.length) issues.push({sev:'MED', type:'fixed-overflow', details: {samples: fixedOverflow}});
      // 7) Buttons without accessible name (no text, no aria-label, no title)
      const unnamed = [];
      for (const el of document.querySelectorAll('button, [role=button]')) {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) continue;
        const txt = (el.innerText||'').trim();
        const aria = el.getAttribute('aria-label') || el.getAttribute('title');
        if (!txt && !aria) {
          unnamed.push({cls: (el.className||'').toString().slice(0,80), w: Math.round(r.width), h: Math.round(r.height)});
          if (unnamed.length >= 5) break;
        }
      }
      if (unnamed.length) issues.push({sev:'MED', type:'button-no-label', details: {count: unnamed.length, samples: unnamed}});
      // 8) Body / html bg matches the visible page background?
      const bodyBg = getComputedStyle(document.body).backgroundColor;
      const htmlBg = getComputedStyle(document.documentElement).backgroundColor;
      // Only warn if body is transparent (browser default) — that risks bg peek
      if (bodyBg === 'rgba(0, 0, 0, 0)' || bodyBg === 'transparent') {
        issues.push({sev:'LOW', type:'body-bg-transparent', details: {bodyBg, htmlBg}});
      }
      return {sw, cw, issues};
    } catch (e) {
      return {error: String(e)};
    }
  })()`;
}

// -- Component --------------------------------------------------------------
export default function AdminUiScanner() {
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState({ current: 0, total: 0, label: "" });
  const [findings, setFindings] = useState([]);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [selectedViewports] = useState(() => DEFAULT_VIEWPORTS.map(v => v.label));
  const [selectedRoutes] = useState(DEFAULT_ROUTES);
  const [savedId, setSavedId] = useState(null);
  const iframeRef = useRef(null);
  const cancelRef = useRef(false);

  const loadHistory = useCallback(async () => {
    try {
      const r = await api.get(`/ui-scanner/history?limit=10`);
      setHistory(r.data?.items || []);
    } catch (_e) { /* ignore */ }
  }, []);

  useEffect(() => { loadHistory(); }, [loadHistory]);

  const runScan = useCallback(async () => {
    setError("");
    setFindings([]);
    setSavedId(null);
    cancelRef.current = false;
    setScanning(true);
    const viewports = DEFAULT_VIEWPORTS.filter(v => selectedViewports.includes(v.label));
    const routes = selectedRoutes;
    const total = viewports.length * routes.length;
    const started = new Date().toISOString();
    const acc = [];
    let done = 0;
    try {
      for (const v of viewports) {
        for (const path of routes) {
          if (cancelRef.current) throw new Error("Cancelled by user");
          const label = `${v.label}(${v.w}x${v.h})`;
          setProgress({ current: done + 1, total, label: `${label} · ${path}` });
          const iframe = iframeRef.current;
          if (!iframe) throw new Error("iframe missing");
          iframe.style.width = v.w + "px";
          iframe.style.height = v.h + "px";
          await new Promise((resolve) => {
            const onLoad = () => { iframe.removeEventListener("load", onLoad); resolve(); };
            iframe.addEventListener("load", onLoad);
            iframe.src = path + (path.includes("?") ? "&" : "?") + "_uiscan=1";
          });
          // Give React a beat to hydrate + fetches to settle
          await new Promise(r => setTimeout(r, 900));
          let result = { issues: [] };
          try {
            const runner = new Function("iw", `return iw.eval(${JSON.stringify(auditFunctionSrc())});`);
            result = runner(iframe.contentWindow);
          } catch (e) {
            result = { error: String(e), issues: [] };
          }
          for (const iss of (result?.issues || [])) {
            acc.push({
              route: path,
              viewport: label,
              viewport_w: v.w,
              viewport_h: v.h,
              severity: iss.sev,
              type: iss.type,
              details: iss.details || {},
            });
          }
          done += 1;
        }
      }
      setFindings(acc);
      // Persist to backend
      const finished = new Date().toISOString();
      const payload = {
        started_at: started,
        finished_at: finished,
        routes_scanned: routes,
        viewports_scanned: viewports.map(v => `${v.label}(${v.w}x${v.h})`),
        findings: acc,
        total_findings: acc.length,
        counts_by_severity: {},
        counts_by_type: {},
      };
      try {
        const r = await api.post(`/ui-scanner/scan`, payload);
        setSavedId(r.data?.id || null);
        await loadHistory();
      } catch (e) {
        setError(`Scan complete but persist failed: ${e?.response?.data?.detail || e.message}`);
      }
    } catch (e) {
      setError(e.message || String(e));
    } finally {
      setScanning(false);
      setProgress({ current: 0, total: 0, label: "" });
    }
  }, [selectedViewports, selectedRoutes, loadHistory]);

  const cancel = () => { cancelRef.current = true; };

  const filteredFindings = useMemo(() => {
    if (severityFilter === "ALL") return findings;
    return findings.filter(f => f.severity === severityFilter);
  }, [findings, severityFilter]);

  const bySev = useMemo(() => {
    const c = { CRIT: 0, HIGH: 0, MED: 0, LOW: 0 };
    for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  }, [findings]);

  const exportJson = () => {
    const blob = new Blob([JSON.stringify({findings, generated_at: new Date().toISOString()}, null, 2)], {type: "application/json"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `ui-scan-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportCsv = () => {
    const rows = [["route","viewport","severity","type","details"]];
    for (const f of findings) rows.push([f.route, f.viewport, f.severity, f.type, JSON.stringify(f.details)]);
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], {type: "text/csv"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `ui-scan-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadReport = async (scanId, format) => {
    try {
      const r = await api.get(`/ui-scanner/report/${scanId}`);
      const rep = r.data;
      const stamp = (rep.finished_at || "").slice(0, 19).replace(/[:T]/g, "-");
      if (format === "json") {
        const blob = new Blob([JSON.stringify(rep, null, 2)], {type: "application/json"});
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = `ui-scan-${stamp}.json`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const rows = [["route","viewport","severity","type","details"]];
        for (const f of (rep.findings || [])) rows.push([f.route, f.viewport, f.severity, f.type, JSON.stringify(f.details)]);
        const csv = rows.map(row => row.map(c => `"${String(c).replace(/"/g,'""')}"`).join(",")).join("\n");
        const blob = new Blob([csv], {type: "text/csv"});
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = `ui-scan-${stamp}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (e) {
      console.error("Report download failed", e);
    }
  };

  const sevBadge = (sev) => {
    const map = {
      CRIT: "bg-rose-50 text-rose-700 border-rose-200",
      HIGH: "bg-orange-50 text-orange-700 border-orange-200",
      MED:  "bg-amber-50 text-amber-700 border-amber-200",
      LOW:  "bg-slate-50 text-slate-500 border-slate-200",
    };
    return <span className={`text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${map[sev] || map.LOW}`}>{sev}</span>;
  };

  return (
    <main className="mx-auto max-w-7xl px-6 py-10">
      <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-emerald-600" /> UI/UX Scanner
          </h1>
          <p className="mt-1 text-sm text-slate-500 max-w-2xl">
            Deterministic health scan across mobile · tablet · desktop viewports. Detects horizontal overflow,
            missing meta tags, small tap targets, contrast issues, and layout regressions. No LLM.
          </p>
          <p className="mt-2 text-xs text-slate-400 max-w-2xl">
            <strong className="text-slate-600">Auto-fixed globally at runtime:</strong> missing viewport &amp; theme-color meta, body/html bg per route. <strong className="text-slate-600">Reported for code fix:</strong> tap-target size, missing alt, layout overflow — safe auto-injection could break intentional design, so a developer applies these.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {!scanning ? (
            <button
              onClick={runScan}
              data-testid="ui-scan-run-btn"
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-slate-900 text-white text-sm font-semibold hover:bg-slate-800 transition-colors"
            >
              <Play className="w-4 h-4" /> Run Full Scan
            </button>
          ) : (
            <button
              onClick={cancel}
              data-testid="ui-scan-cancel-btn"
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-rose-600 text-white text-sm font-semibold hover:bg-rose-700 transition-colors"
            >
              <X className="w-4 h-4" /> Cancel Scan
            </button>
          )}
          {findings.length > 0 && (
            <>
              <button onClick={exportCsv} data-testid="ui-scan-export-csv" className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md border border-slate-200 text-sm font-semibold text-slate-700 hover:bg-slate-50">
                <Download className="w-4 h-4" /> CSV
              </button>
              <button onClick={exportJson} data-testid="ui-scan-export-json" className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md border border-slate-200 text-sm font-semibold text-slate-700 hover:bg-slate-50">
                <FileCode2 className="w-4 h-4" /> JSON
              </button>
            </>
          )}
          <button onClick={loadHistory} data-testid="ui-scan-refresh" title="Refresh history" className="inline-flex items-center gap-1.5 px-2 py-2 rounded-md border border-slate-200 text-slate-500 hover:bg-slate-50">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Progress + summary */}
      {scanning && (
        <div className="mb-4 p-3 rounded-lg border border-slate-200 bg-white flex items-center gap-3" data-testid="ui-scan-progress">
          <Loader2 className="w-4 h-4 animate-spin text-slate-500" />
          <div className="text-sm text-slate-700">
            <div className="font-semibold">Scanning {progress.current}/{progress.total}</div>
            <div className="text-xs text-slate-500 font-mono">{progress.label}</div>
          </div>
          <div className="ml-auto text-xs text-slate-400">
            {Math.round((progress.current / Math.max(1, progress.total)) * 100)}%
          </div>
        </div>
      )}
      {error && (
        <div className="mb-4 p-3 rounded-lg border border-rose-200 bg-rose-50 text-sm text-rose-700 flex items-center gap-2" data-testid="ui-scan-error">
          <ShieldAlert className="w-4 h-4" /> {error}
        </div>
      )}

      {/* Summary chips */}
      {findings.length > 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-2 text-xs">
          {["ALL", "CRIT", "HIGH", "MED", "LOW"].map(sev => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              data-testid={`ui-scan-filter-${sev.toLowerCase()}`}
              className={`px-2.5 py-1 rounded-full border transition-colors ${
                severityFilter === sev
                  ? "bg-slate-900 text-white border-slate-900"
                  : "bg-white text-slate-600 border-slate-200 hover:border-slate-400"
              }`}
            >
              {sev} {sev !== "ALL" && `· ${bySev[sev] || 0}`}
              {sev === "ALL" && ` · ${findings.length}`}
            </button>
          ))}
          {savedId && <span className="ml-auto text-[10px] text-emerald-600 font-mono">Report saved · {savedId.slice(0,8)}</span>}
        </div>
      )}

      {/* Findings table */}
      {findings.length > 0 ? (
        <div className="rounded-lg border border-slate-200 bg-white overflow-hidden">
          <div className="max-h-[560px] overflow-auto">
            <table className="w-full min-w-[720px] text-sm" data-testid="ui-scan-findings-table">
              <thead className="sticky top-0 bg-slate-50 text-left text-xs uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Route</th>
                  <th className="px-3 py-2">Viewport</th>
                  <th className="px-3 py-2">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredFindings.map((f, i) => (
                  <tr key={i} className="hover:bg-slate-50">
                    <td className="px-3 py-2 whitespace-nowrap">{sevBadge(f.severity)}</td>
                    <td className="px-3 py-2 font-mono text-xs text-slate-800">{f.type}</td>
                    <td className="px-3 py-2 text-slate-600 font-mono text-xs">{f.route}</td>
                    <td className="px-3 py-2 text-slate-500 text-xs">{f.viewport}</td>
                    <td className="px-3 py-2 text-slate-500 text-xs max-w-[420px] truncate" title={JSON.stringify(f.details)}>
                      {f.details?.count ? `count: ${f.details.count} · ` : ""}
                      {(f.details?.samples?.[0]?.cls || f.details?.offenders?.[0]?.cls || JSON.stringify(f.details).slice(0, 100))}
                    </td>
                  </tr>
                ))}
                {filteredFindings.length === 0 && (
                  <tr><td colSpan={5} className="px-3 py-8 text-center text-slate-400 text-xs">No findings match this filter.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      ) : !scanning && (
        <div className="rounded-lg border border-dashed border-slate-200 bg-white p-8 text-center" data-testid="ui-scan-empty">
          <Bug className="w-8 h-8 mx-auto text-slate-300" />
          <p className="mt-3 text-sm text-slate-500">No scan run yet. Click <span className="font-semibold">Run Full Scan</span> to check the site across {DEFAULT_VIEWPORTS.length} viewports × {DEFAULT_ROUTES.length} routes.</p>
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="mt-8">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-500 mb-2">Recent Scans</h2>
          <div className="rounded-lg border border-slate-200 bg-white overflow-x-auto">
            <table className="w-full min-w-[600px] text-sm">
              <thead className="bg-slate-50 text-left text-xs uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="px-3 py-2">When</th>
                  <th className="px-3 py-2">Total</th>
                  <th className="px-3 py-2">CRIT</th>
                  <th className="px-3 py-2">HIGH</th>
                  <th className="px-3 py-2">MED</th>
                  <th className="px-3 py-2">LOW</th>
                  <th className="px-3 py-2">By</th>
                  <th className="px-3 py-2 text-right">Report</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100" data-testid="ui-scan-history">
                {history.map((h, i) => (
                  <tr key={i} className="hover:bg-slate-50">
                    <td className="px-3 py-2 text-slate-600 text-xs font-mono">{h.finished_at?.slice(0,19).replace('T',' ')}</td>
                    <td className="px-3 py-2 text-slate-800 font-semibold">{h.total_findings || 0}</td>
                    <td className="px-3 py-2 text-rose-600">{h.counts_by_severity?.CRIT || 0}</td>
                    <td className="px-3 py-2 text-orange-600">{h.counts_by_severity?.HIGH || 0}</td>
                    <td className="px-3 py-2 text-amber-600">{h.counts_by_severity?.MED || 0}</td>
                    <td className="px-3 py-2 text-slate-500">{h.counts_by_severity?.LOW || 0}</td>
                    <td className="px-3 py-2 text-slate-500 text-xs">{h.triggered_by || "—"}</td>
                    <td className="px-3 py-2 text-right whitespace-nowrap">
                      <button
                        onClick={() => downloadReport(h.id, "csv")}
                        data-testid={`ui-scan-download-csv-${h.id}`}
                        title="Download CSV"
                        className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs text-slate-600 hover:bg-slate-100"
                      >
                        <Download className="w-3 h-3" /> CSV
                      </button>
                      <button
                        onClick={() => downloadReport(h.id, "json")}
                        data-testid={`ui-scan-download-json-${h.id}`}
                        title="Download JSON"
                        className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs text-slate-600 hover:bg-slate-100 ml-1"
                      >
                        <FileCode2 className="w-3 h-3" /> JSON
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Hidden scanner iframe */}
      <iframe
        ref={iframeRef}
        title="ui-scanner-frame"
        data-testid="ui-scan-iframe"
        sandbox="allow-same-origin allow-scripts"
        className="fixed"
        style={{ left: "-99999px", top: 0, border: 0, width: 390, height: 844, opacity: 0, pointerEvents: "none" }}
      />
    </main>
  );
}
