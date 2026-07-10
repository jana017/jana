/**
 * AdminHealthBot — NivX HealthBot control panel.
 *
 * One-click 360° health scan across the entire backend + MongoDB + plugin
 * registry + OSINT keys + disk/env sanity. Fully deterministic; runs 100%
 * offline (no LLM), so it keeps working after the app is moved to any VPS.
 *
 * Endpoints (all admin-only):
 *   POST /api/healthbot/scan            — run all checks
 *   POST /api/healthbot/scan-and-fix    — run + auto-fix safe subset
 *   POST /api/healthbot/fix/{check_id}  — fix a single check
 *   GET  /api/healthbot/history         — last 50 scans
 */
import { useEffect, useState, useCallback } from "react";
import { toast } from "sonner";
import {
  Activity, RefreshCw, Wrench, CheckCircle2, AlertTriangle, AlertOctagon,
  Info, ShieldCheck, PlayCircle, ChevronDown, ChevronUp, Clock,
} from "lucide-react";
import { api } from "@/lib/api";

const SEV_STYLE = {
  ok: { color: "text-emerald-700 bg-emerald-50 border-emerald-200", icon: CheckCircle2, label: "OK" },
  info: { color: "text-sky-700 bg-sky-50 border-sky-200", icon: Info, label: "INFO" },
  warning: { color: "text-amber-700 bg-amber-50 border-amber-200", icon: AlertTriangle, label: "WARN" },
  critical: { color: "text-rose-700 bg-rose-50 border-rose-200", icon: AlertOctagon, label: "CRIT" },
};

function SeverityChip({ severity }) {
  const s = SEV_STYLE[severity] || SEV_STYLE.info;
  const Icon = s.icon;
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wide border rounded px-1.5 py-0.5 ${s.color}`}>
      <Icon className="w-3 h-3" />
      {s.label}
    </span>
  );
}

function OverallBanner({ scan }) {
  if (!scan) return null;
  const style = SEV_STYLE[scan.overall] || SEV_STYLE.info;
  const Icon = style.icon;
  return (
    <div className={`rounded-xl border p-4 flex items-center gap-3 ${style.color}`}>
      <Icon className="w-6 h-6 shrink-0" />
      <div className="flex-1 min-w-0">
        <div className="font-heading text-sm font-bold uppercase tracking-wide">
          Overall: {scan.overall}
        </div>
        <div className="text-xs opacity-80">
          {scan.summary?.ok ?? 0} ok · {scan.summary?.info ?? 0} info ·{" "}
          {scan.summary?.warning ?? 0} warnings · {scan.summary?.critical ?? 0} critical
          {scan.auto_fixed > 0 && (
            <span className="ml-2 text-emerald-700 font-semibold">
              · {scan.auto_fixed} auto-fixed
            </span>
          )}
          <span className="opacity-70">
            {" · "}scan took {Math.round(scan.duration_ms || 0)}ms
          </span>
        </div>
      </div>
    </div>
  );
}

export default function AdminHealthBot() {
  const [scan, setScan] = useState(null);
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState([]);
  const [expandedId, setExpandedId] = useState(null);

  const loadHistory = useCallback(async () => {
    try {
      const { data } = await api.get("/healthbot/history?limit=20");
      setHistory(data);
    } catch (e) {
      // silent — history is nice-to-have
    }
  }, []);

  useEffect(() => { loadHistory(); }, [loadHistory]);

  const runScan = async (fix = false) => {
    setBusy(true);
    try {
      const url = fix ? "/healthbot/scan-and-fix" : "/healthbot/scan";
      const { data } = await api.post(url);
      setScan(data);
      if (fix && data.auto_fixed > 0) {
        toast.success(`HealthBot repaired ${data.auto_fixed} issue${data.auto_fixed === 1 ? "" : "s"} — see report below.`);
      } else if (data.overall === "ok") {
        toast.success("All checks pass — app is healthy.");
      } else {
        toast.info(`Scan complete — overall: ${data.overall}`);
      }
      loadHistory();
    } catch (e) {
      toast.error(`HealthBot failed: ${e.response?.data?.detail || e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const fixOne = async (checkId) => {
    setBusy(true);
    try {
      const { data } = await api.post(`/healthbot/fix/${checkId}`);
      if (data.fixed) {
        toast.success(data.fix_message || "Fix applied.");
      } else {
        toast.error(data.fix_message || "Fix could not be applied.");
      }
      await runScan(false);
    } catch (e) {
      toast.error(`Fix failed: ${e.response?.data?.detail || e.message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="mx-auto max-w-7xl px-6 py-10 space-y-6" data-testid="admin-healthbot">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="font-heading text-2xl font-semibold text-slate-900 flex items-center gap-2">
            <Activity className="w-6 h-6 text-[#2E7DF5]" />
            NivX HealthBot
          </h1>
          <p className="text-sm text-slate-500 mt-1 max-w-2xl">
            360° self-diagnostic + safe auto-repair for the entire NivX Machines stack.
            <strong className="text-slate-700"> Runs entirely offline</strong> — no LLM
            required. Keeps working after transferring to any VPS. A silent hourly cron also
            audits the app in the background.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            data-testid="healthbot-scan-btn"
            disabled={busy}
            onClick={() => runScan(false)}
            className="inline-flex items-center gap-2 rounded-md bg-slate-800 hover:bg-slate-700 text-white text-sm font-semibold px-4 py-2 disabled:opacity-40"
          >
            {busy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <PlayCircle className="w-4 h-4" />}
            Run scan
          </button>
          <button
            data-testid="healthbot-fix-btn"
            disabled={busy}
            onClick={() => runScan(true)}
            className="inline-flex items-center gap-2 rounded-md bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold px-4 py-2 disabled:opacity-40"
          >
            {busy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Wrench className="w-4 h-4" />}
            Scan + auto-fix
          </button>
        </div>
      </div>

      <OverallBanner scan={scan} />

      {/* Check results */}
      {scan && (
        <section className="bg-white rounded-xl border border-slate-200 overflow-hidden" data-testid="healthbot-results">
          <div className="px-4 py-3 border-b border-slate-100 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-800">
              {scan.results?.length ?? 0} checks · latest at {new Date(scan.finished_at).toLocaleString()}
            </h2>
            <button
              onClick={() => runScan(false)}
              disabled={busy}
              className="text-xs font-semibold text-slate-500 hover:text-slate-900 inline-flex items-center gap-1"
            >
              <RefreshCw className="w-3 h-3" /> Re-scan
            </button>
          </div>
          <div className="divide-y divide-slate-100">
            {(scan.results || []).map((c) => (
              <div key={c.id} data-testid={`check-${c.id}`}>
                <div className="px-4 py-3 flex items-start gap-3">
                  <SeverityChip severity={c.severity} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-semibold text-slate-800">{c.name}</div>
                    <div className="text-xs text-slate-500">{c.message}</div>
                    {c.fixed && (
                      <div className="mt-1 inline-flex items-center gap-1 text-[11px] text-emerald-700 font-semibold bg-emerald-50 border border-emerald-200 rounded px-1.5 py-0.5">
                        <ShieldCheck className="w-3 h-3" /> {c.fix_message}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] font-mono text-slate-400">
                      {Math.round(c.duration_ms || 0)}ms
                    </span>
                    {c.auto_fixable && !c.fixed && c.severity !== "ok" && (
                      <button
                        data-testid={`fix-${c.id}`}
                        onClick={() => fixOne(c.id)}
                        disabled={busy}
                        className="text-xs font-semibold text-emerald-700 hover:bg-emerald-50 border border-emerald-200 rounded px-2 py-1 inline-flex items-center gap-1"
                      >
                        <Wrench className="w-3 h-3" /> Fix
                      </button>
                    )}
                    {(c.details && Object.keys(c.details).length > 0) && (
                      <button
                        onClick={() => setExpandedId(expandedId === c.id ? null : c.id)}
                        className="text-slate-400 hover:text-slate-700"
                      >
                        {expandedId === c.id ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </button>
                    )}
                  </div>
                </div>
                {expandedId === c.id && c.details && (
                  <pre className="px-4 pb-3 text-[11px] font-mono text-slate-500 whitespace-pre-wrap bg-slate-50/40">
                    {JSON.stringify(c.details, null, 2)}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* History */}
      <section className="bg-white rounded-xl border border-slate-200 overflow-hidden" data-testid="healthbot-history">
        <div className="px-4 py-3 border-b border-slate-100 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-800 flex items-center gap-2">
            <Clock className="w-4 h-4 text-slate-500" /> Scan history
            <span className="text-xs font-normal text-slate-400">last {history.length} runs</span>
          </h2>
          <button onClick={loadHistory} className="text-xs font-semibold text-slate-500 hover:text-slate-900 inline-flex items-center gap-1">
            <RefreshCw className="w-3 h-3" /> Reload
          </button>
        </div>
        <div className="max-h-72 overflow-auto">
          {history.length === 0 && (
            <div className="px-4 py-6 text-xs text-slate-400 text-center">
              No history yet — run your first scan to populate this log.
            </div>
          )}
          {history.map((h) => (
            <div key={h.id} className="px-4 py-2 border-t border-slate-100 flex items-center gap-3 text-xs" data-testid={`history-${h.id}`}>
              <SeverityChip severity={h.overall} />
              <span className="text-slate-600 flex-1 truncate">
                {new Date(h.started_at).toLocaleString()} · by {h.triggered_by || "unknown"}
              </span>
              <span className="font-mono text-slate-500">
                ok={h.summary?.ok ?? 0} · w={h.summary?.warning ?? 0} · c={h.summary?.critical ?? 0}
                {h.auto_fixed > 0 && (
                  <span className="ml-2 text-emerald-700 font-semibold">
                    fixed={h.auto_fixed}
                  </span>
                )}
              </span>
            </div>
          ))}
        </div>
      </section>

      <div className="text-[11px] text-slate-400 italic">
        All HealthBot checks + fixes are 100% deterministic (pure Python stdlib + MongoDB).
        No LLM keys required — safe to run after transferring to Hostinger VPS or any other host.
      </div>
    </main>
  );
}
