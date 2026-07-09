import { CheckCircle2, Loader2, XCircle, Radar, FileSearch, Zap, Brain, Network } from "lucide-react";

/**
 * Live step-by-step progress panel for the "Auto Investigate" pipeline.
 *
 * Props:
 *   stages   Array<{name: "detect"|"auto-decode"|"parse-log"|"analyze"|"ai"|"render",
 *                    status: "pending"|"running"|"ok"|"failed",
 *                    duration_ms?: number,
 *                    meta?: object}>
 *   summary  Optional string shown below the stepper.
 */
const STAGE_META = {
  detect:        { label: "Detect Format",   icon: FileSearch, hint: "Identify log vs. payload" },
  "auto-decode": { label: "Recursive Decode", icon: Zap,       hint: "Auto-decode nested encodings" },
  "parse-log":   { label: "Parse Log",        icon: Network,   hint: "Normalize forensic events + build process tree" },
  analyze:       { label: "Threat Analysis",  icon: Radar,     hint: "MITRE ATT&CK · YARA-lite · IOCs · risk" },
  ai:            { label: "AI Analyst",       icon: Brain,     hint: "Claude Sonnet 4.5 · SIEM queries" },
  enrich:        { label: "OSINT Enrich",     icon: FileSearch,hint: "VT · AbuseIPDB · Shodan · urlscan · CIRCL" },
  render:        { label: "Render",           icon: Radar,     hint: "Attack chain + investigation timeline" },
};

const STATUS_STYLE = {
  pending: "text-slate-500 border-slate-800 bg-slate-950",
  running: "text-cyan-300 border-cyan-500/50 bg-cyan-500/5",
  ok:      "text-emerald-300 border-emerald-500/40 bg-emerald-500/5",
  failed:  "text-red-300 border-red-500/40 bg-red-500/5",
};

export default function AutoInvestigateProgress({ stages, summary }) {
  if (!stages?.length) return null;
  return (
    <div
      data-testid="auto-investigate-progress"
      className="rounded-xl border border-cyan-500/30 bg-gradient-to-b from-cyan-950/40 to-slate-950 p-4 mb-4"
    >
      <div className="flex items-center gap-2 mb-3">
        <div className="relative">
          <Radar className="w-4 h-4 text-cyan-400" />
          {stages.some((s) => s.status === "running") && (
            <span className="absolute inset-0 rounded-full bg-cyan-400/30 animate-ping" />
          )}
        </div>
        <h3 className="font-semibold text-white text-sm">Auto Investigation Pipeline</h3>
        <span className="ml-auto text-[10px] uppercase font-bold tracking-widest text-slate-400">
          {stages.filter((s) => s.status === "ok").length}/{stages.length} stages
        </span>
      </div>
      <ol className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-2">
        {stages.map((s, i) => {
          const M = STAGE_META[s.name] || { label: s.name, icon: Radar, hint: "" };
          const tone = STATUS_STYLE[s.status] || STATUS_STYLE.pending;
          const StatusIcon = s.status === "ok" ? CheckCircle2
                          : s.status === "running" ? Loader2
                          : s.status === "failed" ? XCircle
                          : null;
          return (
            <li
              key={i}
              data-testid={`stage-${s.name}`}
              data-status={s.status}
              className={`rounded-md border p-2.5 transition-colors ${tone}`}
            >
              <div className="flex items-center gap-1.5 mb-1">
                <M.icon className="w-3 h-3" />
                <span className="text-[10px] font-bold uppercase tracking-widest">{M.label}</span>
                <span className="ml-auto">
                  {StatusIcon && (
                    <StatusIcon className={`w-3.5 h-3.5 ${s.status === "running" ? "animate-spin" : ""}`} />
                  )}
                </span>
              </div>
              <div className="text-[10px] text-slate-400 mb-1">{M.hint}</div>
              {s.duration_ms != null && s.status !== "pending" && (
                <div className="text-[10px] font-mono text-slate-500">{Math.round(s.duration_ms)} ms</div>
              )}
              {s.meta && Object.keys(s.meta).length > 0 && s.status === "ok" && (
                <div className="mt-1 flex flex-wrap gap-1">
                  {Object.entries(s.meta).slice(0, 3).map(([k, v]) => (
                    <span
                      key={k}
                      className="text-[9px] font-mono px-1 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400"
                    >
                      {k}={typeof v === "object" ? "…" : String(v).slice(0, 20)}
                    </span>
                  ))}
                </div>
              )}
              {s.status === "failed" && s.meta?.error && (
                <div className="mt-1 text-[10px] font-mono text-red-400 truncate" title={s.meta.error}>
                  {s.meta.error}
                </div>
              )}
            </li>
          );
        })}
      </ol>
      {summary && (
        <div className="mt-3 text-xs text-slate-300 border-t border-slate-800 pt-2">{summary}</div>
      )}
    </div>
  );
}
