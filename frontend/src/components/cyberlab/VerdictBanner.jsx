import { Shield, ShieldAlert, ShieldX, Check } from "lucide-react";

/**
 * Verdict + Risk Score visualization with categorized indicator list.
 *
 * Props:
 *   verdict     "clean" | "suspicious" | "malicious"
 *   riskScore   0-100
 *   reasons     Array<{label, severity: "high"|"medium"|"low", category, evidence?}>
 *   summary     Optional short summary line.
 */
const SEVERITY_TONE = {
  high:   { chip: "border-red-500/40 bg-red-500/10 text-red-300",       dot: "bg-red-400" },
  medium: { chip: "border-amber-500/40 bg-amber-500/10 text-amber-300", dot: "bg-amber-400" },
  low:    { chip: "border-slate-600 bg-slate-800/60 text-slate-300",    dot: "bg-slate-500" },
};

const VERDICT_META = {
  malicious:  { label: "MALICIOUS",  icon: ShieldX,     bar: "from-red-500 to-red-700",     text: "text-red-400",    ring: "ring-red-500/50",     bg: "bg-red-500/5",     border: "border-red-500/30" },
  suspicious: { label: "SUSPICIOUS", icon: ShieldAlert, bar: "from-amber-500 to-orange-600", text: "text-amber-400",  ring: "ring-amber-500/50",   bg: "bg-amber-500/5",   border: "border-amber-500/30" },
  clean:      { label: "CLEAN",      icon: Shield,      bar: "from-emerald-500 to-emerald-600", text: "text-emerald-400", ring: "ring-emerald-500/50", bg: "bg-emerald-500/5", border: "border-emerald-500/30" },
};

const CATEGORY_LABEL = {
  encoding: "Encoding",
  execution: "Execution",
  lolbin: "LOLBin",
  network: "Network",
  persistence: "Persistence",
  impact: "Impact",
  credential: "Credential Access",
  recon: "Reconnaissance",
  forensic: "Forensic",
};

function riskBucket(score) {
  if (score >= 80) return { label: "Critical Risk", tone: "text-red-400" };
  if (score >= 60) return { label: "High Risk",     tone: "text-red-300" };
  if (score >= 30) return { label: "Medium Risk",   tone: "text-amber-300" };
  if (score >= 10) return { label: "Low Risk",      tone: "text-yellow-300" };
  return                     { label: "Minimal Risk", tone: "text-emerald-300" };
}

export default function VerdictBanner({ verdict = "clean", riskScore = 0, reasons = [], summary = "" }) {
  const meta = VERDICT_META[verdict] || VERDICT_META.clean;
  const Icon = meta.icon;
  const bucket = riskBucket(riskScore);

  // Group reasons by category for the "why" section.
  const byCategory = reasons.reduce((acc, r) => {
    const cat = r.category || "forensic";
    (acc[cat] = acc[cat] || []).push(r);
    return acc;
  }, {});
  const orderedCats = Object.keys(byCategory).sort((a, b) => {
    const rank = { encoding: 0, execution: 1, lolbin: 2, network: 3, persistence: 4, impact: 5, credential: 6, recon: 7, forensic: 8 };
    return (rank[a] ?? 9) - (rank[b] ?? 9);
  });

  return (
    <div
      data-testid="verdict-banner"
      className={`rounded-xl border ${meta.border} ${meta.bg} p-5 mb-4`}
    >
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_auto] gap-4 lg:gap-8">
        {/* Left column — verdict + risk bar */}
        <div className="min-w-0">
          <div className="flex items-center gap-3 mb-3">
            <div className={`p-2 rounded-lg bg-slate-900 ring-1 ${meta.ring}`}>
              <Icon className={`w-5 h-5 ${meta.text}`} />
            </div>
            <div>
              <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Verdict</div>
              <div
                className={`text-lg font-black ${meta.text}`}
                data-testid="verdict-label"
              >
                {meta.label}
              </div>
            </div>
            <div className="ml-auto text-right">
              <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Risk Score</div>
              <div className="flex items-baseline gap-1 justify-end" data-testid="risk-score">
                <span className={`text-3xl font-black ${meta.text}`}>{riskScore}</span>
                <span className="text-sm text-slate-500 font-mono">/100</span>
              </div>
              <div className={`text-[10px] font-bold uppercase tracking-widest ${bucket.tone}`}>{bucket.label}</div>
            </div>
          </div>

          {/* Segmented progress bar (10 segments, filled in proportion to score) */}
          <div
            className="w-full h-2.5 rounded-full bg-slate-900 border border-slate-800 overflow-hidden"
            data-testid="risk-progress-bar"
          >
            <div
              className={`h-full bg-gradient-to-r ${meta.bar} transition-all duration-700`}
              style={{ width: `${Math.max(4, Math.min(100, riskScore))}%` }}
            />
          </div>
          <div className="mt-1 flex justify-between text-[9px] font-mono uppercase tracking-widest text-slate-500">
            <span>0</span><span>25</span><span>50</span><span>75</span><span>100</span>
          </div>

          {summary && (
            <div className="mt-3 text-xs text-slate-300 border-t border-slate-800 pt-2">{summary}</div>
          )}
        </div>

        {/* Right column — reasons summary count */}
        <div className="hidden lg:flex flex-col items-end gap-1 min-w-[140px]">
          <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Indicators</div>
          <div className="flex items-baseline gap-1">
            <span className={`text-3xl font-black ${meta.text}`}>{reasons.length}</span>
            <span className="text-sm text-slate-500">reasons</span>
          </div>
          <div className="flex gap-1.5 mt-1">
            {["high", "medium", "low"].map((sev) => {
              const n = reasons.filter((r) => r.severity === sev).length;
              if (!n) return null;
              const tone = SEVERITY_TONE[sev];
              return (
                <span
                  key={sev}
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${tone.chip}`}
                  data-testid={`reason-count-${sev}`}
                >
                  {n} {sev}
                </span>
              );
            })}
          </div>
        </div>
      </div>

      {/* Reasons list */}
      {reasons.length > 0 && (
        <div className="mt-4 border-t border-slate-800 pt-3" data-testid="risk-reasons">
          <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2">
            Why this score
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-x-6 gap-y-1">
            {orderedCats.map((cat) => (
              <div key={cat}>
                <div className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mt-2 mb-1">
                  {CATEGORY_LABEL[cat] || cat}
                </div>
                <ul className="space-y-0.5">
                  {byCategory[cat].map((r, i) => {
                    const tone = SEVERITY_TONE[r.severity] || SEVERITY_TONE.low;
                    return (
                      <li
                        key={i}
                        className="flex items-start gap-2 text-xs text-slate-200 py-0.5"
                        data-testid={`risk-reason-${r.severity}`}
                        title={r.evidence || undefined}
                      >
                        <span className={`inline-flex items-center justify-center w-4 h-4 rounded-full ${tone.dot} shrink-0 mt-0.5`}>
                          <Check className="w-2.5 h-2.5 text-slate-900" strokeWidth={4} />
                        </span>
                        <span className="min-w-0 truncate" title={r.label}>
                          {r.label}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
