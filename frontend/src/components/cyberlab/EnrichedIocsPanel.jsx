import { useMemo } from "react";
import { Shield, ShieldAlert, ShieldX, ShieldCheck, Globe, Server, FileDigit, ExternalLink } from "lucide-react";

/**
 * Compact table showing per-IOC OSINT enrichment from CyberLab's
 * in-page bulk enrich. Read-only — pure display, no fetch logic.
 *
 * Props:
 *   iocs          Array<enriched IOC result> from `POST /api/cyberlab/enrich-iocs`
 *   meta          { duration_ms, iocs_per_sec, cache_hit_rate, flagged, count, depth }
 */

const TYPE_ICON = {
  ip:     Server,
  ipv4:   Server,
  ipv6:   Server,
  domain: Globe,
  url:    Globe,
  md5:    FileDigit,
  sha1:   FileDigit,
  sha256: FileDigit,
};

const VERDICT_STYLE = {
  CRITICAL: { chip: "bg-red-500/15 text-red-400 border-red-500/30",       icon: ShieldX },
  HIGH:     { chip: "bg-orange-500/15 text-orange-400 border-orange-500/30", icon: ShieldAlert },
  SUSPECT:  { chip: "bg-amber-500/15 text-amber-400 border-amber-500/30",  icon: ShieldAlert },
  CLEAN:    { chip: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30", icon: ShieldCheck },
};

function classify(r) {
  const vt = r?.reputation?.vt || {};
  const ab = r?.reputation?.abuseipdb || {};
  const vtMal = !vt.error ? (vt.malicious || 0) : 0;
  const vtSusp = !vt.error ? (vt.suspicious || 0) : 0;
  const abScore = !ab.error ? (ab.score || 0) : 0;
  if (vtMal >= 5 || abScore >= 75) return "CRITICAL";
  if (vtMal + vtSusp > 0 || abScore >= 50) return "HIGH";
  if (vtMal + vtSusp > 0 || abScore > 0) return "SUSPECT";
  return "CLEAN";
}

function vtSummary(r) {
  const vt = r?.reputation?.vt;
  if (!vt || vt.error) return "—";
  if (vt.found === false) return "0/0";
  const mal = vt.malicious || 0;
  const total = vt.total || 0;
  return `${mal}/${total}`;
}

function abSummary(r) {
  const ab = r?.reputation?.abuseipdb;
  if (!ab || ab.error || ab.score == null) return "—";
  return `${ab.score}%`;
}

function locSummary(r) {
  const en = r?.enrichment || {};
  if (en.kind === "ip") {
    const g = en.geo || {};
    return [g.country, g.isp || g.org].filter(Boolean).join(" · ") || "—";
  }
  if (en.kind === "web") {
    return en.resolved_ip || "—";
  }
  if (en.kind === "hash") {
    if (en.known_malicious) return "known malicious";
    if (en.found) return "known file";
    return "unknown";
  }
  return "—";
}

export default function EnrichedIocsPanel({ iocs = [], meta = {} }) {
  const total = iocs.length;
  const counts = useMemo(() => {
    const c = { CRITICAL: 0, HIGH: 0, SUSPECT: 0, CLEAN: 0 };
    iocs.forEach((r) => { c[classify(r)] += 1; });
    return c;
  }, [iocs]);

  if (!total) return null;

  return (
    <div
      data-testid="enriched-iocs-panel"
      className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 mb-4"
    >
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <Shield className="w-4 h-4 text-cyan-400" />
        <h3 className="font-semibold text-white text-sm">OSINT Enrichment</h3>
        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-slate-700 text-slate-400 bg-slate-900">
          {total} IOC{total === 1 ? "" : "s"}
        </span>
        {["CRITICAL", "HIGH", "SUSPECT", "CLEAN"].map((k) =>
          counts[k] ? (
            <span
              key={k}
              data-testid={`enriched-count-${k.toLowerCase()}`}
              className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${VERDICT_STYLE[k].chip}`}
            >
              {counts[k]} {k.toLowerCase()}
            </span>
          ) : null
        )}
        <span className="ml-auto text-[10px] font-mono text-slate-500">
          {meta.depth ? `${meta.depth} · ` : ""}
          {meta.duration_ms != null ? `${(meta.duration_ms / 1000).toFixed(1)}s` : ""}
          {meta.iocs_per_sec ? ` · ${meta.iocs_per_sec}/s` : ""}
          {meta.cache_hit_rate != null ? ` · cache ${Math.round(meta.cache_hit_rate * 100)}%` : ""}
        </span>
      </div>
      <div className="overflow-x-auto -mx-1">
        <table className="min-w-full text-xs" data-testid="enriched-iocs-table">
          <thead>
            <tr className="text-[10px] uppercase tracking-widest text-slate-500 border-b border-slate-800">
              <th className="px-2 py-1.5 text-left">IOC</th>
              <th className="px-2 py-1.5 text-left">Type</th>
              <th className="px-2 py-1.5 text-left">Verdict</th>
              <th className="px-2 py-1.5 text-left">VT</th>
              <th className="px-2 py-1.5 text-left">Abuse</th>
              <th className="px-2 py-1.5 text-left">Geo / Host</th>
              <th className="px-2 py-1.5 text-left">Links</th>
            </tr>
          </thead>
          <tbody>
            {iocs.map((r, i) => {
              const verdict = classify(r);
              const V = VERDICT_STYLE[verdict];
              const Icon = TYPE_ICON[(r.type || "").toLowerCase()] || FileDigit;
              return (
                <tr
                  key={i}
                  data-testid="enriched-ioc-row"
                  data-verdict={verdict.toLowerCase()}
                  className="border-b border-slate-900 hover:bg-slate-900/50"
                >
                  <td className="px-2 py-1.5 font-mono text-slate-200 max-w-[240px] truncate" title={r.value}>
                    {r.value}
                  </td>
                  <td className="px-2 py-1.5 text-slate-400 uppercase text-[10px] font-mono">
                    <span className="inline-flex items-center gap-1"><Icon className="w-3 h-3" />{r.type || "?"}</span>
                  </td>
                  <td className="px-2 py-1.5">
                    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border ${V.chip} text-[10px] font-bold`}>
                      <V.icon className="w-3 h-3" />{verdict}
                    </span>
                  </td>
                  <td className="px-2 py-1.5 font-mono text-slate-300">{vtSummary(r)}</td>
                  <td className="px-2 py-1.5 font-mono text-slate-300">{abSummary(r)}</td>
                  <td className="px-2 py-1.5 text-slate-400 truncate max-w-[180px]" title={locSummary(r)}>{locSummary(r)}</td>
                  <td className="px-2 py-1.5">
                    <div className="flex items-center gap-2">
                      {Object.entries(r.links || {}).slice(0, 3).map(([label, href]) => (
                        <a
                          key={label}
                          href={href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[10px] text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-0.5"
                          title={label}
                        >
                          {label.slice(0, 6)}<ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      ))}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {iocs.some((r) => r.ai_summary) && (
        <div className="mt-3 border-t border-slate-800 pt-3">
          <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2">AI Verdicts</div>
          <ul className="space-y-1.5" data-testid="enriched-ai-list">
            {iocs.filter((r) => r.ai_summary).map((r, i) => (
              <li key={i} className="text-xs text-slate-300">
                <span className="font-mono text-cyan-400">{r.value}</span>
                <span className="text-slate-500"> — </span>
                {r.ai_summary}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
