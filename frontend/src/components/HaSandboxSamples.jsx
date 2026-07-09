import { useState } from "react";
import { motion } from "framer-motion";
import { Loader2, ExternalLink, FlaskConical, ShieldAlert, ChevronDown, ChevronUp } from "lucide-react";
import { api, formatApiErrorDetail } from "@/lib/api";

// Renders a "Sandboxed samples that contacted this host" enrichment panel.
// Value can be an IP, domain or URL — backend chooses the correct HA search term.
export default function HaSandboxSamples({ value, kindLabel = "host" }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [expanded, setExpanded] = useState(false);

  const load = async () => {
    if (loading || data) return;
    setLoading(true);
    setErr("");
    try {
      const { data: d } = await api.post("/hybrid/search-samples", { value });
      setData(d);
      setExpanded(true);
    } catch (e) {
      setErr(formatApiErrorDetail(e.response?.data?.detail) || "Hybrid Analysis search failed");
    } finally {
      setLoading(false);
    }
  };

  const verdictColor = (v) => {
    const s = (v || "").toLowerCase();
    if (s === "malicious") return "bg-red-50 text-red-700 border-red-200";
    if (s === "suspicious") return "bg-orange-50 text-orange-700 border-orange-200";
    if (s.includes("no ")) return "bg-slate-50 text-slate-500 border-slate-200";
    return "bg-slate-50 text-slate-600 border-slate-200";
  };

  return (
    <div data-testid="ha-sandbox-panel" className="rounded-lg border border-slate-200 bg-white p-4">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5 mb-1">
            <FlaskConical className="w-3.5 h-3.5 text-[#F5821F]" /> Sandboxed samples that contacted this {kindLabel}
            <span className="text-slate-400 font-normal normal-case">· Hybrid Analysis</span>
          </div>
          {!data && !loading && !err && (
            <p className="text-sm text-slate-500">See which malware samples in the Hybrid Analysis sandbox connected to this {kindLabel}.</p>
          )}
          {err && <p data-testid="ha-sandbox-err" className="text-sm text-red-600">{err}</p>}
        </div>
        {!data && (
          <button
            onClick={load}
            disabled={loading}
            data-testid="ha-sandbox-load-btn"
            className="shrink-0 inline-flex items-center gap-1.5 border border-[#F5821F] text-[#F5821F] hover:bg-[#F5821F] hover:text-white text-xs font-semibold px-3 py-1.5 rounded-md transition-colors disabled:opacity-60"
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FlaskConical className="w-3.5 h-3.5" />}
            {loading ? "Searching HA…" : "Search HA sandbox"}
          </button>
        )}
        {data && (
          <button
            onClick={() => setExpanded((v) => !v)}
            data-testid="ha-sandbox-toggle"
            className="shrink-0 inline-flex items-center gap-1 text-xs font-semibold text-slate-500 hover:text-[#2E7DF5]"
          >
            {expanded ? <><ChevronUp className="w-3.5 h-3.5" /> Collapse</> : <><ChevronDown className="w-3.5 h-3.5" /> Expand</>}
          </button>
        )}
      </div>

      {data && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-3">
          <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-sm">
            <span className="text-slate-700"><span className="font-bold text-slate-900">{data.count?.toLocaleString?.() ?? 0}</span> total samples</span>
            {data.malicious > 0 && (
              <span className="inline-flex items-center gap-1 text-red-700 font-semibold"><ShieldAlert className="w-3.5 h-3.5" /> {data.malicious} malicious</span>
            )}
            {data.families?.length > 0 && (
              <span className="text-slate-500">
                Top families: {data.families.slice(0, 4).map((f) => `${f.name} (${f.count})`).join(" · ")}
              </span>
            )}
          </div>

          {expanded && (
            <div className="mt-3 rounded-md border border-slate-100 divide-y divide-slate-100 max-h-72 overflow-y-auto">
              {(data.samples || []).length === 0 ? (
                <div className="p-4 text-sm text-slate-400">No sandboxed samples matched.</div>
              ) : (
                data.samples.map((s, i) => (
                  <a
                    key={s.sha256 || i}
                    href={s.url || `https://www.hybrid-analysis.com/sample/${s.sha256}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    data-testid={`ha-sample-${i}`}
                    className="grid grid-cols-[auto_1fr_auto] gap-3 items-center px-3 py-2.5 hover:bg-orange-50/40 transition-colors"
                  >
                    <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${verdictColor(s.verdict)}`}>
                      {s.verdict || "—"}
                    </span>
                    <div className="min-w-0">
                      <div className="text-sm text-slate-800 truncate">
                        {s.vx_family || s.submit_name || s.sha256}
                      </div>
                      <div className="text-[11px] text-slate-500 truncate font-mono-data">
                        {s.sha256?.slice(0, 24)}… · {s.environment}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {s.threat_score != null && (
                        <span className="text-xs font-mono-data text-slate-500">score {s.threat_score}</span>
                      )}
                      <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
                    </div>
                  </a>
                ))
              )}
            </div>
          )}
        </motion.div>
      )}
    </div>
  );
}
