import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Zap, Loader2, ExternalLink, ShieldAlert, ShieldCheck, ShieldQuestion, FileSearch, Globe, Fingerprint, FlaskConical } from "lucide-react";
import { api, formatApiErrorDetail } from "@/lib/api";

const VERDICT_TONE = {
  malicious:   { tone: "bg-red-50 border-red-200 text-red-700",       Icon: ShieldAlert, label: "Malicious" },
  suspicious:  { tone: "bg-orange-50 border-orange-200 text-orange-700",Icon: ShieldAlert, label: "Suspicious" },
  "no threat": { tone: "bg-green-50 border-green-200 text-green-700",  Icon: ShieldCheck, label: "No threat" },
  "no specific threat": { tone: "bg-slate-50 border-slate-200 text-slate-600", Icon: ShieldQuestion, label: "No specific threat" },
};
const tone = (v) => VERDICT_TONE[(v || "").toLowerCase()] || { tone: "bg-slate-50 border-slate-200 text-slate-600", Icon: ShieldQuestion, label: v || "Unknown" };

const kindMeta = {
  url:    { label: "URL",     Icon: Globe },
  sha256: { label: "SHA-256", Icon: Fingerprint },
  sha1:   { label: "SHA-1",   Icon: Fingerprint },
  md5:    { label: "MD5",     Icon: Fingerprint },
  ip:     { label: "IP",      Icon: Globe },
  domain: { label: "Domain",  Icon: Globe },
};

function UrlResult({ r }) {
  const V = tone(r.verdict);
  return (
    <>
      <div className="flex flex-wrap items-center gap-3">
        <span data-testid="ha-verdict" className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-md border ${V.tone}`}>
          <V.Icon className="w-3.5 h-3.5" /> {V.label}
        </span>
        <span className="text-xs text-slate-500">
          <span className="font-bold text-slate-800">{r.malicious_scanners}</span>/{r.total_scanners} scanners flagged · {r.reports_count} prior reports
        </span>
        {r.report_url && (
          <a href={r.report_url} target="_blank" rel="noopener noreferrer" data-testid="ha-report-link" className="ml-auto inline-flex items-center gap-1 text-xs font-semibold text-[#2E7DF5] hover:underline">
            View full report <ExternalLink className="w-3 h-3" />
          </a>
        )}
      </div>
      {r.scanners?.length > 0 && (
        <div className="mt-3 rounded-md border border-slate-200 bg-white divide-y divide-slate-100">
          {r.scanners.map((s, i) => {
            const flagged = s.positives != null && s.positives > 0;
            return (
              <div key={i} className="grid grid-cols-[1fr_auto_auto] gap-3 items-center px-3 py-2 text-sm">
                <span className="text-slate-800 truncate">{s.name}</span>
                <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${flagged ? "bg-red-50 text-red-700" : "bg-slate-100 text-slate-500"}`}>{s.status || (flagged ? "detected" : "clean")}</span>
                <span className="text-xs text-slate-500 font-mono-data w-16 text-right tabular-nums">{s.positives != null && s.total != null ? `${s.positives}/${s.total}` : "—"}</span>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

function HashResult({ r, value }) {
  if (r.found === false) {
    return <div data-testid="ha-hash-notfound" className="text-sm text-slate-500 py-1">No Hybrid Analysis report for <span className="font-mono-data">{value.slice(0, 16)}…</span></div>;
  }
  const V = tone(r.verdict);
  return (
    <>
      <div className="flex flex-wrap items-center gap-3">
        <span data-testid="ha-verdict" className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-md border ${V.tone}`}>
          <V.Icon className="w-3.5 h-3.5" /> {V.label}
        </span>
        {r.vx_family && <span className="text-xs font-semibold text-slate-700">Family: <span className="text-red-600">{r.vx_family}</span></span>}
        {r.threat_score != null && <span className="text-xs text-slate-500">Threat score <span className="font-bold text-slate-800">{r.threat_score}</span></span>}
        {r.reports != null && <span className="text-xs text-slate-500">{r.reports} report{r.reports === 1 ? "" : "s"}</span>}
        {r.url && (
          <a href={r.url} target="_blank" rel="noopener noreferrer" data-testid="ha-report-link" className="ml-auto inline-flex items-center gap-1 text-xs font-semibold text-[#2E7DF5] hover:underline">
            View full report <ExternalLink className="w-3 h-3" />
          </a>
        )}
      </div>
      <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
        {r.last_file_name && <div className="text-slate-500">Last filename: <span className="text-slate-800 font-mono-data">{r.last_file_name}</span></div>}
        {r.type_short && <div className="text-slate-500">Type: <span className="text-slate-800 font-mono-data">{r.type_short}</span></div>}
        {r.size != null && <div className="text-slate-500">Size: <span className="text-slate-800 font-mono-data">{r.size} bytes</span></div>}
        {r.submitted_at && <div className="text-slate-500">Analyzed: <span className="text-slate-800 font-mono-data">{r.submitted_at}</span></div>}
      </div>
      {r.classification?.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {r.classification.map((c) => (
            <span key={c} className="text-[10px] font-semibold uppercase tracking-wider bg-orange-50 text-orange-700 border border-orange-200 px-2 py-0.5 rounded">{c}</span>
          ))}
        </div>
      )}
    </>
  );
}

function HostResult({ r, kindLabel }) {
  return (
    <>
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-sm">
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-md border bg-orange-50 border-orange-200 text-orange-700">
          <FlaskConical className="w-3.5 h-3.5" /> Sandbox linkage
        </span>
        <span className="text-slate-700"><span className="font-bold text-slate-900">{r.count?.toLocaleString?.() ?? 0}</span> total samples contacted this {kindLabel}</span>
        {r.malicious > 0 && <span className="inline-flex items-center gap-1 text-red-700 font-semibold text-xs"><ShieldAlert className="w-3.5 h-3.5" /> {r.malicious} malicious</span>}
      </div>
      {r.families?.length > 0 && (
        <div className="mt-2 text-xs text-slate-500">
          Top families: <span className="text-slate-800">{r.families.slice(0, 5).map((f) => `${f.name} (${f.count})`).join(" · ")}</span>
        </div>
      )}
      {(r.samples || []).length > 0 && (
        <div className="mt-3 rounded-md border border-slate-200 divide-y divide-slate-100 max-h-72 overflow-y-auto bg-white">
          {r.samples.map((s, i) => {
            const V = tone(s.verdict);
            return (
              <a key={s.sha256 || i} href={s.url || `https://www.hybrid-analysis.com/sample/${s.sha256}`} target="_blank" rel="noopener noreferrer" data-testid={`ha-sample-${i}`}
                 className="grid grid-cols-[auto_1fr_auto] gap-3 items-center px-3 py-2 hover:bg-orange-50/40 transition-colors">
                <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${V.tone}`}>{V.label}</span>
                <div className="min-w-0">
                  <div className="text-sm text-slate-800 truncate">{s.vx_family || s.submit_name || s.sha256}</div>
                  <div className="text-[11px] text-slate-500 truncate font-mono-data">{s.sha256?.slice(0, 24)}… · {s.environment}</div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {s.threat_score != null && <span className="text-xs font-mono-data text-slate-500">score {s.threat_score}</span>}
                  <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
                </div>
              </a>
            );
          })}
        </div>
      )}
    </>
  );
}

export default function HaAnalyzer() {
  const [value, setValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [resp, setResp] = useState(null); // { kind, value, result }
  const [err, setErr] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    const v = value.trim();
    if (!v) return;
    setLoading(true);
    setErr("");
    setResp(null);
    try {
      const { data } = await api.post("/hybrid/lookup", { value: v });
      setResp(data);
    } catch (e2) {
      setErr(formatApiErrorDetail(e2.response?.data?.detail) || "Hybrid Analysis lookup failed");
    } finally {
      setLoading(false);
    }
  };

  const KindPill = () => {
    if (!resp) return null;
    const meta = kindMeta[resp.kind] || { label: resp.kind?.toUpperCase() || "IOC", Icon: FileSearch };
    return (
      <span className="inline-flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider bg-slate-100 text-slate-600 px-2 py-0.5 rounded">
        <meta.Icon className="w-3 h-3" /> {meta.label}
      </span>
    );
  };

  return (
    <div data-testid="ha-analyzer" className="rounded-xl border border-slate-200 bg-white p-6">
      <div className="flex items-start gap-2 mb-2">
        <span className="w-8 h-8 rounded-lg bg-orange-50 text-[#F5821F] flex items-center justify-center shrink-0">
          <Zap className="w-4 h-4" strokeWidth={2.2} />
        </span>
        <div>
          <h3 className="font-heading text-base font-semibold text-slate-900">Hybrid Analysis · IOC Analyzer</h3>
          <p className="text-xs text-slate-500">Multi-scanner verdict from Falcon Sandbox — accepts URLs, SHA-256 hashes, IPs and domains.</p>
        </div>
      </div>

      <form onSubmit={submit} data-testid="ha-analyzer-form" className="mt-4 flex flex-col sm:flex-row gap-3">
        <input
          data-testid="ha-analyzer-input"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="Paste any IOC — https://…, SHA-256, 1.2.3.4, example.com"
          className="flex-1 bg-white border border-slate-300 focus:border-[#F5821F] focus:ring-2 focus:ring-orange-100 outline-none px-3.5 py-2.5 text-sm text-slate-800 placeholder:text-slate-400 rounded-md transition-shadow font-mono-data"
        />
        <button
          type="submit"
          disabled={loading || !value.trim()}
          data-testid="ha-analyzer-submit"
          className="inline-flex items-center justify-center gap-2 bg-[#F5821F] hover:bg-[#E27614] text-white text-sm font-semibold px-5 py-2.5 rounded-md transition-colors disabled:opacity-60"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />} Analyze
        </button>
      </form>

      <div className="mt-2 text-[11px] text-slate-400">
        Supported: URL, SHA-256, IP, Domain. SHA-1 / MD5 are only supported via the OSINT analyzer above (HA sandbox indexes on SHA-256).
      </div>

      {err && <div data-testid="ha-analyzer-err" className="mt-3 text-sm text-red-600">{err}</div>}

      <AnimatePresence>
        {resp && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="mt-5 rounded-lg border border-slate-200 bg-slate-50 p-4"
            data-testid="ha-analyzer-result"
          >
            <div className="flex items-center gap-2 mb-3">
              <KindPill />
              <span className="text-xs text-slate-500 truncate font-mono-data">{resp.value}</span>
            </div>
            {resp.kind === "url" && <UrlResult r={resp.result} />}
            {(resp.kind === "sha256" || resp.kind === "sha1" || resp.kind === "md5") && <HashResult r={resp.result} value={resp.value} />}
            {(resp.kind === "ip" || resp.kind === "domain") && <HostResult r={resp.result} kindLabel={resp.kind === "ip" ? "IP" : "domain"} />}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
