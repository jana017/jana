import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Zap, Loader2, ExternalLink, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import { api, formatApiErrorDetail } from "@/lib/api";

const VERDICT_STYLE = {
  malicious:  { tone: "bg-red-50 border-red-200 text-red-700", Icon: ShieldAlert, label: "Malicious" },
  suspicious: { tone: "bg-orange-50 border-orange-200 text-orange-700", Icon: ShieldAlert, label: "Suspicious" },
  "no threat":{ tone: "bg-green-50 border-green-200 text-green-700", Icon: ShieldCheck, label: "No threat" },
};

export default function HaUrlQuickScan() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState("");

  const run = async (e) => {
    e.preventDefault();
    const v = url.trim();
    if (!v) return;
    setLoading(true);
    setErr("");
    setResult(null);
    try {
      const { data } = await api.post("/hybrid/quick-scan-url", { url: v });
      setResult(data);
    } catch (e2) {
      setErr(formatApiErrorDetail(e2.response?.data?.detail) || "Quick scan failed");
    } finally {
      setLoading(false);
    }
  };

  const verdictKey = (result?.verdict || "").toLowerCase();
  const V = VERDICT_STYLE[verdictKey] || { tone: "bg-slate-50 border-slate-200 text-slate-600", Icon: ShieldQuestion, label: result?.verdict || "Unknown" };

  return (
    <div data-testid="ha-quickscan" className="rounded-xl border border-slate-200 bg-white p-6">
      <div className="flex items-center gap-2 mb-2">
        <span className="w-8 h-8 rounded-lg bg-orange-50 text-[#F5821F] flex items-center justify-center">
          <Zap className="w-4 h-4" strokeWidth={2.2} />
        </span>
        <div>
          <h3 className="font-heading text-base font-semibold text-slate-900">Hybrid Analysis · URL Quick Scan</h3>
          <p className="text-xs text-slate-500">Multi-scanner verdict from Falcon Sandbox — no upload required.</p>
        </div>
      </div>

      <form onSubmit={run} data-testid="ha-quickscan-form" className="mt-4 flex flex-col sm:flex-row gap-3">
        <input
          data-testid="ha-quickscan-input"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com/suspicious-page"
          className="flex-1 bg-white border border-slate-300 focus:border-[#F5821F] focus:ring-2 focus:ring-orange-100 outline-none px-3.5 py-2.5 text-sm text-slate-800 placeholder:text-slate-400 rounded-md transition-shadow"
        />
        <button
          type="submit"
          disabled={loading || !url.trim()}
          data-testid="ha-quickscan-submit"
          className="inline-flex items-center justify-center gap-2 bg-[#F5821F] hover:bg-[#E27614] text-white text-sm font-semibold px-5 py-2.5 rounded-md transition-colors disabled:opacity-60"
        >
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />} Quick scan
        </button>
      </form>

      {err && <div data-testid="ha-quickscan-err" className="mt-3 text-sm text-red-600">{err}</div>}

      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="mt-5 rounded-lg border border-slate-200 bg-slate-50 p-4"
            data-testid="ha-quickscan-result"
          >
            <div className="flex flex-wrap items-center gap-3">
              <span data-testid="ha-quickscan-verdict" className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-md border ${V.tone}`}>
                <V.Icon className="w-3.5 h-3.5" /> {V.label}
              </span>
              <span className="text-xs text-slate-500">
                <span className="font-bold text-slate-800">{result.malicious_scanners}</span>/{result.total_scanners} scanners flagged · {result.reports_count} prior reports
              </span>
              {result.report_url && (
                <a
                  href={result.report_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  data-testid="ha-quickscan-report-link"
                  className="ml-auto inline-flex items-center gap-1 text-xs font-semibold text-[#2E7DF5] hover:underline"
                >
                  View full report <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>

            {result.scanners?.length > 0 && (
              <div className="mt-3 rounded-md border border-slate-200 bg-white divide-y divide-slate-100">
                {result.scanners.map((s, i) => {
                  const isMalicious = s.positives != null && s.positives > 0;
                  return (
                    <div key={i} data-testid={`ha-scanner-${i}`} className="grid grid-cols-[1fr_auto_auto] gap-3 items-center px-3 py-2 text-sm">
                      <span className="text-slate-800 truncate">{s.name}</span>
                      <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${isMalicious ? "bg-red-50 text-red-700" : "bg-slate-100 text-slate-500"}`}>
                        {s.status || (isMalicious ? "detected" : "clean")}
                      </span>
                      <span className="text-xs text-slate-500 font-mono-data w-16 text-right tabular-nums">
                        {s.positives != null && s.total != null ? `${s.positives}/${s.total}` : "—"}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
