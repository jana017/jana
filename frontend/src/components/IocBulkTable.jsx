import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Loader2, Download, ListChecks, ShieldQuestion, ExternalLink } from "lucide-react";
import { api, formatApiErrorDetail } from "@/lib/api";
import { FAVICON, TYPE_LABEL, iocSummary, resultsToCSV, downloadCSV } from "@/lib/iocUtils";
import ReputationBadges from "./ReputationBadges";

const TYPE_TONE = {
  ip: "bg-blue-50 text-blue-700 border-blue-200",
  domain: "bg-indigo-50 text-indigo-700 border-indigo-200",
  url: "bg-violet-50 text-violet-700 border-violet-200",
  md5: "bg-slate-100 text-slate-700 border-slate-200",
  sha1: "bg-slate-100 text-slate-700 border-slate-200",
  sha256: "bg-slate-100 text-slate-700 border-slate-200",
  unknown: "bg-red-50 text-red-600 border-red-200",
};

export default function IocBulkTable() {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  const parsedCount = useMemo(() => {
    const set = new Set(text.split(/[\s,;]+/).map((t) => t.trim().toLowerCase()).filter(Boolean));
    return set.size;
  }, [text]);

  const analyze = async () => {
    if (!text.trim()) return;
    setLoading(true);
    setError("");
    setResults(null);
    try {
      const { data } = await api.post("/ioc-lookup-batch", { values: [text] });
      setResults(data.results || []);
    } catch (err) {
      setError(formatApiErrorDetail(err.response?.data?.detail) || "Batch lookup failed");
    } finally {
      setLoading(false);
    }
  };

  const exportCSV = () => {
    if (results?.length) downloadCSV(resultsToCSV(results), "nivx-ioc-analysis.csv");
  };

  return (
    <div>
      <div className="relative">
        <textarea
          data-testid="ioc-bulk-input"
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={5}
          placeholder={"Paste multiple IOCs — one per line, comma or space separated\n1.1.1.1\nexample.com\n275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}
          className="w-full bg-white border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none px-4 py-3 text-sm font-mono-data text-slate-800 placeholder:text-slate-400 placeholder:font-sans rounded-md transition-shadow resize-y"
        />
      </div>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
        <span className="text-xs text-slate-500 flex items-center gap-1.5"><ListChecks className="w-4 h-4 text-[#2E7DF5]" /> {parsedCount} unique IOC{parsedCount === 1 ? "" : "s"} detected {parsedCount > 50 && <span className="text-orange-600">(first 50 analyzed)</span>}</span>
        <div className="flex items-center gap-2">
          {results?.length > 0 && (
            <button onClick={exportCSV} data-testid="ioc-bulk-export" className="inline-flex items-center gap-2 border border-slate-300 hover:border-[#2E7DF5] hover:text-[#2E7DF5] text-slate-700 text-sm font-semibold px-4 py-2.5 rounded-md transition-colors">
              <Download className="w-4 h-4" /> Download CSV
            </button>
          )}
          <button onClick={analyze} disabled={loading || !text.trim()} data-testid="ioc-bulk-submit" className="inline-flex items-center justify-center gap-2 bg-[#2E7DF5] hover:bg-[#2563EB] text-white text-sm font-semibold px-6 py-2.5 rounded-md transition-colors disabled:opacity-60">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ListChecks className="w-4 h-4" />} Analyze all
          </button>
        </div>
      </div>

      {error && <div data-testid="ioc-bulk-error" className="mt-3 text-sm text-red-600 flex items-center gap-1.5"><ShieldQuestion className="w-4 h-4" /> {error}</div>}

      {results?.length > 0 && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} data-testid="ioc-bulk-results" className="mt-5 rounded-xl border border-slate-200 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-left text-xs uppercase tracking-wide text-slate-500">
                  <th className="px-4 py-3 font-semibold">Indicator</th>
                  <th className="px-4 py-3 font-semibold">Type</th>
                  <th className="px-4 py-3 font-semibold">Summary</th>
                  <th className="px-4 py-3 font-semibold">Reputation</th>
                  <th className="px-4 py-3 font-semibold">Investigate</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {results.map((r, i) => (
                  <tr key={i} data-testid={`ioc-bulk-row-${i}`} className="bg-white hover:bg-slate-50/60 transition-colors align-top">
                    <td className="px-4 py-3"><code className="font-mono-data text-xs text-slate-800 break-all">{r.value}</code></td>
                    <td className="px-4 py-3"><span className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md border ${TYPE_TONE[r.type] || TYPE_TONE.unknown}`}>{TYPE_LABEL[r.type] || r.type}</span></td>
                    <td className="px-4 py-3 text-slate-600 whitespace-nowrap">{iocSummary(r)}</td>
                    <td className="px-4 py-3">{r.reputation ? <ReputationBadges reputation={r.reputation} /> : <span className="text-xs text-slate-300">—</span>}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1.5">
                        {Object.entries(r.links || {}).slice(0, 5).map(([name, url]) => (
                          <a key={name} href={url} target="_blank" rel="noopener noreferrer" title={name} data-testid={`ioc-bulk-link-${i}-${name.replace(/\s+/g, "-").toLowerCase()}`} className="inline-flex items-center justify-center w-7 h-7 rounded border border-slate-200 hover:border-[#2E7DF5] bg-white transition-colors">
                            <img src={`https://www.google.com/s2/favicons?domain=${FAVICON[name]}&sz=32`} alt={name} className="w-4 h-4" onError={(e) => { e.currentTarget.style.display = "none"; }} />
                          </a>
                        ))}
                        {!Object.keys(r.links || {}).length && <span className="text-xs text-slate-300 inline-flex items-center gap-1"><ExternalLink className="w-3 h-3" />—</span>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>
      )}
    </div>
  );
}
