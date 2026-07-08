import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Search, ExternalLink, Loader2, ShieldQuestion, MapPin, Server, AlertTriangle, Globe2, ShieldCheck } from "lucide-react";
import { api, formatApiErrorDetail } from "@/lib/api";

const FAVICON = {
  "VirusTotal": "virustotal.com",
  "AbuseIPDB": "abuseipdb.com",
  "Cisco Talos": "talosintelligence.com",
  "IBM X-Force": "exchange.xforce.ibmcloud.com",
  "urlscan.io": "urlscan.io",
  "MalwareBazaar": "abuse.ch",
  "ThreatFox": "threatfox.abuse.ch",
  "Hybrid Analysis": "hybrid-analysis.com",
  "Shodan": "shodan.io",
  "GreyNoise": "greynoise.io",
};

const TYPE_LABEL = { md5: "MD5 Hash", sha1: "SHA1 Hash", sha256: "SHA256 Hash", ip: "IP Address", domain: "Domain", url: "URL" };

export default function IocAnalyzer() {
  const [value, setValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const analyze = async (e) => {
    e.preventDefault();
    if (!value.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const { data } = await api.get("/ioc-lookup", { params: { value: value.trim() } });
      setResult(data);
    } catch (err) {
      setError(formatApiErrorDetail(err.response?.data?.detail) || "Lookup failed");
    } finally {
      setLoading(false);
    }
  };

  const en = result?.enrichment;

  return (
    <div className="mb-10">
      <form onSubmit={analyze} data-testid="ioc-analyzer-form" className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            data-testid="ioc-input"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Paste an IOC — hash, IP, domain or URL (e.g. 1.1.1.1)"
            className="w-full bg-white border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none pl-10 pr-4 py-3 text-sm text-slate-800 placeholder:text-slate-400 rounded-md transition-shadow"
          />
        </div>
        <button data-testid="ioc-submit" disabled={loading} className="inline-flex items-center justify-center gap-2 bg-[#2E7DF5] hover:bg-[#2563EB] text-white text-sm font-semibold px-6 py-3 rounded-md transition-colors disabled:opacity-60">
          {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} Analyze
        </button>
      </form>

      {error && <div data-testid="ioc-error" className="mt-3 text-sm text-red-600 flex items-center gap-1.5"><ShieldQuestion className="w-4 h-4" /> {error}</div>}

      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            data-testid="ioc-result"
            className="mt-5 rounded-xl border border-slate-200 bg-slate-50 overflow-hidden"
          >
            <div className="flex flex-wrap items-center gap-3 px-5 py-4 bg-white border-b border-slate-100">
              <span className="text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md bg-[#2E7DF5] text-white">{TYPE_LABEL[result.type] || result.type}</span>
              <code className="font-mono-data text-sm text-slate-800 break-all">{result.value}</code>
            </div>

            {/* Enrichment */}
            <div className="px-5 py-4">
              {en?.kind === "ip" && (
                <div className="space-y-4">
                  {en.geo && (
                    <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
                      <span className="flex items-center gap-1.5 text-slate-700"><MapPin className="w-4 h-4 text-[#F5821F]" />{[en.geo.city, en.geo.country].filter(Boolean).join(", ") || "—"}</span>
                      <span className="text-slate-600">{en.geo.isp}</span>
                      <span className="text-slate-400 font-mono-data text-xs">{en.geo.asn}</span>
                    </div>
                  )}
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2 flex items-center gap-1.5"><Server className="w-4 h-4 text-[#2E7DF5]" /> Open Ports ({en.open_ports.length})</div>
                    <div className="flex flex-wrap gap-1.5">
                      {en.open_ports.length ? en.open_ports.map((p) => (
                        <span key={p} className="font-mono-data text-xs bg-white border border-slate-200 text-slate-700 px-2 py-0.5 rounded">{p}</span>
                      )) : <span className="text-sm text-slate-400">None detected</span>}
                    </div>
                  </div>
                  {en.vulns?.length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-red-600 mb-2 flex items-center gap-1.5"><AlertTriangle className="w-4 h-4" /> Known Vulnerabilities ({en.vulns.length})</div>
                      <div className="flex flex-wrap gap-1.5">
                        {en.vulns.slice(0, 12).map((v) => (
                          <a key={v} href={`https://nvd.nist.gov/vuln/detail/${v}`} target="_blank" rel="noopener noreferrer" className="font-mono-data text-xs bg-red-50 border border-red-200 text-red-700 px-2 py-0.5 rounded hover:underline">{v}</a>
                        ))}
                      </div>
                    </div>
                  )}
                  {en.tags?.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {en.tags.map((t) => <span key={t} className="text-xs bg-orange-50 border border-orange-200 text-orange-700 px-2 py-0.5 rounded-full">{t}</span>)}
                    </div>
                  )}
                  <div className="text-xs text-slate-400">Enrichment: {en.sources.join(" · ")}</div>
                </div>
              )}

              {en?.kind === "web" && (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-sm text-slate-700"><Globe2 className="w-4 h-4 text-[#2E7DF5]" /> <span className="font-semibold">{en.scan_count.toLocaleString()}</span> prior scans on urlscan.io</div>
                  {en.recent_scans?.length > 0 && (
                    <div className="space-y-1.5">
                      {en.recent_scans.map((s, i) => (
                        <a key={i} href={`https://urlscan.io/search/#${encodeURIComponent(result.value)}`} target="_blank" rel="noopener noreferrer" className="block text-xs text-slate-500 hover:text-[#2E7DF5] truncate">{s.url}</a>
                      ))}
                    </div>
                  )}
                  <div className="text-xs text-slate-400">Enrichment: {en.sources.join(" · ")}</div>
                </div>
              )}

              {en?.kind === "hash" && (
                <div className="space-y-3" data-testid="ioc-hash-result">
                  {en.found ? (
                    <>
                      <div className="flex flex-wrap items-center gap-2">
                        {en.known_malicious ? (
                          <span data-testid="ioc-hash-verdict" className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-md bg-red-50 border border-red-200 text-red-700"><AlertTriangle className="w-3.5 h-3.5" /> Known Malicious</span>
                        ) : (
                          <span data-testid="ioc-hash-verdict" className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-md bg-green-50 border border-green-200 text-green-700"><ShieldCheck className="w-3.5 h-3.5" /> Known Good File</span>
                        )}
                        <span className="text-xs text-slate-500">in CIRCL known-file database</span>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5 text-sm">
                        {en.filename && <div><span className="text-slate-400 text-xs uppercase tracking-wide">File name</span><div className="text-slate-800 font-mono-data break-all">{en.filename}</div></div>}
                        {en.filesize && <div><span className="text-slate-400 text-xs uppercase tracking-wide">Size</span><div className="text-slate-800">{Number(en.filesize).toLocaleString()} bytes</div></div>}
                        {en.product && <div><span className="text-slate-400 text-xs uppercase tracking-wide">Product</span><div className="text-slate-800">{en.product}</div></div>}
                        {en.source_label && <div><span className="text-slate-400 text-xs uppercase tracking-wide">Source</span><div className="text-slate-800">{en.source_label}</div></div>}
                      </div>
                    </>
                  ) : (
                    <div className="flex items-start gap-2 text-sm text-slate-600 bg-white border border-slate-200 rounded-lg px-3.5 py-3">
                      <ShieldQuestion className="w-4 h-4 text-slate-400 mt-0.5 shrink-0" />
                      <span>{en.note}</span>
                    </div>
                  )}
                  <div className="text-xs text-slate-400">Enrichment: {en.sources.join(" · ")}</div>
                </div>
              )}

              {/* Deep links */}
              <div className="mt-5 pt-4 border-t border-slate-200">
                <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-3">Open full analysis in</div>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(result.links).map(([name, url]) => (
                    <a
                      key={name}
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      data-testid={`ioc-link-${name.replace(/\s+/g, "-").toLowerCase()}`}
                      className="inline-flex items-center gap-2 bg-white border border-slate-300 hover:border-[#2E7DF5] hover:text-[#2E7DF5] text-slate-700 text-sm font-semibold px-3.5 py-2 rounded-md transition-colors"
                    >
                      <img src={`https://www.google.com/s2/favicons?domain=${FAVICON[name]}&sz=32`} alt="" className="w-4 h-4" onError={(e) => { e.currentTarget.style.display = "none"; }} />
                      {name} <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
