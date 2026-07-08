import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Search, ExternalLink, Loader2, ShieldQuestion, MapPin, Server, AlertTriangle, Globe2, ShieldCheck, List, Sparkles, Database, Check } from "lucide-react";
import { api, formatApiErrorDetail } from "@/lib/api";
import { FAVICON, TYPE_LABEL } from "@/lib/iocUtils";
import { useAuth } from "@/context/AuthContext";
import ReputationBadges from "./ReputationBadges";
import KnownIocBanner from "./KnownIocBanner";
import IocBulkTable from "./IocBulkTable";

export default function IocAnalyzer() {
  const { user } = useAuth();
  const isAdmin = !!user;
  const [mode, setMode] = useState("single");
  const [value, setValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [ai, setAi] = useState({ loading: false, text: "", error: "" });
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  const analyze = async (e) => {
    e.preventDefault();
    if (!value.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);
    setAi({ loading: false, text: "", error: "" });
    setSaved(false);
    try {
      const { data } = await api.get("/ioc-lookup", { params: { value: value.trim() } });
      setResult(data);
      if (data.local_db) setSaved(true);
    } catch (err) {
      setError(formatApiErrorDetail(err.response?.data?.detail) || "Lookup failed");
    } finally {
      setLoading(false);
    }
  };

  const runAi = async () => {
    if (!result) return;
    setAi({ loading: true, text: "", error: "" });
    try {
      const { data } = await api.post("/ioc-ai-summary", { value: result.value });
      setAi({ loading: false, text: data.summary, error: "" });
    } catch (err) {
      setAi({ loading: false, text: "", error: formatApiErrorDetail(err.response?.data?.detail) || "AI analysis failed" });
    }
  };

  const suggestedSeverity = () => {
    const vt = result?.reputation?.vt;
    const ab = result?.reputation?.abuseipdb;
    const mal = vt && !vt.error ? (vt.malicious || 0) + (vt.suspicious || 0) : 0;
    const score = ab && !ab.error ? (ab.score || 0) : 0;
    if (mal >= 5 || score >= 75) return "critical";
    if (mal >= 1 || score >= 40) return "high";
    if (result?.enrichment?.kind === "hash" && result?.enrichment?.known_malicious) return "critical";
    return "medium";
  };

  const saveToDb = async () => {
    if (!result) return;
    setSaving(true);
    try {
      const vt = result.reputation?.vt;
      await api.post("/iocs", {
        value: result.value,
        threat_name: (vt && !vt.error && vt.threat_label) || null,
        tags: (vt && !vt.error && (vt.threat_categories || []).slice(0, 4)) || [],
        severity: suggestedSeverity(),
        source: "IOC Analyzer",
        notes: vt && !vt.error && vt.total ? `VirusTotal ${(vt.malicious || 0)}/${vt.total} at time of save` : null,
      });
      setSaved(true);
    } catch (err) {
      setError(formatApiErrorDetail(err.response?.data?.detail) || "Could not save IOC");
    } finally {
      setSaving(false);
    }
  };

  const en = result?.enrichment;

  return (
    <div className="mb-10">
      {/* Mode toggle */}
      <div className="inline-flex items-center gap-1 p-1 mb-4 bg-slate-100 rounded-lg" data-testid="ioc-mode-toggle">
        <button
          onClick={() => setMode("single")}
          data-testid="ioc-mode-single"
          className={`inline-flex items-center gap-1.5 text-sm font-semibold px-3.5 py-1.5 rounded-md transition-colors ${mode === "single" ? "bg-white text-[#2E7DF5] shadow-sm" : "text-slate-500 hover:text-slate-700"}`}
        >
          <Search className="w-4 h-4" /> Single
        </button>
        <button
          onClick={() => setMode("bulk")}
          data-testid="ioc-mode-bulk"
          className={`inline-flex items-center gap-1.5 text-sm font-semibold px-3.5 py-1.5 rounded-md transition-colors ${mode === "bulk" ? "bg-white text-[#2E7DF5] shadow-sm" : "text-slate-500 hover:text-slate-700"}`}
        >
          <List className="w-4 h-4" /> Bulk paste
        </button>
      </div>

      {mode === "bulk" ? (
        <IocBulkTable />
      ) : (
        <>
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
              <div className="ml-auto"><ReputationBadges reputation={result.reputation} size="md" /></div>
            </div>

            {/* Enrichment */}
            <div className="px-5 py-4 space-y-4">
              {result.local_db && <KnownIocBanner local={result.local_db} />}

              {/* Action toolbar */}
              <div className="flex flex-wrap items-center gap-2">
                <button onClick={runAi} disabled={ai.loading} data-testid="ioc-ai-btn" className="inline-flex items-center gap-1.5 text-sm font-semibold px-3.5 py-2 rounded-md bg-gradient-to-r from-[#2E7DF5] to-[#6d5cf5] text-white hover:opacity-90 transition-opacity disabled:opacity-60">
                  {ai.loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />} Analyze with AI
                </button>
                {isAdmin && (
                  saved ? (
                    <span data-testid="ioc-saved-badge" className="inline-flex items-center gap-1.5 text-sm font-semibold px-3.5 py-2 rounded-md bg-green-50 border border-green-200 text-green-700"><Check className="w-4 h-4" /> In IOC database</span>
                  ) : (
                    <button onClick={saveToDb} disabled={saving} data-testid="ioc-save-btn" className="inline-flex items-center gap-1.5 text-sm font-semibold px-3.5 py-2 rounded-md border border-slate-300 text-slate-700 hover:border-[#2E7DF5] hover:text-[#2E7DF5] transition-colors disabled:opacity-60">
                      {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Database className="w-4 h-4" />} Save to IOC Database
                    </button>
                  )
                )}
              </div>

              {ai.error && <div data-testid="ioc-ai-error" className="text-sm text-red-600 flex items-center gap-1.5"><ShieldQuestion className="w-4 h-4" /> {ai.error}</div>}
              {ai.text && (
                <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} data-testid="ioc-ai-summary" className="rounded-lg border border-[#2E7DF5]/20 bg-blue-50/50 p-4">
                  <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wide text-[#2E7DF5] mb-2"><Sparkles className="w-3.5 h-3.5" /> AI Threat Assessment <span className="text-slate-400 font-normal normal-case">· Gemini</span></div>
                  <p className="text-sm text-slate-700 leading-relaxed">{ai.text}</p>
                </motion.div>
              )}

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
                <div className="space-y-4" data-testid="ioc-web-result">
                  {en.preview?.screenshot && (
                    <a
                      href={en.preview.url || `https://urlscan.io/search/#${encodeURIComponent(result.value)}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      data-testid="ioc-web-preview"
                      className="block relative rounded-lg overflow-hidden border border-slate-200 bg-slate-100 group max-w-md"
                    >
                      <img
                        src={en.preview.screenshot}
                        alt={`Landing page preview of ${en.host}`}
                        loading="lazy"
                        className="w-full h-auto max-h-72 object-cover object-top"
                        onError={(e) => { e.currentTarget.closest('a').style.display = 'none'; }}
                      />
                      <div className="absolute top-2 left-2 flex items-center gap-1.5 bg-black/60 backdrop-blur text-white text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded">
                        <Globe2 className="w-3 h-3" /> Live page preview · urlscan.io
                      </div>
                      <div className="absolute inset-0 bg-[#2E7DF5]/0 group-hover:bg-[#2E7DF5]/5 transition-colors" />
                    </a>
                  )}
                  {(en.resolved_ip || en.geo) && (
                    <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
                      {en.resolved_ip && <span className="flex items-center gap-1.5 text-slate-700"><Server className="w-4 h-4 text-[#2E7DF5]" /> Resolves to <code className="font-mono-data text-slate-800">{en.resolved_ip}</code></span>}
                      {en.geo && <span className="flex items-center gap-1.5 text-slate-700"><MapPin className="w-4 h-4 text-[#F5821F]" />{[en.geo.city, en.geo.country].filter(Boolean).join(", ") || "—"}</span>}
                      {en.geo?.isp && <span className="text-slate-600">{en.geo.isp}</span>}
                      {en.geo?.asn && <span className="text-slate-400 font-mono-data text-xs">{en.geo.asn}</span>}
                    </div>
                  )}
                  {en.open_ports?.length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2 flex items-center gap-1.5"><Server className="w-4 h-4 text-[#2E7DF5]" /> Open Ports ({en.open_ports.length})</div>
                      <div className="flex flex-wrap gap-1.5">
                        {en.open_ports.map((p) => (
                          <span key={p} className="font-mono-data text-xs bg-white border border-slate-200 text-slate-700 px-2 py-0.5 rounded">{p}</span>
                        ))}
                      </div>
                    </div>
                  )}
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
                  <div className="flex items-center gap-2 text-sm text-slate-700"><Globe2 className="w-4 h-4 text-[#2E7DF5]" /> <span className="font-semibold">{(en.scan_count || 0).toLocaleString()}</span> prior scans on urlscan.io</div>
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
                  {result.reputation?.vt && !result.reputation.vt.error && result.reputation.vt.found && (
                    <div className="pt-3 mt-1 border-t border-slate-200" data-testid="ioc-hash-vt-community">
                      <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">
                        <img src="https://www.google.com/s2/favicons?domain=virustotal.com&sz=32" alt="" className="w-3.5 h-3.5" /> VirusTotal Community
                      </div>
                      <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm mb-2">
                        {result.reputation.vt.threat_label && (
                          <span className="text-slate-700">Threat label: <span className="font-mono-data text-red-700">{result.reputation.vt.threat_label}</span></span>
                        )}
                        {result.reputation.vt.last_analysis_date && (
                          <span className="text-slate-500 text-xs">Last analyzed {new Date(result.reputation.vt.last_analysis_date * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })}</span>
                        )}
                      </div>
                      {(result.reputation.vt.threat_categories?.length > 0 || result.reputation.vt.tags?.length > 0) && (
                        <div className="flex flex-wrap gap-1.5">
                          {result.reputation.vt.threat_categories?.map((c) => (
                            <span key={`cat-${c}`} className="text-xs bg-red-50 border border-red-200 text-red-700 px-2 py-0.5 rounded-full">{c}</span>
                          ))}
                          {result.reputation.vt.tags?.map((t) => (
                            <span key={`tag-${t}`} className="text-xs bg-slate-100 border border-slate-200 text-slate-600 px-2 py-0.5 rounded-full font-mono-data">{t}</span>
                          ))}
                        </div>
                      )}
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
        </>
      )}
    </div>
  );
}
