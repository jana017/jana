import React, { useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import { Loader2, Download, ListChecks, ShieldQuestion, ExternalLink, ShieldPlus, Check, ChevronDown, ChevronRight, FileText, FileJson, FileSpreadsheet } from "lucide-react";
import { api, formatApiErrorDetail } from "@/lib/api";
import {
  FAVICON, TYPE_LABEL, iocSummary, severityStyle,
  resultsToCSV, downloadCSV,
  resultsToJSON, downloadJSON,
  resultsToMarkdown, downloadMarkdown,
} from "@/lib/iocUtils";
import { useAuth } from "@/context/AuthContext";
import ReputationBadges from "./ReputationBadges";
import IocBulkDetailPanel from "./IocBulkDetailPanel";

const TYPE_TONE = {
  ip: "bg-blue-50 text-blue-700 border-blue-200",
  domain: "bg-indigo-50 text-indigo-700 border-indigo-200",
  url: "bg-violet-50 text-violet-700 border-violet-200",
  md5: "bg-slate-100 text-slate-700 border-slate-200",
  sha1: "bg-slate-100 text-slate-700 border-slate-200",
  sha256: "bg-slate-100 text-slate-700 border-slate-200",
  unknown: "bg-red-50 text-red-600 border-red-200",
};

// "Flagged" = malicious (VT hits > 0 or Abuse >= 50) OR suspicious (VT suspicious > 0 or Abuse > 0).
function isFlagged(r) {
  const vt = r?.reputation?.vt;
  const ab = r?.reputation?.abuseipdb;
  const vtHits = vt && !vt.error && vt.found !== false ? (vt.malicious || 0) + (vt.suspicious || 0) : 0;
  const abScore = ab && !ab.error ? (ab.score || 0) : 0;
  return vtHits > 0 || abScore > 0;
}

function inferredSeverity(r) {
  const vt = r?.reputation?.vt;
  const ab = r?.reputation?.abuseipdb;
  const vtMal = vt && !vt.error && vt.found !== false ? (vt.malicious || 0) : 0;
  const abScore = ab && !ab.error ? (ab.score || 0) : 0;
  if (vtMal >= 5 || abScore >= 75) return "critical";
  if (vtMal >= 1 || abScore >= 50) return "high";
  return "medium";
}

export default function IocBulkTable({ initialText, autoRun, prefillKey }) {
  const { user } = useAuth();
  const isAdmin = !!user;
  const [text, setText] = useState(initialText || "");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState(null); // {kind, text}
  const [exportOpen, setExportOpen] = useState(false);
  const exportRef = useRef(null);
  // Which rows are expanded to show the full OSINT dossier.
  const [expanded, setExpanded] = useState(() => new Set());
  const toggleRow = (idx) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx); else next.add(idx);
      return next;
    });
  };
  const expandAll = () => setExpanded(new Set((results || []).map((_, i) => i)));
  const collapseAll = () => setExpanded(new Set());

  // Close the export dropdown on outside click.
  useEffect(() => {
    if (!exportOpen) return;
    const onDoc = (e) => {
      if (exportRef.current && !exportRef.current.contains(e.target)) setExportOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [exportOpen]);

  const parsedCount = useMemo(() => {
    const set = new Set(text.split(/[\s,;]+/).map((t) => t.trim().toLowerCase()).filter(Boolean));
    return set.size;
  }, [text]);

  const flaggedResults = useMemo(() => (results || []).filter(isFlagged), [results]);

  const analyze = async (overrideText) => {
    const payload = (overrideText ?? text).trim();
    if (!payload) return;
    setLoading(true);
    setError("");
    setResults(null);
    setSaveMsg(null);
    try {
      const { data } = await api.post("/ioc-lookup-batch", { values: [payload] });
      setResults(data.results || []);
    } catch (err) {
      setError(formatApiErrorDetail(err.response?.data?.detail) || "Batch lookup failed");
    } finally {
      setLoading(false);
    }
  };

  // Consume prefill from a parent handoff (NivX Forge → analyzer). When
  // `prefillKey` changes we hydrate the textarea and, if `autoRun` is on,
  // immediately fire the batch lookup.
  useEffect(() => {
    if (!prefillKey) return;
    if (initialText != null) setText(initialText);
    if (autoRun && initialText?.trim()) {
      analyze(initialText);
    }
  }, [prefillKey]);

  const stamp = () => new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const doExportCSV = () => {
    if (!results?.length) return;
    downloadCSV(resultsToCSV(results), `nivx-ioc-analysis-${stamp()}.csv`);
    setExportOpen(false);
  };
  const doExportJSON = () => {
    if (!results?.length) return;
    downloadJSON(resultsToJSON(results), `nivx-ioc-analysis-${stamp()}.json`);
    setExportOpen(false);
  };
  const doExportMarkdown = () => {
    if (!results?.length) return;
    downloadMarkdown(resultsToMarkdown(results), `nivx-ioc-analysis-${stamp()}.md`);
    setExportOpen(false);
  };

  const saveFlagged = async () => {
    if (!flaggedResults.length) return;
    setSaving(true);
    setSaveMsg(null);
    try {
      // Group by inferred severity so each POST carries a consistent severity.
      const groups = { critical: [], high: [], medium: [] };
      flaggedResults.forEach((r) => { groups[inferredSeverity(r)].push(r.value); });
      let added = 0, updated = 0, skipped = 0;
      for (const [severity, values] of Object.entries(groups)) {
        if (!values.length) continue;
        const { data } = await api.post("/iocs/bulk", {
          values,
          severity,
          source: "IOC Analyzer (bulk save)",
          tags: ["analyzer-flagged"],
        });
        added += data.added || 0;
        updated += data.updated || 0;
        skipped += data.skipped || 0;
      }
      setSaveMsg({ kind: "ok", text: `Saved ${added} new · ${updated} updated · ${skipped} skipped` });
    } catch (err) {
      setSaveMsg({ kind: "err", text: formatApiErrorDetail(err.response?.data?.detail) || "Failed to save flagged IOCs" });
    } finally {
      setSaving(false);
    }
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
            <div className="relative" ref={exportRef}>
              <button
                onClick={() => setExportOpen((v) => !v)}
                data-testid="ioc-bulk-export"
                className="inline-flex items-center gap-2 border border-slate-300 hover:border-[#2E7DF5] hover:text-[#2E7DF5] text-slate-700 text-sm font-semibold px-4 py-2.5 rounded-md transition-colors"
              >
                <Download className="w-4 h-4" /> Download report
                <ChevronDown className={`w-3 h-3 transition-transform ${exportOpen ? "rotate-180" : ""}`} />
              </button>
              {exportOpen && (
                <div
                  data-testid="ioc-bulk-export-menu"
                  className="absolute right-0 mt-1 w-52 rounded-md border border-slate-200 bg-white shadow-lg z-10 py-1"
                >
                  <button
                    onClick={doExportCSV}
                    data-testid="ioc-bulk-export-csv"
                    className="w-full text-left px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 inline-flex items-center gap-2"
                  ><FileSpreadsheet className="w-4 h-4 text-emerald-600" /> CSV (spreadsheet)</button>
                  <button
                    onClick={doExportJSON}
                    data-testid="ioc-bulk-export-json"
                    className="w-full text-left px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 inline-flex items-center gap-2"
                  ><FileJson className="w-4 h-4 text-blue-600" /> JSON (full reputation)</button>
                  <button
                    onClick={doExportMarkdown}
                    data-testid="ioc-bulk-export-md"
                    className="w-full text-left px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 inline-flex items-center gap-2"
                  ><FileText className="w-4 h-4 text-fuchsia-600" /> Markdown (report)</button>
                </div>
              )}
            </div>
          )}
          {isAdmin && flaggedResults.length > 0 && (
            <button onClick={saveFlagged} disabled={saving} data-testid="ioc-bulk-save-flagged" className="inline-flex items-center gap-2 bg-red-600 hover:bg-red-700 disabled:opacity-60 text-white text-sm font-semibold px-4 py-2.5 rounded-md transition-colors">
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldPlus className="w-4 h-4" />} Save all flagged ({flaggedResults.length})
            </button>
          )}
          <button onClick={() => analyze()} disabled={loading || !text.trim()} data-testid="ioc-bulk-submit" className="inline-flex items-center justify-center gap-2 bg-[#2E7DF5] hover:bg-[#2563EB] text-white text-sm font-semibold px-6 py-2.5 rounded-md transition-colors disabled:opacity-60">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ListChecks className="w-4 h-4" />} Analyze all
          </button>
        </div>
      </div>

      {error && <div data-testid="ioc-bulk-error" className="mt-3 text-sm text-red-600 flex items-center gap-1.5"><ShieldQuestion className="w-4 h-4" /> {error}</div>}
      {saveMsg && (
        <div data-testid="ioc-bulk-save-msg" className={`mt-3 text-sm flex items-center gap-1.5 px-3 py-2 rounded-md border ${saveMsg.kind === "ok" ? "bg-green-50 border-green-200 text-green-700" : "bg-red-50 border-red-200 text-red-600"}`}>
          <Check className="w-4 h-4" /> {saveMsg.text}
        </div>
      )}

      {results?.length > 0 && (
        <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} data-testid="ioc-bulk-results" className="mt-5 rounded-xl border border-slate-200 overflow-hidden">
          <div className="px-4 py-2 border-b border-slate-100 bg-slate-50/60 flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={expanded.size === results.length ? collapseAll : expandAll}
              data-testid="ioc-bulk-toggle-all"
              className="text-xs font-semibold text-[#2E7DF5] hover:text-[#1E5FCC] inline-flex items-center gap-1"
            >
              {expanded.size === results.length ? (
                <>Collapse all <ChevronDown className="w-3 h-3 rotate-180" /></>
              ) : (
                <>Expand all dossiers <ChevronDown className="w-3 h-3" /></>
              )}
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-left text-xs uppercase tracking-wide text-slate-500">
                  <th className="px-2 py-3 font-semibold w-8"></th>
                  <th className="px-4 py-3 font-semibold">Indicator</th>
                  <th className="px-4 py-3 font-semibold">Type</th>
                  <th className="px-4 py-3 font-semibold">Summary</th>
                  <th className="px-4 py-3 font-semibold">Reputation</th>
                  <th className="px-4 py-3 font-semibold">Investigate</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {results.map((r, i) => {
                  const isOpen = expanded.has(i);
                  return (
                  <React.Fragment key={i}>
                  <tr data-testid={`ioc-bulk-row-${i}`} className="bg-white hover:bg-slate-50/60 transition-colors align-top">
                    <td className="px-2 py-3">
                      <button
                        onClick={() => toggleRow(i)}
                        data-testid={`ioc-bulk-expand-${i}`}
                        className="w-6 h-6 flex items-center justify-center text-slate-400 hover:text-[#2E7DF5] hover:bg-slate-100 rounded transition-colors"
                        aria-label={isOpen ? "Collapse dossier" : "Expand dossier"}
                        title={isOpen ? "Hide OSINT dossier" : "Show full OSINT dossier"}
                      >
                        {isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      </button>
                    </td>
                    <td className="px-4 py-3"><code className="font-mono-data text-xs text-slate-800 break-all">{r.value}</code></td>
                    <td className="px-4 py-3"><span className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md border ${TYPE_TONE[r.type] || TYPE_TONE.unknown}`}>{TYPE_LABEL[r.type] || r.type}</span></td>
                    <td className="px-4 py-3 text-slate-600 whitespace-nowrap">{iocSummary(r)}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-1.5">
                        {r.local_db && (
                          <span data-testid={`ioc-bulk-known-${i}`} title={r.local_db.threat_name || "Known IOC"} className={`inline-flex w-fit items-center gap-1 text-[10px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded ${severityStyle(r.local_db.severity).badge}`}>
                            Known · {r.local_db.severity}
                          </span>
                        )}
                        {r.reputation ? <ReputationBadges reputation={r.reputation} /> : (!r.local_db && <span className="text-xs text-slate-300">—</span>)}
                      </div>
                    </td>
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
                  {isOpen && (
                    <tr key={`row-${i}-detail`} className="bg-slate-50/60">
                      <td colSpan={6} className="p-0 border-t border-slate-100">
                        <IocBulkDetailPanel row={r} />
                      </td>
                    </tr>
                  )}
                  </React.Fragment>
                );})}
              </tbody>
            </table>
          </div>
        </motion.div>
      )}
    </div>
  );
}
