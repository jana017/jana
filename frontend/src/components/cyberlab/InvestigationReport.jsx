import { useRef, useState } from "react";
import { toast } from "sonner";
import { FileText, Upload, Play, Loader2, Copy, Download, Sparkles, ShieldAlert } from "lucide-react";
import { api, formatApiErrorDetail } from "@/lib/api";

/**
 * NivX Forge — Offline Investigation Report.
 *
 * Deterministic (no LLM). Takes a free-form analyst instruction plus a
 * data/logs corpus (typed or uploaded, any text-readable format up to 5 MB),
 * extracts IOCs / timestamps / users / devices, enriches IOCs via OSINT,
 * and emits a factual multi-paragraph MDR-style investigation report.
 *
 * Placed at the bottom of the NivX Forge page — after decode / auto-decode /
 * auto-investigate — so the analyst can pipe the current pipeline output
 * straight into a customer-ready report.
 */
export default function InvestigationReport({ pipelineOutput, extractedIocs = [] }) {
  const [instructions, setInstructions] = useState(
    "As a MDR Threat Hunter, analyze the below provided data/logs line by line and write the investigation report in 2 paras to escalate the incident to the customer."
  );
  const [data, setData] = useState("");
  const [enrich, setEnrich] = useState(true);
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState(null); // {report, iocs_extracted, stats, context, paragraph_count, generated_at}
  const [fileName, setFileName] = useState("");
  const fileRef = useRef(null);

  const usePipeline = () => {
    // Compose a corpus from the current pipeline: decoded output plus the
    // extracted IOCs so the report generator has everything at once.
    const bits = [];
    if (pipelineOutput) bits.push(pipelineOutput);
    if (extractedIocs?.length) bits.push("\n\n[extracted IOCs]\n" + extractedIocs.join("\n"));
    setData(bits.join("\n").trim());
    setFileName("");
    toast.info("Loaded current NivX Forge output into the report generator.");
  };

  const uploadFile = (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (f.size > 5 * 1024 * 1024) { toast.error("Max file size 5 MB"); return; }
    const reader = new FileReader();
    reader.onload = (ev) => {
      setData(String(ev.target?.result || ""));
      setFileName(f.name);
    };
    reader.readAsText(f);
    e.target.value = "";
  };

  const generate = async () => {
    if (!data.trim()) { toast.error("Paste or upload data/logs to analyze"); return; }
    setBusy(true);
    setReport(null);
    try {
      const { data: res } = await api.post("/forge/investigation-report", {
        instructions,
        data,
        enrich,
        max_iocs: 15,
      });
      setReport(res);
      toast.success(`Report generated · ${res.iocs_extracted?.length || 0} IOC${res.iocs_extracted?.length === 1 ? "" : "s"} · ${res.paragraph_count} para${res.paragraph_count === 1 ? "" : "s"}`);
    } catch (e) {
      toast.error(`Report generation failed: ${formatApiErrorDetail(e.response?.data?.detail) || e.message}`);
    } finally { setBusy(false); }
  };

  const copyReport = () => {
    if (!report?.report) return;
    navigator.clipboard.writeText(report.report);
    toast.success("Report copied to clipboard");
  };

  const downloadReport = () => {
    if (!report?.report) return;
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const header = `# NivX Forge — Offline Investigation Report\nGenerated: ${report.generated_at || new Date().toISOString()}\nParagraphs: ${report.paragraph_count}\n\n## Analyst instructions\n${report.instructions || "—"}\n\n## Extracted IOCs\n${(report.iocs_extracted || []).map((v) => `- ${v}`).join("\n") || "—"}\n\n## Report\n\n`;
    const blob = new Blob([header + report.report + "\n"], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `nivx-forge-report-${stamp}.md`; a.click();
    URL.revokeObjectURL(url);
  };

  const stats = report?.stats || {};

  return (
    <section
      data-testid="forge-investigation-report"
      className="mt-6 rounded-xl border border-slate-800 bg-slate-900/40 backdrop-blur-sm"
    >
      <header className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <FileText className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100">Offline Investigation Report</h3>
          <span className="text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-300">
            No AI · Deterministic
          </span>
        </div>
        <p className="text-[11px] text-slate-500 max-w-xl">
          Analyst-style MDR report from raw data/logs. IOCs are enriched against integrated OSINT (VirusTotal, AbuseIPDB, MalwareBazaar, URLhaus, ThreatFox, internal DB) and summarized deterministically — no LLM is called.
        </p>
      </header>

      <div className="p-4 space-y-4">
        <div>
          <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-400 mb-1.5">
            Analyst instructions
          </label>
          <textarea
            data-testid="forge-report-instructions"
            value={instructions}
            onChange={(e) => setInstructions(e.target.value)}
            rows={2}
            placeholder="e.g. As a MDR Threat Hunter, analyze the logs and write a 2-paragraph report to escalate to the customer."
            className="w-full bg-slate-950/60 border border-slate-800 focus:border-cyan-400 outline-none rounded-md px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 font-mono-data resize-y"
          />
          <p className="text-[10px] text-slate-500 mt-1">
            Format hints like <span className="text-slate-300">&quot;in 2 paras&quot;</span> or <span className="text-slate-300">&quot;three paragraphs&quot;</span> control the report length (max 6).
          </p>
        </div>

        <div>
          <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
            <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-400">
              Data / Logs {fileName && <span className="text-cyan-400 normal-case tracking-normal">· {fileName}</span>}
            </label>
            <div className="flex items-center gap-1.5">
              {pipelineOutput ? (
                <button
                  type="button"
                  onClick={usePipeline}
                  data-testid="forge-report-use-pipeline"
                  className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-300 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/60 rounded px-2 py-1 transition-colors"
                >
                  <Sparkles className="w-3 h-3" /> Use current NivX Forge output
                </button>
              ) : null}
              <label
                data-testid="forge-report-upload"
                title="Upload any text-readable file (txt, log, csv, json, xml, yaml, eml, md — max 5 MB)"
                className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-300 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/60 rounded px-2 py-1 cursor-pointer transition-colors"
              >
                <Upload className="w-3 h-3" /> Upload file
                <input
                  ref={fileRef}
                  type="file"
                  accept=".txt,.log,.csv,.tsv,.json,.jsonl,.ndjson,.xml,.yaml,.yml,.md,.eml,.evtx,text/*,application/json,application/octet-stream"
                  className="hidden"
                  onChange={uploadFile}
                />
              </label>
            </div>
          </div>
          <textarea
            data-testid="forge-report-data"
            value={data}
            onChange={(e) => { setData(e.target.value); if (fileName) setFileName(""); }}
            rows={8}
            placeholder={"Paste raw logs, alerts, or any incident data here — or upload a file.\n\nAny format (txt / log / csv / json / xml / yaml / eml / md / evtx-text ...) is accepted."}
            className="w-full bg-slate-950/60 border border-slate-800 focus:border-cyan-400 outline-none rounded-md px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 font-mono-data resize-y"
          />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={enrich}
              onChange={(e) => setEnrich(e.target.checked)}
              data-testid="forge-report-enrich-toggle"
              className="w-3.5 h-3.5 accent-cyan-500"
            />
            Enrich extracted IOCs against OSINT (VirusTotal / AbuseIPDB / MalwareBazaar / URLhaus / ThreatFox / internal DB)
          </label>
          <button
            type="button"
            onClick={generate}
            disabled={busy || !data.trim()}
            data-testid="forge-report-generate"
            className="inline-flex items-center gap-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 text-sm font-semibold px-4 py-2 rounded-md transition-colors"
          >
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {busy ? "Generating…" : "Generate report"}
          </button>
        </div>

        {report && (
          <div data-testid="forge-report-output" className="mt-2 rounded-md border border-slate-800 bg-slate-950/60 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded border border-slate-700 text-slate-300">
                  {report.iocs_extracted?.length || 0} IOC{report.iocs_extracted?.length === 1 ? "" : "s"}
                </span>
                {stats.malicious > 0 && (
                  <span className="text-[11px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded border border-red-500/40 bg-red-500/10 text-red-300 inline-flex items-center gap-1">
                    <ShieldAlert className="w-3 h-3" /> {stats.malicious} malicious
                  </span>
                )}
                {stats.suspicious > 0 && (
                  <span className="text-[11px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-300">
                    {stats.suspicious} suspicious
                  </span>
                )}
                {stats.clean > 0 && (
                  <span className="text-[11px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-300">
                    {stats.clean} clean
                  </span>
                )}
                {stats.known_internal > 0 && (
                  <span className="text-[11px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded border border-blue-500/40 bg-blue-500/10 text-blue-300">
                    {stats.known_internal} in NivX DB
                  </span>
                )}
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={copyReport}
                  data-testid="forge-report-copy"
                  className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-300 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/60 rounded px-2 py-1 transition-colors"
                >
                  <Copy className="w-3 h-3" /> Copy
                </button>
                <button
                  type="button"
                  onClick={downloadReport}
                  data-testid="forge-report-download"
                  className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-300 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/60 rounded px-2 py-1 transition-colors"
                >
                  <Download className="w-3 h-3" /> Download .md
                </button>
              </div>
            </div>
            <article className="text-sm leading-relaxed text-slate-100 whitespace-pre-wrap font-sans">
              {report.report}
            </article>
          </div>
        )}
      </div>
    </section>
  );
}
