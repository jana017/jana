import { useRef, useState } from "react";
import { toast } from "sonner";
import { FileText, Upload, Play, Loader2, Copy, Download, Sparkles, ShieldAlert, GraduationCap, X, Pencil, Save } from "lucide-react";
import { api, formatApiErrorDetail } from "@/lib/api";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { getToken } from "@/lib/auth";

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
  const [aiMode, setAiMode] = useState(true);   // AI narrative by default (matches Circuit quality)
  const [aiModel, setAiModel] = useState("gemini-3-flash-preview");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState(null); // {report, iocs_extracted, stats, context, paragraph_count, generated_at, engine, ai_model}
  const [fileName, setFileName] = useState("");
  const fileRef = useRef(null);

  // Refinement dialog — analyst edits the generated report and saves as
  // training material for NivX Cognis AI's next similar case.
  const [refineOpen, setRefineOpen] = useState(false);
  const [refineBusy, setRefineBusy] = useState(false);
  // Inline edit of the generated report — stays local until analyst clicks
  // Refine & teach (which persists the edited version as training material).
  const [inlineEdit, setInlineEdit] = useState(false);
  const [inlineEditText, setInlineEditText] = useState("");
  const [refineForm, setRefineForm] = useState({
    title: "",
    case_type: "generic",
    tags: "",
    narrative: "",
    recommendations: "",
    analyst_notes: "",
  });

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

  const uploadFile = async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    if (f.size > 10 * 1024 * 1024) { toast.error("Max file size 10 MB"); return; }
    // If the file is an image, route through /api/forge/ocr-image so the
    // Tesseract-extracted text lands in the data box automatically.
    const isImage = (f.type || "").startsWith("image/") || /\.(png|jpe?g|webp|bmp|tiff?|gif)$/i.test(f.name);
    if (isImage) {
      const fd = new FormData();
      fd.append("file", f);
      try {
        toast.info(`Running OCR on ${f.name}…`);
        const { data: r } = await api.post("/forge/ocr-image", fd, { headers: { "Content-Type": "multipart/form-data" } });
        if (!r.text || !r.text.trim()) {
          toast.error(`OCR found no text in ${f.name}. Try a higher-resolution image.`);
          e.target.value = "";
          return;
        }
        setData(r.text);
        setFileName(`${f.name} (OCR · ${r.char_count} chars)`);
        toast.success(`Extracted ${r.char_count} chars from ${f.name}`);
      } catch (err) {
        toast.error(`OCR failed: ${formatApiErrorDetail(err.response?.data?.detail) || err.message}`);
      } finally {
        e.target.value = "";
      }
      return;
    }
    // Text-readable file — read as text.
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
        ai_mode: aiMode,
        ai_model: aiModel,
      });
      setReport(res);
      const fmt = res.format || {};
      const fmtLabel = fmt.mode === "bullets" ? "bullets" : `${fmt.count || 0} ${fmt.mode || "paras"}`;
      const engineLabel = res.engine === "ai" ? `NivX Cognis AI (${res.ai_model || aiModel})` : "offline";
      toast.success(`Report generated · ${engineLabel} · ${res.case_type || "generic"} case · ${res.iocs_extracted?.length || 0} IOC${res.iocs_extracted?.length === 1 ? "" : "s"} · ${fmtLabel}`);
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
    const fmt = report.format || {};
    const engineLine = report.engine === "ai" ? `Engine: NivX Cognis AI (${report.ai_model || "gemini"})` : "Engine: Offline deterministic";
    const header = `# NivX Forge — Investigation Report\nGenerated: ${report.generated_at || new Date().toISOString()}\n${engineLine}\nCase type: ${report.case_type || "generic"}\nFormat: ${fmt.mode || "paragraphs"}${fmt.count ? ` × ${fmt.count}` : ""}${fmt.verbose ? " (verbose)" : ""}\n\n## Analyst instructions\n${report.instructions || "—"}\n\n## Extracted IOCs\n${(report.iocs_extracted || []).map((v) => `- ${v}`).join("\n") || "—"}\n\n## Report\n\n`;
    const blob = new Blob([header + report.report + "\n"], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `nivx-forge-report-${stamp}.md`; a.click();
    URL.revokeObjectURL(url);
  };

  const openRefine = () => {
    if (!report?.report) return;
    if (!getToken()) {
      toast.error("Please log in as an analyst (admin or employee) to refine and save training material.");
      return;
    }
    // Split the report so the analyst edits only the narrative — recommendations
    // are shown separately and both saved back.
    const parts = String(report.report || "").split(/\n\nRecommendations:\n/);
    const narrative = (parts[0] || "").trim();
    const recsBlock = parts[1] || "";
    const recs = recsBlock
      .split("\n")
      .map((l) => l.replace(/^-\s*/, "").trim())
      .filter(Boolean);
    // Auto-title from the first line of the raw log.
    const firstLine = String(data || "").split("\n").map((s) => s.trim()).find((s) => s) || "";
    setRefineForm({
      title: firstLine ? firstLine.slice(0, 120) : `Refined MDR report · ${report.case_type || "generic"}`,
      case_type: report.case_type || "generic",
      tags: (report.iocs_extracted || []).slice(0, 5).join(", "),
      narrative,
      recommendations: recs.join("\n"),
      analyst_notes: "",
    });
    setRefineOpen(true);
  };

  const submitRefine = async () => {
    if (!refineForm.narrative.trim()) { toast.error("Refined narrative is required"); return; }
    setRefineBusy(true);
    try {
      const payload = {
        title: refineForm.title.trim(),
        case_type: refineForm.case_type.trim().toLowerCase() || "generic",
        tags: refineForm.tags.split(",").map((t) => t.trim()).filter(Boolean),
        raw_data: data,
        narrative: refineForm.narrative,
        recommendations: refineForm.recommendations.split("\n").map((r) => r.trim()).filter(Boolean),
        ai_original: report?.engine === "ai" ? String(report?.report || "").split(/\n\nRecommendations:\n/)[0] : "",
        ai_model: report?.ai_model || "",
        analyst_notes: refineForm.analyst_notes,
      };
      const { data: saved } = await api.post("/forge/training/refinements", payload);
      toast.success(`Saved as training example — NivX Cognis AI will use "${saved.title}" on the next similar case.`);
      setRefineOpen(false);
    } catch (e) {
      toast.error(`Save refinement failed: ${formatApiErrorDetail(e.response?.data?.detail) || e.message}`);
    } finally { setRefineBusy(false); }
  };

  const openInlineEdit = () => {
    if (!report?.report) return;
    setInlineEditText(String(report.report || ""));
    setInlineEdit(true);
  };
  const saveInlineEdit = () => {
    if (!inlineEditText.trim()) { toast.error("Report cannot be empty"); return; }
    setReport((r) => ({ ...(r || {}), report: inlineEditText }));
    setInlineEdit(false);
    toast.success("Report edited locally — click 'Refine & teach' to save it as a training example for NivX Cognis AI.");
  };
  const cancelInlineEdit = () => { setInlineEdit(false); setInlineEditText(""); };

  const stats = report?.stats || {};
  const caseType = report?.case_type || "";
  const caseLabel = { malware: "Malware / Endpoint", dns_proxy: "DNS / Proxy", mixed: "Mixed (malware + DNS)", generic: "Generic" }[caseType] || caseType;
  const caseTone = {
    malware:   "border-red-500/40 bg-red-500/10 text-red-300",
    dns_proxy: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    mixed:     "border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-300",
    generic:   "border-slate-500/40 bg-slate-500/10 text-slate-300",
  }[caseType] || "border-slate-500/40 bg-slate-500/10 text-slate-300";

  return (
    <section
      data-testid="forge-investigation-report"
      className="mt-6 rounded-xl border border-slate-800 bg-slate-900/40 backdrop-blur-sm"
    >
      <header className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <FileText className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100">Investigation Report</h3>
          {aiMode ? (
            <span data-testid="forge-report-mode-badge" className="text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded border border-violet-500/40 bg-violet-500/10 text-violet-300 inline-flex items-center gap-1">
              <Sparkles className="w-2.5 h-2.5" /> NivX Cognis AI · {aiModel === "gemini-3.5-flash" ? "Gemini 3.5 Flash" : "Gemini 3 Flash"}
            </span>
          ) : (
            <span data-testid="forge-report-mode-badge" className="text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-300">
              Offline · Deterministic
            </span>
          )}
        </div>
        <p className="text-[11px] text-slate-500 max-w-xl">
          MDR-style investigation report from raw data/logs. IOC extraction, OSINT enrichment (VirusTotal, AbuseIPDB, MalwareBazaar, URLhaus, ThreatFox, internal DB), case classification and remediation recommendations are ALWAYS deterministic. Narrative paragraphs are written by Gemini in AI mode or a rule engine in offline mode.
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
            Format is dynamic — try <span className="text-slate-300">&quot;in 2 paras&quot;</span>, <span className="text-slate-300">&quot;in 10 lines&quot;</span>, <span className="text-slate-300">&quot;5 sentences&quot;</span>, <span className="text-slate-300">&quot;bullet points&quot;</span> or <span className="text-slate-300">&quot;1 para with all details&quot;</span>. Case type (malware / DNS-proxy / mixed) auto-detected and remediation recommendations tailored accordingly.
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
                title="Upload any text-readable file (txt, log, csv, json, xml, yaml, eml, md) or an image screenshot (png/jpg/webp — auto-OCR) — max 10 MB"
                className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-300 hover:text-cyan-300 border border-slate-700 hover:border-cyan-500/60 rounded px-2 py-1 cursor-pointer transition-colors"
              >
                <Upload className="w-3 h-3" /> Upload file / screenshot
                <input
                  ref={fileRef}
                  type="file"
                  accept=".txt,.log,.csv,.tsv,.json,.jsonl,.ndjson,.xml,.yaml,.yml,.md,.eml,.evtx,.png,.jpg,.jpeg,.webp,.bmp,.tiff,.tif,.gif,text/*,image/*,application/json,application/octet-stream"
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
            placeholder={"Paste raw logs, alerts, or any incident data here — or upload a file / screenshot.\n\nText formats (txt / log / csv / json / xml / yaml / eml / md ...) are read directly. Image screenshots (png / jpg / webp) are auto-OCR'd via Tesseract into text."}
            className="w-full bg-slate-950/60 border border-slate-800 focus:border-cyan-400 outline-none rounded-md px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 font-mono-data resize-y"
          />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-4">
            <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={enrich}
                onChange={(e) => setEnrich(e.target.checked)}
                data-testid="forge-report-enrich-toggle"
                className="w-3.5 h-3.5 accent-cyan-500"
              />
              Enrich IOCs via OSINT
            </label>
            <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={aiMode}
                onChange={(e) => setAiMode(e.target.checked)}
                data-testid="forge-report-ai-toggle"
                className="w-3.5 h-3.5 accent-violet-500"
              />
              <span className="inline-flex items-center gap-1">
                <Sparkles className="w-3 h-3 text-violet-400" />
                NivX Cognis AI (Gemini)
              </span>
            </label>
            {aiMode && (
              <select
                value={aiModel}
                onChange={(e) => setAiModel(e.target.value)}
                data-testid="forge-report-ai-model"
                className="text-xs bg-slate-950/60 border border-slate-700 focus:border-violet-500 outline-none rounded px-2 py-1 text-slate-200"
              >
                <option value="gemini-3-flash-preview">Gemini 3 Flash (fast)</option>
                <option value="gemini-3.5-flash">Gemini 3.5 Flash (latest)</option>
              </select>
            )}
          </div>
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
                {report.engine === "ai" ? (
                  <span data-testid="forge-report-engine" className="text-[11px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded border border-violet-500/40 bg-violet-500/10 text-violet-300 inline-flex items-center gap-1">
                    <Sparkles className="w-3 h-3" /> Cognis · {report.ai_model === "gemini-3.5-flash" ? "3.5 Flash" : "3 Flash"}
                  </span>
                ) : (
                  <span data-testid="forge-report-engine" className="text-[11px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-300">
                    Offline
                  </span>
                )}
                {caseType && (
                  <span data-testid="forge-report-case" className={`text-[11px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded border ${caseTone}`}>
                    {caseLabel}
                  </span>
                )}
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
                {!inlineEdit ? (
                  <button
                    type="button"
                    onClick={openInlineEdit}
                    data-testid="forge-report-edit"
                    title="Edit the report inline"
                    className="inline-flex items-center gap-1 text-[11px] font-semibold text-amber-300 hover:text-amber-100 border border-amber-500/40 hover:border-amber-400 bg-amber-500/10 hover:bg-amber-500/20 rounded px-2 py-1 transition-colors"
                  >
                    <Pencil className="w-3 h-3" /> Edit
                  </button>
                ) : (
                  <>
                    <button
                      type="button"
                      onClick={saveInlineEdit}
                      data-testid="forge-report-edit-save"
                      title="Save the edited report to this session (use Refine & teach to persist)"
                      className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-200 hover:text-emerald-100 border border-emerald-500/40 hover:border-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 rounded px-2 py-1 transition-colors"
                    >
                      <Save className="w-3 h-3" /> Save edit
                    </button>
                    <button
                      type="button"
                      onClick={cancelInlineEdit}
                      data-testid="forge-report-edit-cancel"
                      className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-300 hover:text-slate-100 border border-slate-600 hover:border-slate-500 rounded px-2 py-1 transition-colors"
                    >
                      <X className="w-3 h-3" /> Cancel
                    </button>
                  </>
                )}
                <button
                  type="button"
                  onClick={openRefine}
                  data-testid="forge-report-refine"
                  title="Refine this report and save it as training material for NivX Cognis AI"
                  className="inline-flex items-center gap-1 text-[11px] font-semibold text-violet-300 hover:text-violet-100 border border-violet-500/40 hover:border-violet-400 bg-violet-500/10 hover:bg-violet-500/20 rounded px-2 py-1 transition-colors"
                >
                  <GraduationCap className="w-3 h-3" /> Refine &amp; teach
                </button>
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
            {inlineEdit ? (
              <textarea
                data-testid="forge-report-edit-textarea"
                value={inlineEditText}
                onChange={(e) => setInlineEditText(e.target.value)}
                rows={16}
                className="w-full bg-slate-900/80 border border-amber-500/40 focus:border-amber-400 outline-none rounded-md px-3 py-2 text-sm leading-relaxed text-slate-100 font-sans resize-y whitespace-pre-wrap"
              />
            ) : (
              <article className="text-sm leading-relaxed text-slate-100 whitespace-pre-wrap font-sans">
                {report.report}
              </article>
            )}
          </div>
        )}
      </div>

      {/* Refine & teach — analyst edits the report and saves the refined
          version as training material for NivX Cognis AI. */}
      <Dialog open={refineOpen} onOpenChange={setRefineOpen}>
        <DialogContent className="max-w-3xl max-h-[92vh] overflow-y-auto" data-testid="forge-refine-dialog">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-slate-900">
              <GraduationCap className="w-5 h-5 text-violet-500" />
              Refine &amp; teach NivX Cognis AI
            </DialogTitle>
            <DialogDescription className="text-slate-500">
              Edit the generated report to how it <em>should</em> read, then save. Your refined version is stored as a training example and retrieved as a style/content reference the next time a similar case is investigated — the AI gets better with every teach.
            </DialogDescription>
          </DialogHeader>

          {report?.engine === "ai" && (
            <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">
                NivX Cognis AI original (for reference — not saved as the refined version)
              </div>
              <p className="text-xs text-slate-700 whitespace-pre-wrap max-h-32 overflow-y-auto">
                {String(report?.report || "").split(/\n\nRecommendations:\n/)[0]}
              </p>
            </div>
          )}

          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Title</label>
              <input
                data-testid="forge-refine-title"
                value={refineForm.title}
                onChange={(e) => setRefineForm({ ...refineForm, title: e.target.value })}
                placeholder="e.g. XDR malicious hash on Startup folder — resource-manager mojibake"
                className="w-full text-sm px-3 py-2 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none"
              />
            </div>
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Case type</label>
              <select
                data-testid="forge-refine-case"
                value={refineForm.case_type}
                onChange={(e) => setRefineForm({ ...refineForm, case_type: e.target.value })}
                className="w-full text-sm px-3 py-2 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none bg-white"
              >
                {["malware","dns_proxy","mixed","phishing","insider","data_exfil","cloud_iam","ransomware","generic"].map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Tags (comma separated — e.g. IOCs, detection sources)</label>
            <input
              data-testid="forge-refine-tags"
              value={refineForm.tags}
              onChange={(e) => setRefineForm({ ...refineForm, tags: e.target.value })}
              placeholder="cisco-xdr, secure-endpoint, startup-folder, quarantine, mojibake"
              className="w-full text-sm px-3 py-2 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none font-mono-data"
            />
          </div>

          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">
              Refined narrative <span className="text-red-500">*</span> — <span className="normal-case text-slate-400">this is what future reports should read like</span>
            </label>
            <textarea
              data-testid="forge-refine-narrative"
              value={refineForm.narrative}
              onChange={(e) => setRefineForm({ ...refineForm, narrative: e.target.value })}
              rows={12}
              className="w-full text-sm px-3 py-2 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none text-slate-800"
            />
            <p className="text-[10px] text-slate-500 mt-1">
              The AI will match this tone, structure and phrasing on the next similar case — but it will NEVER copy specific IOCs, hostnames or dates from here.
            </p>
          </div>

          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Refined recommendations (one per line)</label>
            <textarea
              data-testid="forge-refine-recs"
              value={refineForm.recommendations}
              onChange={(e) => setRefineForm({ ...refineForm, recommendations: e.target.value })}
              rows={5}
              className="w-full text-sm px-3 py-2 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none text-slate-800"
            />
          </div>

          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Analyst notes (optional — when to use this style)</label>
            <textarea
              data-testid="forge-refine-notes"
              value={refineForm.analyst_notes}
              onChange={(e) => setRefineForm({ ...refineForm, analyst_notes: e.target.value })}
              rows={2}
              placeholder="Optional: 'Use for XDR alerts where SEP quarantined the file and it re-executed from the Startup folder.'"
              className="w-full text-sm px-3 py-2 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none"
            />
          </div>

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-100">
            <button
              type="button"
              onClick={() => setRefineOpen(false)}
              data-testid="forge-refine-cancel"
              className="inline-flex items-center gap-1.5 text-sm font-semibold text-slate-600 hover:text-slate-900 border border-slate-300 hover:border-slate-500 rounded-md px-3 py-2 transition-colors"
            >
              <X className="w-3.5 h-3.5" /> Cancel
            </button>
            <button
              type="button"
              onClick={submitRefine}
              disabled={refineBusy || !refineForm.narrative.trim()}
              data-testid="forge-refine-submit"
              className="inline-flex items-center gap-1.5 text-sm font-semibold text-white bg-violet-600 hover:bg-violet-500 disabled:opacity-50 rounded-md px-4 py-2 transition-colors"
            >
              {refineBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <GraduationCap className="w-4 h-4" />}
              Save &amp; teach Cognis AI
            </button>
          </div>
        </DialogContent>
      </Dialog>
    </section>
  );
}
