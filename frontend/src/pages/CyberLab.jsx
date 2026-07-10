import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import {
  Search, X, ChevronUp, ChevronDown, Copy, Trash2, Download, Upload, Sparkles,
  ShieldAlert, ShieldCheck, Zap, Play, Beaker, Bug, Fingerprint, Network,
  FileWarning, RefreshCw, Layers, Radar, Target, Cpu, Share2, Plus,
} from "lucide-react";
import Navbar from "@/components/Navbar";
import Contact from "@/components/Contact";
import useSeo from "@/lib/useSeo";
import { listPlugins, autoDecode, runRecipe, analyze, detectFormat, processTree, runAiAnalysis, enrichIocs, downloadReport } from "@/lib/cyberlabApi";
import AttackChainViewer from "@/components/cyberlab/AttackChainViewer";
import ProcessTreeViewer from "@/components/cyberlab/ProcessTreeViewer";
import AiPanel from "@/components/cyberlab/AiPanel";
import ShareModal from "@/components/cyberlab/ShareModal";
import CustomRuleModal from "@/components/cyberlab/CustomRuleModal";
import AutoInvestigateProgress from "@/components/cyberlab/AutoInvestigateProgress";
import VerdictBanner from "@/components/cyberlab/VerdictBanner";
import EnrichedIocsPanel from "@/components/cyberlab/EnrichedIocsPanel";

const CATEGORY_STYLE = {
  Encoding:      { chip: "bg-blue-500/10 text-blue-300 border-blue-500/30",         dot: "bg-blue-400" },
  Compression:   { chip: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30", dot: "bg-emerald-400" },
  Cryptography:  { chip: "bg-amber-500/10 text-amber-300 border-amber-500/30",       dot: "bg-amber-400" },
  Deobfuscation: { chip: "bg-fuchsia-500/10 text-fuchsia-300 border-fuchsia-500/30", dot: "bg-fuchsia-400" },
  Extractors:    { chip: "bg-rose-500/10 text-rose-300 border-rose-500/30",           dot: "bg-rose-400" },
  Utilities:     { chip: "bg-slate-500/10 text-slate-300 border-slate-500/30",       dot: "bg-slate-400" },
  Hashing:       { chip: "bg-indigo-500/10 text-indigo-300 border-indigo-500/30",     dot: "bg-indigo-400" },
};

const SEVERITY_STYLE = {
  critical: "bg-red-500/15 text-red-300 border-red-500/40",
  high:     "bg-orange-500/15 text-orange-300 border-orange-500/40",
  medium:   "bg-yellow-500/15 text-yellow-300 border-yellow-500/40",
  low:      "bg-blue-500/15 text-blue-300 border-blue-500/40",
  info:     "bg-slate-500/15 text-slate-300 border-slate-500/40",
};

const VERDICT_STYLE = {
  malicious:  { bg: "bg-red-500/10 border-red-500/40", text: "text-red-300", label: "Malicious", icon: ShieldAlert },
  suspicious: { bg: "bg-amber-500/10 border-amber-500/40", text: "text-amber-300", label: "Suspicious", icon: FileWarning },
  clean:      { bg: "bg-emerald-500/10 border-emerald-500/40", text: "text-emerald-300", label: "Clean", icon: ShieldCheck },
};

const EXAMPLES = [
  {
    label: "PowerShell -EncodedCommand",
    input: "powershell.exe -e JABvAHMAIAA9ACAARwBlAHQALQBDAGkAbQBJAG4AcwB0AGEAbgBjAGUAIABXAGkAbgAzADIAXwBPAHAAZQByAGEAdABpAG4AZwBTAHkAcwB0AGUAbQAKAEkAZgAgACgAJABvAHMALgBDAGEAcAB0AGkAbwBuACAALQBsAGkAawBlACAAIgAqAFcAaQBuAGQAbwB3AHMAKgAiACkAIAB7ACAAaAB0AHQAcABzADoALwAvADEAOAA1AC4AMgAyADAALgAxADAAMQAuADQAMgAvAGIAZQBhAGMAbwBuACAAfQA=",
  },
  {
    label: "Ransomware Note",
    input: "All your files have been encrypted with AES-256!\nContact us at hxxps://attacker[.]xyz/pay-btc-now\nBitcoin address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\nTo restore your files, you must pay the ransom in 72 hours.\nvssadmin.exe delete shadows /all /quiet\nbcdedit /set {default} recoveryenabled No",
  },
  {
    label: "Defanged IOCs bundle",
    input: "C2 = 45[.]137[.]21[.]90\nCallback: hxxps://malicious[.]site/beacon\nDropper hash: 44d88612fea8a8f36de82e1278abb02f\nDropper sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nContact: bad[at]attacker[.]xyz",
  },
  {
    label: "Nested base64 → gzip",
    input: "H4sIAAAAAAAAA0vOSCxKzUlNAQBqRZ2gCQAAAA==",
  },
  {
    label: "URL-encoded XSS",
    input: "%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E",
  },
];

const RISK_TEXT = (score) => {
  if (score >= 60) return "text-red-400";
  if (score >= 30) return "text-amber-400";
  return "text-emerald-400";
};

export default function CyberLab() {
  useSeo({
    title: "NivX Forge — Decoder & Threat Analysis Platform · NivX Machines",
    description: "Enterprise-grade payload decoder for DFIR analysts. Auto-decode PowerShell, MITRE ATT&CK mapping, YARA-lite rules, IOC extraction, and risk scoring.",
    canonical: "https://nivxmachines.com/nivx-forge",
  });

  const [plugins, setPlugins] = useState([]);
  const [q, setQ] = useState("");
  const [input, setInput] = useState("powershell.exe -e JABvAHMAIAA9ACAARwBlAHQALQBDAGkAbQBJAG4AcwB0AGEAbgBjAGUAIABXAGkAbgAzADIAXwBPAHAAZQByAGEAdABpAG4AZwBTAHkAcwB0AGUAbQA=");
  const [recipe, setRecipe] = useState([]);
  const [running, setRunning] = useState(false);
  const [autoBusy, setAutoBusy] = useState(false);
  const [investigateBusy, setInvestigateBusy] = useState(false);
  const [investigateStages, setInvestigateStages] = useState([]);
  const [investigateSummary, setInvestigateSummary] = useState("");
  const [result, setResult] = useState(null);
  const [processTreeData, setProcessTreeData] = useState(null); // {nodes,edges,stats,forensic_events}
  const [ai, setAi] = useState(null); // { summary, sigma_rule, yara_rule } — set when AI generates
  const [enrichedIocs, setEnrichedIocs] = useState(null); // enriched list from /enrich-iocs
  const [enrichMeta, setEnrichMeta] = useState(null); // {count, flagged, duration_ms, iocs_per_sec, cache_hit_rate, depth}
  const [enrichEnabled, setEnrichEnabled] = useState(true);
  const [enrichDepth, setEnrichDepth] = useState("comprehensive"); // free | comprehensive | ai
  const [enrichBusy, setEnrichBusy] = useState(false);
  const [downloadOpen, setDownloadOpen] = useState(false);
  const [downloading, setDownloading] = useState(null); // format label while download in flight
  const [selectedIocs, setSelectedIocs] = useState(() => new Set()); // Set<string> of IOC values checked in the IOCs tab
  const [tab, setTab] = useState("mitre");
  const [shareOpen, setShareOpen] = useState(false);
  const [ruleModalOpen, setRuleModalOpen] = useState(false);
  const [graphMode, setGraphMode] = useState("chain"); // "chain" | "process"

  useEffect(() => {
    listPlugins().then(setPlugins).catch((e) => toast.error(`Load plugins: ${e.message}`));
  }, []);

  // Group plugins by category
  const grouped = useMemo(() => {
    const term = q.trim().toLowerCase();
    const out = {};
    for (const p of plugins) {
      if (term && !p.name.toLowerCase().includes(term) && !p.description.toLowerCase().includes(term)) continue;
      (out[p.category] ||= []).push(p);
    }
    return out;
  }, [plugins, q]);

  const pluginMap = useMemo(() => Object.fromEntries(plugins.map((p) => [p.id, p])), [plugins]);

  const addStep = (id) => setRecipe((r) => [...r, { id, params: {} }]);
  const removeStep = (i) => setRecipe((r) => r.filter((_, idx) => idx !== i));
  const moveStep = (i, delta) => setRecipe((r) => {
    const next = [...r]; const t = i + delta;
    if (t < 0 || t >= next.length) return r;
    [next[i], next[t]] = [next[t], next[i]]; return next;
  });
  const clearRecipe = () => setRecipe([]);
  const updateParam = (i, key, val) => setRecipe((r) => r.map((s, idx) =>
    idx === i ? { ...s, params: { ...(s.params || {}), [key]: val } } : s));

  // -- Auto Decode: server-side chain search + full analysis --
  const runAuto = useCallback(async () => {
    if (!input.trim()) { toast.error("Paste a payload first"); return; }
    setAutoBusy(true);
    setResult(null);
    setAi(null);
    try {
      const res = await autoDecode(input, { include_analysis: true, max_depth: 10 });
      setResult(res);
      if (res.trace?.length) {
        setRecipe(res.trace.map((s) => ({ id: s.id, params: {} })));
        toast.success(`Auto-decoded ${res.trace.length} step${res.trace.length === 1 ? "" : "s"} · ${res.trace.map((s) => s.name).join(" → ")}`);
      } else {
        toast.info("No decoding needed — input is already plaintext.");
      }
    } catch (e) {
      toast.error(`Auto Decode failed: ${e.message}`);
    } finally { setAutoBusy(false); }
  }, [input]);

  // -- Auto Investigate: full orchestrated pipeline with live progress --
  // Runs sequential stages so the UI can render a live progress log:
  //    1. detect-format      2. auto-decode | parse-log
  //    3. threat analysis    4. AI analysis (Claude 4.5)
  //    5. render (graph + timeline)
  const runAutoInvestigate = useCallback(async () => {
    if (!input.trim()) { toast.error("Paste a payload first"); return; }
    setInvestigateBusy(true);
    setResult(null);
    setAi(null);
    setProcessTreeData(null);
    setInvestigateSummary("");
    // Seed all stages as pending so the panel appears immediately.
    const initial = [
      { name: "detect",       status: "pending" },
      { name: "auto-decode",  status: "pending" },
      { name: "analyze",      status: "pending" },
      { name: "ai",           status: "pending" },
      ...(enrichEnabled ? [{ name: "enrich", status: "pending" }] : []),
      { name: "render",       status: "pending" },
    ];
    setInvestigateStages(initial);
    setEnrichedIocs(null);
    setEnrichMeta(null);

    const markStage = (name, patch) =>
      setInvestigateStages((prev) => prev.map((s) => (s.name === name ? { ...s, ...patch } : s)));
    const swapStage = (from, to) =>
      setInvestigateStages((prev) => prev.map((s) => (s.name === from ? { ...s, name: to } : s)));

    try {
      // Stage 1 — detect
      markStage("detect", { status: "running" });
      const t0 = performance.now();
      const detect = await detectFormat(input);
      markStage("detect", {
        status: "ok",
        duration_ms: performance.now() - t0,
        meta: { kind: detect.kind, format: detect.format },
      });

      let analysis, output = "", trace = [];

      if (detect.kind === "log") {
        // swap "auto-decode" placeholder for "parse-log"
        swapStage("auto-decode", "parse-log");
        markStage("parse-log", { status: "running" });
        const t1 = performance.now();
        const tree = await processTree(input, detect.format);
        markStage("parse-log", {
          status: "ok",
          duration_ms: performance.now() - t1,
          meta: { event_count: tree.stats?.event_count ?? 0, process_count: tree.stats?.process_count ?? 0 },
        });
        setProcessTreeData(tree);

        // Aggregate MITRE from all events
        markStage("analyze", { status: "running" });
        const t2 = performance.now();
        const mitreSeen = new Map();
        for (const e of tree.forensic_events || []) {
          for (const t of e.mitre_techniques || []) {
            if (!mitreSeen.has(t.id)) {
              mitreSeen.set(t.id, { id: t.id, name: t.name, tactic: t.tactic, description: "", evidence: [] });
            }
            const evd = e.command_line || e.registry_key || e.url || "";
            const m = mitreSeen.get(t.id);
            if (evd && m.evidence.length < 5) m.evidence.push(evd);
          }
        }
        const mitreList = [...mitreSeen.values()];
        const iocs = tree.iocs || [];
        const worst = tree.stats?.worst_risk || "info";
        const boost = { critical: 40, high: 25, medium: 10, low: 5, info: 0 }[worst] ?? 0;
        let score = Math.min(100, Math.min(mitreList.length * 8, 40) + Math.min(iocs.length, 20) + boost);
        const verdict = score >= 60 ? "malicious" : score >= 30 ? "suspicious" : "clean";
        analysis = {
          iocs, mitre: mitreList, rules: [],
          risk_score: score, verdict,
          summary: `${verdict[0].toUpperCase()}${verdict.slice(1)} — ${mitreList.length} MITRE technique${mitreList.length === 1 ? "" : "s"}, ${iocs.length} IOC${iocs.length === 1 ? "" : "s"}, ${tree.stats?.process_count ?? 0} process${(tree.stats?.process_count ?? 0) === 1 ? "" : "es"}.`,
        };
        markStage("analyze", {
          status: "ok",
          duration_ms: performance.now() - t2,
          meta: { mitre: mitreList.length, iocs: iocs.length, risk_score: score },
        });
        setResult({ output: "", trace: [], analysis, duration_ms: 0, output_size: 0 });
        setGraphMode("process");
      } else {
        // Payload path — recursive decode + analysis
        markStage("auto-decode", { status: "running" });
        const t1 = performance.now();
        const dec = await autoDecode(input, { include_analysis: true, max_depth: 10 });
        markStage("auto-decode", {
          status: "ok",
          duration_ms: performance.now() - t1,
          meta: { steps: dec.trace?.length ?? 0, output_size: dec.output_size ?? 0 },
        });
        output = dec.output || "";
        trace = dec.trace || [];
        analysis = dec.analysis || {};
        markStage("analyze", {
          status: "ok",
          duration_ms: 0,
          meta: {
            mitre: analysis.mitre?.length ?? 0,
            rules: analysis.rules?.length ?? 0,
            iocs: analysis.iocs?.length ?? 0,
            risk_score: analysis.risk_score ?? 0,
          },
        });
        setResult({
          output, output_size: dec.output_size, trace,
          duration_ms: dec.duration_ms, analysis,
        });
        if (trace.length) setRecipe(trace.map((s) => ({ id: s.id, params: {} })));
        setGraphMode("chain");
      }

      // Stage 4 — AI analysis
      markStage("ai", { status: "running" });
      const t3 = performance.now();
      try {
        const aiPayload = {
          input,
          output: output || "",
          analysis: {
            mitre: analysis.mitre || [],
            rules: analysis.rules || [],
            iocs: analysis.iocs || [],
            verdict: analysis.verdict || "clean",
            risk_score: analysis.risk_score || 0,
          },
        };
        const aiResult = await runAiAnalysis(aiPayload);
        setAi(aiResult);
        markStage("ai", {
          status: "ok",
          duration_ms: performance.now() - t3,
          meta: { sigma: !!aiResult.sigma_rule, yara: !!aiResult.yara_rule, splunk: !!aiResult.splunk_spl },
        });
      } catch (e) {
        markStage("ai", { status: "failed", duration_ms: performance.now() - t3, meta: { error: e.message } });
      }

      // Stage 4.5 — OSINT Enrichment on extracted IOCs (opt-in, default on).
      // Fails soft — enrichment failure does not abort the investigation.
      if (enrichEnabled) {
        const iocValues = (analysis.iocs || [])
          .map((i) => i.value)
          .filter((v) => v && v.length < 512);
        if (iocValues.length > 0) {
          markStage("enrich", { status: "running" });
          const t4 = performance.now();
          try {
            const enrichRes = await enrichIocs(iocValues.slice(0, 20), enrichDepth);
            setEnrichedIocs(enrichRes.results || []);
            setEnrichMeta({
              count: enrichRes.count,
              flagged: enrichRes.flagged,
              duration_ms: enrichRes.duration_ms,
              iocs_per_sec: enrichRes.iocs_per_sec,
              cache_hit_rate: enrichRes.cache_hit_rate,
              depth: enrichRes.depth,
            });
            markStage("enrich", {
              status: "ok",
              duration_ms: performance.now() - t4,
              meta: {
                count: enrichRes.count,
                flagged: enrichRes.flagged,
                cache_pct: Math.round((enrichRes.cache_hit_rate || 0) * 100),
              },
            });
          } catch (e) {
            markStage("enrich", { status: "failed", duration_ms: performance.now() - t4, meta: { error: e.message } });
          }
        } else {
          markStage("enrich", { status: "ok", duration_ms: 0, meta: { count: 0, note: "no IOCs to enrich" } });
        }
      }

      // Stage 5 — Render (client-side, essentially instant)
      markStage("render", { status: "ok", duration_ms: 0, meta: {} });
      // Switch to graph tab so the analyst sees the flow immediately.
      setTab("graph");

      setInvestigateSummary(
        `${detect.kind === "log" ? "Log" : "Payload"} · ${detect.format} · verdict ${analysis.verdict?.toUpperCase()} · risk ${analysis.risk_score}/100`
      );
      toast.success(`Auto Investigation complete — ${analysis.verdict?.toUpperCase()} · risk ${analysis.risk_score}/100`);
    } catch (e) {
      toast.error(`Auto Investigation failed: ${e.message}`);
      // Mark any pending stages as failed for clarity
      setInvestigateStages((prev) =>
        prev.map((s) => (s.status === "pending" || s.status === "running" ? { ...s, status: "failed", meta: { error: e.message } } : s))
      );
    } finally {
      setInvestigateBusy(false);
    }
  }, [input, enrichEnabled, enrichDepth]);

  // -- Run current recipe manually --
  const runManual = useCallback(async () => {
    if (!input.trim()) { toast.error("Paste a payload first"); return; }
    setRunning(true);
    setAi(null);
    try {
      const res = await runRecipe(input, recipe);
      // For a manual run, also fetch full analysis of the resulting output
      const analysis = await analyze(res.output, false);
      setResult({
        output: res.output,
        output_size: res.output_size,
        trace: res.trace,
        duration_ms: res.duration_ms,
        analysis: {
          iocs: analysis.iocs,
          mitre: analysis.mitre,
          rules: analysis.rules,
          risk_score: analysis.risk_score,
          verdict: analysis.verdict,
          summary: analysis.summary,
        },
      });
    } catch (e) {
      toast.error(`Run failed: ${e.message}`);
    } finally { setRunning(false); }
  }, [input, recipe]);

  const copyOutput = () => {
    if (!result?.output) return;
    navigator.clipboard.writeText(result.output);
    toast.success("Output copied");
  };

  const downloadReport = () => {
    if (!result) return;
    const report = {
      input,
      output: result.output,
      pipeline: result.trace?.map((s) => `${s.name} (${s.category})`),
      analysis: result.analysis,
      generated_at: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `cyberlab-report-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
    toast.success("Report downloaded");
  };

  const sendToAnalyzer = () => {
    const iocs = (result?.analysis?.iocs || []).map((i) => i.value);
    if (!iocs.length) { toast.error("No IOCs to send."); return; }
    try { sessionStorage.setItem("nivx.iocBatch", JSON.stringify(iocs)); } catch { /* quota */ }
    window.location.href = "/threat-intelligence#analyzer";
  };

  // -- Inline bulk IOC analyzer: enrich a hand-picked subset of extracted
  // IOCs using the existing /api/cyberlab/enrich-iocs endpoint. Reuses the
  // same EnrichedIocsPanel that Auto Investigate uses.
  const enrichSelectedIocs = useCallback(async (valuesOverride) => {
    const src = (result?.analysis?.iocs || []).map((i) => i.value).filter(Boolean);
    let picked = valuesOverride;
    if (!picked) {
      picked = src.filter((v) => selectedIocs.has(v));
    }
    if (!picked.length) {
      toast.error("Select at least one IOC to analyze");
      return;
    }
    if (picked.length > 20) {
      toast.info(`Capped at 20 IOCs (you selected ${picked.length}).`);
      picked = picked.slice(0, 20);
    }
    setEnrichBusy(true);
    try {
      const res = await enrichIocs(picked, enrichDepth);
      setEnrichedIocs(res.results || []);
      setEnrichMeta({
        count: res.count, flagged: res.flagged,
        duration_ms: res.duration_ms, iocs_per_sec: res.iocs_per_sec,
        cache_hit_rate: res.cache_hit_rate, depth: res.depth,
      });
      toast.success(`Enriched ${res.count} IOC${res.count === 1 ? "" : "s"} · ${res.flagged} flagged · ${(res.duration_ms / 1000).toFixed(1)}s`);
      // Scroll the enrichment panel into view
      setTimeout(() => {
        document.querySelector('[data-testid="enriched-iocs-panel"]')?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 100);
    } catch (e) {
      toast.error(`Enrichment failed: ${e.message}`);
    } finally { setEnrichBusy(false); }
  }, [result, selectedIocs, enrichDepth]);

  // Selection helpers for the IOC checkboxes.
  const toggleIocSelected = useCallback((value) => {
    setSelectedIocs((prev) => {
      const next = new Set(prev);
      if (next.has(value)) next.delete(value); else next.add(value);
      return next;
    });
  }, []);
  const selectAllIocs = useCallback(() => {
    const all = (result?.analysis?.iocs || []).map((i) => i.value).filter(Boolean);
    setSelectedIocs(new Set(all));
  }, [result]);
  const clearSelectedIocs = useCallback(() => setSelectedIocs(new Set()), []);
  // Reset selection whenever a new investigation runs
  useEffect(() => { setSelectedIocs(new Set()); }, [result?.analysis?.iocs]);

  const uploadFile = (e) => {
    const f = e.target.files?.[0]; if (!f) return;
    if (f.size > 5 * 1024 * 1024) { toast.error("Max file size 5 MB"); return; }
    const r = new FileReader();
    r.onload = (ev) => setInput(String(ev.target?.result || ""));
    r.readAsText(f);
  };

  const analysis = result?.analysis || null;
  const verdict = analysis?.verdict || null;
  const V = verdict ? VERDICT_STYLE[verdict] : null;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100" data-testid="cyberlab-root">
      <Navbar />

      {/* Grid backdrop */}
      <div className="pointer-events-none absolute inset-0 -z-0 opacity-[0.03]"
        style={{ backgroundImage: "linear-gradient(#22d3ee 1px, transparent 1px), linear-gradient(90deg, #22d3ee 1px, transparent 1px)", backgroundSize: "56px 56px" }} />

      <main className="relative mx-auto max-w-[1600px] px-4 lg:px-8 pt-24 pb-8">
        {/* Header */}
        <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-cyan-400 mb-2">
              <Cpu className="w-3.5 h-3.5" /> NivX Forge
              <span className="ml-2 inline-flex items-center gap-1 text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                <Radar className="w-3 h-3" /> Auto-decode · MITRE · YARA · IOC
              </span>
            </div>
            <h1 className="font-heading text-3xl md:text-4xl font-semibold tracking-tight text-white">
              Decoder &amp; Threat Analysis Platform
            </h1>
            <p className="mt-2 text-sm text-slate-400 max-w-3xl">
              DFIR-grade payload triage — chain 28+ decoders, auto-solve nested encodings, and get MITRE ATT&amp;CK mapping, YARA-lite rule hits, IOC extraction &amp; risk scoring in a single click.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              data-testid="auto-investigate-btn"
              onClick={runAutoInvestigate}
              disabled={investigateBusy}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-gradient-to-r from-cyan-500 to-fuchsia-500 hover:from-cyan-400 hover:to-fuchsia-400 text-slate-900 font-bold text-sm disabled:opacity-50 transition-colors shadow-lg shadow-cyan-500/20"
            >
              {investigateBusy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />}
              Auto Investigate
            </button>
            <button
              data-testid="auto-decode-btn"
              onClick={runAuto}
              disabled={autoBusy || investigateBusy}
              className="inline-flex items-center gap-2 px-3 py-2 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-semibold text-sm disabled:opacity-40 transition-colors"
            >
              {autoBusy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
              Auto Decode
            </button>
            <button
              data-testid="run-recipe-btn"
              onClick={runManual}
              disabled={running || recipe.length === 0 || investigateBusy}
              className="inline-flex items-center gap-2 px-3 py-2 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white font-semibold text-sm disabled:opacity-40 transition-colors"
            >
              {running ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              Run Recipe
            </button>
            <button
              data-testid="share-export-btn"
              onClick={() => setShareOpen(true)}
              disabled={!result}
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-300 hover:text-cyan-400 border border-slate-700 hover:border-cyan-500/50 rounded-md px-3 py-2 disabled:opacity-40 transition-colors"
            >
              <Share2 className="w-3.5 h-3.5" /> Share
            </button>

            {/* Download Report split-button — CSV / PDF / JSON / Markdown */}
            <div className="relative">
              <button
                data-testid="download-report-btn"
                onClick={() => setDownloadOpen((v) => !v)}
                disabled={!result || !!downloading}
                className="inline-flex items-center gap-1.5 text-xs font-semibold text-cyan-300 border border-cyan-500/40 hover:border-cyan-400/60 bg-cyan-500/10 hover:bg-cyan-500/15 rounded-md px-3 py-2 disabled:opacity-40 transition-colors"
              >
                {downloading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
                {downloading ? `Generating ${downloading.toUpperCase()}…` : "Download Report"}
                <ChevronDown className="w-3 h-3" />
              </button>
              {downloadOpen && !downloading && (
                <div
                  data-testid="download-report-menu"
                  className="absolute right-0 mt-1 w-52 rounded-lg border border-slate-700 bg-slate-950 shadow-xl z-30 p-1"
                  onMouseLeave={() => setDownloadOpen(false)}
                >
                  {[
                    { fmt: "pdf",      label: "PDF · Threat Card",   sub: "Branded, full context" },
                    { fmt: "csv",      label: "CSV · IOC + OSINT",   sub: "Spreadsheet-friendly" },
                    { fmt: "json",     label: "JSON · Machine",      sub: "For SOAR/pipelines" },
                    { fmt: "markdown", label: "Markdown · Jira/Doc", sub: "Copy-paste ready" },
                  ].map((opt) => (
                    <button
                      key={opt.fmt}
                      data-testid={`download-${opt.fmt}`}
                      onClick={async () => {
                        setDownloadOpen(false);
                        setDownloading(opt.fmt);
                        try {
                          await downloadReport(opt.fmt, {
                            input,
                            output: result?.output || "",
                            trace: result?.trace || [],
                            analysis: analysis || {},
                            ai: ai || null,
                            enriched_iocs: enrichedIocs || [],
                            enrichment_meta: enrichMeta || null,
                          });
                          toast.success(`${opt.fmt.toUpperCase()} report downloaded`);
                        } catch (e) {
                          toast.error(`${opt.fmt.toUpperCase()} export failed: ${e.message}`);
                        } finally { setDownloading(null); }
                      }}
                      className="w-full text-left px-3 py-2 rounded hover:bg-slate-800 transition-colors"
                    >
                      <div className="text-xs font-semibold text-white">{opt.label}</div>
                      <div className="text-[10px] text-slate-500">{opt.sub}</div>
                    </button>
                  ))}
                </div>
              )}
            </div>

            <label
              data-testid="upload-btn"
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-300 hover:text-cyan-400 border border-slate-700 hover:border-cyan-500/50 rounded-md px-3 py-2 cursor-pointer transition-colors"
            >
              <Upload className="w-3.5 h-3.5" /> Upload
              <input type="file" accept=".txt,.log,.b64,.hex,.json,.js,.ps1,.eml,.bin" className="hidden" onChange={uploadFile} />
            </label>
          </div>
        </div>

        {/* OSINT enrichment controls — toggle + depth selector (compact) */}
        <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-slate-400" data-testid="enrich-controls">
          <label className="inline-flex items-center gap-1.5 cursor-pointer select-none" title="Automatically enrich extracted IOCs against VirusTotal, AbuseIPDB, Shodan, urlscan, CIRCL, Hybrid Analysis & MalwareBazaar after Auto Investigate.">
            <input
              type="checkbox"
              data-testid="enrich-toggle"
              checked={enrichEnabled}
              onChange={(e) => setEnrichEnabled(e.target.checked)}
              className="w-3.5 h-3.5 rounded border-slate-600 bg-slate-800 accent-cyan-500"
            />
            <span>Auto-enrich IOCs</span>
          </label>
          <div className="inline-flex items-center gap-1 rounded-md border border-slate-800 bg-slate-950 p-0.5" data-testid="enrich-depth">
            {[
              { v: "free",          l: "Free",          h: "Shodan · geo · DNS · urlscan · CIRCL (fastest)" },
              { v: "comprehensive", l: "Comprehensive", h: "Free + VT · AbuseIPDB · HA · MalwareBazaar" },
              { v: "ai",            l: "+ AI Verdict",  h: "Comprehensive + Claude/Gemini per-IOC summary" },
            ].map((d) => (
              <button
                key={d.v}
                data-testid={`enrich-depth-${d.v}`}
                disabled={!enrichEnabled}
                title={d.h}
                onClick={() => setEnrichDepth(d.v)}
                className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-widest transition-colors ${
                  enrichDepth === d.v
                    ? "bg-cyan-500/20 text-cyan-300"
                    : "text-slate-500 hover:text-slate-300"
                } disabled:opacity-40`}
              >
                {d.l}
              </button>
            ))}
          </div>
        </div>

        {/* Verdict banner with risk-score bar + reason breakdown */}
        {analysis && (
          <VerdictBanner
            verdict={analysis.verdict || "clean"}
            riskScore={analysis.risk_score || 0}
            reasons={analysis.risk_reasons || []}
            summary={analysis.summary}
          />
        )}

        {/* Auto Investigation progress panel */}
        {investigateStages.length > 0 && (
          <AutoInvestigateProgress stages={investigateStages} summary={investigateSummary} />
        )}

        {/* OSINT enrichment results panel */}
        {enrichedIocs && enrichedIocs.length > 0 && (
          <EnrichedIocsPanel iocs={enrichedIocs} meta={enrichMeta || {}} />
        )}

        {/* Example chips */}
        <div className="mb-4 flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Load example:</span>
          {EXAMPLES.map((ex) => (
            <button
              key={ex.label}
              data-testid={`example-${ex.label.replace(/\s+/g, "-")}`}
              onClick={() => { setInput(ex.input); setResult(null); toast.success(`Loaded: ${ex.label}`); }}
              className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-300 hover:text-cyan-400 border border-slate-700 hover:border-cyan-500/50 bg-slate-900 rounded-full px-2.5 py-0.5 transition-colors"
            >
              <Sparkles className="w-3 h-3" /> {ex.label}
            </button>
          ))}
        </div>

        {/* 3-column layout */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* ---- Column 1: Palette ---- */}
          <aside className="lg:col-span-3 rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur p-4 h-fit lg:sticky lg:top-24">
            <div className="flex items-center gap-2 mb-3">
              <Beaker className="w-4 h-4 text-cyan-400" />
              <h3 className="font-semibold text-white text-sm">Operations</h3>
              <span className="ml-auto text-[10px] text-slate-500">{plugins.length}</span>
            </div>
            <div className="relative mb-3">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
              <input
                data-testid="ops-search"
                placeholder="Search operations…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                className="w-full text-xs pl-7 pr-3 py-1.5 rounded-md bg-slate-950 border border-slate-800 focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 outline-none text-slate-100 placeholder-slate-600"
              />
            </div>
            <div className="space-y-3 max-h-[75vh] overflow-y-auto pr-1">
              {Object.entries(grouped).map(([cat, items]) => (
                <div key={cat}>
                  <div className={`inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border ${(CATEGORY_STYLE[cat] || CATEGORY_STYLE.Utilities).chip} mb-1.5`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${(CATEGORY_STYLE[cat] || CATEGORY_STYLE.Utilities).dot}`} /> {cat}
                  </div>
                  <div className="space-y-0.5">
                    {items.map((op) => (
                      <button
                        key={op.id}
                        data-testid={`add-op-${op.id}`}
                        onClick={() => addStep(op.id)}
                        title={op.description}
                        className="w-full text-left text-xs px-2 py-1.5 rounded hover:bg-slate-800/70 border border-transparent hover:border-slate-700 text-slate-300 hover:text-white transition-colors"
                      >
                        {op.name}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </aside>

          {/* ---- Column 2: Input / Recipe / Output ---- */}
          <section className="lg:col-span-5 space-y-4">
            {/* Input */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="flex items-center justify-between mb-2 gap-2 flex-wrap">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-400" />
                  <h3 className="text-xs font-bold uppercase tracking-widest text-slate-300">Input</h3>
                  <span className="text-[10px] text-slate-500">{input.length.toLocaleString()} chars</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <button
                    data-testid="input-auto-investigate-btn"
                    onClick={runAutoInvestigate}
                    disabled={investigateBusy || !input.trim()}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-gradient-to-r from-cyan-500 to-fuchsia-500 hover:from-cyan-400 hover:to-fuchsia-400 text-slate-900 font-bold text-[10px] uppercase tracking-widest disabled:opacity-40 transition-colors shadow shadow-cyan-500/20"
                    title="Run full pipeline: detect → decode → analyze → AI → enrich → render"
                  >
                    {investigateBusy ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Radar className="w-3 h-3" />}
                    Auto Investigate
                  </button>
                  <button
                    data-testid="input-auto-decode-btn"
                    onClick={runAuto}
                    disabled={autoBusy || investigateBusy || !input.trim()}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded-md border border-slate-700 hover:border-cyan-500/40 text-[10px] font-semibold text-slate-300 hover:text-cyan-300 disabled:opacity-40 transition-colors"
                    title="Recursive decode only (no AI, no enrichment)"
                  >
                    {autoBusy ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3" />}
                    Decode
                  </button>
                  <button
                    data-testid="clear-input-btn"
                    onClick={() => { setInput(""); setResult(null); }}
                    className="text-[10px] text-slate-400 hover:text-red-400 inline-flex items-center gap-1 transition-colors px-1.5 py-1"
                  >
                    <X className="w-3 h-3" /> Clear
                  </button>
                </div>
              </div>
              <textarea
                data-testid="input-textarea"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Paste a suspicious payload — base64, hex, URL-encoded, PowerShell -EncodedCommand, obfuscated JS, ransomware notes, defanged IOCs..."
                className="w-full h-40 font-mono text-xs bg-slate-950 border border-slate-800 rounded-md px-3 py-2 outline-none focus:border-cyan-500/50 text-slate-100 placeholder-slate-600 resize-y"
              />
            </div>

            {/* Recipe */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Layers className="w-3.5 h-3.5 text-cyan-400" />
                  <h3 className="text-xs font-bold uppercase tracking-widest text-slate-300">Recipe</h3>
                  <span className="text-[10px] text-slate-500">{recipe.length} step{recipe.length === 1 ? "" : "s"}</span>
                </div>
                {recipe.length > 0 && (
                  <button data-testid="clear-recipe-btn" onClick={clearRecipe} className="text-[10px] text-slate-400 hover:text-red-400 inline-flex items-center gap-1 transition-colors">
                    <Trash2 className="w-3 h-3" /> Clear
                  </button>
                )}
              </div>
              {recipe.length === 0 ? (
                <div className="text-xs text-slate-500 italic px-2 py-6 text-center border border-dashed border-slate-800 rounded-md">
                  Click operations on the left to build a pipeline, or hit <span className="text-cyan-400 font-semibold">Auto Decode</span> to let NivX Forge figure it out.
                </div>
              ) : (
                <div className="space-y-1.5">
                  {recipe.map((step, i) => {
                    const p = pluginMap[step.id];
                    if (!p) return null;
                    const tone = CATEGORY_STYLE[p.category] || CATEGORY_STYLE.Utilities;
                    return (
                      <div key={i} data-testid={`recipe-step-${i}`}
                        className="group flex items-center gap-2 px-2 py-1.5 rounded-md border border-slate-800 bg-slate-950 hover:border-slate-700 transition-colors">
                        <span className="text-[10px] font-bold text-slate-500 w-4 text-center">{i + 1}</span>
                        <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded border ${tone.chip}`}>
                          <span className={`w-1 h-1 rounded-full ${tone.dot}`} /> {p.category}
                        </span>
                        <span className="text-xs text-white flex-1">{p.name}</span>
                        {p.params?.length > 0 && (
                          <input
                            data-testid={`step-${i}-param`}
                            placeholder={p.params[0].name}
                            value={step.params?.[p.params[0].name] ?? ""}
                            onChange={(e) => updateParam(i, p.params[0].name, e.target.value)}
                            className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 w-24 outline-none focus:border-cyan-500/50"
                          />
                        )}
                        <div className="opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-0.5">
                          <button onClick={() => moveStep(i, -1)} className="p-0.5 text-slate-500 hover:text-white" title="Move up"><ChevronUp className="w-3 h-3" /></button>
                          <button onClick={() => moveStep(i, 1)} className="p-0.5 text-slate-500 hover:text-white" title="Move down"><ChevronDown className="w-3 h-3" /></button>
                          <button onClick={() => removeStep(i)} data-testid={`remove-step-${i}`} className="p-0.5 text-slate-500 hover:text-red-400" title="Remove"><X className="w-3 h-3" /></button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Output */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  <h3 className="text-xs font-bold uppercase tracking-widest text-slate-300">Output</h3>
                  {result && (
                    <span className="text-[10px] text-slate-500">
                      {result.output_size?.toLocaleString()} bytes · {result.duration_ms?.toFixed(1)} ms
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <button data-testid="copy-output-btn" onClick={copyOutput} disabled={!result?.output} className="text-[10px] text-slate-400 hover:text-cyan-400 inline-flex items-center gap-1 disabled:opacity-40 transition-colors">
                    <Copy className="w-3 h-3" /> Copy
                  </button>
                  <button data-testid="download-report-btn" onClick={downloadReport} disabled={!result} className="text-[10px] text-slate-400 hover:text-cyan-400 inline-flex items-center gap-1 disabled:opacity-40 transition-colors">
                    <Download className="w-3 h-3" /> Report
                  </button>
                </div>
              </div>
              <pre
                data-testid="output-pre"
                className="w-full min-h-40 max-h-96 overflow-auto font-mono text-xs bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-emerald-300 whitespace-pre-wrap break-all"
              >{result?.output ?? <span className="text-slate-600 italic">Run a recipe or click Auto Decode to see decoded output here…</span>}</pre>
            </div>
          </section>

          {/* ---- Column 3: Threat Analysis ---- */}
          <aside className="lg:col-span-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4 h-fit">
            <div className="flex items-center gap-2 mb-3">
              <Radar className="w-4 h-4 text-cyan-400" />
              <h3 className="font-semibold text-white text-sm">Threat Analysis</h3>
            </div>

            {/* Tab bar */}
            <div className="flex items-center gap-1 mb-3 border-b border-slate-800">
              {[
                { id: "mitre",  label: "MITRE",   icon: Target,      count: analysis?.mitre?.length ?? 0 },
                { id: "rules",  label: "Rules",   icon: Bug,         count: analysis?.rules?.length ?? 0 },
                { id: "iocs",   label: "IOCs",    icon: Fingerprint, count: analysis?.iocs?.length ?? 0 },
                { id: "trace",  label: "Chain",   icon: Network,     count: result?.trace?.length ?? 0 },
                { id: "graph",  label: "Graph",   icon: Radar,       count: result?.trace?.length ?? 0 },
              ].map((t) => (
                <button
                  key={t.id}
                  data-testid={`tab-${t.id}`}
                  onClick={() => setTab(t.id)}
                  className={`inline-flex items-center gap-1 px-2.5 py-1.5 text-[11px] font-semibold border-b-2 transition-colors ${
                    tab === t.id
                      ? "border-cyan-400 text-cyan-300"
                      : "border-transparent text-slate-500 hover:text-slate-300"
                  }`}
                >
                  <t.icon className="w-3 h-3" />
                  {t.label}
                  {t.count > 0 && (
                    <span className={`ml-0.5 text-[9px] px-1.5 py-0.5 rounded-full font-bold ${tab === t.id ? "bg-cyan-500/20 text-cyan-300" : "bg-slate-800 text-slate-400"}`}>{t.count}</span>
                  )}
                </button>
              ))}
            </div>

            <div className="max-h-[70vh] overflow-y-auto pr-1 space-y-2">
              {!analysis && !result?.trace?.length && (
                <div className="text-xs text-slate-500 italic px-2 py-8 text-center">
                  No analysis yet — run auto-decode or a recipe.
                </div>
              )}

              {tab === "mitre" && (analysis?.mitre?.length ? analysis.mitre.map((m) => (
                <div key={m.id} data-testid={`mitre-${m.id}`} className="rounded-md border border-slate-800 bg-slate-950 p-2.5">
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <a href={`https://attack.mitre.org/techniques/${m.id.replace(".", "/")}/`} target="_blank" rel="noreferrer" className="text-xs font-bold text-cyan-300 hover:text-cyan-200">{m.id}</a>
                    <span className="text-[9px] uppercase font-bold text-slate-500 tracking-widest">{m.tactic}</span>
                  </div>
                  <div className="text-xs font-semibold text-white mb-1">{m.name}</div>
                  <div className="text-[11px] text-slate-400 mb-1.5">{m.description}</div>
                  {m.evidence?.length > 0 && (
                    <div className="space-y-0.5">
                      {m.evidence.map((e, i) => (
                        <div key={i} className="font-mono text-[10px] bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5 text-amber-300 break-all">{e}</div>
                      ))}
                    </div>
                  )}
                </div>
              )) : analysis && <div className="text-xs text-slate-500 italic px-2 py-4">No ATT&amp;CK techniques detected.</div>)}

              {tab === "rules" && (analysis?.rules?.length ? analysis.rules.map((r, i) => (
                <div key={i} data-testid={`rule-${r.rule}`} className="rounded-md border border-slate-800 bg-slate-950 p-2.5">
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <div className="text-xs font-bold text-white flex items-center gap-1.5">
                      <Bug className="w-3 h-3 text-fuchsia-400" /> {r.rule}
                    </div>
                    <span className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded border ${SEVERITY_STYLE[r.severity] || SEVERITY_STYLE.medium}`}>{r.severity}</span>
                  </div>
                  <div className="text-[11px] text-slate-400 mb-1.5">{r.description}</div>
                  <div className="flex flex-wrap gap-1 mb-1.5">
                    {r.tags?.map((t) => (
                      <span key={t} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">#{t}</span>
                    ))}
                  </div>
                  {r.matched?.length > 0 && (
                    <div className="space-y-0.5">
                      {r.matched.slice(0, 3).map((m, k) => (
                        <div key={k} className="font-mono text-[10px] bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5 text-fuchsia-300 break-all">{m}</div>
                      ))}
                    </div>
                  )}
                </div>
              )) : analysis && <div className="text-xs text-slate-500 italic px-2 py-4">No rule matches.</div>)}

              {tab === "iocs" && (
                analysis?.iocs?.length ? (
                  <>
                    <div className="mb-2 flex items-center justify-between flex-wrap gap-2" data-testid="ioc-toolbar">
                      <div className="flex items-center gap-2">
                        <label className="inline-flex items-center gap-1.5 text-[10px] text-slate-400 cursor-pointer select-none">
                          <input
                            type="checkbox"
                            data-testid="ioc-select-all"
                            checked={selectedIocs.size > 0 && selectedIocs.size === analysis.iocs.length}
                            onChange={(e) => (e.target.checked ? selectAllIocs() : clearSelectedIocs())}
                            className="w-3.5 h-3.5 rounded border-slate-600 bg-slate-800 accent-cyan-500"
                          />
                          <span>{selectedIocs.size > 0 ? `${selectedIocs.size}/${analysis.iocs.length}` : `${analysis.iocs.length} extracted`}</span>
                        </label>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <button
                          data-testid="analyze-selected-iocs-btn"
                          onClick={() => enrichSelectedIocs()}
                          disabled={enrichBusy || selectedIocs.size === 0}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded bg-cyan-500/15 border border-cyan-500/40 text-[10px] font-bold uppercase tracking-widest text-cyan-300 hover:bg-cyan-500/25 disabled:opacity-40 transition-colors"
                          title="Enrich the selected IOCs inline via VT/AbuseIPDB/Shodan/urlscan/CIRCL/HA/MalwareBazaar"
                        >
                          {enrichBusy ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Radar className="w-3 h-3" />}
                          {enrichBusy ? "Analyzing…" : `Analyze ${selectedIocs.size || ""}`}
                        </button>
                        <button
                          data-testid="analyze-all-iocs-btn"
                          onClick={() => {
                            const all = analysis.iocs.map((i) => i.value).filter(Boolean);
                            enrichSelectedIocs(all);
                          }}
                          disabled={enrichBusy}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-700 text-[10px] font-semibold text-slate-400 hover:text-cyan-300 hover:border-cyan-500/40 disabled:opacity-40 transition-colors"
                          title="Analyze all extracted IOCs (capped at 20)"
                        >
                          Analyze all
                        </button>
                        <button
                          data-testid="send-to-analyzer-btn"
                          onClick={sendToAnalyzer}
                          className="inline-flex items-center gap-1 text-[10px] font-semibold text-slate-400 hover:text-cyan-300 transition-colors"
                          title="Send to the separate Threat Intelligence Bulk Analyzer page"
                        >
                          Send →
                        </button>
                      </div>
                    </div>
                    <div className="space-y-1">
                      {analysis.iocs.map((i, k) => {
                        const checked = selectedIocs.has(i.value);
                        return (
                          <label
                            key={k}
                            data-testid={`ioc-${k}`}
                            data-selected={checked ? "true" : "false"}
                            className={`flex items-center gap-2 rounded border px-2 py-1.5 cursor-pointer transition-colors ${checked ? "border-cyan-500/40 bg-cyan-500/5" : "border-slate-800 bg-slate-950 hover:border-slate-700"}`}
                          >
                            <input
                              type="checkbox"
                              data-testid={`ioc-check-${k}`}
                              checked={checked}
                              onChange={() => toggleIocSelected(i.value)}
                              className="w-3.5 h-3.5 rounded border-slate-600 bg-slate-800 accent-cyan-500 shrink-0"
                            />
                            <span className="text-[9px] font-bold uppercase tracking-widest text-slate-500 w-14 shrink-0">{i.type}</span>
                            <span className="font-mono text-[11px] text-cyan-300 flex-1 truncate" title={i.value}>{i.value}</span>
                            <button
                              onClick={(e) => { e.preventDefault(); navigator.clipboard.writeText(i.value); toast.success("Copied"); }}
                              className="text-slate-500 hover:text-white"
                              title="Copy"
                            ><Copy className="w-3 h-3" /></button>
                          </label>
                        );
                      })}
                    </div>
                  </>
                ) : analysis && <div className="text-xs text-slate-500 italic px-2 py-4">No IOCs extracted.</div>
              )}

              {tab === "trace" && (result?.trace?.length ? (
                <div className="space-y-1.5">
                  {result.trace.map((s, i) => {
                    const tone = CATEGORY_STYLE[s.category] || CATEGORY_STYLE.Utilities;
                    return (
                      <div key={i} data-testid={`trace-${i}`} className="rounded-md border border-slate-800 bg-slate-950 p-2">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-[10px] font-bold text-slate-500 w-4">{i + 1}</span>
                          <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded border ${tone.chip}`}>
                            <span className={`w-1 h-1 rounded-full ${tone.dot}`} /> {s.category}
                          </span>
                          <span className="text-xs font-semibold text-white flex-1">{s.name}</span>
                          {s.confidence && <span className="text-[10px] text-emerald-400 font-mono">conf: {s.confidence}</span>}
                          <span className="text-[10px] text-slate-500 font-mono">{s.duration_ms?.toFixed(1)}ms</span>
                        </div>
                        {s.error && <div className="font-mono text-[10px] text-red-400 mt-1">✕ {s.error}</div>}
                        {!s.error && (
                          <div className="font-mono text-[10px] text-slate-400 bg-slate-900 border border-slate-800 rounded px-1.5 py-1 truncate">
                            → {s.output_preview}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              ) : <div className="text-xs text-slate-500 italic px-2 py-4">No pipeline steps yet.</div>)}

              {tab === "graph" && (
                <div>
                  {/* Data-Source toggle */}
                  <div className="mb-3 inline-flex rounded-md border border-slate-800 bg-slate-950 p-0.5">
                    <button
                      data-testid="graph-mode-chain"
                      onClick={() => setGraphMode("chain")}
                      className={`px-2.5 py-1 text-[10px] font-semibold rounded transition-colors ${
                        graphMode === "chain"
                          ? "bg-cyan-500 text-slate-900"
                          : "text-slate-400 hover:text-white"
                      }`}
                    >Decoding Chain</button>
                    <button
                      data-testid="graph-mode-process"
                      onClick={() => setGraphMode("process")}
                      className={`px-2.5 py-1 text-[10px] font-semibold rounded transition-colors ${
                        graphMode === "process"
                          ? "bg-cyan-500 text-slate-900"
                          : "text-slate-400 hover:text-white"
                      }`}
                    >Process Tree (Sysmon / EDR)</button>
                  </div>
                  {graphMode === "chain" ? (
                    <AttackChainViewer
                      input={input}
                      output={result?.output || ""}
                      trace={result?.trace || []}
                      mitre={analysis?.mitre || []}
                    />
                  ) : (
                    <ProcessTreeViewer
                      initialTree={processTreeData}
                      initialText={processTreeData ? input : ""}
                    />
                  )}
                </div>
              )}
            </div>
          </aside>
        </div>

        {/* AI Analyst panel — spans full width under the 3-column area */}
        {result && (
          <div className="mt-4">
            <AiPanel
              input={input}
              output={result.output}
              analysis={result.analysis || {}}
              onGenerated={setAi}
              key={result.output?.slice(0, 40)}
            />
          </div>
        )}

        {/* Custom rule + session rule management link */}
        <div className="mt-4 flex items-center justify-between rounded-xl border border-slate-800 bg-slate-900/40 px-4 py-3">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Bug className="w-3.5 h-3.5 text-fuchsia-400" />
            <span>Custom detection rules — add your own regex/hex/string patterns scoped to this browser (30-day retention).</span>
          </div>
          <button
            data-testid="add-session-rule-btn"
            onClick={() => setRuleModalOpen(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-fuchsia-500/10 text-fuchsia-300 border border-fuchsia-500/30 hover:bg-fuchsia-500/20 text-xs font-semibold transition-colors"
          >
            <Plus className="w-3 h-3" /> Add session rule
          </button>
        </div>

        {/* Footer note */}
        <div className="mt-8 text-center text-[11px] text-slate-500">
          <ShieldCheck className="w-3 h-3 inline mr-1 text-emerald-400" />
          Server-side analysis is scoped to this session — payloads are not stored unless you use the Share button.
        </div>
      </main>

      {/* Modals */}
      <ShareModal
        open={shareOpen}
        onClose={() => setShareOpen(false)}
        report={{
          input,
          output: result?.output || "",
          trace: result?.trace || [],
          analysis: analysis || {},
          ai,
        }}
      />
      <CustomRuleModal
        open={ruleModalOpen}
        onClose={() => setRuleModalOpen(false)}
        onSaved={() => {
          toast.info("Session rule active — re-run analysis to see it match.");
        }}
      />

      <div className="bg-white text-slate-900">
        <Contact />
      </div>
    </div>
  );
}
