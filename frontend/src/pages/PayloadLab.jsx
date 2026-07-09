import { useEffect, useMemo, useState, useCallback } from "react";
import { motion } from "framer-motion";
import { toast } from "sonner";
import {
  Beaker, Search, X, GripVertical, ChevronUp, ChevronDown, Copy, Trash2,
  Download, Upload, Sparkles, ShieldAlert, ArrowRightLeft, ShieldCheck, RefreshCw, Wand2,
} from "lucide-react";
import { OPS, OP_CATEGORIES, runRecipe, autoDecode } from "@/lib/payloadOps";
import Navbar from "@/components/Navbar";
import Contact from "@/components/Contact";
import useSeo from "@/lib/useSeo";

const CATEGORY_TONE = {
  Auto:         { chip: "bg-fuchsia-100 text-fuchsia-700 border-fuchsia-200",   dot: "bg-fuchsia-500" },
  Encoding:     { chip: "bg-blue-100 text-blue-700 border-blue-200",             dot: "bg-blue-500" },
  Cryptography: { chip: "bg-amber-100 text-amber-800 border-amber-200",         dot: "bg-amber-500" },
  Compression:  { chip: "bg-emerald-100 text-emerald-700 border-emerald-200",   dot: "bg-emerald-500" },
  Hashing:      { chip: "bg-indigo-100 text-indigo-700 border-indigo-200",       dot: "bg-indigo-500" },
  Extractors:   { chip: "bg-rose-100 text-rose-700 border-rose-200",             dot: "bg-rose-500" },
  Utilities:    { chip: "bg-slate-100 text-slate-700 border-slate-200",           dot: "bg-slate-500" },
};

const EXAMPLES = [
  { label: "PowerShell -e (auto-decode)", input: "powershell.exe -e JABvAHMAIAA9ACAARwBlAHQALQBDAGkAbQBJAG4AcwB0AGEAbgBjAGUAIABXAGkAbgAzADIAXwBPAHAAZQByAGEAdABpAG4AZwBTAHkAcwB0AGUAbQA=", recipe: [{ id: "base64-decode" }] },
  { label: "PowerShell Base64 payload", input: "cG93ZXJzaGVsbCAtbm9wIC1lbmMgVzFOelBTPT0=", recipe: [{ id: "base64-decode" }] },
  { label: "Defanged IOC bundle", input: "Contact hxxps://malicious[.]site/beacon then C2 = 45[.]137[.]21[.]90 and hash 44d88612fea8a8f36de82e1278abb02f", recipe: [{ id: "refang" }, { id: "extract-urls" }] },
  { label: "URL-encoded payload", input: "%3Cscript%3Ealert(1)%3C%2Fscript%3E", recipe: [{ id: "url-decode" }] },
  { label: "Nested Base64 → gzip", input: "H4sIAAAAAAAAA0vOSCxKzUlNAQBqRZ2gCQAAAA==", recipe: [{ id: "gzip-decompress-b64" }] },
  { label: "Hex-encoded string", input: "48656c6c6f204e6976582e", recipe: [{ id: "hex-decode" }] },
];

export default function PayloadLab() {
  useSeo({
    title: "Payload Lab — Decode, analyze, extract IOCs · NivX Machines",
    description: "A client-side decoder & malware payload lab: chain Base64, Hex, URL, XOR, Gzip, ROT13, AES, hash, extract IOCs — everything runs in your browser, nothing leaves your machine.",
    canonical: "https://nivxmachines.com/detonate",
  });

  const [q, setQ] = useState("");
  const [input, setInput] = useState("aGVsbG8gTml2WCwgd2VsY29tZSB0byB0aGUgUGF5bG9hZCBMYWIu");
  const [recipe, setRecipe] = useState([{ id: "base64-decode" }]);
  const [output, setOutput] = useState("");
  const [trace, setTrace] = useState([]);
  const [running, setRunning] = useState(false);
  const [autoBusy, setAutoBusy] = useState(false);
  const [autoResult, setAutoResult] = useState(null);

  const filteredOps = useMemo(() => {
    const term = q.trim().toLowerCase();
    const grouped = {};
    for (const cat of OP_CATEGORIES) grouped[cat] = [];
    for (const [id, op] of Object.entries(OPS)) {
      if (!term || op.name.toLowerCase().includes(term) || op.desc.toLowerCase().includes(term) || op.category.toLowerCase().includes(term)) {
        grouped[op.category].push({ id, ...op });
      }
    }
    return grouped;
  }, [q]);

  const run = useCallback(async () => {
    setRunning(true);
    try {
      const { output: o, trace: t } = await runRecipe(input, recipe);
      setOutput(o); setTrace(t);
    } finally { setRunning(false); }
  }, [input, recipe]);

  // Auto-recompute on input / recipe change (debounced).
  useEffect(() => {
    const t = setTimeout(run, 150);
    return () => clearTimeout(t);
  }, [run]);

  const addOp = (id) => setRecipe((r) => [...r, { id, params: OPS[id].params ? { ...OPS[id].params } : undefined }]);
  const removeStep = (idx) => setRecipe((r) => r.filter((_, i) => i !== idx));
  const moveStep = (idx, delta) => setRecipe((r) => {
    const next = [...r]; const target = idx + delta;
    if (target < 0 || target >= next.length) return r;
    [next[idx], next[target]] = [next[target], next[idx]]; return next;
  });
  const updateParam = (idx, key, value) => setRecipe((r) => r.map((s, i) => i === idx ? { ...s, params: { ...(s.params || {}), [key]: value } } : s));
  const clearRecipe = () => { setRecipe([]); toast.info("Recipe cleared"); };
  const copyOutput = () => { navigator.clipboard.writeText(output); toast.success("Output copied"); };
  const downloadOutput = () => {
    const blob = new Blob([output], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "payload-lab-output.txt"; a.click();
    URL.revokeObjectURL(url);
  };
  const uploadInput = (e) => {
    const file = e.target.files?.[0]; if (!file) return;
    if (file.size > 5 * 1024 * 1024) { toast.error("Files must be < 5 MB"); return; }
    const reader = new FileReader();
    reader.onload = (ev) => setInput(String(ev.target?.result || ""));
    reader.readAsText(file);
  };
  const loadExample = (ex) => { setInput(ex.input); setRecipe(ex.recipe); setAutoResult(null); toast.success(`Loaded: ${ex.label}`); };

  // The killer feature: Auto Decode. Runs a recursive best-first chain search
  // over base64 (UTF-8 + UTF-16LE), hex, URL, gzip, HTML entities, unicode
  // escapes, ROT13 and refang — picks the chain that yields the most-readable
  // text, and auto-loads it into the recipe.
  const runAutoDecode = useCallback(async () => {
    if (!input.trim()) { toast.error("Paste something to decode first"); return; }
    setAutoBusy(true);
    setAutoResult(null);
    try {
      const res = await autoDecode(input);
      setAutoResult(res);
      if (res.improved && res.chain.length > 0) {
        setRecipe(res.chain.map((id) => ({ id, params: OPS[id].params ? { ...OPS[id].params } : undefined })));
        toast.success(`Auto Decode: ${res.chain.length} step${res.chain.length === 1 ? "" : "s"} · ${res.steps.map((s) => s.name).join(" → ")}`);
      } else {
        toast.info("Input already looks like plain text — no decoding needed.");
      }
    } catch (e) {
      toast.error(`Auto Decode failed: ${e.message}`);
    } finally {
      setAutoBusy(false);
    }
  }, [input]);

  // Send extracted IOCs to the Smart IOC Analyzer.
  const sendToAnalyzer = () => {
    const iocs = output.split("\n").map((s) => s.trim()).filter(Boolean).slice(0, 200);
    if (!iocs.length) { toast.error("Nothing to analyze — recipe output is empty."); return; }
    try { sessionStorage.setItem("nivx.iocBatch", JSON.stringify(iocs)); } catch { /* quota */ }
    window.location.href = "/threat-intelligence#analyzer";
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />

      <main className="mx-auto max-w-7xl px-6 py-10">
        {/* Header */}
        <div className="mb-6 flex items-start justify-between flex-wrap gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-[#F5821F] mb-2">
              <Beaker className="w-3.5 h-3.5" /> Payload Lab
              <span className="ml-2 inline-flex items-center gap-1 text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                <ShieldCheck className="w-3 h-3" /> 100% Client-Side
              </span>
            </div>
            <h1 className="font-heading text-3xl md:text-4xl font-semibold tracking-tight text-slate-900">Decode, analyze &amp; extract — right in your browser</h1>
            <p className="mt-2 text-base text-slate-600 max-w-3xl">
              Chain Base64, Hex, URL, XOR, Gzip, ROT13, AES, hashes, IOC extractors and more into a recipe. Every byte stays in your browser — perfect for suspicious payloads you can&rsquo;t send to a remote sandbox.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <label className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600 hover:text-[#2E7DF5] border border-slate-200 hover:border-[#2E7DF5] rounded-md px-3 py-1.5 cursor-pointer" data-testid="upload-input-btn">
              <Upload className="w-3.5 h-3.5" /> Upload
              <input type="file" accept=".txt,.log,.b64,.hex,.json,.js,.ps1,.eml" className="hidden" onChange={uploadInput} />
            </label>
          </div>
        </div>

        {/* Example loaders */}
        <div className="mb-6 flex items-center gap-2 flex-wrap">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Load example:</span>
          {EXAMPLES.map((ex) => (
            <button key={ex.label} data-testid={`example-${ex.label.replace(/\s+/g,"-")}`} onClick={() => loadExample(ex)} className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-700 hover:text-[#2E7DF5] border border-slate-200 hover:border-[#2E7DF5] bg-white rounded-full px-2.5 py-0.5">
              <Sparkles className="w-3 h-3" /> {ex.label}
            </button>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* -------- Column 1: Operations palette -------- */}
          <div className="lg:col-span-3 rounded-xl border border-slate-200 bg-white p-4 h-fit sticky top-24">
            <div className="flex items-center gap-2 mb-3">
              <Beaker className="w-4 h-4 text-slate-500" />
              <h3 className="font-semibold text-slate-900 text-sm">Operations</h3>
              <span className="ml-auto text-[10px] text-slate-400">{Object.keys(OPS).length}</span>
            </div>
            <div className="relative mb-3">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
              <input data-testid="ops-search" placeholder="Search operations…" value={q} onChange={(e) => setQ(e.target.value)}
                className="w-full text-xs pl-7 pr-3 py-1.5 rounded-md border border-slate-200 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none" />
            </div>
            <div className="space-y-3 max-h-[70vh] overflow-y-auto pr-1">
              {OP_CATEGORIES.map((cat) => filteredOps[cat].length > 0 && (
                <div key={cat}>
                  <div className={`inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border ${CATEGORY_TONE[cat].chip} mb-1.5`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${CATEGORY_TONE[cat].dot}`} /> {cat}
                  </div>
                  <div className="space-y-1">
                    {filteredOps[cat].map((op) => (
                      <button
                        key={op.id}
                        data-testid={`add-op-${op.id}`}
                        onClick={() => addOp(op.id)}
                        title={op.desc}
                        className="w-full text-left text-xs px-2 py-1.5 rounded hover:bg-slate-50 border border-transparent hover:border-slate-200 text-slate-700 hover:text-slate-900"
                      >
                        {op.name}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* -------- Column 2: Recipe -------- */}
          <div className="lg:col-span-4 rounded-xl border border-slate-200 bg-white p-4 h-fit">
            <div className="flex items-center gap-2 mb-3">
              <ArrowRightLeft className="w-4 h-4 text-slate-500" />
              <h3 className="font-semibold text-slate-900 text-sm">Recipe</h3>
              <span className="ml-auto text-[10px] text-slate-400">{recipe.length} step{recipe.length === 1 ? "" : "s"}</span>
              {recipe.length > 0 && (
                <button data-testid="clear-recipe" onClick={clearRecipe} className="ml-1 text-[11px] text-red-600 hover:underline inline-flex items-center gap-1"><Trash2 className="w-3 h-3" /> Clear</button>
              )}
            </div>
            {recipe.length === 0 && (
              <div className="text-xs text-slate-400 border border-dashed border-slate-200 rounded-md py-8 text-center">Click any operation on the left to add it to your recipe.</div>
            )}
            <ol className="space-y-2" data-testid="recipe-list">
              {recipe.map((step, idx) => {
                const op = OPS[step.id];
                if (!op) return null;
                const tone = CATEGORY_TONE[op.category];
                return (
                  <motion.li key={`${step.id}-${idx}`} layout initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} data-testid={`recipe-step-${idx}`}
                    className="rounded-md border border-slate-200 bg-slate-50 p-2.5">
                    <div className="flex items-center gap-2">
                      <GripVertical className="w-3.5 h-3.5 text-slate-400" />
                      <span className={`inline-flex text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border ${tone.chip}`}>{op.category}</span>
                      <span className="text-xs font-semibold text-slate-800 truncate flex-1">{op.name}</span>
                      <button data-testid={`move-up-${idx}`} onClick={() => moveStep(idx, -1)} className="text-slate-400 hover:text-slate-700"><ChevronUp className="w-3.5 h-3.5" /></button>
                      <button data-testid={`move-down-${idx}`} onClick={() => moveStep(idx, +1)} className="text-slate-400 hover:text-slate-700"><ChevronDown className="w-3.5 h-3.5" /></button>
                      <button data-testid={`remove-step-${idx}`} onClick={() => removeStep(idx)} className="text-red-500 hover:text-red-700"><X className="w-3.5 h-3.5" /></button>
                    </div>
                    {op.params && (
                      <div className="mt-2 space-y-1.5 pl-6">
                        {Object.entries(op.params).map(([pKey, pDefault]) => (
                          <div key={pKey} className="flex items-center gap-2">
                            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 w-20">{pKey}</label>
                            <input
                              data-testid={`param-${idx}-${pKey}`}
                              value={(step.params && step.params[pKey]) ?? pDefault}
                              onChange={(e) => updateParam(idx, pKey, e.target.value)}
                              className="flex-1 text-xs font-mono px-2 py-1 rounded border border-slate-200 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none"
                            />
                          </div>
                        ))}
                      </div>
                    )}
                  </motion.li>
                );
              })}
            </ol>

            {/* Trace */}
            {trace.length > 0 && (
              <div className="mt-4 pt-3 border-t border-slate-100">
                <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1.5">Execution trace</div>
                <ol className="space-y-1 text-[11px]">
                  {trace.map((t, i) => (
                    <li key={i} className={`font-mono ${t.ok ? "text-slate-500" : "text-red-600"}`}>{i + 1}. {t.name} → {t.ok ? `${t.size} bytes` : `error: ${t.error}`}</li>
                  ))}
                </ol>
              </div>
            )}
          </div>

          {/* -------- Column 3: Input & Output -------- */}
          <div className="lg:col-span-5 space-y-4">
            <div className="rounded-xl border border-slate-200 bg-white p-4">
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Input</div>
                <span className="text-[10px] text-slate-400">{input.length.toLocaleString()} chars</span>
                <button
                  data-testid="auto-decode-btn"
                  onClick={runAutoDecode}
                  disabled={autoBusy || !input.trim()}
                  className="ml-auto inline-flex items-center gap-1.5 rounded-md bg-gradient-to-r from-fuchsia-500 to-purple-600 hover:from-fuchsia-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-semibold px-3 py-1.5 shadow-sm"
                  title="Recursively try Base64/Hex/URL/Gzip/UTF-16 chains and load the best one into the recipe"
                >
                  {autoBusy ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Wand2 className="w-3.5 h-3.5" />}
                  Auto Decode
                </button>
              </div>
              <textarea
                data-testid="lab-input"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Paste a payload here — Base64, hex, URL-encoded, obfuscated, whatever. Then click Auto Decode."
                className="w-full h-40 md:h-44 font-mono text-xs text-slate-800 border border-slate-200 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none rounded-md p-3 bg-slate-50"
                spellCheck={false}
              />
              {autoResult && (
                <div data-testid="auto-decode-result" className={`mt-2 rounded-md border px-3 py-2 text-xs ${autoResult.improved ? "border-fuchsia-200 bg-fuchsia-50 text-fuchsia-900" : "border-slate-200 bg-slate-50 text-slate-600"}`}>
                  {autoResult.improved ? (
                    <>
                      <div className="font-semibold mb-1 inline-flex items-center gap-1"><Sparkles className="w-3.5 h-3.5" /> Auto-decoded via {autoResult.chain.length}-step chain (score {autoResult.score.toFixed(2)}):</div>
                      <div className="font-mono text-[11px]">{autoResult.steps.map((s) => s.name).join("  →  ")}</div>
                    </>
                  ) : (
                    <span>Input already looks like plain text — no chain gave a better result.</span>
                  )}
                </div>
              )}
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="text-[10px] font-bold uppercase tracking-wider text-emerald-600">Output</div>
                {running && <RefreshCw className="w-3 h-3 animate-spin text-slate-400" />}
                <span className="text-[10px] text-slate-400 ml-auto">{output.length.toLocaleString()} chars</span>
                <button data-testid="copy-output" onClick={copyOutput} disabled={!output} className="ml-2 inline-flex items-center gap-1 text-[10px] font-semibold text-slate-600 hover:text-[#2E7DF5] border border-slate-200 rounded px-2 py-0.5 disabled:opacity-50">
                  <Copy className="w-3 h-3" /> Copy
                </button>
                <button data-testid="download-output" onClick={downloadOutput} disabled={!output} className="inline-flex items-center gap-1 text-[10px] font-semibold text-slate-600 hover:text-[#2E7DF5] border border-slate-200 rounded px-2 py-0.5 disabled:opacity-50">
                  <Download className="w-3 h-3" /> Download
                </button>
              </div>
              <pre data-testid="lab-output" className="w-full h-56 md:h-72 font-mono text-xs text-slate-800 border border-slate-200 rounded-md p-3 bg-slate-50 overflow-auto whitespace-pre-wrap break-all">{output}</pre>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button data-testid="send-to-analyzer" onClick={sendToAnalyzer} disabled={!output} className="inline-flex items-center gap-1.5 rounded-md bg-[#2E7DF5] hover:bg-[#1E6BE0] disabled:opacity-50 text-white text-xs font-semibold px-3 py-2">
                  <ShieldAlert className="w-3.5 h-3.5" /> Send to IOC Analyzer
                </button>
                <p className="text-[11px] text-slate-500">Pipes the current output as a line-separated indicator batch into the Smart IOC Analyzer (VT · AbuseIPDB · URLScan · Hybrid Analysis · MalwareBazaar).</p>
              </div>
            </div>
          </div>
        </div>

        {/* Trust banner */}
        <div className="mt-8 rounded-xl border border-emerald-200 bg-emerald-50 px-5 py-4 flex items-start gap-3">
          <ShieldCheck className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
          <div className="text-sm text-emerald-900">
            <strong>Privacy by design.</strong> Every byte you paste, upload, or type stays in your browser. There are no backend calls, no network requests, no logging. Payload Lab is safe to use on live incident-response artefacts.
          </div>
        </div>
      </main>

      <Contact />
    </div>
  );
}
