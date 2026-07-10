/**
 * AI Analysis panel — calls Claude Sonnet 4.5 for triage summary + draft
 * Sigma & YARA rules. Presents them in tabs with copy buttons.
 */
import { useState, useEffect } from "react";
import { toast } from "sonner";
import { Brain, Copy, RefreshCw, Sparkles } from "lucide-react";
import { runAiAnalysis } from "@/lib/cyberlabApi";
import PushToSIEMButton from "./PushToSIEMButton";

const MODEL_LABELS = {
  claude: "Claude Sonnet 4.6",
  gpt:    "GPT 5.4",
  gemini: "Gemini 3.1 Pro",
};

export default function AiPanel({ input, output, analysis, ai, onGenerated }) {
  const [busy, setBusy] = useState(false);
  const [data, setData] = useState(ai || null);
  const [tab, setTab] = useState("summary");
  const [model, setModel] = useState("claude");

  // Sync when the parent's Auto Investigate orchestrator generates AI content
  // — otherwise this panel would keep showing "Generate" even after the pipe
  // successfully ran /ai-analysis at the orchestrator level.
  useEffect(() => {
    if (ai && ai !== data) setData(ai);
  }, [ai]);

  const generate = async () => {
    if (!output && !input) { toast.error("No decoded output to analyze."); return; }
    setBusy(true);
    try {
      const res = await runAiAnalysis({ input, output, analysis, model });
      setData(res);
      onGenerated?.(res);
      toast.success(`AI analysis complete · ${MODEL_LABELS[model]}`);
    } catch (e) {
      toast.error(`AI failed: ${e.message.slice(0, 100)}`);
    } finally { setBusy(false); }
  };

  const copy = (text, label) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied`);
  };

  return (
    <div className="rounded-xl border border-purple-500/30 bg-gradient-to-br from-purple-500/5 to-slate-900/60 p-4" data-testid="ai-panel">
      <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Brain className="w-4 h-4 text-purple-400" />
          <h3 className="text-sm font-semibold text-white">AI Analyst</h3>
          <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30" data-testid="ai-model-label">
            {MODEL_LABELS[model]}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <div className="inline-flex items-center gap-0.5 rounded-md border border-slate-700 bg-slate-900 p-0.5" data-testid="ai-model-selector">
            {[
              { v: "claude", l: "Claude", h: "Anthropic Claude Sonnet 4.6 — deep reasoning" },
              { v: "gpt",    l: "GPT",    h: "OpenAI GPT 5.4 — versatile, well-rounded" },
              { v: "gemini", l: "Gemini", h: "Google Gemini 3.1 Pro — fast + long context" },
            ].map((m) => (
              <button
                key={m.v}
                data-testid={`ai-model-${m.v}`}
                onClick={() => setModel(m.v)}
                disabled={busy}
                title={m.h}
                className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest transition-colors ${
                  model === m.v
                    ? "bg-purple-500/25 text-purple-200"
                    : "text-slate-500 hover:text-slate-300"
                } disabled:opacity-40`}
              >
                {m.l}
              </button>
            ))}
          </div>
          <button
            data-testid="run-ai-btn"
            onClick={generate}
            disabled={busy}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-purple-500 hover:bg-purple-400 text-white text-xs font-semibold disabled:opacity-50 transition-colors"
          >
            {busy ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Sparkles className="w-3 h-3" />}
            {data ? "Regenerate" : "Generate summary + draft rules"}
          </button>
          {data && (
            <PushToSIEMButton input={input} output={output} ai={data} analysis={analysis} />
          )}
        </div>
      </div>

      {!data && !busy && (
        <p className="text-xs text-slate-400 italic px-1">
          Ask Claude to produce a DFIR triage summary + draft Sigma &amp; YARA rules based on the decoded payload and detected TTPs.
        </p>
      )}

      {busy && (
        <div className="text-xs text-purple-300 flex items-center gap-2">
          <RefreshCw className="w-3 h-3 animate-spin" /> Claude is analyzing…
        </div>
      )}

      {data && (
        <>
          <div className="flex items-center gap-1 mb-2 border-b border-slate-800 flex-wrap">
            {[
              { id: "summary", label: "Summary" },
              { id: "sigma",   label: "Sigma" },
              { id: "yara",    label: "YARA" },
              { id: "spl",     label: "Splunk SPL" },
              { id: "kql",     label: "Sentinel KQL" },
              { id: "xdr",     label: "Cisco XDR" },
            ].map((t) => (
              <button
                key={t.id}
                data-testid={`ai-tab-${t.id}`}
                onClick={() => setTab(t.id)}
                className={`px-2.5 py-1 text-[11px] font-semibold border-b-2 transition-colors ${
                  tab === t.id ? "border-purple-400 text-purple-200" : "border-transparent text-slate-500 hover:text-slate-300"
                }`}
              >{t.label}</button>
            ))}
          </div>

          {tab === "summary" && (
            <div className="relative">
              <button data-testid="copy-ai-summary" onClick={() => copy(data.summary, "Summary")}
                className="absolute top-2 right-2 text-slate-400 hover:text-white"><Copy className="w-3 h-3" /></button>
              <p className="text-[13px] text-slate-200 leading-relaxed whitespace-pre-wrap pr-6" data-testid="ai-summary">
                {data.summary}
              </p>
            </div>
          )}

          {tab === "sigma" && <RulePane text={data.sigma_rule} testid="ai-sigma-rule" copyId="copy-ai-sigma" color="text-amber-200" label="Sigma rule" copyFn={copy} />}
          {tab === "yara" && <RulePane text={data.yara_rule} testid="ai-yara-rule" copyId="copy-ai-yara" color="text-fuchsia-200" label="YARA rule" copyFn={copy} />}
          {tab === "spl" && <RulePane text={data.splunk_spl} testid="ai-splunk-spl" copyId="copy-ai-spl" color="text-emerald-200" label="Splunk SPL query" copyFn={copy} />}
          {tab === "kql" && <RulePane text={data.sentinel_kql} testid="ai-sentinel-kql" copyId="copy-ai-kql" color="text-blue-200" label="Sentinel KQL query" copyFn={copy} />}
          {tab === "xdr" && <RulePane text={data.cisco_xdr} testid="ai-cisco-xdr" copyId="copy-ai-xdr" color="text-cyan-200" label="Cisco XDR query" copyFn={copy} />}

          <p className="mt-2 text-[10px] text-slate-500 italic">
            AI-generated draft rules and hunt queries — always human-review before production deployment.
          </p>
        </>
      )}
    </div>
  );
}

function RulePane({ text, testid, copyId, color, label, copyFn }) {
  return (
    <div className="relative">
      <button data-testid={copyId} onClick={() => copyFn(text, label)}
        className="absolute top-2 right-2 text-slate-400 hover:text-white z-10"><Copy className="w-3 h-3" /></button>
      <pre className={`text-[11px] font-mono ${color} bg-slate-950 border border-slate-800 rounded p-3 max-h-96 overflow-auto whitespace-pre-wrap`}
        data-testid={testid}>{text || "(empty — regenerate to try again)"}</pre>
    </div>
  );
}
