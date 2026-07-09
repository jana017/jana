/**
 * Public read-only view of a shared CyberLab analysis.
 * Route: /cyberlab/share/:shareId
 */
import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  ShieldAlert, ShieldCheck, FileWarning, Target, Bug, Fingerprint,
  ExternalLink, RefreshCw, Beaker, Brain,
} from "lucide-react";
import Navbar from "@/components/Navbar";
import Contact from "@/components/Contact";
import { fetchShare } from "@/lib/cyberlabApi";
import useSeo from "@/lib/useSeo";

const VERDICT_STYLE = {
  malicious:  { bg: "bg-red-500/10 border-red-500/40", text: "text-red-300", label: "Malicious", icon: ShieldAlert },
  suspicious: { bg: "bg-amber-500/10 border-amber-500/40", text: "text-amber-300", label: "Suspicious", icon: FileWarning },
  clean:      { bg: "bg-emerald-500/10 border-emerald-500/40", text: "text-emerald-300", label: "Clean", icon: ShieldCheck },
};

const SEVERITY_STYLE = {
  critical: "bg-red-500/15 text-red-300 border-red-500/40",
  high:     "bg-orange-500/15 text-orange-300 border-orange-500/40",
  medium:   "bg-yellow-500/15 text-yellow-300 border-yellow-500/40",
  low:      "bg-blue-500/15 text-blue-300 border-blue-500/40",
  info:     "bg-slate-500/15 text-slate-300 border-slate-500/40",
};

const RISK_TEXT = (score) => {
  if (score >= 60) return "text-red-400";
  if (score >= 30) return "text-amber-400";
  return "text-emerald-400";
};

export default function CyberLabShare() {
  const { shareId } = useParams();
  const [state, setState] = useState({ loading: true, data: null, error: null });

  useSeo({
    title: "Shared analysis · NivX CyberLab",
    description: "Public shared CyberLab analysis report.",
  });

  useEffect(() => {
    let cancelled = false;
    fetchShare(shareId)
      .then((d) => { if (!cancelled) setState({ loading: false, data: d, error: null }); })
      .catch((e) => { if (!cancelled) setState({ loading: false, data: null, error: e.message }); });
    return () => { cancelled = true; };
  }, [shareId]);

  if (state.loading) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center">
        <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
      </div>
    );
  }

  if (state.error || !state.data) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100">
        <Navbar />
        <div className="pt-32 mx-auto max-w-md text-center">
          <FileWarning className="w-12 h-12 text-amber-400 mx-auto mb-4" />
          <h1 className="text-2xl font-semibold text-white mb-2">Share not found</h1>
          <p className="text-sm text-slate-400 mb-6">
            {state.error || "This shared analysis is missing or has expired (shares auto-delete after 30 days)."}
          </p>
          <Link to="/cyberlab" data-testid="back-to-cyberlab"
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-900 text-sm font-semibold">
            <Beaker className="w-4 h-4" /> Open CyberLab
          </Link>
        </div>
      </div>
    );
  }

  const { payload, created_at, expires_at } = state.data;
  const { input, output, trace, analysis, ai } = payload;
  const V = VERDICT_STYLE[analysis?.verdict || "clean"];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100" data-testid="cyberlab-share-root">
      <Navbar />
      <main className="mx-auto max-w-5xl px-4 lg:px-8 pt-24 pb-8">
        <div className="mb-6 flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-cyan-400 mb-2">
              <Beaker className="w-3.5 h-3.5" /> Shared CyberLab Analysis
            </div>
            <h1 className="font-heading text-2xl md:text-3xl font-semibold text-white">Read-only report</h1>
            <p className="text-xs text-slate-500 mt-1">
              Created {new Date(created_at).toLocaleString()} · expires {new Date(expires_at).toLocaleDateString()}
            </p>
          </div>
          <Link to="/cyberlab" data-testid="open-cyberlab-link"
            className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white text-xs font-semibold transition-colors">
            <ExternalLink className="w-3.5 h-3.5" /> Analyze your own
          </Link>
        </div>

        <div className={`mb-6 rounded-lg border ${V.bg} p-4 flex items-center justify-between gap-4`}>
          <div className="flex items-center gap-3">
            <V.icon className={`w-6 h-6 ${V.text}`} />
            <div>
              <div className={`text-xs font-bold uppercase tracking-widest ${V.text}`} data-testid="share-verdict">
                Verdict · {V.label}
              </div>
              <div className="text-sm text-slate-200 mt-0.5">{analysis?.summary}</div>
            </div>
          </div>
          <div className="text-right">
            <div className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Risk Score</div>
            <div className={`text-3xl font-bold tabular-nums ${RISK_TEXT(analysis?.risk_score || 0)}`}>
              {analysis?.risk_score || 0}<span className="text-sm text-slate-500">/100</span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <Panel title="Input Payload">
            <pre className="font-mono text-[11px] text-slate-300 whitespace-pre-wrap break-all max-h-56 overflow-auto">{input}</pre>
          </Panel>
          <Panel title="Decoded Output">
            <pre className="font-mono text-[11px] text-emerald-300 whitespace-pre-wrap break-all max-h-56 overflow-auto">{output}</pre>
          </Panel>
        </div>

        {ai?.summary && (
          <div className="rounded-xl border border-purple-500/30 bg-gradient-to-br from-purple-500/5 to-slate-900/60 p-4 mb-4">
            <div className="flex items-center gap-2 mb-2">
              <Brain className="w-4 h-4 text-purple-400" />
              <h3 className="text-sm font-semibold text-white">AI Analyst Summary</h3>
              <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/30">Claude Sonnet 4.5</span>
            </div>
            <p className="text-[13px] text-slate-200 leading-relaxed whitespace-pre-wrap">{ai.summary}</p>
          </div>
        )}

        {trace?.length > 0 && (
          <Panel title="Decoding Chain" className="mb-4">
            <ol className="space-y-1">
              {trace.map((s, i) => (
                <li key={i} className="flex items-center gap-2 text-xs">
                  <span className="text-slate-500 w-4 text-right">{i + 1}.</span>
                  <span className="text-cyan-300 font-mono">{s.name}</span>
                  <span className="text-slate-500">·</span>
                  <span className="text-slate-400">{s.category}</span>
                  {s.confidence && <span className="ml-auto text-emerald-400 font-mono text-[10px]">conf {s.confidence}</span>}
                </li>
              ))}
            </ol>
          </Panel>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Panel title={<><Target className="w-3.5 h-3.5 inline mr-1" /> MITRE ({analysis?.mitre?.length || 0})</>}>
            {analysis?.mitre?.length ? analysis.mitre.map((m) => (
              <a key={m.id} href={`https://attack.mitre.org/techniques/${m.id.replace(".", "/")}/`} target="_blank" rel="noreferrer"
                className="block rounded border border-slate-800 bg-slate-950 p-2 mb-1.5 hover:border-cyan-500/40 transition-colors">
                <div className="text-xs font-bold text-cyan-300 font-mono">{m.id}</div>
                <div className="text-[11px] text-white">{m.name}</div>
                <div className="text-[9px] uppercase text-slate-500 tracking-widest mt-0.5">{m.tactic}</div>
              </a>
            )) : <div className="text-xs text-slate-500 italic">None detected.</div>}
          </Panel>

          <Panel title={<><Bug className="w-3.5 h-3.5 inline mr-1" /> Rules ({analysis?.rules?.length || 0})</>}>
            {analysis?.rules?.length ? analysis.rules.map((r, i) => (
              <div key={i} className="rounded border border-slate-800 bg-slate-950 p-2 mb-1.5">
                <div className="flex items-center justify-between gap-2 mb-0.5">
                  <span className="text-xs font-bold text-white">{r.rule}</span>
                  <span className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded border ${SEVERITY_STYLE[r.severity] || SEVERITY_STYLE.medium}`}>{r.severity}</span>
                </div>
                <div className="text-[11px] text-slate-400">{r.description}</div>
              </div>
            )) : <div className="text-xs text-slate-500 italic">None triggered.</div>}
          </Panel>

          <Panel title={<><Fingerprint className="w-3.5 h-3.5 inline mr-1" /> IOCs ({analysis?.iocs?.length || 0})</>}>
            {analysis?.iocs?.length ? analysis.iocs.slice(0, 30).map((i, k) => (
              <div key={k} className="flex items-center gap-2 rounded border border-slate-800 bg-slate-950 px-2 py-1 mb-1">
                <span className="text-[9px] font-bold uppercase tracking-widest text-slate-500 w-12 shrink-0">{i.type}</span>
                <span className="font-mono text-[11px] text-cyan-300 truncate">{i.value}</span>
              </div>
            )) : <div className="text-xs text-slate-500 italic">None extracted.</div>}
          </Panel>
        </div>

        <div className="mt-8 text-center text-[11px] text-slate-500">
          <ShieldCheck className="w-3 h-3 inline mr-1 text-emerald-400" />
          Shared reports auto-delete after 30 days.
        </div>
      </main>

      <div className="bg-white text-slate-900">
        <Contact />
      </div>
    </div>
  );
}

function Panel({ title, children, className = "" }) {
  return (
    <div className={`rounded-xl border border-slate-800 bg-slate-900/60 p-4 ${className}`}>
      <h3 className="text-xs font-bold uppercase tracking-widest text-slate-300 mb-2">{title}</h3>
      {children}
    </div>
  );
}
