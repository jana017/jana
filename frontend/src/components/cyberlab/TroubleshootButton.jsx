/**
 * TroubleshootButton — smart triage for NivX Forge.
 *
 * NEW FLOW (Feb 2026 redesign):
 *   1. Click → calls /api/cyberlab/diagnose (dry-run, no changes)
 *   2. Modal opens showing every issue found:
 *        - Green checkmark rows: "here's what I can fix"
 *        - Amber warning rows: "issues I found but CAN'T fix — need a dev"
 *   3. User reviews and clicks "Proceed & Fix" or Cancel
 *   4. On proceed: applies /refine, re-runs Auto Investigate
 *   5. If input was already clean, tells the analyst upfront and offers
 *      to re-run Auto Investigate anyway (skip the modal)
 *
 * This replaces the previous silent "just apply everything" behavior that
 * caused the Feb 2026 padding-corruption incident — analysts now see
 * exactly what Troubleshoot is about to change before it does.
 *
 * The underlying /diagnose + /refine endpoints have zero external
 * dependencies — this feature keeps working after transfer to any VPS
 * without an Emergent LLM key.
 */
import { useState } from "react";
import { toast } from "sonner";
import {
  Wrench, CheckCircle2, AlertTriangle, X, ArrowRight, Loader2, ShieldQuestion,
} from "lucide-react";
import { diagnosePayload, refinePayload } from "@/lib/cyberlabApi";

export default function TroubleshootButton({
  input,
  setInput,
  clearResults,
  reinvestigate,
  disabled = false,
  className = "",
}) {
  const [busy, setBusy] = useState(false);
  const [applying, setApplying] = useState(false);
  const [diagnosis, setDiagnosis] = useState(null);

  const openDiagnosis = async () => {
    const text = (input || "").trim();
    if (!text) {
      toast.error("Paste a payload first — nothing to troubleshoot.");
      return;
    }
    setBusy(true);
    try {
      const d = await diagnosePayload(input);
      // If diagnose shows nothing to fix and no anomalies, offer to just
      // re-run Auto Investigate — no need for the modal at all.
      if (!d.would_change && (!d.anomalies || d.anomalies.length === 0)) {
        toast.info("Input looks clean — no repairs needed.", {
          description:
            "Nothing for Troubleshoot to fix. If Auto Investigate is still failing, a decoder plugin may be missing — pin the sample to the Regression Suite so a developer can add it.",
        });
        setBusy(false);
        return;
      }
      setDiagnosis(d);
    } catch (e) {
      toast.error(`Diagnose failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  const applyFixes = async () => {
    setApplying(true);
    try {
      const r = await refinePayload(input);
      if (r.changed && r.refined !== input) {
        setInput(r.refined);
      }
      clearResults?.();
      toast.success(r.summary || "Repairs applied", {
        description:
          reinvestigate
            ? `${r.fixes.length} repair${r.fixes.length === 1 ? "" : "s"} — re-running Auto Investigate…`
            : `${r.fixes.length} repair${r.fixes.length === 1 ? "" : "s"} applied.`,
      });
      setDiagnosis(null);
      if (reinvestigate) {
        setTimeout(() => reinvestigate(r.refined), 80);
      }
    } catch (e) {
      toast.error(`Troubleshoot failed: ${e.message}`);
    } finally {
      setApplying(false);
    }
  };

  const findings = diagnosis?.findings || [];
  const anomalies = diagnosis?.anomalies || [];
  const hasAnyFinding = findings.length + anomalies.length > 0;

  return (
    <>
      <button
        onClick={openDiagnosis}
        disabled={disabled || busy}
        data-testid="troubleshoot-btn"
        title="Scan the payload for paste artifacts and known obfuscation tricks, then show you exactly what can be fixed before applying anything. Deterministic, no LLM."
        className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-md border font-semibold text-sm transition-colors disabled:opacity-40 ${className || "bg-slate-800 hover:bg-amber-500/10 border-amber-500/40 text-amber-300 hover:text-amber-100"}`}
      >
        {busy ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <Wrench className="w-4 h-4" />
        )}
        Troubleshoot
      </button>

      {diagnosis && (
        <div
          className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4"
          onClick={() => !applying && setDiagnosis(null)}
          data-testid="troubleshoot-modal"
        >
          <div
            className="w-full max-w-2xl max-h-[85vh] overflow-y-auto rounded-xl border border-slate-700 bg-slate-900 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <div className="text-lg font-bold text-slate-100 flex items-center gap-2">
                  <ShieldQuestion className="w-5 h-5 text-amber-400" /> Troubleshoot Diagnosis
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  {hasAnyFinding
                    ? `Found ${findings.length} repairable issue${findings.length === 1 ? "" : "s"}${anomalies.length ? ` · ${anomalies.length} anomaly${anomalies.length === 1 ? "" : "ies"} (needs dev)` : ""}`
                    : "No issues detected."}
                </div>
              </div>
              <button
                onClick={() => !applying && setDiagnosis(null)}
                className="text-slate-400 hover:text-slate-100 disabled:opacity-40"
                disabled={applying}
                data-testid="troubleshoot-modal-close"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              {findings.length > 0 && (
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wider text-emerald-400 mb-2 flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4" />
                    Troubleshoot can fix these:
                  </div>
                  <ul className="space-y-2" data-testid="troubleshoot-findings">
                    {findings.map((f) => (
                      <li
                        key={f.id}
                        className="rounded-lg border border-emerald-800/40 bg-emerald-950/30 p-3"
                        data-testid={`troubleshoot-finding-${f.id}`}
                      >
                        <div className="text-sm font-semibold text-emerald-200 flex items-center gap-2">
                          {f.title}
                          {f.count > 1 && (
                            <span className="text-[10px] font-mono bg-emerald-900/60 text-emerald-200 px-1.5 py-0.5 rounded">
                              ×{f.count}
                            </span>
                          )}
                        </div>
                        <div className="text-xs text-slate-300 mt-1">{f.description}</div>
                        {(f.sample_before || f.sample_after) && (
                          <div className="mt-2 text-[10px] font-mono grid grid-cols-1 sm:grid-cols-2 gap-2">
                            <div className="rounded bg-slate-800/60 px-2 py-1.5">
                              <div className="text-[9px] uppercase text-slate-500 mb-0.5">Before</div>
                              <div className="text-red-200/80 break-all">{f.sample_before}</div>
                            </div>
                            <div className="rounded bg-slate-800/60 px-2 py-1.5">
                              <div className="text-[9px] uppercase text-slate-500 mb-0.5">After</div>
                              <div className="text-emerald-200/80 break-all">{f.sample_after}</div>
                            </div>
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {anomalies.length > 0 && (
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wider text-amber-400 mb-2 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4" />
                    Anomalies Troubleshoot can&apos;t fix on its own:
                  </div>
                  <ul className="space-y-2" data-testid="troubleshoot-anomalies">
                    {anomalies.map((a) => (
                      <li
                        key={a.id}
                        className="rounded-lg border border-amber-800/40 bg-amber-950/30 p-3"
                        data-testid={`troubleshoot-anomaly-${a.id}`}
                      >
                        <div className="text-sm font-semibold text-amber-200">{a.title}</div>
                        <div className="text-xs text-slate-300 mt-1">{a.description}</div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            <div className="px-5 py-4 border-t border-slate-800 flex items-center justify-end gap-2 bg-slate-950/50">
              <button
                onClick={() => setDiagnosis(null)}
                disabled={applying}
                className="text-sm font-semibold text-slate-400 hover:text-slate-100 px-3 py-2 disabled:opacity-40"
                data-testid="troubleshoot-cancel"
              >
                Cancel
              </button>
              <button
                onClick={applyFixes}
                disabled={applying || findings.length === 0}
                className="inline-flex items-center gap-1.5 bg-amber-500 hover:bg-amber-400 text-black font-bold text-sm px-4 py-2 rounded-md disabled:opacity-40 disabled:cursor-not-allowed"
                data-testid="troubleshoot-proceed"
              >
                {applying ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <ArrowRight className="w-4 h-4" />
                )}
                {findings.length > 0
                  ? `Proceed & fix ${findings.length} issue${findings.length === 1 ? "" : "s"}`
                  : "Nothing to fix"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
