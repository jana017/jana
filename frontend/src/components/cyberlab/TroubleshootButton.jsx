/**
 * TroubleshootButton — one-click fix for NivX Forge.
 *
 * On click:
 *   1. Sends the current input to the /api/cyberlab/refine endpoint (100%
 *      deterministic — no LLM). Repairs typographic Unicode, base64 padding,
 *      CMD carets, email quote markers, ellipsis truncation, etc.
 *   2. If the input changed, updates the parent textarea state.
 *   3. Clears any stale result / AI panel state.
 *   4. Optionally re-runs Auto Investigate with the cleaned input.
 *   5. Shows a modal listing every repair applied so the analyst can audit.
 *
 * The underlying `/refine` endpoint has zero external dependencies — this
 * feature keeps working after the app is transferred to any VPS without an
 * Emergent LLM key.
 */
import { useState } from "react";
import { toast } from "sonner";
import { Wrench, CheckCircle2, X, ArrowRight, Loader2 } from "lucide-react";
import { refinePayload } from "@/lib/cyberlabApi";

export default function TroubleshootButton({
  input,
  setInput,
  clearResults,
  reinvestigate,
  disabled = false,
  className = "",
}) {
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState(null);

  const runTroubleshoot = async () => {
    const text = (input || "").trim();
    if (!text) {
      toast.error("Paste a payload first — nothing to troubleshoot.");
      return;
    }
    setBusy(true);
    try {
      const r = await refinePayload(input);
      // 1. Apply repairs to the input textarea
      if (r.changed && r.refined !== input) {
        setInput(r.refined);
      }
      // 2. Clear stale results / AI panel so the retry starts fresh
      clearResults?.();
      // 3. Show the audit report
      setReport(r);
      if (r.fixes.length === 0) {
        toast.info("No repairs needed — input looks clean.", {
          description:
            "Try Auto Investigate directly. If it still misbehaves, use Clear and re-paste from the source.",
        });
      } else {
        toast.success(r.summary, {
          description: `${r.fixes.length} repair${r.fixes.length === 1 ? "" : "s"} applied — re-running Auto Investigate…`,
        });
        // 4. Re-run Auto Investigate on the fixed input.
        //    (Skip if the parent didn't wire a re-run callback.)
        if (reinvestigate) {
          // Give React a beat to commit the setInput change before triggering
          // the investigation (which reads from state).
          setTimeout(() => reinvestigate(r.refined), 80);
        }
      }
    } catch (e) {
      toast.error(`Troubleshoot failed: ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <button
        onClick={runTroubleshoot}
        disabled={disabled || busy}
        data-testid="troubleshoot-btn"
        title="One-click fix — normalize Unicode, repair base64 padding, strip CMD carets/email quotes, then re-run Auto Investigate. Works offline, no LLM needed."
        className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-md border font-semibold text-sm transition-colors disabled:opacity-40 ${className || "bg-slate-800 hover:bg-amber-500/10 border-amber-500/40 text-amber-300 hover:text-amber-100"}`}
      >
        {busy ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : (
          <Wrench className="w-4 h-4" />
        )}
        Troubleshoot
      </button>

      {report && (
        <div
          className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm flex items-start justify-center p-6 overflow-y-auto"
          onClick={() => setReport(null)}
          data-testid="troubleshoot-report"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="my-8 w-full max-w-2xl rounded-xl border border-amber-500/30 bg-slate-900 shadow-2xl"
          >
            <div className="flex items-start justify-between p-5 border-b border-slate-800">
              <div>
                <h2 className="font-heading text-lg font-semibold text-amber-200 flex items-center gap-2">
                  <Wrench className="w-5 h-5" /> Troubleshoot report
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  {report.summary}
                  {" · "}
                  <span className="text-slate-500 font-mono">
                    {report.original_length} → {report.refined_length} chars
                  </span>
                </p>
              </div>
              <button
                onClick={() => setReport(null)}
                className="text-slate-500 hover:text-slate-300"
                data-testid="troubleshoot-close"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-5 space-y-3">
              {report.fixes.length === 0 ? (
                <div className="text-sm text-slate-400 py-4 text-center">
                  Nothing to fix — the input was already clean.
                </div>
              ) : (
                report.fixes.map((f) => (
                  <div
                    key={f.id}
                    className="rounded-lg border border-slate-800 bg-slate-950/50 p-3"
                    data-testid={`fix-${f.id}`}
                  >
                    <div className="flex items-center gap-2 text-sm font-semibold text-emerald-300">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                      {f.label}
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300">
                        ×{f.count}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1 pl-6">{f.detail}</p>
                    {f.before_preview && (
                      <div className="mt-2 pl-6 flex items-center gap-2 text-[11px] font-mono">
                        <span className="text-rose-300 line-through opacity-70 truncate max-w-[42%]">
                          {f.before_preview}
                        </span>
                        <ArrowRight className="w-3 h-3 text-slate-600 shrink-0" />
                        <span className="text-emerald-200 truncate max-w-[42%]">
                          {f.after_preview}
                        </span>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>

            <div className="px-5 py-3 border-t border-slate-800 flex items-center justify-between">
              <span className="text-[10px] text-slate-500 italic">
                All fixes are deterministic — no LLM used, works offline on any VPS.
              </span>
              <button
                onClick={() => setReport(null)}
                data-testid="troubleshoot-done"
                className="text-xs font-semibold text-amber-300 hover:text-amber-100"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
