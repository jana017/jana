/**
 * PowerShellBadge — status label + expandable quick-decode preview.
 *
 * Rendered inside the NivX Forge Output panel. When the analyst's input
 * contains a PowerShell `-e / -enc / -EncodedCommand` argument we surface a
 * dedicated banner so they can confirm at a glance that the payload was
 * recognized, plus an inline UTF-16LE-decoded preview.
 *
 * The full recursive-decode + MITRE analysis still runs via the backend chain
 * — this component is purely a UX affordance, not a replacement for it.
 */
import { useMemo, useState } from "react";
import { Terminal, ChevronDown, ChevronUp, Copy, CheckCircle2 } from "lucide-react";
import { toast } from "sonner";
import { decodePowerShellCommand } from "@/lib/psDecoder";

export default function PowerShellBadge({ input }) {
  const [expanded, setExpanded] = useState(false);
  const info = useMemo(() => decodePowerShellCommand(input || ""), [input]);

  if (!info.detected) return null;

  const copyDecoded = () => {
    if (!info.decoded) return;
    navigator.clipboard.writeText(info.decoded);
    toast.success("Decoded payload copied");
  };

  return (
    <div
      data-testid="powershell-badge"
      className="rounded-lg border border-cyan-500/40 bg-gradient-to-r from-cyan-950/60 to-slate-900/60 p-3 mb-3"
    >
      {/* Header row: label + encoding chip + expand */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-cyan-500/20 border border-cyan-400/40 text-cyan-200 text-[10px] font-bold uppercase tracking-wider">
            <Terminal className="w-3 h-3" />
            PowerShell Payload Detected
          </span>
          {info.encoding && (
            <span
              className="text-[10px] font-mono uppercase text-slate-400 bg-slate-800/60 border border-slate-700 rounded px-1.5 py-0.5"
              data-testid="ps-encoding"
            >
              {info.encoding}
            </span>
          )}
          {info.byteLength != null && (
            <span className="text-[10px] text-slate-500">
              {info.byteLength.toLocaleString()} decoded bytes
            </span>
          )}
        </div>
        <button
          data-testid="ps-badge-toggle"
          onClick={() => setExpanded((v) => !v)}
          className="text-[10px] text-cyan-300 hover:text-cyan-100 inline-flex items-center gap-1"
        >
          {expanded ? (
            <>
              Hide preview <ChevronUp className="w-3 h-3" />
            </>
          ) : (
            <>
              Show quick preview <ChevronDown className="w-3 h-3" />
            </>
          )}
        </button>
      </div>

      {/* Error state */}
      {info.error && (
        <div className="mt-2 text-xs text-rose-300 bg-rose-950/30 border border-rose-500/40 rounded p-2">
          {info.error}
        </div>
      )}

      {/* Expandable decoded preview */}
      {expanded && info.decoded && (
        <div className="mt-3">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400 inline-flex items-center gap-1.5">
              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
              Client-side quick decode
            </span>
            <button
              data-testid="ps-copy-decoded"
              onClick={copyDecoded}
              className="text-[10px] text-slate-400 hover:text-cyan-300 inline-flex items-center gap-1"
            >
              <Copy className="w-3 h-3" /> Copy
            </button>
          </div>
          <pre
            data-testid="ps-decoded-preview"
            className="max-h-64 overflow-auto rounded bg-slate-950/80 border border-slate-800 p-2 text-[11px] leading-relaxed text-cyan-100 font-mono whitespace-pre-wrap break-all"
          >
            {info.snippet}
            {info.decoded.length > info.snippet.length && (
              <span className="text-slate-500">
                {"\n\n… (+"}
                {info.decoded.length - info.snippet.length}
                {" more chars — run Auto Investigate for full analysis)"}
              </span>
            )}
          </pre>
        </div>
      )}
    </div>
  );
}
