/**
 * GraphPopout — promotes a graph container between inline layout and a
 * full-screen modal via CSS only (no remount / no portal-swap). The graph
 * component always stays in the same React tree and same DOM parent, so
 * ReactFlow's internal state (zoom, viewport, selected nodes, node
 * positions) is fully preserved across pop-out / pop-in.
 *
 * When `popped=true`:
 *   - Container gets `position: fixed inset-0 z-[100]` and full-screen sizing
 *   - A semi-transparent backdrop is rendered above the dashboard
 *   - A dedicated "X" close button appears in the top-right
 *   - ESC key closes the modal; body scroll is locked
 *
 * Usage:
 *   <GraphPopout popped={popped} onClose={() => setPopped(false)} title="Graph">
 *     <YourGraphComponent />
 *   </GraphPopout>
 */
import { useEffect } from "react";
import { X, Maximize2, Minimize2 } from "lucide-react";

export function GraphPopoutToggle({ popped, onToggle, className = "" }) {
  const Icon = popped ? Minimize2 : Maximize2;
  return (
    <button
      type="button"
      onClick={onToggle}
      data-testid={popped ? "graph-popin-btn" : "graph-popout-btn"}
      title={popped ? "Pop the graph back into the dashboard" : "Pop the graph out to a full-screen modal"}
      className={`inline-flex items-center gap-1.5 text-[10px] font-semibold px-2.5 py-1 rounded border transition-colors ${
        popped
          ? "bg-cyan-500/20 text-cyan-200 border-cyan-500/50 hover:bg-cyan-500/30"
          : "bg-slate-950 text-slate-400 border-slate-800 hover:text-cyan-300 hover:border-cyan-500/40"
      } ${className}`}
    >
      <Icon className="w-3 h-3" />
      {popped ? "Pop in" : "Pop out"}
    </button>
  );
}

export default function GraphPopout({ popped, onClose, title = "Graph", children }) {
  // ESC-to-close + body scroll lock while popped.
  useEffect(() => {
    if (!popped) return undefined;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (e) => { if (e.key === "Escape") onClose?.(); };
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prevOverflow;
      window.removeEventListener("keydown", onKey);
    };
  }, [popped, onClose]);

  // We ALWAYS render the same JSX tree. Only class names change so React
  // never unmounts the child (ReactFlow keeps its viewport & selections).
  return (
    <>
      {/* Backdrop — mounted only while popped */}
      {popped && (
        <div
          onClick={onClose}
          data-testid="graph-popout-backdrop"
          className="fixed inset-0 z-[90] bg-slate-950/85 backdrop-blur-sm"
        />
      )}
      <div
        data-testid={popped ? "graph-popout-modal" : "graph-popout-inline"}
        role={popped ? "dialog" : undefined}
        aria-modal={popped ? "true" : undefined}
        aria-label={popped ? `${title} — full screen` : undefined}
        className={
          popped
            ? "fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-[100] w-[95vw] h-[92vh] sm:w-[90vw] sm:h-[85vh] max-w-[1800px] rounded-lg border border-cyan-500/40 bg-slate-950 shadow-2xl shadow-cyan-500/20 flex flex-col overflow-hidden"
            : "relative"
        }
      >
        {popped && (
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-cyan-500/30 bg-slate-900/60 flex-shrink-0">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-cyan-300">
              <Maximize2 className="w-3.5 h-3.5" />
              {title}
              <span className="text-[9px] font-medium tracking-normal text-slate-500 normal-case ml-2 hidden sm:inline">
                Press <kbd className="px-1 py-0.5 rounded bg-slate-800 text-slate-300">Esc</kbd> to close
              </span>
            </div>
            <button
              type="button"
              onClick={onClose}
              data-testid="graph-popout-close"
              aria-label="Close popout"
              className="inline-flex items-center justify-center w-8 h-8 rounded-md border border-slate-700 bg-slate-900 text-slate-400 hover:text-white hover:bg-rose-500/20 hover:border-rose-500/40 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}
        <div className={popped ? "flex-1 min-h-0 relative" : ""}>
          {children}
        </div>
      </div>
    </>
  );
}
