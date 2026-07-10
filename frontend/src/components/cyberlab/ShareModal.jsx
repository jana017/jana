/**
 * Share + Export modal. Creates a shareable URL (30-day TTL) and offers
 * PDF / Markdown download of the current analysis report.
 */
import { useState } from "react";
import { toast } from "sonner";
import { Copy, Download, FileText, Link2, Share2, X, RefreshCw } from "lucide-react";
import { createShare, exportPdf, exportMarkdown } from "@/lib/cyberlabApi";

export default function ShareModal({ open, onClose, report }) {
  const [busy, setBusy] = useState(false);
  const [share, setShare] = useState(null);

  if (!open) return null;

  const doShare = async () => {
    setBusy(true);
    try {
      const res = await createShare(report);
      setShare(res);
      toast.success(`Share link created · expires in ${res.expires_in_days} days`);
    } catch (e) {
      toast.error(`Share failed: ${e.message}`);
    } finally { setBusy(false); }
  };

  const doPdf = async () => {
    setBusy(true);
    try {
      const blob = await exportPdf(report);
      _download(blob, `cyberlab-report-${Date.now()}.pdf`);
      toast.success("PDF downloaded");
    } catch (e) { toast.error(`PDF failed: ${e.message}`); }
    finally { setBusy(false); }
  };

  const doMd = async () => {
    setBusy(true);
    try {
      const text = await exportMarkdown(report);
      _download(new Blob([text], { type: "text/markdown" }), `cyberlab-report-${Date.now()}.md`);
      toast.success("Markdown downloaded");
    } catch (e) { toast.error(`Markdown failed: ${e.message}`); }
    finally { setBusy(false); }
  };

  const shareUrl = share
    ? `${window.location.origin}/nivx-forge/share/${share.share_id}`
    : "";

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}
      data-testid="share-modal">
      <div className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Share2 className="w-4 h-4 text-cyan-400" />
            <h3 className="text-base font-semibold text-white">Share &amp; Export</h3>
          </div>
          <button data-testid="close-share-modal" onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Share block */}
        <div className="rounded-md border border-slate-800 bg-slate-950 p-3 mb-3">
          <div className="flex items-center gap-2 mb-2">
            <Link2 className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-xs font-bold uppercase tracking-widest text-slate-300">Shareable link</span>
            <span className="ml-auto text-[10px] text-slate-500">Expires in 30 days</span>
          </div>
          {!share ? (
            <button data-testid="create-share-btn" onClick={doShare} disabled={busy}
              className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-900 text-sm font-semibold disabled:opacity-50 transition-colors">
              {busy ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Share2 className="w-3.5 h-3.5" />}
              Create shareable link
            </button>
          ) : (
            <div className="flex items-center gap-2">
              <input readOnly value={shareUrl} data-testid="share-url"
                className="flex-1 font-mono text-[11px] bg-slate-900 border border-slate-800 rounded px-2 py-1.5 text-cyan-300 outline-none" />
              <button data-testid="copy-share-url" onClick={() => { navigator.clipboard.writeText(shareUrl); toast.success("Link copied"); }}
                className="inline-flex items-center gap-1 text-xs text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded px-2 py-1.5">
                <Copy className="w-3 h-3" /> Copy
              </button>
            </div>
          )}
        </div>

        {/* Export buttons */}
        <div className="rounded-md border border-slate-800 bg-slate-950 p-3">
          <div className="flex items-center gap-2 mb-2">
            <FileText className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-xs font-bold uppercase tracking-widest text-slate-300">Export report</span>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <button data-testid="export-pdf-btn" onClick={doPdf} disabled={busy}
              className="inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white text-sm font-semibold disabled:opacity-50 transition-colors">
              <Download className="w-3.5 h-3.5" /> PDF (branded)
            </button>
            <button data-testid="export-md-btn" onClick={doMd} disabled={busy}
              className="inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white text-sm font-semibold disabled:opacity-50 transition-colors">
              <Download className="w-3.5 h-3.5" /> Markdown
            </button>
          </div>
        </div>

        <p className="mt-3 text-[10px] text-slate-500 text-center italic">
          Shared reports are publicly readable but auto-delete after 30 days.
        </p>
      </div>
    </div>
  );
}

function _download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
