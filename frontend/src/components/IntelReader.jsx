import { useEffect, useState } from "react";
import { toast } from "sonner";
import { ExternalLink, Copy, FileText, Link2, ListChecks } from "lucide-react";
import { api } from "@/lib/api";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";

export default function IntelReader({ name, onClose }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(false);

  useEffect(() => {
    if (!name) return;
    setReport(null);
    setErr(false);
    setLoading(true);
    api
      .get(`/intel-report/${encodeURIComponent(name)}`)
      .then(({ data }) => setReport(data))
      .catch(() => setErr(true))
      .finally(() => setLoading(false));
  }, [name]);

  const copyAll = () => {
    if (!report?.indicators?.length) return;
    const text = report.indicators.map((i) => i.replace(/^-\s*/, "")).join("\n");
    navigator.clipboard.writeText(text);
    toast.success(`Copied ${report.indicators.length} indicators`);
  };

  return (
    <Dialog open={!!name} onOpenChange={(o) => !o && onClose()}>
      <DialogContent data-testid="intel-reader-dialog" className="max-w-3xl bg-white max-h-[88vh] overflow-y-auto">
        <DialogHeader className="sr-only">
          <DialogTitle>{report?.title || "Threat intelligence report"}</DialogTitle>
          <DialogDescription>Unit42 threat intelligence report with analysis notes, references and indicators of compromise.</DialogDescription>
        </DialogHeader>
        {loading && <div className="py-16 text-center text-sm text-slate-400">Loading report…</div>}
        {err && <div className="py-16 text-center text-sm text-red-500">Unable to load this report.</div>}
        {report && (
          <>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="inline-flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md bg-blue-50 text-blue-700">
                  <FileText className="w-3 h-3" /> {report.source}
                </span>
                <span className="text-xs text-slate-400">{report.date}</span>
              </div>
              <h2 className="font-heading text-xl font-semibold text-slate-900 text-left">{report.title}</h2>
            </div>

            {report.notes?.length > 0 && (
              <div>
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">
                  <ListChecks className="w-4 h-4 text-[#2E7DF5]" /> Analysis
                </div>
                <ul className="space-y-1.5 list-disc pl-5">
                  {report.notes.map((n, i) => (
                    <li key={i} className="text-sm text-slate-600 leading-relaxed">{n}</li>
                  ))}
                </ul>
              </div>
            )}

            {report.references?.length > 0 && (
              <div>
                <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-500 mb-2">
                  <Link2 className="w-4 h-4 text-[#2E7DF5]" /> References
                </div>
                <div className="space-y-1.5">
                  {report.references.map((r, i) => (
                    <a key={i} href={r} target="_blank" rel="noopener noreferrer" className="block text-sm text-[#2E7DF5] hover:underline break-all">{r}</a>
                  ))}
                </div>
              </div>
            )}

            {report.indicators?.length > 0 && (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Indicators of Compromise <span className="text-slate-400">({report.indicators.length})</span>
                  </div>
                  <button data-testid="ioc-copy-all" onClick={copyAll} className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#2E7DF5] hover:underline">
                    <Copy className="w-3.5 h-3.5" /> Copy all
                  </button>
                </div>
                <div className="rounded-lg border border-slate-200 bg-slate-50 max-h-64 overflow-y-auto divide-y divide-slate-100">
                  {report.indicators.map((ioc, i) => (
                    <code key={i} className="font-mono-data block text-[12px] text-slate-700 px-3 py-1.5 break-all">{ioc.replace(/^-\s*/, "")}</code>
                  ))}
                </div>
              </div>
            )}

            <a href={report.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-sm font-semibold text-slate-600 hover:text-slate-900">
              View original on GitHub <ExternalLink className="w-4 h-4" />
            </a>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
