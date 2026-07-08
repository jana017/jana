import { ShieldAlert } from "lucide-react";
import { severityStyle } from "@/lib/iocUtils";

// Prominent, severity-colored banner shown when an analyzed IOC exists in the
// curated NivX IOC database.
export default function KnownIocBanner({ local }) {
  if (!local) return null;
  const st = severityStyle(local.severity);
  return (
    <div className={`rounded-lg border ${st.ring} px-4 py-3`} data-testid="known-ioc-banner">
      <div className="flex items-start gap-3">
        <span className={`mt-0.5 inline-flex items-center justify-center w-8 h-8 rounded-full ${st.badge} shrink-0`}>
          <ShieldAlert className="w-4 h-4" />
        </span>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`text-sm font-bold ${st.text}`}>Known IOC — in your database</span>
            <span data-testid="known-ioc-severity" className={`text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded ${st.badge}`}>{local.severity}</span>
          </div>
          {local.threat_name && <div className="text-sm text-slate-800 mt-1">Threat: <span className="font-semibold">{local.threat_name}</span></div>}
          {local.tags?.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-1.5">
              {local.tags.map((t) => (
                <span key={t} className="text-[11px] bg-white border border-slate-200 text-slate-600 px-2 py-0.5 rounded-full font-mono-data">{t}</span>
              ))}
            </div>
          )}
          {local.notes && <div className="text-xs text-slate-600 mt-1.5">{local.notes}</div>}
          <div className="text-[11px] text-slate-400 mt-1">
            {local.source ? `Source: ${local.source} · ` : ""}Added {local.created_at ? new Date(local.created_at).toLocaleDateString() : ""}
          </div>
        </div>
      </div>
    </div>
  );
}
