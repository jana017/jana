/**
 * PreflightBanner — surfaces HealthBot's current overall status at the top
 * of every Admin page so the operator sees regressions BEFORE clicking
 * "Save & Deploy".
 *
 *  - Polls `/api/healthbot/latest` (last cached scan) on mount → instant
 *  - Auto-refreshes every 60 s in case a background cron writes a new scan
 *  - Hides itself when overall == "ok" (no visual noise on healthy days)
 *  - Red for `critical`, amber for `warning`, blue-info for `info`
 *  - Clicking the banner deep-links to Master → Overview so the operator
 *    can drill into the failing check
 */
import { useEffect, useState } from "react";
import { AlertCircle, AlertTriangle, Info, X, ArrowRight, Loader2 } from "lucide-react";
import { api } from "@/lib/api";

const DISMISS_KEY = "nivx-preflight-banner-dismissed";

const TONE = {
  critical: {
    icon: AlertCircle,
    box: "bg-red-50 border-red-200 text-red-900",
    dot: "bg-red-500",
    label: "CRITICAL",
    labelBg: "bg-red-600 text-white",
  },
  warning: {
    icon: AlertTriangle,
    box: "bg-amber-50 border-amber-200 text-amber-900",
    dot: "bg-amber-500",
    label: "WARNING",
    labelBg: "bg-amber-500 text-white",
  },
  info: {
    icon: Info,
    box: "bg-sky-50 border-sky-200 text-sky-900",
    dot: "bg-sky-500",
    label: "INFO",
    labelBg: "bg-sky-500 text-white",
  },
};

export default function PreflightBanner() {
  const [scan, setScan] = useState(null);
  const [dismissed, setDismissed] = useState(() => {
    try { return sessionStorage.getItem(DISMISS_KEY) === "1"; } catch { return false; }
  });
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      const { data } = await api.get("/healthbot/latest");
      setScan(data);
    } catch {
      // Silent — banner just won't render.
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 60_000);
    return () => clearInterval(t);
  }, []);

  const dismiss = () => {
    setDismissed(true);
    try { sessionStorage.setItem(DISMISS_KEY, "1"); } catch { /* ignore */ }
  };

  const rescan = async (e) => {
    e.stopPropagation();
    setBusy(true);
    try {
      const { data } = await api.post("/healthbot/scan");
      setScan(data);
      setDismissed(false);
      try { sessionStorage.removeItem(DISMISS_KEY); } catch { /* ignore */ }
    } catch { /* toast handled elsewhere */ } finally {
      setBusy(false);
    }
  };

  const gotoMaster = () => {
    window.dispatchEvent(new CustomEvent("nivx-admin-goto", { detail: "master" }));
  };

  if (!scan || dismissed) return null;
  const overall = scan.overall;
  if (overall === "ok") return null;

  const tone = TONE[overall] || TONE.warning;
  const Icon = tone.icon;
  const criticals = (scan.results || []).filter((r) => r.severity === "critical");
  const warnings = (scan.results || []).filter((r) => r.severity === "warning");
  const failing = criticals.length > 0 ? criticals : warnings;
  const primary = failing[0];

  return (
    <div
      data-testid="preflight-banner"
      className={`border-b ${tone.box} cursor-pointer group`}
      onClick={gotoMaster}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => { if (e.key === "Enter") gotoMaster(); }}
    >
      <div className="mx-auto max-w-7xl px-6 py-2 flex items-center gap-3">
        <span className={`relative flex h-2.5 w-2.5 shrink-0`}>
          <span className={`absolute inline-flex h-full w-full animate-ping rounded-full ${tone.dot} opacity-60`}></span>
          <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${tone.dot}`}></span>
        </span>
        <Icon className="w-4 h-4 shrink-0" />
        <span className={`text-[10px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${tone.labelBg}`}>
          {tone.label}
        </span>
        <div className="text-sm min-w-0 flex-1 truncate" data-testid="preflight-message">
          <strong>Pre-flight: {criticals.length || 0} critical · {warnings.length || 0} warning</strong>
          {primary && (
            <span className="ml-2 opacity-80">— {primary.name}: {primary.message}</span>
          )}
        </div>
        <button
          onClick={rescan}
          disabled={busy}
          className="hidden sm:inline-flex items-center gap-1 text-xs font-semibold px-2 py-1 rounded border border-current opacity-80 hover:opacity-100 disabled:opacity-40"
          data-testid="preflight-rescan"
        >
          {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
          {busy ? "Scanning…" : "Re-scan"}
        </button>
        <span className="hidden md:inline-flex items-center gap-1 text-xs font-semibold opacity-80 group-hover:opacity-100">
          Open Master <ArrowRight className="w-3 h-3" />
        </span>
        <button
          onClick={(e) => { e.stopPropagation(); dismiss(); }}
          className="opacity-60 hover:opacity-100"
          data-testid="preflight-dismiss"
          aria-label="Dismiss"
        >
          <X className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}
