import { useState } from "react";
import { toast } from "sonner";
import { AlertTriangle, ShieldCheck, Zap, Loader2, Clock, Save, CheckCircle2, XCircle } from "lucide-react";
import { api } from "@/lib/api";

const TIER_LABEL = {
  enterprise: { text: "Enterprise", cls: "bg-orange-50 text-orange-700 border-orange-300" },
  free:       { text: "Free API",   cls: "bg-emerald-50 text-emerald-700 border-emerald-200" },
};

function timeAgo(iso) {
  if (!iso) return "never";
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

/**
 * Enterprise / Free tier controls for VIRUSTOTAL_API_KEY (extensible if more
 * providers ever gain enterprise tiers). Renders:
 *   • Enterprise-key input + Free-key input (masked once saved)
 *   • Live "Active tier" badge — pulsing red when Enterprise is currently active
 *   • "Monthly Enterprise Sync" button → swap → sync → auto-revert to Free
 *   • Timeline of last successful Enterprise sync
 */
export default function EnterpriseTierPanel({ item, onRefresh }) {
  const [entValue, setEntValue] = useState("");
  const [freeValue, setFreeValue] = useState("");
  const [savingEnt, setSavingEnt] = useState(false);
  const [savingFree, setSavingFree] = useState(false);
  const [running, setRunning] = useState(false);
  const [lastResult, setLastResult] = useState(null);

  const active = item.active_tier;               // 'enterprise' | 'free' | null
  const enterpriseSaved = !!item.enterprise_masked;
  const freeSaved = !!item.free_masked;
  const lastSync = item.last_enterprise_sync;

  const saveTier = async (tier, value, setter) => {
    const v = (value || "").trim();
    if (!v) { toast.error("Enter a key first"); return; }
    setter(true);
    try {
      await api.put(`/admin/settings/api-key/${item.name}/tier/${tier}`, { value: v });
      toast.success(`${TIER_LABEL[tier].text} key saved`);
      if (tier === "enterprise") setEntValue("");
      if (tier === "free") setFreeValue("");
      await onRefresh();
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Save failed");
    } finally {
      setter(false);
    }
  };

  const runEnterpriseSync = async () => {
    if (!enterpriseSaved) { toast.error("Save the Enterprise key first"); return; }
    if (!freeSaved) {
      if (!confirm("⚠️ No Free key saved — after the sync, the Enterprise key will remain active until you save a Free key. Continue?")) return;
    } else {
      if (!confirm("Run Monthly Enterprise Sync? The system will:\n\n1. Swap to the Enterprise key\n2. Run VirusTotal + Talos bulk IOC ingestion\n3. Automatically revert to the Free key\n\nEnterprise credits will be consumed during the sync window only.")) return;
    }
    setRunning(true);
    setLastResult(null);
    try {
      const { data } = await api.post("/admin/settings/enterprise-sync");
      setLastResult(data);
      const vt = data?.vt || {};
      const talos = data?.talos || {};
      if (data.ok) {
        toast.success(`Enterprise sync complete · VT +${vt.added || 0} · Talos +${talos.added || 0} · reverted to Free in ${(data.duration_ms/1000).toFixed(1)}s`);
      } else {
        toast.warning("Enterprise sync finished with errors — see result panel below");
      }
      await onRefresh();
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Enterprise sync failed");
    } finally {
      setRunning(false);
    }
  };

  const inputCls = "flex-1 bg-white border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none px-3 py-2 text-sm text-slate-800 placeholder:text-slate-400 rounded-md font-mono";

  return (
    <div data-testid={`tier-panel-${item.name}`} className={`mt-4 -mx-5 -mb-5 px-5 py-4 border-t ${active === "enterprise" ? "bg-orange-50 border-orange-300 ring-2 ring-orange-400 animate-pulse-slow" : "bg-slate-50 border-slate-200"}`}>
      <div className="flex items-center justify-between flex-wrap gap-2 mb-3">
        <div className="flex items-center gap-2">
          <ShieldCheck className={`w-4 h-4 ${active === "enterprise" ? "text-orange-600" : "text-slate-500"}`} />
          <div className="text-xs font-bold uppercase tracking-wider text-slate-700">Enterprise / Free tier control</div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-bold uppercase text-slate-500">Currently active:</span>
          {active === "enterprise" ? (
            <span data-testid={`active-tier-badge-${item.name}`} className="inline-flex items-center gap-1 text-[10px] font-bold uppercase px-2 py-0.5 rounded border bg-orange-100 text-orange-800 border-orange-400 animate-pulse">
              <AlertTriangle className="w-3 h-3" /> Enterprise · consuming credits
            </span>
          ) : active === "free" ? (
            <span data-testid={`active-tier-badge-${item.name}`} className="inline-flex items-center gap-1 text-[10px] font-bold uppercase px-2 py-0.5 rounded border bg-emerald-50 text-emerald-700 border-emerald-200">
              <CheckCircle2 className="w-3 h-3" /> Free API
            </span>
          ) : (
            <span data-testid={`active-tier-badge-${item.name}`} className="inline-flex items-center gap-1 text-[10px] font-bold uppercase px-2 py-0.5 rounded border bg-slate-100 text-slate-500 border-slate-200">
              <XCircle className="w-3 h-3" /> Not set
            </span>
          )}
        </div>
      </div>

      {/* Enterprise key row */}
      <div className="mb-3">
        <div className="flex items-center gap-2 mb-1.5">
          <span className={`text-[10px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border ${TIER_LABEL.enterprise.cls}`}>Enterprise API</span>
          {enterpriseSaved && <code className="text-[11px] text-slate-600 font-mono">{item.enterprise_masked}</code>}
          {!enterpriseSaved && <span className="text-[11px] text-red-500 font-semibold">Not saved</span>}
        </div>
        <div className="flex gap-2">
          <input
            data-testid={`tier-enterprise-input-${item.name}`}
            type="password" autoComplete="off"
            placeholder={enterpriseSaved ? "Update Enterprise key…" : "Paste your Enterprise VT key…"}
            value={entValue} onChange={(e) => setEntValue(e.target.value)}
            className={inputCls}
          />
          <button data-testid={`tier-enterprise-save-${item.name}`} onClick={() => saveTier("enterprise", entValue, setSavingEnt)} disabled={savingEnt || !entValue.trim()} className="inline-flex items-center gap-1.5 rounded-md bg-orange-600 hover:bg-orange-700 disabled:opacity-50 text-white text-xs font-semibold px-3 py-2">
            {savingEnt ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />} Save
          </button>
        </div>
      </div>

      {/* Free key row */}
      <div className="mb-4">
        <div className="flex items-center gap-2 mb-1.5">
          <span className={`text-[10px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border ${TIER_LABEL.free.cls}`}>Free API</span>
          {freeSaved && <code className="text-[11px] text-slate-600 font-mono">{item.free_masked}</code>}
          {!freeSaved && <span className="text-[11px] text-amber-600 font-semibold">Not saved — revert target missing</span>}
        </div>
        <div className="flex gap-2">
          <input
            data-testid={`tier-free-input-${item.name}`}
            type="password" autoComplete="off"
            placeholder={freeSaved ? "Update Free key…" : "Paste your Free VT key (the revert-to key)…"}
            value={freeValue} onChange={(e) => setFreeValue(e.target.value)}
            className={inputCls}
          />
          <button data-testid={`tier-free-save-${item.name}`} onClick={() => saveTier("free", freeValue, setSavingFree)} disabled={savingFree || !freeValue.trim()} className="inline-flex items-center gap-1.5 rounded-md bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white text-xs font-semibold px-3 py-2">
            {savingFree ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />} Save
          </button>
        </div>
      </div>

      {/* Monthly Enterprise Sync CTA */}
      <div className="flex flex-wrap items-center gap-3 pt-3 border-t border-slate-200">
        <button
          data-testid={`enterprise-sync-btn-${item.name}`}
          onClick={runEnterpriseSync}
          disabled={running || !enterpriseSaved}
          className={`inline-flex items-center gap-2 rounded-md font-semibold text-sm px-4 py-2.5 ${running ? "bg-orange-500 text-white" : enterpriseSaved ? "bg-orange-600 hover:bg-orange-700 text-white" : "bg-slate-200 text-slate-400 cursor-not-allowed"}`}
        >
          {running ? (<><Loader2 className="w-4 h-4 animate-spin" /> Enterprise sync running…</>) : (<><Zap className="w-4 h-4" /> Monthly Enterprise Sync</>)}
        </button>
        <div className="flex items-center gap-1.5 text-xs text-slate-600" data-testid={`last-enterprise-sync-${item.name}`}>
          <Clock className="w-3.5 h-3.5 text-slate-400" />
          {lastSync?.finished_at ? (
            <span>
              Last successful Enterprise sync: <strong>{new Date(lastSync.finished_at).toLocaleString()}</strong>
              <span className="text-slate-400"> · {timeAgo(lastSync.finished_at)}</span>
              {lastSync.vt_added != null && <span className="text-slate-500"> · VT +{lastSync.vt_added}</span>}
              {lastSync.talos_added != null && <span className="text-slate-500"> · Talos +{lastSync.talos_added}</span>}
            </span>
          ) : (
            <span>No Enterprise sync yet.</span>
          )}
        </div>
      </div>

      {running && (
        <div className="mt-3 rounded-md border border-orange-300 bg-orange-100 text-orange-900 text-xs px-3 py-2 flex items-start gap-2 animate-pulse" data-testid={`enterprise-sync-live-${item.name}`}>
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
          <div>
            <strong>Enterprise key is temporarily active — premium credits are being consumed.</strong> The system will automatically revert to the Free key as soon as the VT + Talos syncs finish.
          </div>
        </div>
      )}

      {lastResult && (
        <div data-testid={`enterprise-sync-result-${item.name}`} className={`mt-3 rounded-md border text-xs px-3 py-2 space-y-1 ${lastResult.ok ? "border-emerald-200 bg-emerald-50 text-emerald-900" : "border-amber-300 bg-amber-50 text-amber-900"}`}>
          <div className="font-semibold flex items-center gap-1.5">
            {lastResult.ok ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
            Enterprise sync finished in {(lastResult.duration_ms / 1000).toFixed(1)}s · reverted to <strong>{lastResult.final_tier}</strong>
          </div>
          <div>VT: {formatSyncResult(lastResult.vt)}</div>
          <div>Talos: {formatSyncResult(lastResult.talos)}</div>
        </div>
      )}
    </div>
  );
}

function formatSyncResult(r) {
  if (!r) return "no result";
  if (r.error) return `error: ${r.error}`;
  if (r.skipped) return `skipped — ${r.reason || "unavailable"}`;
  return `+${r.added || 0} new · ${r.updated || 0} updated · ${r.items || 0} scanned`;
}
