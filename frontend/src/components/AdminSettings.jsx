import { useEffect, useState, useCallback } from "react";
import { toast } from "sonner";
import { CheckCircle2, XCircle, Loader2, ExternalLink, KeyRound, Radio, RefreshCw, Save, Trash2, Server, History, ChevronDown, ChevronUp, Rewind, Database, Zap } from "lucide-react";
import { api } from "@/lib/api";
import EnterpriseTierPanel from "@/components/EnterpriseTierPanel";

const SYNCABLE_KEYS = new Set([
  "VIRUSTOTAL_API_KEY",
  "OTX_API_KEY",
  "HYBRID_ANALYSIS_API_KEY",
  "ABUSEIPDB_API_KEY",
  "MALWAREBAZAAR_API_KEY",
]);

const SOURCE_BADGE = {
  db:      { text: "Active · DB",  cls: "bg-emerald-50 text-emerald-700 border-emerald-200" },
  env:     { text: "Active · ENV", cls: "bg-blue-50 text-blue-700 border-blue-200" },
  missing: { text: "Missing",       cls: "bg-red-50 text-red-700 border-red-200" },
};

function ApiKeyCard({ item, onSave, onClear, onTest, onLoadHistory, onApplyHistory, onSync, onRefresh }) {
  const [value, setValue] = useState("");
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [syncResult, setSyncResult] = useState(null);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [history, setHistory] = useState(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [applyingId, setApplyingId] = useState(null);
  const badge = SOURCE_BADGE[item.source] || SOURCE_BADGE.missing;
  const canSync = SYNCABLE_KEYS.has(item.name);

  const refreshHistory = useCallback(async () => {
    setHistoryLoading(true);
    try { const h = await onLoadHistory(item.name); setHistory(h); }
    catch (e) { toast.error(e?.response?.data?.detail || "Could not load history"); }
    finally { setHistoryLoading(false); }
  }, [item.name, onLoadHistory]);

  const toggleHistory = async () => {
    const next = !historyOpen;
    setHistoryOpen(next);
    if (next && history === null) await refreshHistory();
  };

  const doApply = async (id) => {
    if (!confirm("Restore this previously-used key as the active one?")) return;
    setApplyingId(id);
    try { await onApplyHistory(item.name, id); await refreshHistory(); toast.success(`${item.label} restored to previous value`); }
    catch (e) { toast.error(e?.response?.data?.detail || "Apply failed"); }
    finally { setApplyingId(null); }
  };

  const doSave = async () => {
    const v = value.trim();
    if (!v) { toast.error("Enter a value first"); return; }
    setSaving(true);
    try {
      await onSave(item.name, v);
      setValue("");
      toast.success(`${item.label} key updated`);
      if (historyOpen) await refreshHistory();
    }
    catch (e) { toast.error(e?.response?.data?.detail || "Save failed"); }
    finally { setSaving(false); }
  };
  const doClear = async () => {
    if (!confirm(`Clear DB override for ${item.label}? The app will fall back to the .env value (if any).`)) return;
    setClearing(true);
    try { await onClear(item.name); toast.success(`${item.label} override cleared`); }
    catch (e) { toast.error(e?.response?.data?.detail || "Clear failed"); }
    finally { setClearing(false); }
  };
  const doTest = async () => {
    setTesting(true);
    setTestResult(null);
    try { const res = await onTest(item.name); setTestResult(res); }
    catch (e) { setTestResult({ ok: false, message: e?.response?.data?.detail || "Test failed" }); }
    finally { setTesting(false); }
  };

  const doSync = async () => {
    setSyncing(true);
    setSyncResult(null);
    try {
      const res = await onSync(item.name);
      setSyncResult(res);
      const r = res?.result || {};
      if (res?.ok) {
        if (r.skipped) toast.info(`${item.label} sync skipped: ${r.reason || "provider unavailable"}`);
        else toast.success(`${item.label} sync: +${r.added || 0} new, ${r.updated || 0} updated, ${r.items || 0} scanned`);
      }
    }
    catch (e) { setSyncResult({ ok: false, message: e?.response?.data?.detail || "Sync failed" }); toast.error(e?.response?.data?.detail || "Sync failed"); }
    finally { setSyncing(false); }
  };

  return (
    <div data-testid={`api-key-card-${item.name}`} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-slate-500 shrink-0" />
            <h3 className="font-semibold text-slate-900 truncate">{item.label}</h3>
          </div>
          <p className="mt-1 text-sm text-slate-500 leading-relaxed">{item.desc}</p>
        </div>
        <span className={`text-[10px] font-bold uppercase tracking-wide px-2 py-1 rounded-md border shrink-0 ${badge.cls}`}>{badge.text}</span>
      </div>

      <div className="flex items-center gap-3 text-xs">
        <span className="text-slate-400 uppercase font-semibold tracking-wider">Current</span>
        <code className="px-2 py-1 rounded bg-slate-50 border border-slate-200 text-slate-700 font-mono">{item.masked || "—"}</code>
        {item.updated_at && <span className="text-slate-400">updated {new Date(item.updated_at).toLocaleString()}{item.updated_by ? ` · ${item.updated_by}` : ""}</span>}
      </div>

      <div className="flex flex-col sm:flex-row gap-2">
        <input
          data-testid={`api-key-input-${item.name}`}
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={`New ${item.label} key…`}
          className="flex-1 bg-white border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none px-3.5 py-2.5 text-sm text-slate-800 placeholder:text-slate-400 rounded-md font-mono"
          autoComplete="off"
        />
        <button
          data-testid={`api-key-save-${item.name}`}
          onClick={doSave}
          disabled={saving || !value.trim()}
          className="inline-flex items-center justify-center gap-1.5 rounded-md bg-[#2E7DF5] hover:bg-[#1E6BE0] disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold px-4 py-2.5"
        >
          {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />} Save
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-100">
        <button
          data-testid={`api-key-test-${item.name}`}
          onClick={doTest}
          disabled={testing}
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-700 hover:text-[#2E7DF5] border border-slate-200 hover:border-[#2E7DF5] rounded-md px-3 py-1.5"
        >
          {testing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />} Test connection
        </button>
        {canSync && (
          <button
            data-testid={`api-key-sync-${item.name}`}
            onClick={doSync}
            disabled={syncing}
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700 hover:text-emerald-800 border border-emerald-200 hover:border-emerald-400 bg-emerald-50 rounded-md px-3 py-1.5"
          >
            {syncing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Database className="w-3.5 h-3.5" />} Sync IOCs now
          </button>
        )}
        <a
          href={item.get_url}
          target="_blank"
          rel="noopener noreferrer"
          data-testid={`api-key-get-${item.name}`}
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 hover:text-[#2E7DF5]"
        >
          Get your key <ExternalLink className="w-3 h-3" />
        </a>
        {item.source === "db" && (
          <button
            data-testid={`api-key-clear-${item.name}`}
            onClick={doClear}
            disabled={clearing}
            className="ml-auto inline-flex items-center gap-1.5 text-xs font-semibold text-red-600 hover:text-red-700 border border-red-200 hover:border-red-400 rounded-md px-3 py-1.5"
          >
            {clearing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />} Reset to env
          </button>
        )}
        {testResult && (
          <div
            data-testid={`api-key-test-result-${item.name}`}
            className={`w-full mt-2 flex items-start gap-2 text-xs rounded-md border px-3 py-2 ${testResult.ok ? "bg-emerald-50 border-emerald-200 text-emerald-800" : "bg-red-50 border-red-200 text-red-800"}`}
          >
            {testResult.ok ? <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0" /> : <XCircle className="w-4 h-4 mt-0.5 shrink-0" />}
            <span>{testResult.message}</span>
          </div>
        )}
        {syncResult && (
          <div
            data-testid={`api-key-sync-result-${item.name}`}
            className={`w-full mt-2 flex items-start gap-2 text-xs rounded-md border px-3 py-2 ${syncResult.ok && !(syncResult.result?.skipped) ? "bg-emerald-50 border-emerald-200 text-emerald-800" : "bg-amber-50 border-amber-200 text-amber-800"}`}
          >
            <Database className="w-4 h-4 mt-0.5 shrink-0" />
            <span>
              {syncResult.result?.skipped
                ? `Skipped — ${syncResult.result.reason || "provider unavailable"}`
                : syncResult.result
                  ? `Sync complete · +${syncResult.result.added || 0} new · ${syncResult.result.updated || 0} updated · ${syncResult.result.items || 0} scanned`
                  : syncResult.message || "Sync ran"}
            </span>
          </div>
        )}
      </div>

      <div className="pt-3 border-t border-slate-100">
        <button
          data-testid={`api-key-history-toggle-${item.name}`}
          onClick={toggleHistory}
          className="w-full inline-flex items-center justify-between text-xs font-semibold text-slate-600 hover:text-[#2E7DF5]"
        >
          <span className="inline-flex items-center gap-1.5"><History className="w-3.5 h-3.5" /> Previously used keys</span>
          {historyOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>

        {historyOpen && (
          <div data-testid={`api-key-history-${item.name}`} className="mt-3 rounded-md border border-slate-200 bg-slate-50 divide-y divide-slate-200 overflow-hidden">
            {historyLoading && (
              <div className="px-3 py-3 flex items-center gap-2 text-xs text-slate-500"><Loader2 className="w-3.5 h-3.5 animate-spin" /> Loading history…</div>
            )}
            {!historyLoading && history && history.length === 0 && (
              <div className="px-3 py-3 text-xs text-slate-500">No previous values yet — this key has never been updated from the admin panel.</div>
            )}
            {!historyLoading && history && history.map((h, idx) => (
              <div key={h.id} data-testid={`api-key-history-row-${item.name}-${idx}`} className="px-3 py-2.5 flex flex-wrap items-center gap-3 bg-white">
                <code className="font-mono text-xs text-slate-800">{h.masked}</code>
                {h.is_current && <span className="text-[10px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-800 border border-emerald-200">Current</span>}
                <span className="text-[11px] text-slate-500 flex-1 min-w-0 truncate">
                  {h.applied_at ? new Date(h.applied_at).toLocaleString() : "—"}{h.applied_by ? ` · ${h.applied_by}` : ""}
                </span>
                <button
                  data-testid={`api-key-history-apply-${item.name}-${idx}`}
                  onClick={() => doApply(h.id)}
                  disabled={h.is_current || applyingId === h.id}
                  className={`inline-flex items-center gap-1 text-xs font-semibold rounded-md px-2.5 py-1 border transition-colors ${h.is_current ? "text-slate-400 border-slate-200 cursor-not-allowed" : "text-[#2E7DF5] border-blue-200 hover:bg-blue-50"}`}
                >
                  {applyingId === h.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Rewind className="w-3.5 h-3.5" />} Apply
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {item.tier_supported && (
        <EnterpriseTierPanel item={item} onRefresh={onRefresh} />
      )}
    </div>
  );
}

function CommunitySources({ available, enabled, onUpdate }) {
  const [saving, setSaving] = useState(false);
  const toggle = async (slug) => {
    const next = enabled.includes(slug) ? enabled.filter((s) => s !== slug) : [...enabled, slug];
    setSaving(true);
    try { await onUpdate(next); toast.success(`Community sources updated (${next.length}/${available.length})`); }
    catch (e) { toast.error(e?.response?.data?.detail || "Update failed"); }
    finally { setSaving(false); }
  };
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex items-center gap-2 mb-1">
        <Radio className="w-4 h-4 text-slate-500" />
        <h3 className="font-semibold text-slate-900">Community feed sources</h3>
      </div>
      <p className="text-sm text-slate-500 mb-4">Toggle which RSS-aggregated sources appear on the public Threat Intelligence page. Disabled sources are hidden from visitors and skipped when refreshing feeds.</p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {available.map((s) => {
          const on = enabled.includes(s.slug);
          return (
            <label
              key={s.slug}
              data-testid={`community-toggle-${s.slug}`}
              className={`flex items-center justify-between gap-3 rounded-lg border px-3 py-2.5 text-sm cursor-pointer transition-colors ${on ? "bg-emerald-50 border-emerald-200" : "bg-slate-50 border-slate-200 opacity-70"}`}
            >
              <span className="font-medium text-slate-800">{s.label}</span>
              <input
                type="checkbox"
                checked={on}
                disabled={saving}
                onChange={() => toggle(s.slug)}
                className="h-4 w-4 rounded border-slate-300 text-[#2E7DF5] focus:ring-[#2E7DF5]"
              />
            </label>
          );
        })}
      </div>
    </div>
  );
}

export default function AdminSettings() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");
  const [syncingAll, setSyncingAll] = useState(false);
  const [syncAllResult, setSyncAllResult] = useState(null);

  const load = useCallback(async () => {
    try { const { data } = await api.get("/admin/settings"); setData(data); }
    catch (e) { setErr(e?.response?.data?.detail || "Failed to load settings"); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const saveKey = async (name, value) => { await api.put(`/admin/settings/api-key/${name}`, { value }); await load(); };
  const clearKey = async (name) => { await api.delete(`/admin/settings/api-key/${name}`); await load(); };
  const testKey = async (name) => { const { data } = await api.post(`/admin/settings/api-key/${name}/test`); return data; };
  const loadHistory = async (name) => { const { data } = await api.get(`/admin/settings/api-key/${name}/history`); return data.history || []; };
  const applyHistory = async (name, id) => { await api.post(`/admin/settings/api-key/${name}/apply-history/${id}`); await load(); };
  const syncKey = async (name) => { const { data } = await api.post(`/admin/settings/api-key/${name}/sync`); return data; };
  const updateSources = async (enabled) => { await api.put("/admin/settings/community-sources", { enabled }); await load(); };

  const doSyncAll = async () => {
    setSyncingAll(true);
    setSyncAllResult(null);
    try {
      const { data } = await api.post("/iocs/sync-all");
      setSyncAllResult(data);
      const t = data?.totals || {};
      toast.success(`All sources synced · +${t.added || 0} new · ${t.updated || 0} updated`);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Sync-all failed");
    } finally {
      setSyncingAll(false);
    }
  };

  if (err) return <div className="mx-auto max-w-7xl px-6 py-10 text-sm text-red-600" data-testid="settings-error">{err}</div>;
  if (!data) return <div className="mx-auto max-w-7xl px-6 py-10 flex items-center gap-2 text-slate-500 text-sm" data-testid="settings-loading"><Loader2 className="w-4 h-4 animate-spin" /> Loading settings…</div>;

  return (
    <main data-testid="admin-settings" className="mx-auto max-w-7xl px-6 py-10 space-y-8">
      <div>
        <div className="flex items-center gap-2 mb-2">
          <Server className="w-5 h-5 text-slate-600" />
          <h2 className="font-heading text-xl font-semibold text-slate-900">OSINT API Keys</h2>
        </div>
        <p className="text-sm text-slate-500 max-w-3xl">
          Rotate or replace provider keys live — no redeploy required. Saving a key <strong>auto-triggers</strong> the matching IOC feed sync so fresh data flows in immediately. Values are stored in your MongoDB and take priority over any <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded">.env</code> value. This makes the app fully portable — move it to any server and re-key everything from this panel.
        </p>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button
            data-testid="sync-all-btn"
            onClick={doSyncAll}
            disabled={syncingAll}
            className="inline-flex items-center gap-2 rounded-md bg-emerald-600 hover:bg-emerald-700 disabled:opacity-60 text-white text-sm font-semibold px-4 py-2.5"
          >
            {syncingAll ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />} Sync all IOC sources now
          </button>
          {syncAllResult && (
            <div data-testid="sync-all-result" className="text-xs text-slate-600">
              <strong>+{syncAllResult.totals?.added || 0} new</strong> · {syncAllResult.totals?.updated || 0} updated across {Object.keys(syncAllResult.results || {}).length} sources
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5" data-testid="settings-api-keys">
        {data.api_keys.map((k) => (
          <ApiKeyCard key={k.name} item={k} onSave={saveKey} onClear={clearKey} onTest={testKey} onLoadHistory={loadHistory} onApplyHistory={applyHistory} onSync={syncKey} onRefresh={load} />
        ))}
      </div>

      <div className="pt-4" data-testid="settings-community-sources">
        <CommunitySources
          available={data.community_sources.available}
          enabled={data.community_sources.enabled}
          onUpdate={updateSources}
        />
      </div>
    </main>
  );
}
