import { useCallback, useEffect, useState } from "react";
import { Database, Search, Trash2, Upload, Plus, ListPlus, FileSpreadsheet, Loader2, RefreshCw, Cloud } from "lucide-react";
import { api, formatApiErrorDetail } from "@/lib/api";
import { useAuth } from "@/context/AuthContext";
import { TYPE_LABEL, severityStyle } from "@/lib/iocUtils";

const SEVERITIES = ["low", "medium", "high", "critical"];

export default function IocDatabase() {
  const { user } = useAuth();
  const isAdmin = !!user;

  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState(null);
  const [q, setQ] = useState("");
  const [type, setType] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [selected, setSelected] = useState(new Set());
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState(null); // {kind:'ok'|'err', text}

  const [addMode, setAddMode] = useState("single");
  const [busy, setBusy] = useState(false);
  const [single, setSingle] = useState({ value: "", threat_name: "", severity: "medium", tags: "", source: "", notes: "" });
  const [bulkText, setBulkText] = useState("");
  const [bulkMeta, setBulkMeta] = useState({ threat_name: "", severity: "medium", tags: "", source: "" });
  const [file, setFile] = useState(null);
  const [otx, setOtx] = useState(null);   // { configured, last_sync }
  const [otxBusy, setOtxBusy] = useState(false);

  const flash = (kind, text) => { setMsg({ kind, text }); setTimeout(() => setMsg(null), 5000); };

  const fetchOtx = useCallback(async () => {
    try { const { data } = await api.get("/otx/status"); setOtx(data); } catch { /* noop */ }
  }, []);

  const syncOtx = async () => {
    setOtxBusy(true);
    try {
      const { data } = await api.post("/otx/sync");
      flash("ok", `OTX synced: ${data.added} new · ${data.updated} updated · ${data.skipped} skipped (${data.pulses} pulses, ${data.indicators} indicators)`);
      await Promise.all([fetchOtx(), fetchList(), fetchStats()]);
    } catch (err) {
      flash("err", formatApiErrorDetail(err.response?.data?.detail) || "OTX sync failed");
    } finally { setOtxBusy(false); }
  };

  const fetchStats = useCallback(async () => {
    try { const { data } = await api.get("/iocs/stats"); setStats(data); } catch { /* noop */ }
  }, []);

  const fetchList = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get("/iocs", { params: { q: q || undefined, type, severity, limit: 200 } });
      setItems(data.items || []);
      setTotal(data.total || 0);
      setSelected(new Set());
    } catch { /* noop */ } finally { setLoading(false); }
  }, [q, type, severity]);

  useEffect(() => { fetchStats(); }, [fetchStats]);
  useEffect(() => { fetchOtx(); }, [fetchOtx]);
  useEffect(() => { const t = setTimeout(fetchList, 300); return () => clearTimeout(t); }, [fetchList]);

  const refresh = () => { fetchList(); fetchStats(); };

  const toggleSel = (id) => setSelected((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const toggleAll = () => setSelected((s) => (s.size === items.length ? new Set() : new Set(items.map((i) => i.id))));

  const addSingle = async (e) => {
    e.preventDefault();
    if (!single.value.trim()) return;
    setBusy(true);
    try {
      await api.post("/iocs", { ...single, tags: single.tags.split(",").map((t) => t.trim()).filter(Boolean) });
      flash("ok", `Added ${single.value}`);
      setSingle({ value: "", threat_name: "", severity: "medium", tags: "", source: "", notes: "" });
      refresh();
    } catch (err) { flash("err", formatApiErrorDetail(err.response?.data?.detail)); } finally { setBusy(false); }
  };

  const addBulk = async () => {
    if (!bulkText.trim()) return;
    setBusy(true);
    try {
      const { data } = await api.post("/iocs/bulk", { values: [bulkText], threat_name: bulkMeta.threat_name || undefined, severity: bulkMeta.severity, source: bulkMeta.source || undefined, tags: bulkMeta.tags.split(",").map((t) => t.trim()).filter(Boolean) });
      flash("ok", `Added ${data.added}, updated ${data.updated}, skipped ${data.skipped}`);
      setBulkText("");
      refresh();
    } catch (err) { flash("err", formatApiErrorDetail(err.response?.data?.detail)); } finally { setBusy(false); }
  };

  const uploadFile = async () => {
    if (!file) return;
    setBusy(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      const { data } = await api.post("/iocs/upload", fd, { headers: { "Content-Type": "multipart/form-data" } });
      flash("ok", `Imported ${data.added} new, ${data.updated} updated, ${data.skipped} skipped (of ${data.total} rows)`);
      setFile(null);
      refresh();
    } catch (err) { flash("err", formatApiErrorDetail(err.response?.data?.detail)); } finally { setBusy(false); }
  };

  const deleteOne = async (id) => {
    try { await api.delete(`/iocs/${id}`); flash("ok", "IOC deleted"); refresh(); }
    catch (err) { flash("err", formatApiErrorDetail(err.response?.data?.detail)); }
  };

  const deleteSelected = async () => {
    if (!selected.size) return;
    try { const { data } = await api.delete("/iocs/bulk", { data: { ids: Array.from(selected) } }); flash("ok", `Deleted ${data.deleted} IOCs`); refresh(); }
    catch (err) { flash("err", formatApiErrorDetail(err.response?.data?.detail)); }
  };

  return (
    <div data-testid="ioc-db-section" className="mt-6">
      {/* Stats */}
      <div className="flex flex-wrap items-center gap-3 mb-5">
        <div className="flex items-center gap-2 text-slate-800 font-semibold"><Database className="w-5 h-5 text-[#2E7DF5]" /> IOC Database <span className="text-slate-400 font-normal" data-testid="ioc-db-total">({stats?.total ?? total} indicators)</span></div>
        <div className="flex flex-wrap gap-1.5 ml-auto">
          {SEVERITIES.slice().reverse().map((s) => (
            <span key={s} className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border ${severityStyle(s).ring} ${severityStyle(s).text}`}>{stats?.by_severity?.[s] ?? 0} {s}</span>
          ))}
        </div>
      </div>

      {msg && (
        <div data-testid="ioc-db-msg" className={`mb-4 text-sm px-3.5 py-2 rounded-md border ${msg.kind === "ok" ? "bg-green-50 border-green-200 text-green-700" : "bg-red-50 border-red-200 text-red-600"}`}>{msg.text}</div>
      )}

      {/* Admin upload panel */}
      {isAdmin && (
        <div className="mb-5 rounded-xl border border-slate-200 bg-slate-50 p-4">
          {/* AlienVault OTX sync bar */}
          {otx?.configured && (
            <div data-testid="otx-sync-bar" className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-blue-200 bg-blue-50/60 px-3.5 py-2.5">
              <div className="flex items-center gap-2 text-sm">
                <Cloud className="w-4 h-4 text-[#2E7DF5]" />
                <span className="font-semibold text-slate-800">AlienVault OTX</span>
                <span className="text-slate-500">
                  {otx.last_sync
                    ? `Last sync ${new Date(otx.last_sync.synced_at).toLocaleString()} · ${otx.last_sync.added} new · ${otx.last_sync.updated} updated (${otx.last_sync.pulses} pulses)`
                    : "Awaiting first sync…"}
                </span>
              </div>
              <button onClick={syncOtx} disabled={otxBusy} data-testid="otx-sync-btn" className="inline-flex items-center gap-2 border border-[#2E7DF5] text-[#2E7DF5] hover:bg-[#2E7DF5] hover:text-white text-sm font-semibold px-3.5 py-1.5 rounded-md transition-colors disabled:opacity-60">
                {otxBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />} Sync now
              </button>
            </div>
          )}

          <div className="inline-flex items-center gap-1 p-1 mb-4 bg-white border border-slate-200 rounded-lg">
            {[["single", "Add one", Plus], ["bulk", "Bulk paste", ListPlus], ["file", "Upload CSV / Excel", FileSpreadsheet]].map(([m, label, Icon]) => (
              <button key={m} onClick={() => setAddMode(m)} data-testid={`ioc-db-add-mode-${m}`} className={`inline-flex items-center gap-1.5 text-sm font-semibold px-3 py-1.5 rounded-md transition-colors ${addMode === m ? "bg-[#2E7DF5] text-white" : "text-slate-500 hover:text-slate-700"}`}>
                <Icon className="w-4 h-4" /> {label}
              </button>
            ))}
          </div>

          {addMode === "single" && (
            <form onSubmit={addSingle} data-testid="ioc-add-form" className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <input required data-testid="ioc-add-value" value={single.value} onChange={(e) => setSingle({ ...single, value: e.target.value })} placeholder="IOC value (hash / IP / domain / URL)" className="sm:col-span-2 border border-slate-300 rounded-md px-3 py-2 text-sm font-mono-data outline-none focus:border-[#2E7DF5]" />
              <input data-testid="ioc-add-threat" value={single.threat_name} onChange={(e) => setSingle({ ...single, threat_name: e.target.value })} placeholder="Threat name / malware family" className="border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:border-[#2E7DF5]" />
              <select data-testid="ioc-add-severity" value={single.severity} onChange={(e) => setSingle({ ...single, severity: e.target.value })} className="border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:border-[#2E7DF5] bg-white">
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              <input data-testid="ioc-add-tags" value={single.tags} onChange={(e) => setSingle({ ...single, tags: e.target.value })} placeholder="Tags (comma separated)" className="border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:border-[#2E7DF5]" />
              <input data-testid="ioc-add-source" value={single.source} onChange={(e) => setSingle({ ...single, source: e.target.value })} placeholder="Source" className="border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:border-[#2E7DF5]" />
              <input data-testid="ioc-add-notes" value={single.notes} onChange={(e) => setSingle({ ...single, notes: e.target.value })} placeholder="Notes" className="sm:col-span-2 border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:border-[#2E7DF5]" />
              <button disabled={busy} data-testid="ioc-add-submit" className="sm:col-span-2 inline-flex items-center justify-center gap-2 bg-[#2E7DF5] hover:bg-[#2563EB] text-white text-sm font-semibold px-5 py-2.5 rounded-md transition-colors disabled:opacity-60">
                {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />} Add to database
              </button>
            </form>
          )}

          {addMode === "bulk" && (
            <div className="space-y-3">
              <textarea data-testid="ioc-bulk-add-input" value={bulkText} onChange={(e) => setBulkText(e.target.value)} rows={4} placeholder={"Paste many IOCs (one per line / comma / space)"} className="w-full border border-slate-300 rounded-md px-3 py-2 text-sm font-mono-data outline-none focus:border-[#2E7DF5] resize-y" />
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                <input value={bulkMeta.threat_name} onChange={(e) => setBulkMeta({ ...bulkMeta, threat_name: e.target.value })} placeholder="Threat name (optional)" className="border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:border-[#2E7DF5]" />
                <select value={bulkMeta.severity} onChange={(e) => setBulkMeta({ ...bulkMeta, severity: e.target.value })} className="border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:border-[#2E7DF5] bg-white">
                  {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
                <input value={bulkMeta.tags} onChange={(e) => setBulkMeta({ ...bulkMeta, tags: e.target.value })} placeholder="Tags" className="border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:border-[#2E7DF5]" />
                <input value={bulkMeta.source} onChange={(e) => setBulkMeta({ ...bulkMeta, source: e.target.value })} placeholder="Source" className="border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:border-[#2E7DF5]" />
              </div>
              <button disabled={busy || !bulkText.trim()} onClick={addBulk} data-testid="ioc-bulk-add-submit" className="inline-flex items-center gap-2 bg-[#2E7DF5] hover:bg-[#2563EB] text-white text-sm font-semibold px-5 py-2.5 rounded-md transition-colors disabled:opacity-60">
                {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <ListPlus className="w-4 h-4" />} Import list
              </button>
            </div>
          )}

          {addMode === "file" && (
            <div className="space-y-3">
              <p className="text-xs text-slate-500">Upload a <b>.csv</b>, <b>.txt</b> or <b>.xlsx</b> file. First column (or a column named <code className="font-mono-data">value</code>) is the IOC. Optional columns: <code className="font-mono-data">threat_name, tags, severity, source, notes</code>.</p>
              <input type="file" accept=".csv,.txt,.xlsx,.xlsm" data-testid="ioc-file-input" onChange={(e) => setFile(e.target.files?.[0] || null)} className="block text-sm text-slate-600 file:mr-3 file:py-2 file:px-4 file:rounded-md file:border-0 file:bg-slate-200 file:text-slate-700 file:font-semibold hover:file:bg-slate-300 file:cursor-pointer" />
              <button disabled={busy || !file} onClick={uploadFile} data-testid="ioc-file-submit" className="inline-flex items-center gap-2 bg-[#2E7DF5] hover:bg-[#2563EB] text-white text-sm font-semibold px-5 py-2.5 rounded-md transition-colors disabled:opacity-60">
                {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />} Upload &amp; import
              </button>
            </div>
          )}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 mb-3">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input data-testid="ioc-db-search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search value, threat name, tag, source…" className="w-full border border-slate-300 rounded-md pl-9 pr-3 py-2.5 text-sm outline-none focus:border-[#2E7DF5]" />
        </div>
        <select data-testid="ioc-db-type-filter" value={type} onChange={(e) => setType(e.target.value)} className="border border-slate-300 rounded-md px-3 py-2.5 text-sm bg-white outline-none focus:border-[#2E7DF5]">
          <option value="all">All types</option>
          <option value="hash">Hash</option>
          <option value="ip">IP</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
        </select>
        <select data-testid="ioc-db-severity-filter" value={severity} onChange={(e) => setSeverity(e.target.value)} className="border border-slate-300 rounded-md px-3 py-2.5 text-sm bg-white outline-none focus:border-[#2E7DF5]">
          <option value="all">All severities</option>
          {SEVERITIES.slice().reverse().map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        {isAdmin && selected.size > 0 && (
          <button onClick={deleteSelected} data-testid="ioc-db-bulk-delete" className="inline-flex items-center gap-2 bg-red-600 hover:bg-red-700 text-white text-sm font-semibold px-4 py-2.5 rounded-md transition-colors">
            <Trash2 className="w-4 h-4" /> Delete ({selected.size})
          </button>
        )}
      </div>

      {/* Table */}
      <div className="rounded-xl border border-slate-200 overflow-hidden">
        <div className="max-h-[520px] overflow-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-slate-50 z-10">
              <tr className="border-b border-slate-200 text-left text-xs uppercase tracking-wide text-slate-500">
                {isAdmin && <th className="px-3 py-3 w-10"><input type="checkbox" data-testid="ioc-db-select-all" checked={items.length > 0 && selected.size === items.length} onChange={toggleAll} /></th>}
                <th className="px-4 py-3 font-semibold">Indicator</th>
                <th className="px-4 py-3 font-semibold">Type</th>
                <th className="px-4 py-3 font-semibold">Threat</th>
                <th className="px-4 py-3 font-semibold">Severity</th>
                <th className="px-4 py-3 font-semibold">Tags</th>
                <th className="px-4 py-3 font-semibold">Source</th>
                {isAdmin && <th className="px-4 py-3 font-semibold" />}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading && <tr><td colSpan={8} className="px-4 py-8 text-center text-slate-400"><Loader2 className="w-4 h-4 animate-spin inline mr-2" /> Loading…</td></tr>}
              {!loading && items.length === 0 && <tr><td colSpan={8} className="px-4 py-8 text-center text-slate-400" data-testid="ioc-db-empty">No IOCs found. {isAdmin ? "Add some above." : ""}</td></tr>}
              {!loading && items.map((it, i) => {
                const st = severityStyle(it.severity);
                return (
                  <tr key={it.id} data-testid={`ioc-db-row-${i}`} className="bg-white hover:bg-slate-50/60 transition-colors align-top">
                    {isAdmin && <td className="px-3 py-3"><input type="checkbox" data-testid={`ioc-db-select-${i}`} checked={selected.has(it.id)} onChange={() => toggleSel(it.id)} /></td>}
                    <td className="px-4 py-3"><code className="font-mono-data text-xs text-slate-800 break-all">{it.value}</code></td>
                    <td className="px-4 py-3 whitespace-nowrap"><span className="text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md bg-slate-100 text-slate-600 border border-slate-200">{TYPE_LABEL[it.type] || it.type}</span></td>
                    <td className="px-4 py-3 text-slate-700">{it.threat_name || <span className="text-slate-300">—</span>}</td>
                    <td className="px-4 py-3"><span className={`text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded ${st.badge}`}>{it.severity}</span></td>
                    <td className="px-4 py-3"><div className="flex flex-wrap gap-1">{(it.tags || []).map((t) => <span key={t} className="text-[10px] bg-slate-100 border border-slate-200 text-slate-500 px-1.5 py-0.5 rounded-full font-mono-data">{t}</span>)}</div></td>
                    <td className="px-4 py-3 text-slate-500 text-xs">{it.source || "—"}</td>
                    {isAdmin && <td className="px-4 py-3"><button onClick={() => deleteOne(it.id)} data-testid={`ioc-db-delete-${i}`} aria-label="Delete IOC" className="text-slate-400 hover:text-red-600 transition-colors"><Trash2 className="w-4 h-4" /></button></td>}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
      {!isAdmin && <p className="mt-3 text-xs text-slate-400">Sign in as admin to add or delete indicators.</p>}
    </div>
  );
}
