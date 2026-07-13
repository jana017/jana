import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { Plus, Trash2, Upload, Save, X, Search, FileText, Image as ImageIcon, Loader2, RefreshCw, BookOpenText, Sparkles, GitCompare, GraduationCap, LayoutGrid, Pencil } from "lucide-react";
import { api, formatApiErrorDetail } from "@/lib/api";

/**
 * NivX Forge — Analyst Training Center
 *
 * Admin surface for teaching the Investigation Report AI mode.  All content
 * pasted / uploaded here is retrieved by the report generator as few-shot
 * style references and (for the persona field) as house-style rules.
 * IMPORTANT: examples are STYLE references — the AI still refuses to copy
 * specific IOCs, hostnames or dates from them.
 */
const EMPTY_EXAMPLE = {
  id: "",
  title: "",
  case_type: "malware",
  tags: [],
  raw_data: "",
  narrative: "",
  recommendations: [],
  analyst_notes: "",
  active: true,
  attachments: [],
  source: "authored",
  ai_original: "",
  ai_model: "",
  created_by: "",
  created_by_role: "",
};

const CASE_TYPES = [
  { key: "malware",           label: "Malware / Endpoint" },
  { key: "dns_proxy",         label: "DNS / Proxy" },
  { key: "mixed",             label: "Mixed (malware + DNS)" },
  { key: "authorized_admin",  label: "Authorized admin (change control)" },
  { key: "unauthorized",      label: "Unauthorized activity" },
  { key: "phishing",          label: "Phishing / BEC" },
  { key: "insider",           label: "Insider Threat" },
  { key: "data_exfil",        label: "Data Exfiltration" },
  { key: "cloud_iam",         label: "Cloud / IAM" },
  { key: "ransomware",        label: "Ransomware" },
  { key: "generic",           label: "Generic" },
];

const btnCls = "inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-md border transition-colors";

export default function AdminForgeTraining() {
  const [examples, setExamples] = useState([]);
  const [selected, setSelected] = useState(null);   // example id currently being edited
  const [form, setForm] = useState(EMPTY_EXAMPLE);
  const [busy, setBusy] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [search, setSearch] = useState("");
  const [caseFilter, setCaseFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [showDiff, setShowDiff] = useState(false);
  const [isEditing, setIsEditing] = useState(false);   // false = read-only view; true = editable
  const [persona, setPersona] = useState("");
  const [personaSaving, setPersonaSaving] = useState(false);
  const [stats, setStats] = useState(null);   // {breakdown, totals}
  const fileRef = useRef(null);

  const loadAll = useCallback(async () => {
    try {
      const { data: list } = await api.get("/admin/forge/training/examples", { params: { case_type: caseFilter || undefined, q: search || undefined, source: sourceFilter || undefined } });
      setExamples(list.examples || []);
    } catch (e) {
      toast.error(`Load examples failed: ${formatApiErrorDetail(e.response?.data?.detail) || e.message}`);
    }
  }, [caseFilter, search, sourceFilter]);

  const loadPersona = useCallback(async () => {
    try {
      const { data } = await api.get("/admin/forge/training/config");
      setPersona(data.persona || "");
    } catch (e) {
      // silent — persona is optional
    }
  }, []);

  const loadStats = useCallback(async () => {
    try {
      const { data } = await api.get("/admin/forge/training/stats");
      setStats(data);
    } catch (e) {
      // silent — dashboard is optional
    }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);
  useEffect(() => { loadPersona(); }, [loadPersona]);
  useEffect(() => { loadStats(); }, [loadStats]);

  const startNew = () => { setSelected(null); setForm(EMPTY_EXAMPLE); setIsEditing(true); };

  const editExisting = (ex) => {
    setSelected(ex.id);
    setIsEditing(false);   // open in read-only view; user clicks Edit to modify
    setForm({
      ...EMPTY_EXAMPLE,
      ...ex,
      tags: Array.isArray(ex.tags) ? ex.tags : [],
      recommendations: Array.isArray(ex.recommendations) ? ex.recommendations : [],
      attachments: Array.isArray(ex.attachments) ? ex.attachments : [],
    });
  };

  const cancelEdit = () => {
    // Revert unsaved edits by re-fetching the original example.
    if (!selected) { startNew(); return; }
    (async () => {
      try {
        const { data } = await api.get(`/admin/forge/training/examples/${selected}`);
        editExisting(data);
      } catch (e) {
        setIsEditing(false);
      }
    })();
  };

  const submit = async (e) => {
    e?.preventDefault?.();
    if (!form.title.trim()) { toast.error("Title is required"); return; }
    setBusy(true);
    const payload = {
      title: form.title,
      case_type: form.case_type || "generic",
      tags: (form.tags || []).map((t) => t.trim()).filter(Boolean),
      raw_data: form.raw_data || "",
      narrative: form.narrative || "",
      recommendations: (form.recommendations || []).map((r) => r.trim()).filter(Boolean),
      analyst_notes: form.analyst_notes || "",
      active: !!form.active,
    };
    try {
      let saved;
      if (selected) {
        const { data } = await api.put(`/admin/forge/training/examples/${selected}`, payload);
        saved = data;
        toast.success("Example updated");
      } else {
        const { data } = await api.post("/admin/forge/training/examples", payload);
        saved = data;
        toast.success("Example added — NivX Cognis AI will use this on future reports");
      }
      await loadAll();
      await loadStats();
      editExisting(saved);   // returns to read-only view after save
    } catch (e) {
      toast.error(`Save failed: ${formatApiErrorDetail(e.response?.data?.detail) || e.message}`);
    } finally { setBusy(false); }
  };

  const remove = async () => {
    if (!selected) return;
    if (!window.confirm("Delete this training example (including attachments)?")) return;
    setBusy(true);
    try {
      await api.delete(`/admin/forge/training/examples/${selected}`);
      toast.success("Example deleted");
      startNew();
      await loadAll();
      await loadStats();
    } catch (e) {
      toast.error(`Delete failed: ${formatApiErrorDetail(e.response?.data?.detail) || e.message}`);
    } finally { setBusy(false); }
  };

  const uploadAttachment = async (file) => {
    if (!selected) { toast.error("Save the example first, then attach files"); return; }
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) { toast.error("Max attachment size is 10 MB"); return; }
    setUploading(true);
    const fd = new FormData();
    fd.append("file", file);
    try {
      const { data: att } = await api.post(`/admin/forge/training/examples/${selected}/attachments`, fd, { headers: { "Content-Type": "multipart/form-data" } });
      setForm((f) => ({ ...f, attachments: [...(f.attachments || []), att] }));
      toast.success(`Attached ${att.filename}`);
    } catch (e) {
      toast.error(`Upload failed: ${formatApiErrorDetail(e.response?.data?.detail) || e.message}`);
    } finally { setUploading(false); }
  };

  const removeAttachment = async (attId) => {
    if (!selected) return;
    try {
      await api.delete(`/admin/forge/training/examples/${selected}/attachments/${attId}`);
      setForm((f) => ({ ...f, attachments: (f.attachments || []).filter((a) => a.id !== attId) }));
      toast.success("Attachment removed");
    } catch (e) {
      toast.error(`Remove failed: ${formatApiErrorDetail(e.response?.data?.detail) || e.message}`);
    }
  };

  const savePersona = async () => {
    setPersonaSaving(true);
    try {
      await api.put("/admin/forge/training/config", { persona });
      toast.success("Analyst persona saved — NivX Cognis AI will use it on next report");
    } catch (e) {
      toast.error(`Save persona failed: ${formatApiErrorDetail(e.response?.data?.detail) || e.message}`);
    } finally { setPersonaSaving(false); }
  };

  return (
    <main className="mx-auto max-w-[1400px] px-6 py-8 space-y-6" data-testid="forge-training-page">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="font-heading text-2xl font-semibold text-slate-900 flex items-center gap-2">
            <BookOpenText className="w-6 h-6 text-[#2E7DF5]" /> NivX Forge — Analyst Training Center
          </h1>
          <p className="text-sm text-slate-500 mt-1 max-w-3xl">
            Add past incidents/alerts with your analyst-written summary and recommendations. Attach source files or screenshots. The Investigation Report NivX Cognis AI retrieves the top matching examples on every generation and mirrors your team&apos;s tone, structure and phrasing.
          </p>
        </div>
        <button data-testid="forge-training-new" onClick={startNew} className={`${btnCls} bg-[#2E7DF5] text-white border-[#2E7DF5] hover:bg-[#2563EB]`}>
          <Plus className="w-3.5 h-3.5" /> New example
        </button>
      </header>

      {/* Analyst persona / house style */}
      <section data-testid="forge-training-persona" className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
          <h2 className="text-sm font-semibold text-slate-800 flex items-center gap-1.5">
            <Sparkles className="w-4 h-4 text-violet-500" /> Analyst persona / house style
          </h2>
          <button onClick={savePersona} disabled={personaSaving} className={`${btnCls} border-[#2E7DF5] text-[#2E7DF5] hover:bg-blue-50`} data-testid="forge-training-persona-save">
            {personaSaving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />} Save persona
          </button>
        </div>
        <p className="text-xs text-slate-500 mb-2">
          House-style rules the NivX Cognis AI obeys on every report. E.g. &quot;Always open with &apos;NivX CSOC observed…&apos;&quot;, tone preferences, sentence ordering, standard closers. Never overrides the &quot;no fabrication&quot; guarantees.
        </p>
        <textarea
          value={persona}
          onChange={(e) => setPersona(e.target.value)}
          rows={4}
          placeholder='e.g. "Open with the incident timestamp in UTC. Refer to the customer as CUSTOMER. Always end with: NivX CSOC recommends the following remediation steps:"'
          className="w-full text-sm bg-slate-50 border border-slate-200 focus:border-[#2E7DF5] outline-none rounded-md px-3 py-2 font-mono-data text-slate-800"
          data-testid="forge-training-persona-text"
        />
      </section>

      {/* Training coverage dashboard — heat-map + tallies */}
      {stats && (
        <section data-testid="forge-training-stats" className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
            <h2 className="text-sm font-semibold text-slate-800 flex items-center gap-1.5">
              <LayoutGrid className="w-4 h-4 text-[#2E7DF5]" /> Training coverage
            </h2>
            <div className="flex flex-wrap items-center gap-2 text-[11px] font-semibold text-slate-500">
              <span className="inline-flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-slate-300" /> Missing
              </span>
              <span className="inline-flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-amber-400" /> Light (1–2)
              </span>
              <span className="inline-flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-emerald-500" /> Covered (3+)
              </span>
              <button onClick={loadStats} className={`${btnCls} border-slate-200 text-slate-600 hover:border-slate-400`} data-testid="forge-training-stats-refresh">
                <RefreshCw className="w-3 h-3" />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
            <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2">
              <div className="text-[10px] uppercase tracking-wide text-slate-500">Grand total</div>
              <div className="text-lg font-semibold text-slate-900" data-testid="stat-grand-total">{stats.totals?.grand_total ?? 0}</div>
            </div>
            <div className="rounded-md border border-blue-200 bg-blue-50 px-3 py-2">
              <div className="text-[10px] uppercase tracking-wide text-blue-700">Authored (admin)</div>
              <div className="text-lg font-semibold text-blue-900" data-testid="stat-authored">{stats.totals?.authored_total ?? 0}</div>
            </div>
            <div className="rounded-md border border-violet-200 bg-violet-50 px-3 py-2">
              <div className="text-[10px] uppercase tracking-wide text-violet-700">Refinements (analyst)</div>
              <div className="text-lg font-semibold text-violet-900" data-testid="stat-refinements">{stats.totals?.refinement_total ?? 0}</div>
            </div>
            <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2">
              <div className="text-[10px] uppercase tracking-wide text-amber-700">Case gaps</div>
              <div className="text-lg font-semibold text-amber-900" data-testid="stat-gaps">
                {stats.totals?.case_types_missing ?? 0}
                <span className="text-[11px] font-normal text-amber-700 ml-1">/ {stats.totals?.case_types_defined ?? 0}</span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2" data-testid="forge-training-heatmap">
            {(stats.breakdown || []).map((row) => {
              const tone = row.tier === "covered"
                ? "border-emerald-300 bg-emerald-50 text-emerald-900"
                : row.tier === "light"
                  ? "border-amber-300 bg-amber-50 text-amber-900"
                  : "border-slate-200 bg-slate-50 text-slate-500";
              const dot = row.tier === "covered" ? "bg-emerald-500" : row.tier === "light" ? "bg-amber-400" : "bg-slate-300";
              return (
                <button
                  key={row.case_type}
                  type="button"
                  onClick={() => { setCaseFilter(row.case_type); setSourceFilter(""); }}
                  data-testid={`heatmap-${row.case_type}`}
                  title={`${row.total} example${row.total !== 1 ? "s" : ""} · ${row.authored} authored · ${row.refinement} refinements — click to filter`}
                  className={`text-left rounded-md border ${tone} px-3 py-2 hover:brightness-95 transition-all`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] font-semibold uppercase tracking-wide truncate">{row.case_type}</span>
                    <span className={`w-2 h-2 rounded-full ${dot}`} />
                  </div>
                  <div className="text-base font-semibold mt-0.5">{row.total}</div>
                  <div className="text-[10px] opacity-80 mt-0.5">
                    {row.authored} authored · {row.refinement} refined
                  </div>
                </button>
              );
            })}
          </div>
        </section>
      )}
      <section className="grid lg:grid-cols-[380px_1fr] gap-6">
        <aside className="bg-white rounded-xl border border-slate-200 shadow-sm">
          <div className="p-3 border-b border-slate-100 space-y-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="search"
                placeholder="Search examples…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full text-sm pl-8 pr-2 py-1.5 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none"
                data-testid="forge-training-search"
              />
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <select value={caseFilter} onChange={(e) => setCaseFilter(e.target.value)} className="text-xs border border-slate-200 rounded px-2 py-1 bg-white flex-1 min-w-0" data-testid="forge-training-filter">
                <option value="">All case types</option>
                {CASE_TYPES.map((c) => <option key={c.key} value={c.key}>{c.label}</option>)}
              </select>
              <select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)} className="text-xs border border-slate-200 rounded px-2 py-1 bg-white" data-testid="forge-training-source-filter">
                <option value="">All sources</option>
                <option value="authored">Authored (admin)</option>
                <option value="refinement">Refinements (analyst)</option>
              </select>
              <button onClick={loadAll} className={`${btnCls} border-slate-200 text-slate-600 hover:border-slate-400`} data-testid="forge-training-refresh">
                <RefreshCw className="w-3 h-3" />
              </button>
            </div>
          </div>
          <ul className="max-h-[70vh] overflow-y-auto divide-y divide-slate-100">
            {examples.length === 0 && <li className="p-6 text-center text-xs text-slate-400">No examples yet.<br />Add your first past incident on the right.</li>}
            {examples.map((ex) => (
              <li key={ex.id}>
                <button
                  onClick={() => editExisting(ex)}
                  data-testid={`forge-training-item-${ex.id}`}
                  className={`w-full text-left px-3 py-2.5 hover:bg-slate-50 transition-colors ${selected === ex.id ? "bg-blue-50/60" : ""}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-slate-800 truncate">{ex.title || "Untitled"}</span>
                    {!ex.active && <span className="text-[9px] uppercase tracking-wide px-1 py-0.5 rounded bg-slate-100 text-slate-500 border border-slate-200">inactive</span>}
                  </div>
                  <div className="flex items-center gap-1 mt-0.5 flex-wrap">
                    <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">{ex.case_type}</span>
                    {ex.source === "refinement" ? (
                      <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-violet-50 text-violet-700 border border-violet-200 inline-flex items-center gap-0.5" title="Refined by analyst">
                        <GraduationCap className="w-2.5 h-2.5" /> Refinement
                      </span>
                    ) : (
                      <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200" title="Authored by admin">
                        Authored
                      </span>
                    )}
                    {(ex.attachments || []).length > 0 && (
                      <span className="text-[10px] text-slate-500 inline-flex items-center gap-0.5">
                        <FileText className="w-2.5 h-2.5" /> {ex.attachments.length}
                      </span>
                    )}
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </aside>

        <form onSubmit={submit} className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 space-y-4" data-testid="forge-training-form">
          <div className="flex items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-slate-800 flex items-center gap-2">
              {selected ? "Edit example" : "New example"}
              {selected && form.source === "refinement" && (
                <span className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded bg-violet-50 text-violet-700 border border-violet-200 inline-flex items-center gap-1" title={`Refined by ${form.created_by || "analyst"}`}>
                  <GraduationCap className="w-3 h-3" /> Refinement · {form.created_by || "analyst"}
                </span>
              )}
            </h2>
            <div className="flex items-center gap-1.5">
              {selected && form.source === "refinement" && (form.ai_original || "").trim() && (
                <button type="button" onClick={() => setShowDiff((v) => !v)} data-testid="forge-training-toggle-diff" className={`${btnCls} border-violet-300 text-violet-600 hover:bg-violet-50`}>
                  <GitCompare className="w-3.5 h-3.5" /> {showDiff ? "Hide diff" : "Diff vs AI original"}
                </button>
              )}
              {selected && (
                <button type="button" onClick={remove} className={`${btnCls} border-red-200 text-red-600 hover:bg-red-50`} data-testid="forge-training-delete">
                  <Trash2 className="w-3.5 h-3.5" /> Delete
                </button>
              )}
              {selected && !isEditing && (
                <button type="button" onClick={() => setIsEditing(true)} data-testid="forge-training-edit" className={`${btnCls} border-slate-300 text-slate-700 hover:border-[#2E7DF5] hover:text-[#2E7DF5]`}>
                  <Pencil className="w-3.5 h-3.5" /> Edit
                </button>
              )}
              {selected && isEditing && (
                <button type="button" onClick={cancelEdit} data-testid="forge-training-cancel-edit" className={`${btnCls} border-slate-300 text-slate-700 hover:border-slate-500`}>
                  <X className="w-3.5 h-3.5" /> Cancel
                </button>
              )}
              <button type="submit" disabled={busy || (selected && !isEditing)} className={`${btnCls} bg-[#2E7DF5] text-white border-[#2E7DF5] hover:bg-[#2563EB] disabled:opacity-40 disabled:cursor-not-allowed`} data-testid="forge-training-save">
                {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />} {selected ? "Update" : "Save"}
              </button>
            </div>
          </div>

          {/* Diff panel — only visible for refinements when the analyst has toggled it on */}
          {selected && showDiff && form.source === "refinement" && (form.ai_original || "").trim() && (
            <div data-testid="forge-training-diff-panel" className="grid md:grid-cols-2 gap-3 rounded-md border border-violet-200 bg-violet-50/40 p-3">
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wide text-violet-700 mb-1 flex items-center gap-1">
                  <Sparkles className="w-3 h-3" /> NivX Cognis AI original {form.ai_model && <span className="normal-case tracking-normal text-violet-600">· {form.ai_model}</span>}
                </div>
                <pre className="text-[11px] leading-relaxed text-slate-700 whitespace-pre-wrap bg-white border border-slate-200 rounded p-2 max-h-64 overflow-y-auto font-sans">{form.ai_original}</pre>
              </div>
              <div>
                <div className="text-[11px] font-semibold uppercase tracking-wide text-emerald-700 mb-1 flex items-center gap-1">
                  <GraduationCap className="w-3 h-3" /> Analyst refined
                </div>
                <pre className="text-[11px] leading-relaxed text-slate-900 whitespace-pre-wrap bg-white border border-emerald-200 rounded p-2 max-h-64 overflow-y-auto font-sans">{form.narrative}</pre>
              </div>
            </div>
          )}

          {selected && !isEditing && (
            <div className="rounded-md border border-slate-200 bg-slate-50/70 px-3 py-2 text-[11px] text-slate-500 flex items-center gap-2" data-testid="forge-training-viewmode-hint">
              <FileText className="w-3.5 h-3.5" />
              Viewing example — click <span className="font-semibold text-slate-700">Edit</span> above to modify fields.
            </div>
          )}

          <fieldset disabled={selected && !isEditing} className="contents">

          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-2">
              <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Title</label>
              <input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} required placeholder="e.g. XDR malicious file hash on user endpoint (July 2026)" className="w-full text-sm px-3 py-2 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none" data-testid="forge-training-title" />
            </div>
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Case type</label>
              <select value={form.case_type} onChange={(e) => setForm({ ...form, case_type: e.target.value })} className="w-full text-sm px-3 py-2 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none bg-white" data-testid="forge-training-case">
                {CASE_TYPES.map((c) => <option key={c.key} value={c.key}>{c.label}</option>)}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Tags (comma separated)</label>
            <input value={(form.tags || []).join(", ")} onChange={(e) => setForm({ ...form, tags: e.target.value.split(",").map((t) => t.trim()).filter(Boolean) })} placeholder="cisco-xdr, secure-endpoint, temp-directory, exploit-prevention" className="w-full text-sm px-3 py-2 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none font-mono-data" data-testid="forge-training-tags" />
          </div>

          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Alert / incident data (raw)</label>
            <textarea value={form.raw_data} onChange={(e) => setForm({ ...form, raw_data: e.target.value })} rows={7} placeholder="Paste the original SIEM / XDR / DNS-proxy log or alert body here." className="w-full text-sm px-3 py-2 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none font-mono-data text-slate-800" data-testid="forge-training-raw" />
          </div>

          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Analyst investigation summary / narrative</label>
            <textarea value={form.narrative} onChange={(e) => setForm({ ...form, narrative: e.target.value })} rows={8} placeholder="Write the ideal investigation report the way your SOC would deliver it to the customer. The NivX Cognis AI will match this tone and structure on future reports." className="w-full text-sm px-3 py-2 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none text-slate-800" data-testid="forge-training-narrative" />
          </div>

          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Recommendations (one per line)</label>
            <textarea value={(form.recommendations || []).join("\n")} onChange={(e) => setForm({ ...form, recommendations: e.target.value.split("\n") })} rows={5} placeholder="Isolate the affected endpoint for forensic analysis.&#10;Reset credentials for the compromised user account.&#10;Verify and update software whitelisting policies." className="w-full text-sm px-3 py-2 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none text-slate-800" data-testid="forge-training-recs" />
          </div>

          <div>
            <label className="block text-[11px] font-semibold uppercase tracking-wide text-slate-500 mb-1">Analyst notes (when to use this style)</label>
            <textarea value={form.analyst_notes} onChange={(e) => setForm({ ...form, analyst_notes: e.target.value })} rows={2} placeholder="Optional: 'Use for XDR EDR quarantine flows where Exploit Prevention blocked the payload.'" className="w-full text-sm px-3 py-2 border border-slate-200 rounded-md focus:border-[#2E7DF5] outline-none" data-testid="forge-training-notes" />
          </div>

          {/* Attachments */}
          <div className="border-t border-slate-100 pt-4">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
              <label className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">Attachments (any format — max 10 MB each)</label>
              <label className={`${btnCls} border-slate-300 text-slate-600 hover:border-[#2E7DF5] hover:text-[#2E7DF5] cursor-pointer ${!selected ? "opacity-40 cursor-not-allowed" : ""}`}>
                {uploading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
                Upload
                <input ref={fileRef} type="file" className="hidden" disabled={!selected || uploading} onChange={(e) => uploadAttachment(e.target.files?.[0])} data-testid="forge-training-attach-input" />
              </label>
            </div>
            {!selected && <p className="text-[11px] text-slate-400 italic mb-2">Save the example first, then attach files or screenshots.</p>}
            {selected && (form.attachments || []).length === 0 && <p className="text-[11px] text-slate-400 italic">No attachments yet.</p>}
            <ul className="grid grid-cols-2 gap-2">
              {(form.attachments || []).map((a) => (
                <li key={a.id} data-testid={`forge-training-att-${a.id}`} className="flex items-center gap-2 px-2 py-1.5 border border-slate-200 rounded-md text-xs bg-slate-50">
                  {a.kind === "image" ? <ImageIcon className="w-4 h-4 text-fuchsia-500" /> : <FileText className="w-4 h-4 text-slate-500" />}
                  <span className="truncate flex-1 text-slate-700" title={a.filename}>{a.filename}</span>
                  <span className="text-[10px] text-slate-400">{Math.ceil((a.size || 0) / 1024)} KB</span>
                  <button type="button" onClick={() => removeAttachment(a.id)} className="text-slate-400 hover:text-red-500 transition-colors" title="Remove">
                    <X className="w-3 h-3" />
                  </button>
                </li>
              ))}
            </ul>
          </div>

          <label className="inline-flex items-center gap-2 text-xs text-slate-600 cursor-pointer pt-2">
            <input type="checkbox" checked={form.active} onChange={(e) => setForm({ ...form, active: e.target.checked })} className="w-3.5 h-3.5 accent-[#2E7DF5]" data-testid="forge-training-active" />
            Active — retrieved as few-shot on new AI reports
          </label>
          </fieldset>
        </form>
      </section>
    </main>
  );
}
