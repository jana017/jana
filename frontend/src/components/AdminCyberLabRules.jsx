/**
 * Admin panel: manage global CyberLab custom detection rules.
 * These are applied to every /api/cyberlab/analyze and auto-decode call
 * (in addition to the built-in 13 rules and per-session rules).
 */
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Bug, Plus, RefreshCw, Trash2, X } from "lucide-react";
import { authHeaders } from "@/lib/auth";

const API = process.env.REACT_APP_BACKEND_URL;
const SEVERITIES = ["info", "low", "medium", "high", "critical"];
const SEV_CHIP = {
  critical: "bg-red-100 text-red-700 border-red-200",
  high:     "bg-orange-100 text-orange-700 border-orange-200",
  medium:   "bg-yellow-100 text-yellow-700 border-yellow-200",
  low:      "bg-blue-100 text-blue-700 border-blue-200",
  info:     "bg-slate-100 text-slate-700 border-slate-200",
};

export default function AdminCyberLabRules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/admin/cyberlab/rules`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const d = await res.json();
      setRules(d.rules || []);
    } catch (e) {
      toast.error(`Load rules: ${e.message}`);
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const remove = async (id, name) => {
    if (!window.confirm(`Delete "${name}" globally?`)) return;
    try {
      const res = await fetch(`${API}/api/admin/cyberlab/rules/${id}`, {
        method: "DELETE", headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      toast.success("Rule deleted");
      load();
    } catch (e) { toast.error(e.message); }
  };

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-6" data-testid="admin-cyberlab-rules">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="font-heading text-lg font-semibold text-slate-900 flex items-center gap-2">
            <Bug className="w-4 h-4 text-fuchsia-500" /> CyberLab custom rules
          </h3>
          <p className="text-xs text-slate-500">
            Global YARA-lite detection rules applied to every CyberLab analysis (in addition to the 13 built-in rules).
          </p>
        </div>
        <button
          data-testid="admin-add-rule-btn"
          onClick={() => setShowForm(true)}
          className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-[#2E7DF5] hover:bg-[#2563EB] text-white text-sm font-semibold transition-colors"
        >
          <Plus className="w-4 h-4" /> Add rule
        </button>
      </div>

      {loading ? (
        <div className="text-sm text-slate-500 flex items-center gap-2 py-6"><RefreshCw className="w-4 h-4 animate-spin" /> Loading…</div>
      ) : rules.length === 0 ? (
        <div className="text-sm text-slate-500 italic py-8 text-center border border-dashed border-slate-200 rounded-md">
          No custom rules yet. Add one to detect internal threat patterns across every CyberLab analysis.
        </div>
      ) : (
        <div className="space-y-2">
          {rules.map((r) => (
            <div key={r.id} data-testid={`admin-rule-${r.id}`}
              className="flex items-start gap-3 rounded-md border border-slate-200 bg-slate-50 p-3 hover:border-slate-300 transition-colors">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-semibold text-slate-900 text-sm">{r.name}</span>
                  <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border ${SEV_CHIP[r.severity] || SEV_CHIP.medium}`}>{r.severity}</span>
                  {r.tags?.map((t) => (
                    <span key={t} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white border border-slate-200 text-slate-500">#{t}</span>
                  ))}
                </div>
                {r.description && <div className="text-xs text-slate-600 mb-1">{r.description}</div>}
                <div className="text-[10px] text-slate-500 font-mono">
                  {r.strings?.length || 0} pattern{(r.strings?.length || 0) === 1 ? "" : "s"} · author: {r.author} · added {r.created_at?.slice(0, 10)}
                </div>
              </div>
              <button
                data-testid={`admin-delete-rule-${r.id}`}
                onClick={() => remove(r.id, r.name)}
                className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded"
                title="Delete rule"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      )}

      {showForm && <AddRuleForm onClose={() => setShowForm(false)} onSaved={() => { setShowForm(false); load(); }} />}
    </div>
  );
}

function AddRuleForm({ onClose, onSaved }) {
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState("high");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("");
  const [strings, setStrings] = useState([{ type: "regex", pattern: "", flags: "i" }]);
  const [busy, setBusy] = useState(false);

  const updateString = (i, key, val) =>
    setStrings((s) => s.map((r, idx) => (idx === i ? { ...r, [key]: val } : r)));

  const save = async () => {
    if (!name.trim()) { toast.error("Rule name is required"); return; }
    const validStrings = strings.filter((s) => s.pattern.trim());
    if (validStrings.length === 0) { toast.error("Add at least one pattern"); return; }
    setBusy(true);
    try {
      const res = await fetch(`${API}/api/admin/cyberlab/rules`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders() },
        body: JSON.stringify({
          name: name.trim(), severity, description: description.trim(),
          tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
          strings: validStrings,
        }),
      });
      if (!res.ok) { const t = await res.text(); throw new Error(t); }
      toast.success(`Rule "${name}" added globally`);
      onSaved();
    } catch (e) {
      toast.error(`Save failed: ${e.message.slice(0, 100)}`);
    } finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/50 flex items-center justify-center p-4" onClick={onClose}
      data-testid="admin-rule-form">
      <div className="w-full max-w-xl rounded-xl bg-white p-6 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-base font-semibold text-slate-900">Add global CyberLab rule</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-900"><X className="w-4 h-4" /></button>
        </div>
        <div className="space-y-3">
          <div>
            <label className="text-xs font-semibold text-slate-600 mb-1 block">Rule name</label>
            <input data-testid="admin-rule-name" value={name} onChange={(e) => setName(e.target.value)}
              placeholder="Internal_Loader_Signature"
              className="w-full font-mono text-sm border border-slate-300 rounded-md px-3 py-2 outline-none focus:border-[#2E7DF5]" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-semibold text-slate-600 mb-1 block">Severity</label>
              <select data-testid="admin-rule-severity" value={severity} onChange={(e) => setSeverity(e.target.value)}
                className="w-full text-sm border border-slate-300 rounded-md px-3 py-2 outline-none focus:border-[#2E7DF5]">
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-600 mb-1 block">Tags (comma-sep)</label>
              <input data-testid="admin-rule-tags" value={tags} onChange={(e) => setTags(e.target.value)}
                placeholder="internal, loader"
                className="w-full text-sm border border-slate-300 rounded-md px-3 py-2 outline-none focus:border-[#2E7DF5]" />
            </div>
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-600 mb-1 block">Description</label>
            <input data-testid="admin-rule-description" value={description} onChange={(e) => setDescription(e.target.value)}
              placeholder="What does this detect?"
              className="w-full text-sm border border-slate-300 rounded-md px-3 py-2 outline-none focus:border-[#2E7DF5]" />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-600 mb-1 block">Patterns</label>
            <div className="space-y-1.5">
              {strings.map((s, i) => (
                <div key={i} className="flex items-center gap-1.5">
                  <select value={s.type} onChange={(e) => updateString(i, "type", e.target.value)}
                    className="text-xs border border-slate-300 rounded px-1.5 py-1.5 outline-none">
                    <option value="regex">regex</option>
                    <option value="string">string</option>
                    <option value="hex">hex</option>
                  </select>
                  <input value={s.pattern} onChange={(e) => updateString(i, "pattern", e.target.value)}
                    placeholder={s.type === "hex" ? "4D 5A ?? ??" : "Invoke-\\w+"}
                    className="flex-1 font-mono text-xs border border-slate-300 rounded px-2 py-1.5 text-slate-800 outline-none focus:border-[#2E7DF5]" />
                  {s.type !== "hex" && (
                    <input value={s.flags || ""} onChange={(e) => updateString(i, "flags", e.target.value)}
                      placeholder="i" title="Flags"
                      className="w-10 text-xs font-mono border border-slate-300 rounded px-1.5 py-1.5 outline-none" />
                  )}
                </div>
              ))}
              <button data-testid="admin-add-pattern-btn" onClick={() => setStrings((s) => [...s, { type: "regex", pattern: "", flags: "i" }])}
                className="text-xs text-[#2E7DF5] hover:text-[#2563EB] inline-flex items-center gap-1">
                <Plus className="w-3 h-3" /> Add pattern
              </button>
            </div>
          </div>
        </div>
        <div className="mt-4 flex items-center justify-end gap-2">
          <button onClick={onClose} className="text-sm text-slate-500 hover:text-slate-900 px-3 py-1.5">Cancel</button>
          <button data-testid="admin-save-rule-btn" onClick={save} disabled={busy}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-md bg-[#2E7DF5] hover:bg-[#2563EB] text-white text-sm font-semibold disabled:opacity-50 transition-colors">
            <Plus className="w-4 h-4" /> Save globally
          </button>
        </div>
      </div>
    </div>
  );
}
