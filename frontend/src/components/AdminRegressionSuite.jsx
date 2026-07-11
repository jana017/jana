/**
 * AdminRegressionSuite — admin-editable list of golden decoder samples that
 * NivX HealthBot's `decoder_coverage` check runs on every scan.
 *
 * Analysts paste real-world malware payloads they've triaged and pin the
 * substring they expect the auto-decoder to eventually produce (e.g.
 * "import os" or "powershell -e"). If the plugin engine ever regresses on
 * that class, HealthBot lights up red before the next deploy.
 *
 * Zero external deps, all local — matches the offline-first design.
 */
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Beaker, Plus, Trash2, Loader2, Power } from "lucide-react";
import { api } from "@/lib/api";

export default function AdminRegressionSuite() {
  const [samples, setSamples] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ label: "", input: "", must_decode_to_contain: "" });

  const load = async () => {
    setLoading(true);
    try {
      const { data } = await api.get("/healthbot/regression-samples");
      setSamples(data || []);
    } catch (e) {
      toast.error("Failed to load regression samples");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const save = async (e) => {
    e.preventDefault();
    const input = form.input.trim();
    const needle = form.must_decode_to_contain.trim();
    if (!input || !needle) {
      toast.error("Both `Payload` and `Must decode to contain` are required.");
      return;
    }
    setSaving(true);
    try {
      await api.post("/healthbot/regression-samples", {
        label: form.label.trim() || null,
        input,
        must_decode_to_contain: needle,
      });
      toast.success("Sample added — will run on next HealthBot scan");
      setForm({ label: "", input: "", must_decode_to_contain: "" });
      setShowAdd(false);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to save sample");
    } finally {
      setSaving(false);
    }
  };

  const remove = async (id) => {
    if (!window.confirm("Delete this sample from the regression suite?")) return;
    try {
      await api.delete(`/healthbot/regression-samples/${encodeURIComponent(id)}`);
      toast.success("Deleted");
      load();
    } catch {
      toast.error("Failed to delete");
    }
  };

  const toggle = async (id) => {
    try {
      await api.post(`/healthbot/regression-samples/${encodeURIComponent(id)}/toggle`);
      load();
    } catch {
      toast.error("Failed to toggle");
    }
  };

  return (
    <section className="rounded-xl border border-slate-200 bg-white overflow-hidden" data-testid="admin-regression-suite">
      <div className="px-5 py-3 border-b border-slate-100 flex items-center justify-between gap-4">
        <div>
          <div className="text-sm font-bold text-slate-900 flex items-center gap-2">
            <Beaker className="w-4 h-4 text-fuchsia-500" /> Regression Suite
          </div>
          <div className="text-xs text-slate-500 mt-0.5">
            Custom golden payloads pinned by analysts. HealthBot&apos;s <code className="bg-slate-100 px-1 rounded">decoder_coverage</code> check runs these on every scan — if the NivX Forge auto-decoder ever regresses, this panel goes red before deploy.
          </div>
        </div>
        <button
          onClick={() => setShowAdd((s) => !s)}
          data-testid="regression-add-btn"
          className="shrink-0 inline-flex items-center gap-1.5 text-sm font-semibold text-[#2E7DF5] hover:text-[#1E5FCC]"
        >
          <Plus className="w-4 h-4" /> Add sample
        </button>
      </div>

      {showAdd && (
        <form onSubmit={save} className="px-5 py-4 border-b border-slate-100 space-y-3 bg-slate-50/50" data-testid="regression-add-form">
          <div>
            <label className="text-xs font-semibold text-slate-600 mb-1 block">Label (optional)</label>
            <input
              value={form.label}
              onChange={(e) => setForm({ ...form, label: e.target.value })}
              placeholder="e.g. Nobelium DUKES Python loader (Feb 2026 incident)"
              className="w-full px-3 py-1.5 text-sm border border-slate-300 rounded-md focus:outline-none focus:border-[#2E7DF5]"
              data-testid="regression-label"
            />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-600 mb-1 block">
              Payload (paste the raw obfuscated commandline / script)
            </label>
            <textarea
              value={form.input}
              onChange={(e) => setForm({ ...form, input: e.target.value })}
              rows={5}
              placeholder="-c exec(__import__('base64').b64decode(b'aW1wb3J0IG9zLHN5cwo=').decode())"
              className="w-full px-3 py-2 text-xs font-mono border border-slate-300 rounded-md focus:outline-none focus:border-[#2E7DF5]"
              required
              data-testid="regression-input"
            />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-600 mb-1 block">
              Must decode to contain (substring HealthBot expects to find in the decoded output)
            </label>
            <input
              value={form.must_decode_to_contain}
              onChange={(e) => setForm({ ...form, must_decode_to_contain: e.target.value })}
              placeholder="import os"
              className="w-full px-3 py-1.5 text-sm border border-slate-300 rounded-md focus:outline-none focus:border-[#2E7DF5]"
              required
              data-testid="regression-needle"
            />
          </div>
          <div className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => { setShowAdd(false); setForm({ label: "", input: "", must_decode_to_contain: "" }); }}
              className="text-xs font-semibold text-slate-500 hover:text-slate-800 px-3 py-1.5"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              data-testid="regression-save"
              className="inline-flex items-center gap-1.5 bg-[#2E7DF5] hover:bg-[#1E5FCC] text-white text-sm font-semibold px-3 py-1.5 rounded-md disabled:opacity-50"
            >
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
              Save sample
            </button>
          </div>
        </form>
      )}

      <div className="divide-y divide-slate-100">
        {loading ? (
          <div className="p-5 text-sm text-slate-400 flex items-center gap-2">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading…
          </div>
        ) : samples.length === 0 ? (
          <div className="p-8 text-sm text-slate-400 text-center">
            No custom samples yet. HealthBot still runs its 5 built-in golden payloads. Click <strong>Add sample</strong> to pin a new one.
          </div>
        ) : (
          samples.map((s) => (
            <div key={s.id} className="p-4 flex items-start gap-3" data-testid={`regression-row-${s.id}`}>
              <button
                onClick={() => toggle(s.id)}
                title={s.enabled ? "Disable — HealthBot will skip this sample" : "Enable"}
                className={`shrink-0 w-7 h-7 rounded flex items-center justify-center transition-colors ${s.enabled ? "bg-emerald-100 text-emerald-700 hover:bg-emerald-200" : "bg-slate-100 text-slate-400 hover:bg-slate-200"}`}
                data-testid={`regression-toggle-${s.id}`}
              >
                <Power className="w-3.5 h-3.5" />
              </button>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold text-slate-800 truncate">{s.label || s.id}</div>
                <div className="text-[11px] font-mono text-slate-500 truncate mt-0.5" title={s.input}>
                  {s.input.slice(0, 140)}{s.input.length > 140 ? "…" : ""}
                </div>
                <div className="text-[11px] text-slate-500 mt-1">
                  Expected substring: <span className="font-mono bg-slate-100 px-1 rounded text-slate-700">{s.must_decode_to_contain}</span>
                  {s.created_by && <span className="ml-2 text-slate-400">by {s.created_by}</span>}
                </div>
              </div>
              <button
                onClick={() => remove(s.id)}
                className="shrink-0 text-slate-400 hover:text-red-600 transition-colors"
                data-testid={`regression-delete-${s.id}`}
                aria-label="Delete"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
