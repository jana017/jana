/**
 * Modal for adding a session-scoped custom YARA-lite rule.
 */
import { useState } from "react";
import { toast } from "sonner";
import { X, Plus, Trash2 } from "lucide-react";
import { addSessionRule } from "@/lib/cyberlabApi";

const SEVERITIES = ["info", "low", "medium", "high", "critical"];

export default function CustomRuleModal({ open, onClose, onSaved }) {
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState("");
  const [strings, setStrings] = useState([{ type: "regex", pattern: "", flags: "i" }]);
  const [busy, setBusy] = useState(false);

  if (!open) return null;

  const updateString = (i, key, val) =>
    setStrings((s) => s.map((r, idx) => (idx === i ? { ...r, [key]: val } : r)));
  const addString = () => setStrings((s) => [...s, { type: "regex", pattern: "", flags: "i" }]);
  const removeString = (i) => setStrings((s) => s.filter((_, idx) => idx !== i));

  const save = async () => {
    if (!name.trim()) { toast.error("Rule name is required"); return; }
    const validStrings = strings.filter((s) => s.pattern.trim());
    if (validStrings.length === 0) { toast.error("Add at least one pattern"); return; }
    setBusy(true);
    try {
      await addSessionRule({
        name: name.trim(), severity, description: description.trim(),
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
        strings: validStrings,
      });
      toast.success(`Session rule "${name}" saved`);
      onSaved?.();
      onClose?.();
    } catch (e) {
      toast.error(`Save failed: ${e.message.slice(0, 100)}`);
    } finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}
      data-testid="custom-rule-modal">
      <div className="w-full max-w-xl rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-base font-semibold text-white">Add session custom rule</h3>
          <button data-testid="close-rule-modal" onClick={onClose} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="space-y-3">
          <div>
            <label className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-1 block">Rule name</label>
            <input data-testid="rule-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Emotet_Loader_v3"
              className="w-full font-mono text-xs bg-slate-950 border border-slate-800 rounded-md px-2 py-1.5 text-white outline-none focus:border-cyan-500/50" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-1 block">Severity</label>
              <select data-testid="rule-severity" value={severity} onChange={(e) => setSeverity(e.target.value)}
                className="w-full text-xs bg-slate-950 border border-slate-800 rounded-md px-2 py-1.5 text-white outline-none focus:border-cyan-500/50">
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-1 block">Tags (comma-sep)</label>
              <input data-testid="rule-tags" value={tags} onChange={(e) => setTags(e.target.value)} placeholder="apt29, loader"
                className="w-full text-xs bg-slate-950 border border-slate-800 rounded-md px-2 py-1.5 text-white outline-none focus:border-cyan-500/50" />
            </div>
          </div>
          <div>
            <label className="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-1 block">Description</label>
            <input data-testid="rule-description" value={description} onChange={(e) => setDescription(e.target.value)}
              placeholder="Detects the Emotet loader stage-1"
              className="w-full text-xs bg-slate-950 border border-slate-800 rounded-md px-2 py-1.5 text-white outline-none focus:border-cyan-500/50" />
          </div>
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-[10px] font-bold uppercase tracking-widest text-slate-400">Patterns</label>
              <button data-testid="add-pattern-btn" onClick={addString} className="text-[10px] text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1">
                <Plus className="w-3 h-3" /> Add pattern
              </button>
            </div>
            <div className="space-y-1.5">
              {strings.map((s, i) => (
                <div key={i} className="flex items-center gap-1.5" data-testid={`pattern-${i}`}>
                  <select value={s.type} onChange={(e) => updateString(i, "type", e.target.value)}
                    className="text-[11px] bg-slate-950 border border-slate-800 rounded px-1.5 py-1 text-slate-200 outline-none">
                    <option value="regex">regex</option>
                    <option value="string">string</option>
                    <option value="hex">hex</option>
                  </select>
                  <input value={s.pattern} onChange={(e) => updateString(i, "pattern", e.target.value)}
                    placeholder={s.type === "hex" ? "4D 5A ?? ??" : "Invoke-\\w+"}
                    className="flex-1 font-mono text-[11px] bg-slate-950 border border-slate-800 rounded px-2 py-1 text-cyan-200 outline-none focus:border-cyan-500/50" />
                  {s.type !== "hex" && (
                    <input value={s.flags || ""} onChange={(e) => updateString(i, "flags", e.target.value)}
                      placeholder="i" title="Flags (i=case-insensitive, s=dotall)"
                      className="w-10 text-[11px] font-mono bg-slate-950 border border-slate-800 rounded px-1.5 py-1 text-slate-200 outline-none" />
                  )}
                  {strings.length > 1 && (
                    <button onClick={() => removeString(i)} className="p-1 text-slate-400 hover:text-red-400"><Trash2 className="w-3 h-3" /></button>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-4 flex items-center justify-end gap-2">
          <button onClick={onClose} className="text-xs text-slate-400 hover:text-white px-3 py-1.5">Cancel</button>
          <button data-testid="save-rule-btn" onClick={save} disabled={busy}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-900 text-xs font-semibold disabled:opacity-50 transition-colors">
            <Plus className="w-3 h-3" /> Save rule
          </button>
        </div>
        <p className="mt-2 text-[10px] text-slate-500 italic">
          Session rules apply only to this browser (30 days). Admins can promote rules globally from the Admin panel.
        </p>
      </div>
    </div>
  );
}
