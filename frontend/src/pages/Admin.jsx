import { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { LogOut, Plus, Pencil, Trash2, ArrowLeft, ShieldCheck } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";

const EMPTY = {
  title: "", summary: "", severity: "high", category: "Malware", threat_actor: "",
  image_url: "", attack_chain: "", iocs: "", process_tree: "", source: "NivX Threat Intel",
};

const inputCls =
  "w-full bg-white border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none px-3.5 py-2.5 text-sm text-slate-800 placeholder:text-slate-400 rounded-md transition-shadow";

function LoginView() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    const res = await login(email, password);
    setLoading(false);
    if (!res.ok) setError(res.error);
    else toast.success("Access granted");
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-6 bg-slate-50">
      <motion.form
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        onSubmit={submit}
        data-testid="admin-login-form"
        className="w-full max-w-md bg-white rounded-2xl border border-slate-200 shadow-lg p-8"
      >
        <div className="flex items-center gap-3 mb-6">
          <img src="/nivx-logo.webp" alt="NivX Machines" className="h-8 w-auto rounded-md" />
        </div>
        <h1 className="font-heading text-xl font-semibold text-slate-900 mb-1">Secure access</h1>
        <p className="text-sm text-slate-500 mb-6">Authorized personnel only</p>

        <label className="block text-sm font-medium text-slate-700 mb-1.5">Email</label>
        <input data-testid="login-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className={`${inputCls} mb-4`} placeholder="admin@nivxmachines.com" />

        <label className="block text-sm font-medium text-slate-700 mb-1.5">Password</label>
        <input data-testid="login-password" type="password" required value={password} onChange={(e) => setPassword(e.target.value)} className={`${inputCls} mb-5`} placeholder="••••••••" />

        {error && <div data-testid="login-error" className="text-sm text-red-600 mb-4">{error}</div>}

        <button data-testid="login-submit" disabled={loading} className="w-full inline-flex items-center justify-center gap-2 bg-[#2E7DF5] hover:bg-[#2563EB] text-white text-sm font-semibold py-2.5 rounded-md transition-colors disabled:opacity-60">
          <ShieldCheck className="w-4 h-4" /> {loading ? "Authenticating…" : "Sign in"}
        </button>
        <Link to="/" className="block text-center mt-5 text-sm text-slate-500 hover:text-slate-900 transition-colors">← Back to site</Link>
      </motion.form>
    </div>
  );
}

function toPayload(f) {
  let process_tree = null;
  if (f.process_tree?.trim()) {
    try { process_tree = JSON.parse(f.process_tree); } catch { throw new Error("Process Tree must be valid JSON"); }
  }
  return {
    title: f.title, summary: f.summary, severity: f.severity, category: f.category,
    threat_actor: f.threat_actor || null, image_url: f.image_url || null,
    attack_chain: f.attack_chain.split(",").map((s) => s.trim()).filter(Boolean),
    iocs: f.iocs.split(",").map((s) => s.trim()).filter(Boolean),
    process_tree, source: f.source || "NivX Threat Intel",
  };
}

function Dashboard() {
  const { user, logout } = useAuth();
  const [reports, setReports] = useState([]);
  const [form, setForm] = useState(EMPTY);
  const [editId, setEditId] = useState(null);

  const load = useCallback(() => {
    api.get("/threats").then(({ data }) => setReports(data)).catch(() => {});
  }, []);
  useEffect(() => { load(); }, [load]);

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const reset = () => { setForm(EMPTY); setEditId(null); };

  const submit = async (e) => {
    e.preventDefault();
    let payload;
    try { payload = toPayload(form); } catch (err) { toast.error(err.message); return; }
    try {
      if (editId) { await api.put(`/threats/${editId}`, payload); toast.success("Threat report updated"); }
      else { await api.post("/threats", payload); toast.success("Threat report published"); }
      reset(); load();
    } catch (err) { toast.error(err.response?.data?.detail || "Failed to save"); }
  };

  const edit = (r) => {
    setEditId(r.id);
    setForm({
      title: r.title, summary: r.summary, severity: r.severity, category: r.category,
      threat_actor: r.threat_actor || "", image_url: r.image_url || "",
      attack_chain: (r.attack_chain || []).join(", "), iocs: (r.iocs || []).join(", "),
      process_tree: r.process_tree ? JSON.stringify(r.process_tree, null, 2) : "",
      source: r.source || "NivX Threat Intel",
    });
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const remove = async (id) => {
    if (!window.confirm("Delete this threat report?")) return;
    await api.delete(`/threats/${id}`);
    toast.success("Deleted");
    load();
  };

  return (
    <div className="min-h-screen bg-slate-50" data-testid="admin-dashboard">
      <header className="bg-white border-b border-slate-200 sticky top-0 z-30">
        <div className="mx-auto max-w-7xl px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img src="/nivx-logo.webp" alt="NivX Machines" className="h-8 w-auto rounded-md" />
            <span className="text-sm text-slate-400 hidden sm:inline">{user?.email}</span>
          </div>
          <div className="flex items-center gap-5">
            <Link to="/" className="flex items-center gap-1.5 text-sm font-medium text-slate-600 hover:text-slate-900 transition-colors"><ArrowLeft className="w-4 h-4" /> Site</Link>
            <button data-testid="logout-btn" onClick={logout} className="flex items-center gap-1.5 text-sm font-medium text-red-600 hover:text-red-700 transition-colors"><LogOut className="w-4 h-4" /> Logout</button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-10 grid lg:grid-cols-[400px_1fr] gap-8">
        <form onSubmit={submit} data-testid="threat-form" className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 space-y-3.5 lg:sticky lg:top-24 self-start">
          <h2 className="font-heading text-lg font-semibold text-slate-900">{editId ? "Edit threat report" : "New threat report"}</h2>
          <input data-testid="form-title" required placeholder="Title" value={form.title} onChange={set("title")} className={inputCls} />
          <textarea data-testid="form-summary" required placeholder="Summary" value={form.summary} onChange={set("summary")} rows={3} className={inputCls} />
          <div className="grid grid-cols-2 gap-3">
            <select data-testid="form-severity" value={form.severity} onChange={set("severity")} className={inputCls}>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
            <input data-testid="form-category" placeholder="Category" value={form.category} onChange={set("category")} className={inputCls} />
          </div>
          <input data-testid="form-actor" placeholder="Threat actor (optional)" value={form.threat_actor} onChange={set("threat_actor")} className={inputCls} />
          <input data-testid="form-image" placeholder="Image URL (optional)" value={form.image_url} onChange={set("image_url")} className={inputCls} />
          <input data-testid="form-chain" placeholder="Attack chain (comma separated)" value={form.attack_chain} onChange={set("attack_chain")} className={inputCls} />
          <input data-testid="form-iocs" placeholder="IOCs (comma separated)" value={form.iocs} onChange={set("iocs")} className={inputCls} />
          <textarea data-testid="form-tree" placeholder="Process tree JSON (optional)" value={form.process_tree} onChange={set("process_tree")} rows={4} className={`${inputCls} font-mono-data text-xs`} />
          <div className="flex gap-2 pt-1">
            <button data-testid="form-submit" type="submit" className="flex-1 inline-flex items-center justify-center gap-2 bg-[#2E7DF5] hover:bg-[#2563EB] text-white text-sm font-semibold py-2.5 rounded-md transition-colors">
              <Plus className="w-4 h-4" /> {editId ? "Update" : "Publish"}
            </button>
            {editId && <button type="button" onClick={reset} className="px-4 border border-slate-300 text-slate-600 text-sm font-medium rounded-md hover:bg-slate-50 transition-colors">Cancel</button>}
          </div>
        </form>

        <div>
          <h2 className="font-heading text-lg font-semibold text-slate-900 mb-4">Published reports <span className="text-sm text-slate-400 font-normal">({reports.length})</span></h2>
          <div className="space-y-3">
            {reports.map((r, i) => (
              <div key={r.id} data-testid={`admin-report-${i}`} className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] font-semibold uppercase tracking-wide text-blue-700 bg-blue-50 border border-blue-200 px-1.5 py-0.5 rounded">{r.severity}</span>
                    <span className="text-xs text-slate-400">{r.category}</span>
                  </div>
                  <h3 className="font-heading font-semibold text-slate-900 truncate">{r.title}</h3>
                  <p className="text-sm text-slate-500 line-clamp-1">{r.summary}</p>
                </div>
                <div className="flex gap-2 shrink-0">
                  <button data-testid={`edit-${i}`} onClick={() => edit(r)} className="w-9 h-9 flex items-center justify-center rounded-md border border-slate-200 text-slate-500 hover:text-[#2E7DF5] hover:border-blue-200 transition-colors"><Pencil className="w-4 h-4" /></button>
                  <button data-testid={`delete-${i}`} onClick={() => remove(r.id)} className="w-9 h-9 flex items-center justify-center rounded-md border border-slate-200 text-slate-500 hover:text-red-600 hover:border-red-200 transition-colors"><Trash2 className="w-4 h-4" /></button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}

export default function Admin() {
  const { user } = useAuth();
  if (user === null) return <div className="min-h-screen flex items-center justify-center text-slate-400 text-sm bg-slate-50">Loading…</div>;
  return user ? <Dashboard /> : <LoginView />;
}
