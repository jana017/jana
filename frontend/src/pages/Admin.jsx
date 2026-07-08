import { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { LogOut, Plus, Pencil, Trash2, ShieldHalf, ArrowLeft } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";

const EMPTY = {
  title: "",
  summary: "",
  severity: "high",
  category: "Malware",
  threat_actor: "",
  image_url: "",
  attack_chain: "",
  iocs: "",
  process_tree: "",
  source: "NivX Threat Intel",
};

const inputCls =
  "w-full bg-black/40 border border-white/10 focus:border-[#00F0FF] outline-none px-4 py-3 font-mono-data text-sm text-white placeholder:text-[#66666E] transition-colors";

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
    <div className="min-h-screen flex items-center justify-center px-6">
      <div className="absolute inset-0 hero-grid-bg" aria-hidden="true" />
      <motion.form
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        onSubmit={submit}
        data-testid="admin-login-form"
        className="relative glass w-full max-w-md p-10"
      >
        <div className="flex items-center gap-2 mb-8">
          <ShieldHalf className="w-6 h-6 text-[#00F0FF]" strokeWidth={1.5} />
          <span className="font-display font-black tracking-tighter text-white">NIVX<span className="text-[#00F0FF]">.</span>ADMIN</span>
        </div>
        <h1 className="font-display font-black text-2xl text-white mb-2 tracking-tight">Secure Access</h1>
        <p className="font-mono-data text-[11px] uppercase tracking-widest text-[#66666E] mb-8">Authorized personnel only</p>

        <label className="block font-mono-data text-[10px] uppercase tracking-widest text-[#A1A1A5] mb-2">Email</label>
        <input data-testid="login-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className={`${inputCls} mb-4`} placeholder="admin@nivxmachines.com" />

        <label className="block font-mono-data text-[10px] uppercase tracking-widest text-[#A1A1A5] mb-2">Password</label>
        <input data-testid="login-password" type="password" required value={password} onChange={(e) => setPassword(e.target.value)} className={`${inputCls} mb-6`} placeholder="••••••••" />

        {error && <div data-testid="login-error" className="font-mono-data text-[12px] text-[#FF0055] mb-4">{error}</div>}

        <button data-testid="login-submit" disabled={loading} className="w-full border border-[#00F0FF] text-[#00F0FF] py-3 font-mono-data text-[12px] uppercase tracking-widest hover:bg-[#00F0FF] hover:text-black transition-colors disabled:opacity-50">
          {loading ? "Authenticating…" : "Enter"}
        </button>
        <Link to="/" className="block text-center mt-6 font-mono-data text-[11px] uppercase tracking-widest text-[#66666E] hover:text-white transition-colors">
          ← Back to site
        </Link>
      </motion.form>
    </div>
  );
}

function toPayload(f) {
  let process_tree = null;
  if (f.process_tree?.trim()) {
    try {
      process_tree = JSON.parse(f.process_tree);
    } catch {
      throw new Error("Process Tree must be valid JSON");
    }
  }
  return {
    title: f.title,
    summary: f.summary,
    severity: f.severity,
    category: f.category,
    threat_actor: f.threat_actor || null,
    image_url: f.image_url || null,
    attack_chain: f.attack_chain.split(",").map((s) => s.trim()).filter(Boolean),
    iocs: f.iocs.split(",").map((s) => s.trim()).filter(Boolean),
    process_tree,
    source: f.source || "NivX Threat Intel",
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
      if (editId) {
        await api.put(`/threats/${editId}`, payload);
        toast.success("Threat report updated");
      } else {
        await api.post("/threats", payload);
        toast.success("Threat report published");
      }
      reset();
      load();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Failed to save");
    }
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
    <div className="min-h-screen" data-testid="admin-dashboard">
      <header className="glass border-b sticky top-0 z-30">
        <div className="mx-auto max-w-[1400px] px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ShieldHalf className="w-5 h-5 text-[#00F0FF]" strokeWidth={1.5} />
            <span className="font-display font-black tracking-tighter text-white text-sm">NIVX<span className="text-[#00F0FF]">.</span>ADMIN</span>
            <span className="font-mono-data text-[10px] text-[#66666E] uppercase tracking-widest ml-2">{user?.email}</span>
          </div>
          <div className="flex items-center gap-5">
            <Link to="/" className="flex items-center gap-1.5 font-mono-data text-[11px] uppercase tracking-widest text-[#A1A1A5] hover:text-white transition-colors">
              <ArrowLeft className="w-3.5 h-3.5" /> Site
            </Link>
            <button data-testid="logout-btn" onClick={logout} className="flex items-center gap-1.5 font-mono-data text-[11px] uppercase tracking-widest text-[#FF0055] hover:text-white transition-colors">
              <LogOut className="w-3.5 h-3.5" /> Logout
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1400px] px-6 py-12 grid lg:grid-cols-[420px_1fr] gap-10">
        <form onSubmit={submit} data-testid="threat-form" className="space-y-4 lg:sticky lg:top-24 self-start">
          <h2 className="font-display font-black text-xl text-white tracking-tight">
            {editId ? "Edit Threat Report" : "New Threat Report"}
          </h2>
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
          <input data-testid="form-actor" placeholder="Threat Actor (optional)" value={form.threat_actor} onChange={set("threat_actor")} className={inputCls} />
          <input data-testid="form-image" placeholder="Image URL (optional)" value={form.image_url} onChange={set("image_url")} className={inputCls} />
          <input data-testid="form-chain" placeholder="Attack chain (comma separated)" value={form.attack_chain} onChange={set("attack_chain")} className={inputCls} />
          <input data-testid="form-iocs" placeholder="IOCs (comma separated)" value={form.iocs} onChange={set("iocs")} className={inputCls} />
          <textarea data-testid="form-tree" placeholder='Process tree JSON (optional)' value={form.process_tree} onChange={set("process_tree")} rows={4} className={`${inputCls} text-[11px]`} />
          <div className="flex gap-3">
            <button data-testid="form-submit" type="submit" className="flex-1 flex items-center justify-center gap-2 border border-[#00F0FF] text-[#00F0FF] py-3 font-mono-data text-[11px] uppercase tracking-widest hover:bg-[#00F0FF] hover:text-black transition-colors">
              <Plus className="w-4 h-4" /> {editId ? "Update" : "Publish"}
            </button>
            {editId && (
              <button type="button" onClick={reset} className="px-4 border border-white/15 text-[#A1A1A5] font-mono-data text-[11px] uppercase tracking-widest hover:text-white transition-colors">
                Cancel
              </button>
            )}
          </div>
        </form>

        <div className="space-y-3">
          <h2 className="font-display font-black text-xl text-white tracking-tight mb-4">
            Published Reports <span className="text-[#66666E] text-sm font-mono-data">({reports.length})</span>
          </h2>
          {reports.map((r, i) => (
            <div key={r.id} data-testid={`admin-report-${i}`} className="glass p-5 flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono-data text-[9px] uppercase tracking-widest text-[#00F0FF] border border-[#00F0FF]/30 px-1.5 py-0.5">{r.severity}</span>
                  <span className="font-mono-data text-[10px] text-[#66666E] uppercase tracking-widest">{r.category}</span>
                </div>
                <h3 className="font-display font-semibold text-white truncate">{r.title}</h3>
                <p className="text-sm text-[#A1A1A5] line-clamp-1">{r.summary}</p>
              </div>
              <div className="flex gap-2 shrink-0">
                <button data-testid={`edit-${i}`} onClick={() => edit(r)} className="w-9 h-9 flex items-center justify-center border border-white/10 text-[#A1A1A5] hover:text-[#00F0FF] hover:border-[#00F0FF]/40 transition-colors">
                  <Pencil className="w-4 h-4" />
                </button>
                <button data-testid={`delete-${i}`} onClick={() => remove(r.id)} className="w-9 h-9 flex items-center justify-center border border-white/10 text-[#A1A1A5] hover:text-[#FF0055] hover:border-[#FF0055]/40 transition-colors">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}

export default function Admin() {
  const { user } = useAuth();
  if (user === null)
    return <div className="min-h-screen flex items-center justify-center font-mono-data text-[#66666E] text-sm">Loading…</div>;
  return user ? <Dashboard /> : <LoginView />;
}
