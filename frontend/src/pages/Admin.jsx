import { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { LogOut, Plus, Pencil, Trash2, ArrowLeft, ShieldCheck, Download, LayoutDashboard, Settings } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";
import useSeo from "@/lib/useSeo";
import SocDashboard from "@/components/SocDashboard";
import AdminSettings from "@/components/AdminSettings";
import AdminCyberLabRules from "@/components/AdminCyberLabRules";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

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
          <img src="/nivx-logo-light.png" alt="NivX Machines" className="h-8 w-auto object-contain" />
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
  const [deleteId, setDeleteId] = useState(null);
  const [view, setView] = useState("overview");
  const [leads, setLeads] = useState([]);
  const [statusFilter, setStatusFilter] = useState("all");

  const load = useCallback(() => {
    api.get("/threats").then(({ data }) => setReports(data)).catch(() => {});
  }, []);
  const loadLeads = useCallback(() => {
    api.get("/leads").then(({ data }) => setLeads(data)).catch(() => {});
  }, []);
  useEffect(() => { load(); loadLeads(); }, [load, loadLeads]);
  useEffect(() => {
    const h = (e) => { if (e.detail) setView(e.detail); };
    window.addEventListener("nivx-admin-goto", h);
    return () => window.removeEventListener("nivx-admin-goto", h);
  }, []);

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

  const remove = async () => {
    if (!deleteId) return;
    await api.delete(`/threats/${deleteId}`);
    setDeleteId(null);
    toast.success("Deleted");
    load();
  };

  const setLeadStatus = async (id, status) => {
    try {
      await api.patch(`/leads/${id}`, { status });
      setLeads((prev) => prev.map((l) => (l.id === id ? { ...l, status } : l)));
      toast.success(`Marked ${status}`);
    } catch {
      toast.error("Failed to update status");
    }
  };

  const updateLeadField = async (id, field, value) => {
    setLeads((prev) => prev.map((l) => (l.id === id ? { ...l, [field]: value } : l)));
    try {
      await api.patch(`/leads/${id}`, { [field]: value });
    } catch {
      toast.error(`Failed to save ${field}`);
    }
  };

  const filteredLeads = statusFilter === "all" ? leads : leads.filter((l) => l.status === statusFilter);

  const exportLeadsCsv = () => {
    if (!leads.length) return;
    const cols = ["name", "email", "phone", "company", "company_size", "interest", "status", "assignee", "notes", "created_at", "message"];
    const esc = (v) => {
      let s = String(v ?? "");
      if (/^[=+\-@]/.test(s)) s = "'" + s; // guard against CSV injection
      return `"${s.replace(/"/g, '""')}"`;
    };
    const rows = [cols.join(",")].concat(leads.map((l) => cols.map((c) => esc(l[c])).join(",")));
    const blob = new Blob([rows.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nivx-leads-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-slate-50" data-testid="admin-dashboard">
      <header className="bg-white border-b border-slate-200 sticky top-0 z-30">
        <div className="mx-auto max-w-7xl px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img src="/nivx-logo-light.png" alt="NivX Machines" className="h-8 w-auto object-contain" />
            <span className="text-sm text-slate-400 hidden sm:inline">{user?.email}</span>
          </div>
          <div className="flex items-center gap-5">
            <Link to="/" className="flex items-center gap-1.5 text-sm font-medium text-slate-600 hover:text-slate-900 transition-colors"><ArrowLeft className="w-4 h-4" /> Site</Link>
            <button data-testid="logout-btn" onClick={logout} className="flex items-center gap-1.5 text-sm font-medium text-red-600 hover:text-red-700 transition-colors"><LogOut className="w-4 h-4" /> Logout</button>
          </div>
        </div>
      </header>

      <div className="bg-white border-b border-slate-200">
        <div className="mx-auto max-w-7xl px-6 flex gap-1">
          <button
            data-testid="tab-overview"
            onClick={() => setView("overview")}
            className={`px-4 py-3 text-sm font-semibold border-b-2 transition-colors flex items-center gap-1.5 ${view === "overview" ? "border-[#2E7DF5] text-[#2E7DF5]" : "border-transparent text-slate-500 hover:text-slate-800"}`}
          >
            <LayoutDashboard className="w-4 h-4" /> Overview
          </button>
          <button
            data-testid="tab-reports"
            onClick={() => setView("reports")}
            className={`px-4 py-3 text-sm font-semibold border-b-2 transition-colors ${view === "reports" ? "border-[#2E7DF5] text-[#2E7DF5]" : "border-transparent text-slate-500 hover:text-slate-800"}`}
          >
            Threat Reports <span className="text-xs font-normal">({reports.length})</span>
          </button>
          <button
            data-testid="tab-leads"
            onClick={() => setView("leads")}
            className={`px-4 py-3 text-sm font-semibold border-b-2 transition-colors ${view === "leads" ? "border-[#2E7DF5] text-[#2E7DF5]" : "border-transparent text-slate-500 hover:text-slate-800"}`}
          >
            Leads <span className="text-xs font-normal">({leads.length})</span>
          </button>
          <button
            data-testid="tab-settings"
            onClick={() => setView("settings")}
            className={`px-4 py-3 text-sm font-semibold border-b-2 transition-colors flex items-center gap-1.5 ${view === "settings" ? "border-[#2E7DF5] text-[#2E7DF5]" : "border-transparent text-slate-500 hover:text-slate-800"}`}
          >
            <Settings className="w-4 h-4" /> Settings
          </button>
          <button
            data-testid="tab-cyberlab-rules"
            onClick={() => setView("cyberlab-rules")}
            className={`px-4 py-3 text-sm font-semibold border-b-2 transition-colors ${view === "cyberlab-rules" ? "border-[#2E7DF5] text-[#2E7DF5]" : "border-transparent text-slate-500 hover:text-slate-800"}`}
          >
            NivX Forge Rules
          </button>
        </div>
      </div>

      {view === "overview" ? (
        <SocDashboard />
      ) : view === "settings" ? (
        <AdminSettings />
      ) : view === "cyberlab-rules" ? (
        <main className="mx-auto max-w-7xl px-6 py-10">
          <AdminCyberLabRules />
        </main>
      ) : view === "reports" ? (
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
                  <button data-testid={`delete-${i}`} onClick={() => setDeleteId(r.id)} className="w-9 h-9 flex items-center justify-center rounded-md border border-slate-200 text-slate-500 hover:text-red-600 hover:border-red-200 transition-colors"><Trash2 className="w-4 h-4" /></button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
      ) : (
      <main className="mx-auto max-w-7xl px-6 py-10" data-testid="leads-view">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <h2 className="font-heading text-lg font-semibold text-slate-900">
            Security assessment requests <span className="text-sm text-slate-400 font-normal">({filteredLeads.length}{statusFilter !== "all" ? ` of ${leads.length}` : ""})</span>
          </h2>
          <div className="flex items-center gap-2">
            <select
              data-testid="lead-status-filter"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="text-sm border border-slate-300 rounded-md px-3 py-2 bg-white outline-none focus:border-[#2E7DF5]"
            >
              <option value="all">All statuses</option>
              <option value="new">New</option>
              <option value="contacted">Contacted</option>
              <option value="qualified">Qualified</option>
              <option value="archived">Archived</option>
            </select>
            <button
              data-testid="export-csv"
              onClick={exportLeadsCsv}
              disabled={!leads.length}
              className="inline-flex items-center gap-2 border border-slate-300 hover:border-[#2E7DF5] hover:text-[#2E7DF5] text-slate-700 text-sm font-semibold px-4 py-2 rounded-md transition-colors disabled:opacity-50"
            >
              <Download className="w-4 h-4" /> Export CSV
            </button>
          </div>
        </div>
        {filteredLeads.length === 0 ? (
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-10 text-center text-sm text-slate-500" data-testid="leads-empty">
            {leads.length === 0 ? "No leads yet. Submissions from the “Request a Security Assessment” form appear here." : "No leads match this status filter."}
          </div>
        ) : (
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-slate-50 text-left text-xs font-semibold uppercase tracking-wide text-slate-500">
                    <th className="px-4 py-3">Name</th>
                    <th className="px-4 py-3">Contact</th>
                    <th className="px-4 py-3">Company</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Assignee</th>
                    <th className="px-4 py-3">Notes</th>
                    <th className="px-4 py-3">Received</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredLeads.map((l, i) => (
                    <tr key={l.id} data-testid={`lead-row-${i}`} className="hover:bg-slate-50 align-top">
                      <td className="px-4 py-3">
                        <div className="font-semibold text-slate-900">{l.name}</div>
                        {l.company_size && <div className="text-xs text-slate-400">{l.company_size} employees</div>}
                        {l.interest && <div className="text-xs text-slate-400">{l.interest}</div>}
                      </td>
                      <td className="px-4 py-3">
                        <a href={`mailto:${l.email}`} className="text-[#2E7DF5] hover:underline block">{l.email}</a>
                        {l.phone && <div className="text-xs text-slate-500">{l.phone}</div>}
                      </td>
                      <td className="px-4 py-3 text-slate-700">{l.company || "—"}</td>
                      <td className="px-4 py-3">
                        <select
                          data-testid={`lead-status-${i}`}
                          value={l.status}
                          onChange={(e) => setLeadStatus(l.id, e.target.value)}
                          className={`text-xs font-semibold rounded-md border px-2 py-1.5 outline-none focus:border-[#2E7DF5] ${
                            l.status === "qualified" ? "bg-green-50 text-green-700 border-green-200"
                            : l.status === "contacted" ? "bg-blue-50 text-blue-700 border-blue-200"
                            : l.status === "archived" ? "bg-slate-100 text-slate-500 border-slate-200"
                            : "bg-orange-50 text-orange-700 border-orange-200"
                          }`}
                        >
                          <option value="new">New</option>
                          <option value="contacted">Contacted</option>
                          <option value="qualified">Qualified</option>
                          <option value="archived">Archived</option>
                        </select>
                      </td>
                      <td className="px-4 py-3">
                        <input
                          data-testid={`lead-assignee-${i}`}
                          defaultValue={l.assignee || ""}
                          placeholder="Unassigned"
                          onBlur={(e) => { if (e.target.value !== (l.assignee || "")) updateLeadField(l.id, "assignee", e.target.value); }}
                          className="w-28 text-xs border border-slate-200 rounded-md px-2 py-1.5 outline-none focus:border-[#2E7DF5]"
                        />
                      </td>
                      <td className="px-4 py-3">
                        <textarea
                          data-testid={`lead-notes-${i}`}
                          defaultValue={l.notes || ""}
                          placeholder="Add a note…"
                          rows={2}
                          onBlur={(e) => { if (e.target.value !== (l.notes || "")) updateLeadField(l.id, "notes", e.target.value); }}
                          className="w-48 text-xs border border-slate-200 rounded-md px-2 py-1.5 outline-none focus:border-[#2E7DF5] resize-y"
                        />
                        {l.message && <div className="text-[11px] text-slate-400 mt-1 max-w-[12rem] truncate" title={l.message}>“{l.message}”</div>}
                      </td>
                      <td className="px-4 py-3 text-slate-500 whitespace-nowrap">{new Date(l.created_at).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
      )}

      <AlertDialog open={!!deleteId} onOpenChange={(o) => !o && setDeleteId(null)}>
        <AlertDialogContent data-testid="delete-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete threat report?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. The report will be permanently removed from the live site.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel data-testid="delete-cancel">Cancel</AlertDialogCancel>
            <AlertDialogAction data-testid="delete-confirm" onClick={remove} className="bg-red-600 hover:bg-red-700">
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

export default function Admin() {
  useSeo({
    title: "Admin · NivX Machines",
    description: "NivX Machines admin console. Manage threat reports, leads and the curated IOC database.",
    noindex: true,
  });
  const { user } = useAuth();
  if (user === null) return <div className="min-h-screen flex items-center justify-center text-slate-400 text-sm bg-slate-50">Loading…</div>;
  return user ? <Dashboard /> : <LoginView />;
}
