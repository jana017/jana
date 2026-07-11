/**
 * EmployeePortal — logged-in employee's self-service page.
 * Features (Phase 1):
 *   - View profile card
 *   - Force-change password on first login (`must_change_password`)
 *   - Upload / list / download / delete own documents (10 categories)
 *   - Storage meter (used / max)
 *
 * Ticketing (Phase 2) will land here as a second sidebar section later.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "@/lib/api";
import { getToken, setToken, clearToken } from "@/lib/auth";
import { toast } from "sonner";
import {
  User, LogOut, FileText, Upload, Download, Trash2, KeyRound,
  Shield, Loader2, HardDrive, CheckCircle2, Plus, Ticket,
} from "lucide-react";
import useSeo from "@/lib/useSeo";
import { NewTicketModal, TicketDetail, TicketRow } from "@/components/TicketWidgets";

const DOC_TYPES = [
  { id: "payslip",           label: "Payslip" },
  { id: "pf_details",        label: "PF Details" },
  { id: "ff_settlement",     label: "F&F Settlement" },
  { id: "id_card",           label: "Company ID Card" },
  { id: "offer_letter",      label: "Offer Letter" },
  { id: "hike_letter",       label: "Hike Letter" },
  { id: "experience_letter", label: "Experience Letter" },
  { id: "relieving_letter",  label: "Relieving Letter" },
  { id: "appraisal_letter",  label: "Appraisal Letter" },
  { id: "tax_form",          label: "Tax Form" },
  { id: "other",             label: "Other" },
];

function fmtBytes(n) {
  if (!n) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function LoginCard({ onLoggedIn }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const r = await api.post("/auth/login", { email, password });
      const token = r.data?.access_token;
      if (!token) throw new Error("no token");
      setToken(token);
      onLoggedIn?.();
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Invalid credentials");
    } finally { setLoading(false); }
  };
  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-white rounded-xl shadow-xl border border-slate-200 p-8">
        <div className="flex items-center gap-2 justify-center mb-1"><Shield className="w-8 h-8 text-[#2E7DF5]" /></div>
        <h1 className="text-2xl font-bold text-center text-slate-900">Employee Portal</h1>
        <p className="mt-1 text-center text-sm text-slate-500">Sign in with the credentials your admin shared</p>
        <form onSubmit={submit} className="mt-6 space-y-4" data-testid="employee-login-form">
          <label className="block">
            <span className="text-xs font-semibold text-slate-600">Work email</span>
            <input type="email" required value={email} onChange={e => setEmail(e.target.value)} data-testid="employee-login-email"
              className="mt-1 w-full px-3 py-2.5 rounded-md border border-slate-200 focus:border-[#2E7DF5] outline-none" />
          </label>
          <label className="block">
            <span className="text-xs font-semibold text-slate-600">Password</span>
            <input type="password" required value={password} onChange={e => setPassword(e.target.value)} data-testid="employee-login-password"
              className="mt-1 w-full px-3 py-2.5 rounded-md border border-slate-200 focus:border-[#2E7DF5] outline-none" />
          </label>
          <button type="submit" disabled={loading} data-testid="employee-login-submit"
            className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2.5 rounded-md bg-[#2E7DF5] text-white text-sm font-semibold hover:bg-[#2563EB] disabled:opacity-60">
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
            {loading ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}

function ChangePasswordModal({ onDone }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async (e) => {
    e.preventDefault();
    if (next !== confirm) return toast.error("New passwords don't match");
    if (next.length < 10) return toast.error("Use at least 10 characters");
    setSaving(true);
    try {
      await api.post("/me/change-password", { current_password: current, new_password: next });
      toast.success("Password updated");
      onDone?.();
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Update failed");
    } finally { setSaving(false); }
  };
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4" data-testid="employee-password-modal">
      <div className="absolute inset-0 bg-slate-950/80" />
      <div className="relative w-full max-w-md bg-white rounded-xl shadow-2xl p-6">
        <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2"><KeyRound className="w-5 h-5 text-[#2E7DF5]" /> Change your password</h3>
        <p className="mt-1 text-xs text-slate-500">This is your first login — set a new password to continue.</p>
        <form onSubmit={submit} className="mt-4 space-y-3">
          <input type="password" required placeholder="Current (temp) password" value={current} onChange={e => setCurrent(e.target.value)}
            data-testid="employee-password-current" className="w-full px-3 py-2 rounded-md border border-slate-200 text-sm" />
          <input type="password" required placeholder="New password (min 10 chars)" value={next} onChange={e => setNext(e.target.value)}
            data-testid="employee-password-new" className="w-full px-3 py-2 rounded-md border border-slate-200 text-sm" />
          <input type="password" required placeholder="Confirm new password" value={confirm} onChange={e => setConfirm(e.target.value)}
            data-testid="employee-password-confirm" className="w-full px-3 py-2 rounded-md border border-slate-200 text-sm" />
          <button type="submit" disabled={saving} data-testid="employee-password-submit"
            className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-md bg-[#2E7DF5] text-white text-sm font-semibold disabled:opacity-60">
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
            Update password
          </button>
        </form>
      </div>
    </div>
  );
}

function Portal({ profile, onLogout, onProfileRefresh }) {
  const [docs, setDocs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [docType, setDocType] = useState("payslip");
  const [tickets, setTickets] = useState([]);
  const [ticketsLoading, setTicketsLoading] = useState(true);
  const [newTicketOpen, setNewTicketOpen] = useState(false);
  const [activeTicket, setActiveTicket] = useState(null);
  const [ticketFilter, setTicketFilter] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get("/me/documents");
      setDocs(r.data || []);
    } catch (err) {
      toast.error("Could not load documents");
    } finally { setLoading(false); }
  }, []);

  const loadTickets = useCallback(async () => {
    setTicketsLoading(true);
    try {
      const params = ticketFilter ? `?status=${ticketFilter}` : "";
      const r = await api.get(`/tickets/mine${params}`);
      setTickets(r.data?.items || []);
    } catch (err) {
      /* ignore */
    } finally { setTicketsLoading(false); }
  }, [ticketFilter]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadTickets(); }, [loadTickets]);

  const upload = async (file) => {
    if (!file) return;
    setUploading(true);
    try {
      const fd = new FormData();
      fd.append("doc_type", docType);
      fd.append("file", file);
      await api.post("/me/documents", fd, { headers: {"Content-Type": "multipart/form-data"} });
      toast.success("Uploaded");
      await load();
      onProfileRefresh?.();
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Upload failed");
    } finally { setUploading(false); }
  };

  const download = async (doc) => {
    try {
      const r = await api.get(`/me/documents/${doc.id}/download`, { responseType: "blob" });
      const url = URL.createObjectURL(r.data);
      const a = document.createElement("a");
      a.href = url; a.download = doc.filename; a.click();
      URL.revokeObjectURL(url);
    } catch (err) { toast.error("Download failed"); }
  };

  const remove = async (doc) => {
    if (!window.confirm(`Delete "${doc.filename}"?`)) return;
    try {
      await api.delete(`/me/documents/${doc.id}`);
      toast.success("Deleted");
      await load();
      onProfileRefresh?.();
    } catch (err) { toast.error("Delete failed"); }
  };

  const usedPct = useMemo(() => {
    const limit = profile.storage_limit_bytes || 1;
    return Math.min(100, Math.round((profile.documents_bytes / limit) * 100));
  }, [profile]);

  const docsByType = useMemo(() => {
    const g = {};
    for (const d of docs) (g[d.doc_type] ||= []).push(d);
    return g;
  }, [docs]);

  return (
    <div className="min-h-screen bg-slate-50">
      <header className="bg-white border-b border-slate-200">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 py-4 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-[#2E7DF5] text-white flex items-center justify-center font-bold">{(profile.name||"E")[0].toUpperCase()}</div>
            <div>
              <div className="font-bold text-slate-900 text-sm">{profile.name}</div>
              <div className="text-xs text-slate-500">{profile.email} · {profile.employee_id}</div>
            </div>
          </div>
          <button onClick={onLogout} data-testid="employee-logout" className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md border border-slate-200 text-sm font-semibold text-slate-700 hover:bg-slate-50"><LogOut className="w-4 h-4" /> Sign out</button>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 sm:px-6 py-6 space-y-6">
        {/* Profile + storage cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="rounded-xl border border-slate-200 bg-white p-4 md:col-span-2">
            <div className="text-xs uppercase font-bold text-slate-500 mb-2 flex items-center gap-1.5"><User className="w-3.5 h-3.5" /> Profile</div>
            <div className="grid grid-cols-2 gap-y-2 gap-x-4 text-sm">
              <div><div className="text-xs text-slate-500">Name</div><div className="font-semibold text-slate-900">{profile.name}</div></div>
              <div><div className="text-xs text-slate-500">Employee ID</div><div className="font-mono text-slate-900">{profile.employee_id}</div></div>
              <div><div className="text-xs text-slate-500">Department</div><div className="text-slate-900">{profile.department || "—"}</div></div>
              <div><div className="text-xs text-slate-500">Designation</div><div className="text-slate-900">{profile.designation || "—"}</div></div>
              <div><div className="text-xs text-slate-500">Joining Date</div><div className="text-slate-900">{profile.joining_date || "—"}</div></div>
              <div><div className="text-xs text-slate-500">Manager</div><div className="text-slate-900">{profile.manager_email || "—"}</div></div>
            </div>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-4">
            <div className="text-xs uppercase font-bold text-slate-500 mb-2 flex items-center gap-1.5"><HardDrive className="w-3.5 h-3.5" /> Storage</div>
            <div className="text-2xl font-bold text-slate-900">{fmtBytes(profile.documents_bytes)} <span className="text-sm text-slate-400 font-normal">/ {profile.storage_limit_mb} MB</span></div>
            <div className="mt-2 h-2 rounded-full bg-slate-100 overflow-hidden"><div className={`h-full ${usedPct > 80 ? "bg-rose-500" : usedPct > 50 ? "bg-amber-500" : "bg-emerald-500"}`} style={{ width: `${usedPct}%` }} data-testid="employee-storage-bar" /></div>
            <div className="mt-1 text-xs text-slate-500">{profile.documents_count} documents</div>
          </div>
        </div>

        {/* Upload strip */}
        <div className="rounded-xl border border-slate-200 bg-white p-4">
          <div className="flex flex-wrap items-center gap-2">
            <div className="text-sm font-semibold text-slate-800 mr-2 flex items-center gap-1.5"><Upload className="w-4 h-4" /> Upload a document</div>
            <select value={docType} onChange={e => setDocType(e.target.value)} data-testid="employee-upload-type"
              className="px-2 py-1.5 rounded-md border border-slate-200 text-sm">
              {DOC_TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
            <label className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-semibold cursor-pointer ${uploading ? "bg-slate-200 text-slate-500" : "bg-[#2E7DF5] text-white hover:bg-[#2563EB]"}`}>
              {uploading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
              {uploading ? "Uploading…" : "Select file"}
              <input type="file" className="hidden" data-testid="employee-upload-input" disabled={uploading}
                onChange={e => { upload(e.target.files?.[0]); e.target.value = ""; }} />
            </label>
            <div className="text-[10px] text-slate-500 ml-auto">Max 25 MB per file · {profile.storage_limit_mb} MB total</div>
          </div>
        </div>

        {/* Documents grouped by type */}
        <section>
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1.5"><FileText className="w-4 h-4" /> My Documents</h2>
          {loading ? (
            <div className="text-center py-12 text-slate-400"><Loader2 className="w-5 h-5 animate-spin inline mr-1.5" /> Loading…</div>
          ) : docs.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-200 bg-white p-12 text-center" data-testid="employee-docs-empty">
              <FileText className="w-10 h-10 mx-auto text-slate-300" />
              <p className="mt-3 text-sm text-slate-500">No documents yet. Upload your first document above.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3" data-testid="employee-docs-grid">
              {DOC_TYPES.filter(t => (docsByType[t.id] || []).length > 0).map(t => (
                <div key={t.id} className="rounded-xl border border-slate-200 bg-white p-4">
                  <div className="text-xs font-bold uppercase text-[#2E7DF5]">{t.label}</div>
                  <div className="mt-2 space-y-1.5">
                    {docsByType[t.id].map(d => (
                      <div key={d.id} className="flex items-center gap-2 text-sm">
                        <FileText className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="truncate text-slate-800 font-medium" title={d.filename}>{d.filename}</div>
                          <div className="text-[10px] text-slate-500">{fmtBytes(d.size)} · {d.uploaded_at?.slice(0,10)}</div>
                        </div>
                        <button onClick={() => download(d)} title="Download" data-testid={`employee-download-${d.id}`} className="p-1 rounded hover:bg-slate-100 text-slate-500"><Download className="w-3.5 h-3.5" /></button>
                        <button onClick={() => remove(d)} title="Delete" data-testid={`employee-delete-${d.id}`} className="p-1 rounded hover:bg-rose-50 text-rose-500"><Trash2 className="w-3.5 h-3.5" /></button>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Service Tickets */}
        <section data-testid="employee-tickets-section">
          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5"><Ticket className="w-4 h-4" /> Support Tickets</h2>
            <div className="flex items-center gap-2">
              <select value={ticketFilter} onChange={e => setTicketFilter(e.target.value)} data-testid="employee-tickets-filter"
                className="px-2 py-1 rounded border border-slate-200 text-xs">
                <option value="">All statuses</option>
                <option value="open">Open</option>
                <option value="in_progress">In Progress</option>
                <option value="resolved">Resolved</option>
                <option value="closed">Closed</option>
              </select>
              <button onClick={() => setNewTicketOpen(true)} data-testid="employee-new-ticket-btn"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#2E7DF5] text-white text-sm font-semibold hover:bg-[#2563EB]">
                <Plus className="w-4 h-4" /> Raise Ticket
              </button>
            </div>
          </div>
          {ticketsLoading ? (
            <div className="text-center py-6 text-slate-400"><Loader2 className="w-4 h-4 animate-spin inline mr-1.5" /> Loading tickets…</div>
          ) : tickets.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-200 bg-white p-8 text-center" data-testid="employee-tickets-empty">
              <Ticket className="w-8 h-8 mx-auto text-slate-300" />
              <p className="mt-2 text-sm text-slate-500">No tickets yet. Have a laptop issue, email problem, or HR request? <strong>Raise Ticket</strong> and we&rsquo;ll help.</p>
            </div>
          ) : (
            <div className="space-y-2" data-testid="employee-tickets-list">
              {tickets.map(t => <TicketRow key={t.id} ticket={t} onOpen={setActiveTicket} />)}
            </div>
          )}
        </section>
      </main>
      <NewTicketModal open={newTicketOpen} onClose={() => setNewTicketOpen(false)} onCreated={() => loadTickets()} />
      {activeTicket && <TicketDetail ticket={activeTicket} mode="employee" onClose={() => setActiveTicket(null)} onUpdated={loadTickets} />}
    </div>
  );
}

export default function EmployeePortal() {
  useSeo({ title: "Employee Portal | NivX Machines", description: "Access your payslips, documents and HR requests." });
  const navigate = useNavigate();
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [needsPwdChange, setNeedsPwdChange] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      if (!getToken()) { setProfile(null); return; }
      const r = await api.get("/me/profile");
      if (r.data?.role === "admin") {
        // Admin visiting /employee — redirect to /admin
        navigate("/admin", { replace: true });
        return;
      }
      setProfile(r.data);
      setNeedsPwdChange(!!r.data.must_change_password);
    } catch (err) {
      if (err?.response?.status === 401 || err?.response?.status === 403) {
        clearToken();
        setProfile(null);
      } else {
        toast.error("Could not load profile");
      }
    } finally { setLoading(false); }
  }, [navigate]);

  useEffect(() => { load(); }, [load]);

  const logout = () => { clearToken(); setProfile(null); };

  if (loading) return <div className="min-h-screen flex items-center justify-center bg-slate-50"><Loader2 className="w-6 h-6 animate-spin text-slate-400" /></div>;
  if (!profile) return <LoginCard onLoggedIn={load} />;
  return (
    <>
      <Portal profile={profile} onLogout={logout} onProfileRefresh={load} />
      {needsPwdChange && <ChangePasswordModal onDone={() => { setNeedsPwdChange(false); load(); }} />}
    </>
  );
}
