/**
 * AdminEmployees — admin panel tab for HR management.
 *
 * Features:
 *   - List employees with search
 *   - Create employee → shows one-time temporary password with copy-to-clipboard
 *   - Edit / delete / reset password
 *   - Upload / download / delete docs on behalf of an employee
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import {
  Users, Plus, Search, KeyRound, Trash2, UserCog, Copy, Check, X,
  FileText, Upload, Download, Loader2,
} from "lucide-react";
import { toast } from "sonner";

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

// ---------- Create employee modal --------------------------------------------
function CreateEmployeeModal({ open, onClose, onCreated }) {
  const [form, setForm] = useState({
    name: "", email: "", employee_id: "",
    department: "", designation: "", joining_date: "", phone: "",
    manager_email: "", notes: "",
  });
  const [saving, setSaving] = useState(false);
  const [creds, setCreds] = useState(null);
  const [copied, setCopied] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      const payload = { ...form };
      // Strip empty optional fields to avoid Pydantic email validation on ""
      for (const k of ["department", "designation", "joining_date", "phone", "manager_email", "notes"]) {
        if (!payload[k]) delete payload[k];
      }
      const r = await api.post("/admin/employees", payload);
      setCreds(r.data);
      onCreated?.();
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Failed to create employee");
    } finally {
      setSaving(false);
    }
  };

  const copyCreds = async () => {
    const text = `Email: ${creds.email}\nTemporary Password: ${creds.temp_password}\n\nLogin at /employee — you'll be asked to set a new password on first sign-in.`;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      toast.success("Credentials copied");
    } catch { /* ignore */ }
  };

  const reset = () => {
    setForm({ name: "", email: "", employee_id: "", department: "", designation: "", joining_date: "", phone: "", manager_email: "", notes: "" });
    setCreds(null); setCopied(false);
  };

  const closeAll = () => { reset(); onClose(); };

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[100] flex items-start sm:items-center justify-center p-3 sm:p-6" data-testid="employee-create-modal">
      <div className="absolute inset-0 bg-slate-950/70 backdrop-blur-sm" onClick={closeAll} />
      <div className="relative w-full max-w-lg bg-white rounded-xl shadow-2xl border border-slate-200 max-h-[90vh] overflow-auto">
        <div className="flex items-center justify-between px-5 py-3 border-b border-slate-100">
          <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <UserCog className="w-5 h-5 text-[#2E7DF5]" /> {creds ? "Employee Created" : "New Employee"}
          </h3>
          <button onClick={closeAll} data-testid="employee-create-close" className="p-1 rounded hover:bg-slate-100"><X className="w-4 h-4" /></button>
        </div>
        {creds ? (
          <div className="p-5 space-y-4">
            <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800">
              ✅ Account created for <strong>{creds.email}</strong>. Copy the credentials below and share them via a secure channel — this password won&rsquo;t be shown again.
            </div>
            <div className="rounded-lg bg-slate-900 text-slate-100 p-3 font-mono text-sm space-y-1">
              <div><span className="text-slate-400">email:</span> {creds.email}</div>
              <div><span className="text-slate-400">temp:</span> <span data-testid="employee-temp-password">{creds.temp_password}</span></div>
            </div>
            <div className="text-xs text-slate-500">{creds.instructions}</div>
            <div className="flex justify-end gap-2 pt-2">
              <button onClick={copyCreds} data-testid="employee-copy-creds" className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-md text-sm font-semibold border transition-colors ${copied ? "bg-emerald-50 text-emerald-700 border-emerald-200" : "bg-white border-slate-200 hover:border-slate-400"}`}>
                {copied ? <><Check className="w-4 h-4" /> Copied</> : <><Copy className="w-4 h-4" /> Copy credentials</>}
              </button>
              <button onClick={() => { reset(); }} className="px-3 py-2 rounded-md text-sm font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200">Create another</button>
              <button onClick={closeAll} data-testid="employee-create-done" className="px-3 py-2 rounded-md text-sm font-semibold text-white bg-slate-900 hover:bg-slate-800">Done</button>
            </div>
          </div>
        ) : (
          <form onSubmit={submit} className="p-5 space-y-3" data-testid="employee-create-form">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <label className="block">
                <span className="text-xs font-semibold text-slate-600">Full name *</span>
                <input required data-testid="employee-form-name" value={form.name} onChange={e => setForm({...form, name: e.target.value})} className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 text-sm focus:border-[#2E7DF5] outline-none" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-slate-600">Work email *</span>
                <input type="email" required data-testid="employee-form-email" value={form.email} onChange={e => setForm({...form, email: e.target.value})} className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 text-sm focus:border-[#2E7DF5] outline-none" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-slate-600">Employee ID *</span>
                <input required data-testid="employee-form-id" value={form.employee_id} onChange={e => setForm({...form, employee_id: e.target.value})} className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 text-sm focus:border-[#2E7DF5] outline-none" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-slate-600">Department</span>
                <input value={form.department} onChange={e => setForm({...form, department: e.target.value})} className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 text-sm focus:border-[#2E7DF5] outline-none" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-slate-600">Designation</span>
                <input value={form.designation} onChange={e => setForm({...form, designation: e.target.value})} className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 text-sm focus:border-[#2E7DF5] outline-none" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-slate-600">Joining date</span>
                <input type="date" value={form.joining_date} onChange={e => setForm({...form, joining_date: e.target.value})} className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 text-sm focus:border-[#2E7DF5] outline-none" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-slate-600">Phone</span>
                <input value={form.phone} onChange={e => setForm({...form, phone: e.target.value})} className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 text-sm focus:border-[#2E7DF5] outline-none" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-slate-600">Manager email</span>
                <input type="email" value={form.manager_email} onChange={e => setForm({...form, manager_email: e.target.value})} className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 text-sm focus:border-[#2E7DF5] outline-none" />
              </label>
            </div>
            <label className="block">
              <span className="text-xs font-semibold text-slate-600">Notes</span>
              <textarea rows={2} value={form.notes} onChange={e => setForm({...form, notes: e.target.value})} className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 text-sm focus:border-[#2E7DF5] outline-none" />
            </label>
            <div className="flex justify-end gap-2 pt-2">
              <button type="button" onClick={closeAll} className="px-3 py-2 rounded-md text-sm font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200">Cancel</button>
              <button type="submit" disabled={saving} data-testid="employee-create-submit" className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md text-sm font-semibold text-white bg-[#2E7DF5] hover:bg-[#2563EB] disabled:opacity-60">
                {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                {saving ? "Creating…" : "Create employee"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

// ---------- Docs panel for an employee ---------------------------------------
function DocsPanel({ employee, onClose }) {
  const [docs, setDocs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [docType, setDocType] = useState("payslip");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get(`/admin/employees/${employee.id}/documents`);
      setDocs(r.data || []);
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Could not load documents");
    } finally { setLoading(false); }
  }, [employee.id]);

  useEffect(() => { load(); }, [load]);

  const upload = async (file) => {
    if (!file) return;
    setUploading(true);
    try {
      const fd = new FormData();
      fd.append("doc_type", docType);
      fd.append("file", file);
      await api.post(`/admin/employees/${employee.id}/documents`, fd, { headers: {"Content-Type": "multipart/form-data"} });
      toast.success("Uploaded");
      await load();
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Upload failed");
    } finally { setUploading(false); }
  };

  const download = async (doc) => {
    try {
      const r = await api.get(`/admin/employees/${employee.id}/documents/${doc.id}/download`, { responseType: "blob" });
      const url = URL.createObjectURL(r.data);
      const a = document.createElement("a");
      a.href = url; a.download = doc.filename; a.click();
      URL.revokeObjectURL(url);
    } catch (err) { toast.error("Download failed"); }
  };

  const remove = async (doc) => {
    if (!window.confirm(`Delete "${doc.filename}"?`)) return;
    try {
      await api.delete(`/admin/employees/${employee.id}/documents/${doc.id}`);
      toast.success("Deleted");
      await load();
    } catch (err) { toast.error("Delete failed"); }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-start sm:items-center justify-center p-3 sm:p-6" data-testid="employee-docs-modal">
      <div className="absolute inset-0 bg-slate-950/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-3xl bg-white rounded-xl shadow-2xl border border-slate-200 max-h-[90vh] overflow-auto">
        <div className="flex items-center justify-between px-5 py-3 border-b border-slate-100">
          <div>
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2"><FileText className="w-5 h-5 text-[#2E7DF5]" /> Documents · {employee.name}</h3>
            <div className="text-xs text-slate-500">{employee.email} · {employee.employee_id}</div>
          </div>
          <button onClick={onClose} className="p-1 rounded hover:bg-slate-100" data-testid="employee-docs-close"><X className="w-4 h-4" /></button>
        </div>
        <div className="p-5 space-y-4">
          <div className="flex flex-wrap items-center gap-2 p-3 rounded-lg border border-dashed border-slate-300 bg-slate-50">
            <select value={docType} onChange={e => setDocType(e.target.value)} data-testid="employee-doc-type-select" className="px-2 py-1.5 rounded-md border border-slate-200 text-sm">
              {DOC_TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
            <label className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-semibold cursor-pointer ${uploading ? "bg-slate-200 text-slate-500" : "bg-[#2E7DF5] text-white hover:bg-[#2563EB]"}`}>
              {uploading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
              {uploading ? "Uploading…" : "Upload"}
              <input type="file" className="hidden" data-testid="employee-doc-upload-input" disabled={uploading}
                onChange={e => { upload(e.target.files?.[0]); e.target.value = ""; }} />
            </label>
            <div className="text-[10px] text-slate-500 ml-auto">Max 25 MB per file · 50 MB total per employee</div>
          </div>
          {loading ? (
            <div className="text-center py-8 text-slate-400"><Loader2 className="w-4 h-4 animate-spin inline mr-1.5" /> Loading…</div>
          ) : docs.length === 0 ? (
            <div className="text-center py-8 text-sm text-slate-400">No documents yet.</div>
          ) : (
            <div className="overflow-x-auto rounded-md border border-slate-200">
              <table className="w-full min-w-[560px] text-sm" data-testid="employee-docs-table">
                <thead className="bg-slate-50 text-left text-xs uppercase text-slate-500">
                  <tr>
                    <th className="px-3 py-2">Type</th>
                    <th className="px-3 py-2">Filename</th>
                    <th className="px-3 py-2">Size</th>
                    <th className="px-3 py-2">Uploaded</th>
                    <th className="px-3 py-2 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {docs.map(d => (
                    <tr key={d.id} className="hover:bg-slate-50">
                      <td className="px-3 py-2 text-xs font-semibold text-[#2E7DF5]">{DOC_TYPES.find(t=>t.id===d.doc_type)?.label || d.doc_type}</td>
                      <td className="px-3 py-2 text-slate-800">{d.filename}</td>
                      <td className="px-3 py-2 text-slate-500 text-xs">{fmtBytes(d.size)}</td>
                      <td className="px-3 py-2 text-slate-500 text-xs">{d.uploaded_at?.slice(0,10)}</td>
                      <td className="px-3 py-2 text-right space-x-1">
                        <button onClick={() => download(d)} data-testid={`employee-doc-download-${d.id}`} className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs text-slate-600 hover:bg-slate-100"><Download className="w-3 h-3" /> Download</button>
                        <button onClick={() => remove(d)} data-testid={`employee-doc-delete-${d.id}`} className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs text-rose-600 hover:bg-rose-50"><Trash2 className="w-3 h-3" /></button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------- Main -------------------------------------------------------------
export default function AdminEmployees() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [docsFor, setDocsFor] = useState(null);
  const [resetShown, setResetShown] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.get(`/admin/employees${q ? `?q=${encodeURIComponent(q)}` : ""}`);
      setItems(r.data?.items || []);
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Could not load employees");
    } finally { setLoading(false); }
  }, [q]);

  useEffect(() => { load(); }, [load]);

  const resetPwd = async (emp) => {
    if (!window.confirm(`Reset password for ${emp.email}?`)) return;
    try {
      const r = await api.post(`/admin/employees/${emp.id}/reset-password`);
      setResetShown({ email: emp.email, temp_password: r.data.temp_password });
    } catch (err) { toast.error("Reset failed"); }
  };

  const remove = async (emp) => {
    if (!window.confirm(`Permanently delete ${emp.email} and all their documents?`)) return;
    try {
      await api.delete(`/admin/employees/${emp.id}`);
      toast.success("Employee deleted");
      await load();
    } catch (err) { toast.error("Delete failed"); }
  };

  const stats = useMemo(() => ({
    total: items.length,
    active: items.filter(i => i.is_active).length,
    totalDocs: items.reduce((a, i) => a + (i.documents_count || 0), 0),
  }), [items]);

  return (
    <main className="mx-auto max-w-7xl px-6 py-10">
      <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 flex items-center gap-2"><Users className="w-6 h-6 text-[#2E7DF5]" /> Employees</h1>
          <p className="mt-1 text-sm text-slate-500">Create accounts, manage docs, reset passwords. All actions audited.</p>
        </div>
        <button onClick={() => setCreateOpen(true)} data-testid="employee-new-btn" className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md bg-[#2E7DF5] text-white text-sm font-semibold hover:bg-[#2563EB]">
          <Plus className="w-4 h-4" /> New Employee
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3 mb-4">
        <div className="rounded-lg border border-slate-200 bg-white p-3"><div className="text-xs uppercase text-slate-500">Total</div><div className="text-2xl font-bold text-slate-900">{stats.total}</div></div>
        <div className="rounded-lg border border-slate-200 bg-white p-3"><div className="text-xs uppercase text-slate-500">Active</div><div className="text-2xl font-bold text-emerald-600">{stats.active}</div></div>
        <div className="rounded-lg border border-slate-200 bg-white p-3"><div className="text-xs uppercase text-slate-500">Documents</div><div className="text-2xl font-bold text-slate-900">{stats.totalDocs}</div></div>
      </div>

      {/* Search */}
      <div className="mb-3 flex items-center gap-2">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search name, email, employee ID, department…"
            data-testid="employee-search" className="w-full pl-9 pr-3 py-2 rounded-md border border-slate-200 text-sm focus:border-[#2E7DF5] outline-none" />
        </div>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-slate-200 bg-white overflow-hidden">
        <div className="max-h-[600px] overflow-auto">
          <table className="w-full min-w-[760px] text-sm" data-testid="employees-table">
            <thead className="sticky top-0 bg-slate-50 text-left text-xs uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-3 py-2">Name / Email</th>
                <th className="px-3 py-2">Employee ID</th>
                <th className="px-3 py-2">Department</th>
                <th className="px-3 py-2">Designation</th>
                <th className="px-3 py-2">Docs</th>
                <th className="px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading && <tr><td colSpan={6} className="px-3 py-8 text-center text-slate-400 text-xs"><Loader2 className="w-4 h-4 animate-spin inline mr-1.5" /> Loading…</td></tr>}
              {!loading && items.length === 0 && <tr><td colSpan={6} className="px-3 py-8 text-center text-slate-400 text-xs">No employees yet. Click <strong>New Employee</strong> to create one.</td></tr>}
              {items.map(emp => (
                <tr key={emp.id} className="hover:bg-slate-50" data-testid={`employee-row-${emp.employee_id}`}>
                  <td className="px-3 py-2">
                    <div className="font-semibold text-slate-900">{emp.name}</div>
                    <div className="text-xs text-slate-500 font-mono">{emp.email}</div>
                  </td>
                  <td className="px-3 py-2 text-slate-700 font-mono text-xs">{emp.employee_id}</td>
                  <td className="px-3 py-2 text-slate-600 text-xs">{emp.department || "—"}</td>
                  <td className="px-3 py-2 text-slate-600 text-xs">{emp.designation || "—"}</td>
                  <td className="px-3 py-2 text-slate-600 text-xs">
                    <button onClick={() => setDocsFor(emp)} data-testid={`employee-docs-btn-${emp.employee_id}`} className="inline-flex items-center gap-1 text-[#2E7DF5] hover:underline">
                      <FileText className="w-3 h-3" /> {emp.documents_count} ({fmtBytes(emp.documents_bytes)})
                    </button>
                  </td>
                  <td className="px-3 py-2 text-right space-x-1">
                    <button onClick={() => resetPwd(emp)} data-testid={`employee-reset-btn-${emp.employee_id}`} title="Reset password" className="inline-flex items-center px-2 py-1 rounded text-xs text-amber-700 hover:bg-amber-50"><KeyRound className="w-3 h-3" /></button>
                    <button onClick={() => remove(emp)} data-testid={`employee-delete-btn-${emp.employee_id}`} title="Delete" className="inline-flex items-center px-2 py-1 rounded text-xs text-rose-600 hover:bg-rose-50"><Trash2 className="w-3 h-3" /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <CreateEmployeeModal open={createOpen} onClose={() => setCreateOpen(false)} onCreated={load} />
      {docsFor && <DocsPanel employee={docsFor} onClose={() => setDocsFor(null)} />}
      {resetShown && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-3" data-testid="employee-reset-shown">
          <div className="absolute inset-0 bg-slate-950/70" onClick={() => setResetShown(null)} />
          <div className="relative w-full max-w-md bg-white rounded-xl shadow-2xl border p-5">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2"><KeyRound className="w-5 h-5 text-amber-600" /> Password reset</h3>
            <div className="mt-2 text-sm text-slate-600">Share these credentials with <strong>{resetShown.email}</strong> securely — this password won&rsquo;t be shown again.</div>
            <div className="mt-3 rounded-lg bg-slate-900 text-slate-100 p-3 font-mono text-sm">
              <div><span className="text-slate-400">temp:</span> <span data-testid="employee-reset-password">{resetShown.temp_password}</span></div>
            </div>
            <div className="mt-4 flex justify-end gap-2">
              <button onClick={() => { navigator.clipboard.writeText(resetShown.temp_password); toast.success("Copied"); }} className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md text-sm font-semibold bg-slate-100 hover:bg-slate-200"><Copy className="w-4 h-4" /> Copy</button>
              <button onClick={() => setResetShown(null)} className="px-3 py-2 rounded-md text-sm font-semibold text-white bg-slate-900 hover:bg-slate-800">Done</button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
