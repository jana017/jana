/**
 * TicketWidgets — shared components used by both Employee Portal and Admin
 * ticketing views. Zero external state; parents pass `mode: "employee" | "admin"`.
 */
import { useState } from "react";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { Loader2, Send, X, Plus, MessageSquare, Tag, AlertTriangle, User as UserIcon, ChevronRight } from "lucide-react";

export const CATEGORIES = [
  { id: "email",    label: "Email" },
  { id: "hardware", label: "Hardware (Laptop, Peripherals)" },
  { id: "software", label: "Software / Tool Access" },
  { id: "hr",       label: "HR / People Ops" },
  { id: "other",    label: "Other" },
];
export const PRIORITIES = [
  { id: "low",    label: "Low",    color: "bg-slate-100 text-slate-600 border-slate-200" },
  { id: "medium", label: "Medium", color: "bg-blue-50 text-blue-700 border-blue-200" },
  { id: "high",   label: "High",   color: "bg-amber-50 text-amber-700 border-amber-200" },
  { id: "urgent", label: "Urgent", color: "bg-rose-50 text-rose-700 border-rose-200" },
];
export const STATUSES = [
  { id: "open",         label: "Open",        color: "bg-sky-50 text-sky-700 border-sky-200" },
  { id: "in_progress",  label: "In Progress", color: "bg-indigo-50 text-indigo-700 border-indigo-200" },
  { id: "resolved",     label: "Resolved",    color: "bg-emerald-50 text-emerald-700 border-emerald-200" },
  { id: "closed",       label: "Closed",      color: "bg-slate-100 text-slate-500 border-slate-200" },
];

export function Chip({ list, id, "data-testid": testid }) {
  const item = list.find(x => x.id === id) || { label: id, color: "bg-slate-100 text-slate-600 border-slate-200" };
  return <span data-testid={testid} className={`inline-block text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${item.color}`}>{item.label}</span>;
}

// ---------- Raise-ticket modal --------------------------------------------
export function NewTicketModal({ open, onClose, onCreated }) {
  const [form, setForm] = useState({ category: "email", priority: "medium", subject: "", description: "" });
  const [saving, setSaving] = useState(false);
  if (!open) return null;
  const submit = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      const r = await api.post("/tickets", form);
      toast.success(`Ticket ${r.data.ticket_id} created`);
      onCreated?.(r.data);
      onClose();
      setForm({ category: "email", priority: "medium", subject: "", description: "" });
    } catch (err) { toast.error(err?.response?.data?.detail || "Failed to create"); }
    finally { setSaving(false); }
  };
  return (
    <div className="fixed inset-0 z-[100] flex items-start sm:items-center justify-center p-3 sm:p-6" data-testid="ticket-new-modal">
      <div className="absolute inset-0 bg-slate-950/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-lg bg-white rounded-xl shadow-2xl max-h-[90vh] overflow-auto">
        <div className="flex items-center justify-between px-5 py-3 border-b">
          <h3 className="font-bold text-slate-900 flex items-center gap-2"><Plus className="w-5 h-5 text-[#2E7DF5]" /> New Service Request</h3>
          <button onClick={onClose} className="p-1 rounded hover:bg-slate-100"><X className="w-4 h-4" /></button>
        </div>
        <form onSubmit={submit} className="p-5 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="text-xs font-semibold text-slate-600">Category *</span>
              <select value={form.category} onChange={e => setForm({...form, category: e.target.value})} data-testid="ticket-form-category"
                className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 text-sm">
                {CATEGORIES.map(c => <option key={c.id} value={c.id}>{c.label}</option>)}
              </select>
            </label>
            <label className="block">
              <span className="text-xs font-semibold text-slate-600">Priority *</span>
              <select value={form.priority} onChange={e => setForm({...form, priority: e.target.value})} data-testid="ticket-form-priority"
                className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 text-sm">
                {PRIORITIES.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
              </select>
            </label>
          </div>
          <label className="block">
            <span className="text-xs font-semibold text-slate-600">Subject *</span>
            <input required value={form.subject} onChange={e => setForm({...form, subject: e.target.value})} data-testid="ticket-form-subject"
              placeholder="e.g., Laptop keyboard stuck on 'a' key" className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 text-sm" />
          </label>
          <label className="block">
            <span className="text-xs font-semibold text-slate-600">Describe the issue *</span>
            <textarea required rows={5} value={form.description} onChange={e => setForm({...form, description: e.target.value})} data-testid="ticket-form-description"
              placeholder="Include steps to reproduce, what you tried, error messages, etc." className="mt-1 w-full px-3 py-2 rounded-md border border-slate-200 text-sm" />
          </label>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={onClose} className="px-3 py-2 rounded-md text-sm font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200">Cancel</button>
            <button type="submit" disabled={saving} data-testid="ticket-form-submit"
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md text-sm font-semibold text-white bg-[#2E7DF5] hover:bg-[#2563EB] disabled:opacity-60">
              {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              {saving ? "Submitting…" : "Raise ticket"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---------- Ticket detail (comments + admin controls) ---------------------
export function TicketDetail({ ticket, mode, onClose, onUpdated }) {
  const [comment, setComment] = useState("");
  const [sending, setSending] = useState(false);
  const [t, setT] = useState(ticket);
  const isAdmin = mode === "admin";

  const send = async (e) => {
    e.preventDefault();
    if (!comment.trim()) return;
    setSending(true);
    try {
      const r = await api.post(`/tickets/${t.ticket_id}/comment`, { body: comment });
      setT({ ...t, comments: [...(t.comments || []), r.data] });
      setComment("");
      onUpdated?.();
    } catch (err) { toast.error(err?.response?.data?.detail || "Comment failed"); }
    finally { setSending(false); }
  };

  const patch = async (updates) => {
    try {
      const r = await api.patch(`/admin/tickets/${t.ticket_id}`, updates);
      setT(r.data);
      onUpdated?.();
      toast.success("Updated");
    } catch (err) { toast.error(err?.response?.data?.detail || "Update failed"); }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-start sm:items-center justify-center p-3 sm:p-6" data-testid="ticket-detail-modal">
      <div className="absolute inset-0 bg-slate-950/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-3xl bg-white rounded-xl shadow-2xl max-h-[92vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-5 py-3 border-b">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-xs text-slate-500">{t.ticket_id}</span>
              <Chip list={STATUSES} id={t.status} data-testid="ticket-detail-status" />
              <Chip list={PRIORITIES} id={t.priority} data-testid="ticket-detail-priority" />
              <Chip list={CATEGORIES} id={t.category} data-testid="ticket-detail-category" />
            </div>
            <h3 className="font-bold text-slate-900 mt-1 truncate">{t.subject}</h3>
            <div className="text-xs text-slate-500">Raised by {t.employee_name || t.employee_email} · {t.created_at?.slice(0,10)}</div>
          </div>
          <button onClick={onClose} className="p-1 rounded hover:bg-slate-100" data-testid="ticket-detail-close"><X className="w-4 h-4" /></button>
        </div>
        {isAdmin && (
          <div className="px-5 py-2.5 border-b bg-slate-50 flex flex-wrap items-center gap-2 text-xs">
            <span className="font-semibold text-slate-600">Admin:</span>
            <select value={t.status} onChange={e => patch({ status: e.target.value })} data-testid="ticket-admin-status"
              className="px-2 py-1 rounded border border-slate-200 text-xs">
              {STATUSES.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>
            <select value={t.priority} onChange={e => patch({ priority: e.target.value })} data-testid="ticket-admin-priority"
              className="px-2 py-1 rounded border border-slate-200 text-xs">
              {PRIORITIES.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
            </select>
            <input placeholder="assigned_to (email)" defaultValue={t.assigned_to || ""} data-testid="ticket-admin-assign"
              onBlur={e => { if (e.target.value !== (t.assigned_to || "")) patch({ assigned_to: e.target.value }); }}
              className="px-2 py-1 rounded border border-slate-200 text-xs min-w-[220px]" />
          </div>
        )}
        <div className="flex-1 overflow-auto p-5 space-y-3" data-testid="ticket-detail-thread">
          <div className="rounded-lg bg-slate-50 border border-slate-200 p-3">
            <div className="text-xs text-slate-500 mb-1">Original description</div>
            <div className="text-sm text-slate-800 whitespace-pre-wrap">{t.description}</div>
          </div>
          {(t.comments || []).length === 0 && (
            <div className="text-center text-xs text-slate-400 py-6">No comments yet.</div>
          )}
          {(t.comments || []).map(c => {
            const isSystem = c.author_role === "system";
            const isAdminC = c.author_role === "admin";
            return (
              <div key={c.id} className={`rounded-lg p-3 border ${
                isSystem ? "bg-slate-50 border-dashed border-slate-200 text-slate-500 text-xs" :
                isAdminC ? "bg-blue-50 border-blue-200" : "bg-white border-slate-200"
              }`} data-testid={`ticket-comment-${c.id}`}>
                {!isSystem && (
                  <div className="flex items-center gap-1.5 text-[10px] uppercase font-bold tracking-wider mb-1">
                    <UserIcon className="w-3 h-3" />
                    <span className={isAdminC ? "text-blue-700" : "text-slate-600"}>{c.author_email}</span>
                    <span className="text-slate-400">· {c.created_at?.slice(11,16)} {c.created_at?.slice(0,10)}</span>
                  </div>
                )}
                <div className={`${isSystem ? "italic" : "text-sm text-slate-800 whitespace-pre-wrap"}`}>{c.body}</div>
              </div>
            );
          })}
        </div>
        {t.status !== "closed" && (
          <form onSubmit={send} className="border-t p-3 flex items-end gap-2" data-testid="ticket-comment-form">
            <textarea value={comment} onChange={e => setComment(e.target.value)} rows={2} placeholder="Reply to this ticket…" data-testid="ticket-comment-input"
              className="flex-1 px-3 py-2 rounded-md border border-slate-200 text-sm resize-none" />
            <button type="submit" disabled={sending || !comment.trim()} data-testid="ticket-comment-send"
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md text-sm font-semibold text-white bg-[#2E7DF5] hover:bg-[#2563EB] disabled:opacity-60">
              {sending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              Send
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

// ---------- Tickets list row (compact, shared) ----------------------------
export function TicketRow({ ticket, onOpen, showEmployee = false }) {
  return (
    <button
      onClick={() => onOpen(ticket)}
      data-testid={`ticket-row-${ticket.ticket_id}`}
      className="w-full text-left rounded-lg border border-slate-200 bg-white hover:border-[#2E7DF5] hover:shadow-sm transition-colors p-3 flex flex-wrap items-center gap-2"
    >
      <span className="font-mono text-xs text-slate-500 shrink-0">{ticket.ticket_id}</span>
      <Chip list={STATUSES} id={ticket.status} />
      <Chip list={PRIORITIES} id={ticket.priority} />
      <Chip list={CATEGORIES} id={ticket.category} />
      <div className="flex-1 min-w-0">
        <div className="text-sm font-semibold text-slate-800 truncate">{ticket.subject}</div>
        {showEmployee && <div className="text-[10px] text-slate-500 font-mono truncate">{ticket.employee_email}</div>}
      </div>
      <div className="text-[10px] text-slate-400 shrink-0 flex items-center gap-1">
        <MessageSquare className="w-3 h-3" /> {(ticket.comments || []).length}
        <ChevronRight className="w-3 h-3" />
      </div>
    </button>
  );
}
