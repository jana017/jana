/**
 * AdminTickets — full ServiceNow-style ticket board for admins.
 * Filters, stats, list + detail modal with inline status/priority/assign controls.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { toast } from "sonner";
import { Loader2, RefreshCw, Filter, Ticket as Ticket2 } from "lucide-react";
import {
  TicketRow, TicketDetail, PRIORITIES, STATUSES, CATEGORIES,
} from "@/components/TicketWidgets";

const STATUS_FILTERS = [{ id: "", label: "All" }, ...STATUSES];

export default function AdminTickets() {
  const [items, setItems] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [statusF, setStatusF] = useState("open");
  const [priorityF, setPriorityF] = useState("");
  const [categoryF, setCategoryF] = useState("");
  const [q, setQ] = useState("");
  const [active, setActive] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (statusF)   params.set("status", statusF);
      if (priorityF) params.set("priority", priorityF);
      if (categoryF) params.set("category", categoryF);
      if (q)         params.set("q", q);
      const [r, s] = await Promise.all([
        api.get(`/admin/tickets?${params}`),
        api.get(`/admin/tickets/stats`),
      ]);
      setItems(r.data?.items || []);
      setStats(s.data);
    } catch (err) {
      toast.error(err?.response?.data?.detail || "Could not load tickets");
    } finally { setLoading(false); }
  }, [statusF, priorityF, categoryF, q]);

  useEffect(() => { load(); }, [load]);

  const statCard = (label, value, className = "text-slate-900") => (
    <div className="rounded-lg border border-slate-200 bg-white p-3">
      <div className="text-[10px] uppercase font-bold tracking-wider text-slate-500">{label}</div>
      <div className={`text-2xl font-bold ${className}`}>{value}</div>
    </div>
  );

  return (
    <main className="mx-auto max-w-7xl px-6 py-10">
      <div className="flex items-start justify-between gap-3 mb-5 flex-wrap">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 flex items-center gap-2"><Ticket2 className="w-6 h-6 text-[#2E7DF5]" /> Support Tickets</h1>
          <p className="mt-1 text-sm text-slate-500">All employee service requests. Change status, priority and assignment inline.</p>
        </div>
        <button onClick={load} data-testid="tickets-refresh" className="inline-flex items-center gap-1.5 px-3 py-2 rounded-md border border-slate-200 text-sm font-semibold text-slate-700 hover:bg-slate-50">
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-4">
          {statCard("Total", stats.total)}
          {statCard("Open", stats.by_status.open, "text-sky-600")}
          {statCard("In Progress", stats.by_status.in_progress, "text-indigo-600")}
          {statCard("Urgent", stats.by_priority.urgent, "text-rose-600")}
          {statCard("Resolved", stats.by_status.resolved, "text-emerald-600")}
        </div>
      )}

      {/* Filters */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Filter className="w-4 h-4 text-slate-400" />
        <select value={statusF} onChange={e => setStatusF(e.target.value)} data-testid="tickets-filter-status"
          className="px-2 py-1.5 rounded border border-slate-200 text-sm">
          {STATUS_FILTERS.map(s => <option key={s.id} value={s.id}>Status: {s.label}</option>)}
        </select>
        <select value={priorityF} onChange={e => setPriorityF(e.target.value)} data-testid="tickets-filter-priority"
          className="px-2 py-1.5 rounded border border-slate-200 text-sm">
          <option value="">Priority: All</option>
          {PRIORITIES.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
        </select>
        <select value={categoryF} onChange={e => setCategoryF(e.target.value)} data-testid="tickets-filter-category"
          className="px-2 py-1.5 rounded border border-slate-200 text-sm">
          <option value="">Category: All</option>
          {CATEGORIES.map(c => <option key={c.id} value={c.id}>{c.label}</option>)}
        </select>
        <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search subject, ticket-id, employee email"
          data-testid="tickets-search" className="flex-1 max-w-xs px-3 py-1.5 rounded border border-slate-200 text-sm" />
      </div>

      {loading ? (
        <div className="text-center py-12 text-slate-400"><Loader2 className="w-5 h-5 animate-spin inline mr-1.5" /> Loading…</div>
      ) : items.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-200 bg-white p-12 text-center text-slate-400" data-testid="tickets-empty">No tickets match these filters.</div>
      ) : (
        <div className="space-y-2" data-testid="admin-tickets-list">
          {items.map(t => <TicketRow key={t.id} ticket={t} onOpen={setActive} showEmployee />)}
        </div>
      )}

      {active && <TicketDetail ticket={active} mode="admin" onClose={() => setActive(null)} onUpdated={load} />}
    </main>
  );
}
