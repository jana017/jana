/**
 * UserDashboard — /me. Simple personal dashboard for role="user" accounts.
 * Two tabs: Bookmarks (ThreatBox actors) + IOC Watchlist.
 * Admin/Employee are redirected to their dedicated portals since this page
 * is designed for public NivX users.
 */
import { useEffect, useState, useCallback } from "react";
import { Link, Navigate, useSearchParams } from "react-router-dom";
import { Bookmark, Eye, Plus, Trash2, Loader2, AlertTriangle, ExternalLink, Fingerprint, ShieldAlert, KeyRound } from "lucide-react";
import { toast } from "sonner";
import Navbar from "@/components/Navbar";
import useSeo from "@/lib/useSeo";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/api";

function TabBtn({ id, active, onClick, icon: Icon, label, count }) {
  const isActive = active === id;
  return (
    <button
      onClick={() => onClick(id)}
      data-testid={`me-tab-${id}`}
      className={`inline-flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors ${
        isActive ? "border-[#2E7DF5] text-[#2E7DF5]" : "border-transparent text-slate-500 hover:text-slate-800"
      }`}
    >
      <Icon className="w-4 h-4" /> {label}
      {typeof count === "number" && (
        <span className="text-[10px] font-mono bg-slate-100 text-slate-600 rounded px-1.5 py-0.5">{count}</span>
      )}
    </button>
  );
}

function BookmarksTab() {
  const [items, setItems] = useState(null);
  const load = useCallback(() => {
    api.get("/me/bookmarks").then(({ data }) => setItems(data.bookmarks || [])).catch(() => setItems([]));
  }, []);
  useEffect(() => { load(); }, [load]);

  const remove = async (slug) => {
    try {
      await api.delete(`/me/bookmarks/threatbox/${encodeURIComponent(slug)}`);
      setItems((xs) => xs.filter((b) => b.slug !== slug));
      toast.success("Removed from bookmarks");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to remove");
    }
  };

  if (items === null) return <div className="flex items-center gap-2 text-slate-500 py-8"><Loader2 className="w-4 h-4 animate-spin" /> Loading…</div>;
  if (items.length === 0) {
    return (
      <div className="text-center py-12" data-testid="bookmarks-empty">
        <Bookmark className="w-10 h-10 text-slate-300 mx-auto mb-3" />
        <div className="text-slate-700 font-semibold mb-1">No bookmarks yet</div>
        <div className="text-sm text-slate-500 mb-4">Bookmark ThreatBox actors to quickly revisit their dossiers.</div>
        <Link to="/threatbox" className="inline-flex items-center gap-1.5 text-sm font-semibold text-[#2E7DF5] hover:underline">
          Browse ThreatBox <ExternalLink className="w-3 h-3" />
        </Link>
      </div>
    );
  }
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3" data-testid="bookmarks-list">
      {items.map((a) => (
        <div key={a.slug} className="group flex items-start justify-between gap-3 rounded-lg border border-slate-200 bg-white p-4 hover:border-[#2E7DF5] transition-colors">
          <Link to={`/threatbox/${a.slug}`} className="min-w-0 flex-1">
            <div className="flex items-center gap-2 mb-1">
              <ShieldAlert className="w-4 h-4 text-red-500" />
              <div className="font-semibold text-slate-900 truncate">{a.name}</div>
            </div>
            <div className="text-xs text-slate-500 space-y-0.5">
              {a.motivation && <div>{a.motivation}</div>}
              {a.origin_country && <div>{a.origin_country}</div>}
            </div>
          </Link>
          <button
            type="button"
            onClick={() => remove(a.slug)}
            data-testid={`bookmark-remove-${a.slug}`}
            className="opacity-0 group-hover:opacity-100 text-slate-400 hover:text-red-600 transition-all"
            aria-label="Remove bookmark"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      ))}
    </div>
  );
}

function WatchlistTab() {
  const [items, setItems] = useState(null);
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.get("/me/watchlist").then(({ data }) => setItems(data.watchlist || [])).catch(() => setItems([]));
  }, []);
  useEffect(() => { load(); }, [load]);

  const add = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      const { data } = await api.post("/me/watchlist", { value: value.trim(), note: note.trim() || null });
      setItems((xs) => [data, ...(xs || [])]);
      setValue(""); setNote("");
      toast.success(data.curated_match ? `Added — hit in NivX curated DB (${data.curated_match.severity || "n/a"})` : "Added to watchlist");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to add");
    } finally {
      setBusy(false);
    }
  };

  const remove = async (v) => {
    try {
      await api.delete(`/me/watchlist/${encodeURIComponent(v)}`);
      setItems((xs) => xs.filter((w) => w.value !== v));
      toast.success("Removed");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed");
    }
  };

  return (
    <div data-testid="watchlist-tab">
      <form onSubmit={add} className="flex flex-col sm:flex-row gap-2 mb-4">
        <input
          type="text"
          data-testid="watchlist-input-value"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          required
          placeholder="Hash · IP · Domain · URL (e.g. 8.8.8.8, evil[.]com)"
          className="flex-1 min-w-0 px-3 py-2 rounded-md border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none text-sm"
        />
        <input
          type="text"
          data-testid="watchlist-input-note"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Optional note"
          maxLength={280}
          className="sm:w-48 px-3 py-2 rounded-md border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none text-sm"
        />
        <button
          type="submit"
          disabled={busy || !value.trim()}
          data-testid="watchlist-add-btn"
          className="inline-flex items-center justify-center gap-1.5 bg-slate-900 hover:bg-[#2E7DF5] text-white text-sm font-semibold px-4 py-2 rounded-md transition-colors disabled:opacity-60"
        >
          <Plus className="w-4 h-4" /> Add
        </button>
      </form>

      {items === null ? (
        <div className="flex items-center gap-2 text-slate-500 py-8"><Loader2 className="w-4 h-4 animate-spin" /> Loading…</div>
      ) : items.length === 0 ? (
        <div className="text-center py-12" data-testid="watchlist-empty">
          <Eye className="w-10 h-10 text-slate-300 mx-auto mb-3" />
          <div className="text-slate-700 font-semibold mb-1">Your watchlist is empty</div>
          <div className="text-sm text-slate-500">Add up to 100 IOCs to track them across NivX feeds.</div>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-200">
          <table className="w-full text-sm" data-testid="watchlist-list">
            <thead>
              <tr className="text-left text-[10px] uppercase tracking-wider text-slate-500 bg-slate-50 border-b border-slate-200">
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Value</th>
                <th className="px-3 py-2">Note</th>
                <th className="px-3 py-2">Added</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {items.map((w) => (
                <tr key={w.key || w.value} className="hover:bg-slate-50">
                  <td className="px-3 py-2"><span className="text-[10px] font-mono uppercase bg-slate-100 rounded px-1.5 py-0.5">{w.type || "?"}</span></td>
                  <td className="px-3 py-2"><code className="text-xs font-mono text-slate-800 break-all">{w.value}</code></td>
                  <td className="px-3 py-2 text-xs text-slate-600">{w.note || "—"}</td>
                  <td className="px-3 py-2 text-[11px] text-slate-500 font-mono whitespace-nowrap">{(w.added_at || "").slice(0, 10)}</td>
                  <td className="px-3 py-2">
                    <button onClick={() => remove(w.value)} data-testid={`watchlist-remove-${w.key || w.value}`} className="text-slate-400 hover:text-red-600" aria-label="Remove">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="mt-3 text-[11px] text-slate-400 flex items-center gap-1.5">
        <Fingerprint className="w-3.5 h-3.5" />
        Coming soon: email alerts when your watchlist entries match a NivX feed sync.
      </div>
    </div>
  );
}

function ChangePasswordTab() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault();
    if (next !== confirm) {
      toast.error("New passwords do not match");
      return;
    }
    if (next.length < 8 || !/[a-zA-Z]/.test(next) || !/\d/.test(next)) {
      toast.error("Password must be 8+ characters with at least one letter and one digit");
      return;
    }
    setBusy(true);
    try {
      await api.post("/auth/change-password", { current_password: current, new_password: next });
      toast.success("Password changed. Sign in again next time with the new one.");
      setCurrent(""); setNext(""); setConfirm("");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to change password");
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} className="max-w-md space-y-4" data-testid="me-change-password">
      <div>
        <label className="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1.5">Current password</label>
        <input type="password" data-testid="pw-current" required value={current} onChange={(e) => setCurrent(e.target.value)}
               className="w-full px-3 py-2.5 rounded-md border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none text-sm" autoComplete="current-password" />
      </div>
      <div>
        <label className="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1.5">New password</label>
        <input type="password" data-testid="pw-new" required minLength={8} value={next} onChange={(e) => setNext(e.target.value)}
               placeholder="8+ chars, letter + digit"
               className="w-full px-3 py-2.5 rounded-md border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none text-sm" autoComplete="new-password" />
      </div>
      <div>
        <label className="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1.5">Confirm new password</label>
        <input type="password" data-testid="pw-confirm" required minLength={8} value={confirm} onChange={(e) => setConfirm(e.target.value)}
               className="w-full px-3 py-2.5 rounded-md border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none text-sm" autoComplete="new-password" />
      </div>
      <button type="submit" disabled={busy} data-testid="pw-submit"
              className="inline-flex items-center gap-2 bg-slate-900 hover:bg-[#2E7DF5] text-white text-sm font-semibold px-5 py-2.5 rounded-md transition-colors disabled:opacity-60">
        {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4" />} Update password
      </button>
      <div className="text-[11px] text-slate-400 pt-3 border-t border-slate-100 flex items-start gap-1.5">
        <AlertTriangle className="w-3.5 h-3.5 mt-px shrink-0" />
        Passwords are stored as one-way bcrypt hashes — nobody, including NivX admins, can view your password.
      </div>
    </form>
  );
}

export default function UserDashboard() {
  const { user } = useAuth();
  const [params, setParams] = useSearchParams();
  const rawTab = params.get("tab");
  const tab = rawTab === "watchlist" ? "watchlist" : rawTab === "password" ? "password" : "bookmarks";

  useSeo({ title: "My NivX — Bookmarks & Watchlist", description: "Manage your ThreatBox bookmarks and IOC watchlist." });

  if (user === null) {
    return <div className="min-h-screen flex items-center justify-center bg-slate-50"><Loader2 className="w-6 h-6 animate-spin text-[#2E7DF5]" /></div>;
  }
  if (!user || !user.id) return <Navigate to="/login" replace state={{ from: "/me" }} />;

  // Redirect staff away from the user dashboard
  const role = (user.role || "user").toLowerCase();
  if (role === "admin") return <Navigate to="/admin" replace />;
  if (role === "employee") return <Navigate to="/employee" replace />;

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <main className="mx-auto max-w-5xl px-6 py-10" data-testid="user-dashboard">
        <div className="mb-6">
          <div className="text-xs font-mono uppercase tracking-widest text-[#F5821F] mb-2">My NivX</div>
          <h1 className="text-3xl font-bold text-slate-900">Welcome{user.name ? `, ${user.name}` : ""}</h1>
          <p className="text-sm text-slate-500 mt-1">{user.email}</p>
        </div>

        <div className="border-b border-slate-200 mb-6">
          <TabBtn id="bookmarks" active={tab} onClick={(id) => setParams({ tab: id })} icon={Bookmark} label="Bookmarks" />
          <TabBtn id="watchlist" active={tab} onClick={(id) => setParams({ tab: id })} icon={Eye} label="IOC Watchlist" />
          <TabBtn id="password"  active={tab} onClick={(id) => setParams({ tab: id })} icon={KeyRound} label="Password" />
        </div>

        {tab === "bookmarks" ? <BookmarksTab /> : tab === "watchlist" ? <WatchlistTab /> : <ChangePasswordTab />}

        <div className="mt-8 text-xs text-slate-400 flex items-center gap-1.5">
          <AlertTriangle className="w-3.5 h-3.5" />
          Your data is private to your account. Only you can see your bookmarks and watchlist.
        </div>
      </main>
    </div>
  );
}
