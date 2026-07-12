/**
 * AdminSecurityAccess — Admin "Security & Access" panel.
 *
 * Lists every user account (admin, employee, public user) with password-hygiene
 * metadata. Admin can:
 *   • Force reset any user's password (backend generates a 16-char temp)
 *   • Toggle "must change password on next login"
 *   • Change their own password (via /auth/change-password)
 *
 * NEVER shows the raw password hash — bcrypt is one-way. The generated temp
 * password is displayed exactly ONCE after reset (admin must copy it and
 * deliver it out-of-band to the target user).
 */
import { useCallback, useEffect, useState } from "react";
import { KeyRound, RefreshCw, ShieldAlert, Loader2, Copy, Check, AlertTriangle, Users, Clock } from "lucide-react";
import { toast } from "sonner";
import { api } from "@/lib/api";

const ROLE_TONE = {
  admin:    "bg-red-50 text-red-700 border-red-200",
  employee: "bg-blue-50 text-blue-700 border-blue-200",
  user:     "bg-slate-50 text-slate-700 border-slate-200",
};

function relativeTime(iso) {
  if (!iso) return "never";
  const d = new Date(iso);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  const days = Math.floor(diff / 86400);
  if (days < 30) return `${days}d ago`;
  return d.toISOString().slice(0, 10);
}

function TempPasswordModal({ result, onClose }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(result.new_password);
    setCopied(true);
    toast.success("Password copied to clipboard");
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4" data-testid="temp-password-modal">
      <div className="w-full max-w-md bg-white rounded-xl shadow-2xl p-6">
        <div className="flex items-center gap-2 mb-2">
          <KeyRound className="w-5 h-5 text-[#F5821F]" />
          <h3 className="text-lg font-bold text-slate-900">Temporary password generated</h3>
        </div>
        <p className="text-sm text-slate-500 mb-4">
          Password for <strong>{result.target_email}</strong>. This value is shown <strong>only once</strong> — copy it now and deliver it to the user securely (Signal, phone, in-person). NivX will never display it again.
        </p>
        <div className="flex items-center gap-2 mb-4">
          <code className="flex-1 font-mono text-sm bg-slate-900 text-emerald-300 px-3 py-2.5 rounded-md break-all" data-testid="temp-password-value">
            {result.new_password}
          </code>
          <button onClick={copy} data-testid="temp-password-copy" className="inline-flex items-center gap-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold px-3 py-2.5 rounded-md">
            {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />} Copy
          </button>
        </div>
        <div className="text-[11px] text-slate-400 bg-amber-50 border border-amber-200 rounded-md p-2.5 flex gap-2 mb-4">
          <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
          <span>User will be required to change this password on next login ({result.must_change_password ? "enforced" : "optional"}).</span>
        </div>
        <button onClick={onClose} data-testid="temp-password-close" className="w-full bg-slate-900 hover:bg-slate-700 text-white text-sm font-semibold py-2.5 rounded-md">
          I have saved the password
        </button>
      </div>
    </div>
  );
}

export default function AdminSecurityAccess({ currentAdminId }) {
  const [users, setUsers] = useState(null);
  const [busy, setBusy] = useState(false);
  const [tempResult, setTempResult] = useState(null);
  const [filterRole, setFilterRole] = useState("all");

  const load = useCallback(() => {
    api.get("/admin/users")
      .then(({ data }) => setUsers(data.users || []))
      .catch((e) => toast.error(e.response?.data?.detail || "Failed to load users"));
  }, []);
  useEffect(() => { load(); }, [load]);

  const forceReset = async (u) => {
    if (!window.confirm(`Force-reset password for ${u.email}? A new temp password will be generated and shown once.`)) return;
    setBusy(true);
    try {
      const { data } = await api.post(`/admin/users/${u.id}/reset-password`, { must_change: true });
      setTempResult(data);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Reset failed");
    } finally {
      setBusy(false);
    }
  };

  const toggleMustChange = async (u) => {
    setBusy(true);
    try {
      await api.post(`/admin/users/${u.id}/must-change-password?force=${!u.must_change_password}`);
      toast.success(u.must_change_password ? "Force-change flag cleared" : "User must change password on next login");
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed");
    } finally {
      setBusy(false);
    }
  };

  const filtered = users?.filter((u) => filterRole === "all" || u.role === filterRole) || [];
  const stats = {
    total: users?.length || 0,
    admin: users?.filter((u) => u.role === "admin").length || 0,
    employee: users?.filter((u) => u.role === "employee").length || 0,
    user: users?.filter((u) => u.role === "user").length || 0,
    mustChange: users?.filter((u) => u.must_change_password).length || 0,
  };

  return (
    <div className="space-y-6" data-testid="admin-security-access">
      <div>
        <h2 className="text-xl font-bold text-slate-900 flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-[#F5821F]" /> Security &amp; Access
        </h2>
        <p className="text-sm text-slate-500 mt-1">
          Manage account passwords across admins, employees, and public users. Passwords are stored as one-way bcrypt hashes — nobody can view them. Only reset actions are possible.
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {[
          { label: "Total accounts", value: stats.total, icon: Users, tone: "text-slate-700" },
          { label: "Admins", value: stats.admin, icon: ShieldAlert, tone: "text-red-600" },
          { label: "Employees", value: stats.employee, icon: Users, tone: "text-blue-600" },
          { label: "Public users", value: stats.user, icon: Users, tone: "text-slate-600" },
          { label: "Must-change", value: stats.mustChange, icon: AlertTriangle, tone: "text-amber-600" },
        ].map((s) => (
          <div key={s.label} className="rounded-lg border border-slate-200 bg-white p-3">
            <div className={`text-2xl font-bold ${s.tone}`}>{s.value}</div>
            <div className="text-[11px] uppercase tracking-wider text-slate-500 mt-1 flex items-center gap-1"><s.icon className="w-3 h-3" /> {s.label}</div>
          </div>
        ))}
      </div>

      {/* Filter */}
      <div className="flex items-center gap-2">
        {["all", "admin", "employee", "user"].map((r) => (
          <button key={r} onClick={() => setFilterRole(r)} data-testid={`sec-filter-${r}`}
                  className={`px-3 py-1.5 rounded-md text-xs font-semibold border transition-colors ${
                    filterRole === r ? "bg-slate-900 text-white border-slate-900" : "bg-white text-slate-600 border-slate-200 hover:border-[#2E7DF5]"
                  }`}>
            {r === "all" ? "All" : r.charAt(0).toUpperCase() + r.slice(1)}s
          </button>
        ))}
        <div className="ml-auto text-xs text-slate-500">
          {users === null ? "loading…" : `${filtered.length} shown`}
        </div>
      </div>

      {/* Table */}
      {users === null ? (
        <div className="flex items-center gap-2 text-sm text-slate-500 py-8"><Loader2 className="w-4 h-4 animate-spin" /> Loading users…</div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr className="text-left text-[10px] uppercase tracking-wider text-slate-500">
                <th className="px-3 py-2.5">User</th>
                <th className="px-3 py-2.5">Role</th>
                <th className="px-3 py-2.5">Password changed</th>
                <th className="px-3 py-2.5">Status</th>
                <th className="px-3 py-2.5">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100" data-testid="sec-users-table">
              {filtered.map((u) => {
                const isSelf = u.id === currentAdminId;
                return (
                  <tr key={u.id} className="hover:bg-slate-50" data-testid={`sec-user-row-${u.id}`}>
                    <td className="px-3 py-3">
                      <div className="font-semibold text-slate-900">{u.name || "—"}</div>
                      <div className="text-xs text-slate-500">{u.email}{isSelf && <span className="ml-1 text-[10px] text-[#2E7DF5]">(you)</span>}</div>
                    </td>
                    <td className="px-3 py-3">
                      <span className={`text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${ROLE_TONE[u.role] || ROLE_TONE.user}`}>{u.role}</span>
                    </td>
                    <td className="px-3 py-3 text-xs text-slate-600">
                      <div className="flex items-center gap-1"><Clock className="w-3 h-3 text-slate-400" /> {relativeTime(u.password_changed_at)}</div>
                    </td>
                    <td className="px-3 py-3 text-xs">
                      {u.must_change_password ? (
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200">
                          <AlertTriangle className="w-3 h-3" /> Must change on next login
                        </span>
                      ) : (
                        <span className="text-slate-400">—</span>
                      )}
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          disabled={busy || isSelf}
                          onClick={() => forceReset(u)}
                          data-testid={`sec-reset-${u.id}`}
                          title={isSelf ? "Use the Password tab in /me to change your own password" : "Force-reset password"}
                          className="inline-flex items-center gap-1 text-xs font-semibold px-2.5 py-1.5 rounded-md bg-white border border-slate-200 text-slate-700 hover:border-red-300 hover:text-red-600 hover:bg-red-50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                          <RefreshCw className="w-3.5 h-3.5" /> Reset
                        </button>
                        <button
                          disabled={busy || isSelf}
                          onClick={() => toggleMustChange(u)}
                          data-testid={`sec-toggle-${u.id}`}
                          title={u.must_change_password ? "Clear force-change flag" : "Force user to change password on next login"}
                          className={`inline-flex items-center gap-1 text-xs font-semibold px-2.5 py-1.5 rounded-md border transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
                            u.must_change_password
                              ? "bg-amber-50 border-amber-200 text-amber-700 hover:bg-white"
                              : "bg-white border-slate-200 text-slate-700 hover:border-amber-300 hover:text-amber-600"
                          }`}
                        >
                          <KeyRound className="w-3.5 h-3.5" /> {u.must_change_password ? "Clear flag" : "Require change"}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {filtered.length === 0 && (
                <tr><td colSpan={5} className="px-3 py-8 text-center text-sm text-slate-400">No users match the filter.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      <div className="text-[11px] text-slate-400 flex items-start gap-1.5">
        <AlertTriangle className="w-3.5 h-3.5 mt-px shrink-0" />
        <span>To change your own password, go to <strong>My NivX → Password</strong>. Admin cannot self-reset from this panel (requires knowledge of current password).</span>
      </div>

      {tempResult && <TempPasswordModal result={tempResult} onClose={() => setTempResult(null)} />}
    </div>
  );
}
