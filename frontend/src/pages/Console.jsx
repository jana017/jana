/**
 * NivX Console — standalone tools platform.
 *
 * Renders Threat Intelligence + NivX Forge as two tabs with a minimal top bar
 * and NO link back to the marketing site. Intended to be served from a
 * dedicated subdomain (e.g. console.nivxmachines.com → /console).
 */
import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Wrench, Loader2, LogOut } from "lucide-react";
import { toast } from "sonner";
import ThreatIntelligence from "@/pages/ThreatIntelligence";
import CyberLab from "@/pages/CyberLab";
import { api } from "@/lib/api";
import { getToken, clearToken } from "@/lib/auth";

const TABS = [
  { key: "ti",    label: "Threat Intelligence", icon: Shield },
  { key: "forge", label: "NivX Forge",          icon: Wrench },
];

const ALLOWED_ROLES = new Set(["admin", "employee"]);

export default function Console() {
  const navigate = useNavigate();
  const [authState, setAuthState] = useState("checking"); // checking | ok | denied
  const [profile, setProfile] = useState(null);

  // ---- Role gate: only admins and employees may access the console.
  useEffect(() => {
    let alive = true;
    (async () => {
      if (!getToken()) {
        navigate("/login", { replace: true, state: { from: "/console" } });
        return;
      }
      try {
        const { data } = await api.get("/auth/me");
        if (!alive) return;
        const role = (data?.role || "").toLowerCase();
        if (!ALLOWED_ROLES.has(role)) {
          setAuthState("denied");
          return;
        }
        setProfile(data);
        setAuthState("ok");
      } catch (err) {
        if (!alive) return;
        if (err?.response?.status === 401 || err?.response?.status === 403) {
          clearToken();
          navigate("/login", { replace: true, state: { from: "/console" } });
        } else {
          toast.error("Could not verify session");
          setAuthState("denied");
        }
      }
    })();
    return () => { alive = false; };
  }, [navigate]);

  const logout = useCallback(() => {
    clearToken();
    navigate("/login", { replace: true });
  }, [navigate]);
  // Persist the active tab across reloads so a bookmark like ?tab=forge works too.
  const [active, setActive] = useState(() => {
    if (typeof window === "undefined") return "ti";
    const q = new URLSearchParams(window.location.search).get("tab");
    if (q && TABS.some((t) => t.key === q)) return q;
    return sessionStorage.getItem("nivx-console-tab") || "ti";
  });

  useEffect(() => {
    try { sessionStorage.setItem("nivx-console-tab", active); } catch { /* noop */ }
    const url = new URL(window.location.href);
    url.searchParams.set("tab", active);
    window.history.replaceState(null, "", url.toString());
  }, [active]);

  if (authState === "checking") {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950" data-testid="console-loading">
        <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
      </div>
    );
  }

  if (authState === "denied") {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950 p-6" data-testid="console-denied">
        <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-xl p-8 text-center">
          <Shield className="w-10 h-10 mx-auto text-amber-400" />
          <h2 className="mt-3 text-lg font-semibold text-slate-100">Restricted Console</h2>
          <p className="mt-2 text-sm text-slate-400">
            NivX Console is available to authorized analysts and admins only. Your account does not have access.
          </p>
          <div className="mt-6 flex items-center justify-center gap-2">
            <button
              onClick={() => navigate("/", { replace: true })}
              className="px-3 py-2 rounded-md bg-slate-800 text-slate-100 text-sm hover:bg-slate-700"
              data-testid="console-denied-home"
            >
              Back to Home
            </button>
            <button
              onClick={logout}
              className="px-3 py-2 rounded-md bg-cyan-500 text-slate-950 text-sm font-semibold hover:bg-cyan-400"
              data-testid="console-denied-signout"
            >
              Sign out
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100" data-testid="nivx-console">
      {/* Minimal top bar — brand + tabs. No marketing links. */}
      <header className="sticky top-0 z-30 border-b border-slate-800 bg-slate-950/95 backdrop-blur">
        <div className="mx-auto max-w-[1600px] px-6 h-14 flex items-center gap-6">
          <div className="flex items-center gap-2">
            <img src="/nivx-forge-icon.svg" alt="NivX" className="w-7 h-7" onError={(e) => { e.currentTarget.style.display = "none"; }} />
            <span className="font-heading text-lg font-semibold text-slate-100 tracking-tight">NivX Console</span>
          </div>
          <nav className="flex items-center gap-1" role="tablist">
            {TABS.map((t) => {
              const Icon = t.icon;
              const on = active === t.key;
              return (
                <button
                  key={t.key}
                  role="tab"
                  aria-selected={on}
                  onClick={() => setActive(t.key)}
                  data-testid={`console-tab-${t.key}`}
                  className={`inline-flex items-center gap-2 h-14 px-4 text-sm font-semibold border-b-2 transition-colors ${
                    on
                      ? "border-cyan-400 text-cyan-300"
                      : "border-transparent text-slate-400 hover:text-slate-100"
                  }`}
                >
                  <Icon className="w-4 h-4" /> {t.label}
                </button>
              );
            })}
          </nav>
          <div className="ml-auto flex items-center gap-3">
            {profile && (
              <span className="hidden sm:inline text-xs text-slate-400" data-testid="console-user-label">
                {profile.email} · <span className="text-cyan-300 font-medium uppercase tracking-wide">{profile.role}</span>
              </span>
            )}
            <button
              onClick={logout}
              data-testid="console-logout"
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-semibold text-slate-300 hover:text-white hover:bg-slate-800 border border-slate-800"
            >
              <LogOut className="w-3.5 h-3.5" /> Sign out
            </button>
          </div>
        </div>
      </header>

      <main className={active === "ti" ? "bg-white text-slate-900" : ""}>
        {active === "ti"    && <ThreatIntelligence hideChrome />}
        {active === "forge" && <CyberLab           hideChrome />}
      </main>
    </div>
  );
}
