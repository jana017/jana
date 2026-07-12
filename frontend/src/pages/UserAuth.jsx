/**
 * UserAuth — /login (public User accounts).
 * Unified page with two tabs: Sign in (existing user) and Create account
 * (new sign-up). On success, redirects to previous page or /.
 *
 * Employees/Admins should use /employee and /admin respectively — those
 * have dedicated login pages with role-specific portals. This page is for
 * public visitors who want a NivX account for bookmarks & IOC watchlists.
 */
import { useState, useEffect } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { LogIn, UserPlus, Loader2, ShieldCheck, ArrowLeft, Mail, Lock, User } from "lucide-react";
import { toast } from "sonner";
import Navbar from "@/components/Navbar";
import useSeo from "@/lib/useSeo";
import { useAuth } from "@/context/AuthContext";

export default function UserAuth() {
  const { user, login, signup } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const initialTab = (location.state?.tab === "signup") ? "signup" : "login";
  const [tab, setTab] = useState(initialTab);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useSeo({
    title: tab === "signup" ? "Create a NivX Account — Sign up" : "Sign in — NivX Machines",
    description: "Sign in to your NivX account to bookmark ThreatBox actors and follow IOC watchlists.",
  });

  useEffect(() => {
    if (user && user.role) {
      const redirect = location.state?.from || "/";
      navigate(redirect, { replace: true });
    }
  }, [user, navigate, location.state]);

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    const res = tab === "signup"
      ? await signup(email.trim(), password, name.trim())
      : await login(email.trim(), password);
    setLoading(false);
    if (!res.ok) {
      setError(res.error || "Something went wrong");
      return;
    }
    toast.success(tab === "signup" ? "Account created — welcome!" : "Signed in");
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <main className="mx-auto max-w-md px-6 py-16" data-testid="user-auth-page">
        <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-[#2E7DF5] mb-6">
          <ArrowLeft className="w-4 h-4" /> Back to home
        </Link>

        <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-sm">
          <div className="text-center mb-6">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-gradient-to-br from-[#2E7DF5] to-[#F5821F] mb-3">
              <ShieldCheck className="w-6 h-6 text-white" strokeWidth={2.2} />
            </div>
            <h1 className="text-2xl font-bold text-slate-900">
              {tab === "signup" ? "Create your NivX account" : "Welcome back"}
            </h1>
            <p className="mt-1 text-sm text-slate-500">
              {tab === "signup"
                ? "Bookmark threat actors and follow IOC watchlists."
                : "Sign in to your NivX account."}
            </p>
          </div>

          <div className="grid grid-cols-2 gap-1 rounded-lg bg-slate-100 p-1 mb-6" data-testid="user-auth-tabs">
            <button
              type="button"
              onClick={() => { setTab("login"); setError(""); }}
              data-testid="user-auth-tab-login"
              className={`inline-flex items-center justify-center gap-1.5 text-sm font-semibold py-2 rounded-md transition-all ${
                tab === "login" ? "bg-white text-slate-900 shadow-sm" : "text-slate-500 hover:text-slate-700"
              }`}
            >
              <LogIn className="w-4 h-4" /> Sign in
            </button>
            <button
              type="button"
              onClick={() => { setTab("signup"); setError(""); }}
              data-testid="user-auth-tab-signup"
              className={`inline-flex items-center justify-center gap-1.5 text-sm font-semibold py-2 rounded-md transition-all ${
                tab === "signup" ? "bg-white text-slate-900 shadow-sm" : "text-slate-500 hover:text-slate-700"
              }`}
            >
              <UserPlus className="w-4 h-4" /> Create account
            </button>
          </div>

          <form onSubmit={submit} className="space-y-4" data-testid="user-auth-form">
            {tab === "signup" && (
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1.5">Name (optional)</label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                  <input
                    type="text"
                    data-testid="user-auth-name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Your name"
                    className="w-full pl-9 pr-3 py-2.5 rounded-md border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none text-sm"
                    autoComplete="name"
                  />
                </div>
              </div>
            )}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1.5">Email</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  type="email"
                  data-testid="user-auth-email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  placeholder="you@example.com"
                  className="w-full pl-9 pr-3 py-2.5 rounded-md border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none text-sm"
                  autoComplete="email"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1.5">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  type="password"
                  data-testid="user-auth-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  minLength={tab === "signup" ? 8 : undefined}
                  placeholder={tab === "signup" ? "8+ chars, letter + digit" : "Your password"}
                  className="w-full pl-9 pr-3 py-2.5 rounded-md border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none text-sm"
                  autoComplete={tab === "signup" ? "new-password" : "current-password"}
                />
              </div>
              {tab === "signup" && (
                <div className="text-[11px] text-slate-400 mt-1">Minimum 8 characters, at least 1 letter and 1 digit.</div>
              )}
            </div>

            {error && (
              <div data-testid="user-auth-error" className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              data-testid="user-auth-submit"
              className="w-full inline-flex items-center justify-center gap-2 bg-slate-900 hover:bg-[#2E7DF5] text-white text-sm font-semibold py-2.5 rounded-md transition-all disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : (tab === "signup" ? <UserPlus className="w-4 h-4" /> : <LogIn className="w-4 h-4" />)}
              {tab === "signup" ? "Create account" : "Sign in"}
            </button>

            <div className="text-center text-xs text-slate-500 pt-2 border-t border-slate-100">
              Are you a NivX staff member?
              <Link to="/employee" className="ml-1 text-[#2E7DF5] hover:underline font-medium">Employee login</Link>
              <span className="mx-1 text-slate-300">·</span>
              <Link to="/admin" className="text-[#2E7DF5] hover:underline font-medium">Admin login</Link>
            </div>
          </form>
        </div>
      </main>
    </div>
  );
}
