import { useState, useEffect } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { useLenis } from "lenis/react";
import { Menu, X, ShieldCheck, FileSearch, LayoutGrid, GraduationCap, Briefcase, LifeBuoy, LogIn, Bookmark, Eye, LogOut, User as UserIcon } from "lucide-react";
import { prefetchRoute } from "@/lib/routePrefetch";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { useAuth } from "@/context/AuthContext";

const SECTION_LINKS = [
  { label: "About", id: "about" },
  { label: "Services", id: "services" },
  { label: "Gallery", id: "gallery" },
];

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const lenis = useLenis();
  const { user, logout } = useAuth();

  // Only treat as signed-in when we have a real user object.
  const signedIn = Boolean(user && typeof user === "object" && user.id);
  const initials = signedIn
    ? (user.name || user.email || "?").trim().split(/\s+/).map((s) => s[0]).slice(0, 2).join("").toUpperCase()
    : "";
  const roleBadge = signedIn ? (user.role || "user").toLowerCase() : "";
  const roleTone = roleBadge === "admin"
    ? "bg-red-50 text-red-700 border-red-200"
    : roleBadge === "employee"
      ? "bg-blue-50 text-blue-700 border-blue-200"
      : "bg-slate-50 text-slate-700 border-slate-200";

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // Warm up all lazy chunks once the initial route is idle — makes every
  // subsequent nav-click near-instant regardless of which link the user hits first.
  useEffect(() => {
    const idle = window.requestIdleCallback || ((cb) => setTimeout(cb, 800));
    const handle = idle(() => {
      ["/blog", "/learn", "/threat-intelligence", "/cybersecurity-101", "/nivx-forge", "/threatbox", "/employee", "/admin"].forEach(prefetchRoute);
    });
    return () => {
      if (window.cancelIdleCallback) window.cancelIdleCallback(handle);
    };
  }, []);

  const go = (id) => {
    setOpen(false);
    if (location.pathname !== "/") {
      sessionStorage.setItem("scrollTo", id);
      navigate("/");
      return;
    }
    const el = document.getElementById(id);
    if (!el) return;
    // Fast snap (~350ms) instead of the default long ease.
    if (lenis) lenis.scrollTo(el, { offset: -70, duration: 0.35 });
    else el.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const isIntel = location.pathname === "/threat-intelligence";
  const isKb = location.pathname.startsWith("/cybersecurity-101");
  const isBlog = location.pathname === "/blog" || location.pathname.startsWith("/blog/");
  const isLearn = location.pathname.startsWith("/learn") || isKb || isBlog;

  return (
    <header
      data-testid="main-navbar"
      className={`fixed top-0 left-0 right-0 z-50 transition-shadow duration-300 bg-white/90 backdrop-blur-md border-b border-slate-200 ${scrolled ? "shadow-sm" : ""}`}
    >
      <nav className="mx-auto max-w-7xl px-6 h-16 flex items-center justify-between">
        <button data-testid="logo-home" onClick={() => navigate("/")} className="flex items-center">
          <img src="/nivx-logo-light.png" alt="NivX Machines" className="h-8 w-auto object-contain" />
        </button>

        <div className="hidden lg:flex items-center gap-7">
          {SECTION_LINKS.map((l) => (
            <button key={l.id} data-testid={`nav-${l.id}`} onClick={() => go(l.id)} className="text-sm font-medium text-slate-600 hover:text-slate-900 transition-colors">
              {l.label}
            </button>
          ))}
          <Link
            to="/threat-intelligence"
            data-testid="nav-threat-intelligence"
            onMouseEnter={() => prefetchRoute("/threat-intelligence")}
            onFocus={() => prefetchRoute("/threat-intelligence")}
            className="group relative inline-flex items-center gap-1.5 text-sm font-bold transition-all hover:-translate-y-0.5"
          >
            <span
              className="relative flex h-2 w-2"
              aria-hidden="true"
            >
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-500 opacity-70"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-red-500 ring-2 ring-red-100"></span>
            </span>
            <span
              className="bg-gradient-to-r from-[#0F172A] via-[#F5821F] to-[#F5821F] bg-clip-text text-transparent bg-[length:200%_100%] bg-[position:0%_50%] group-hover:bg-[position:100%_50%] transition-[background-position] duration-500"
            >
              Threat Intelligence
            </span>
            <span
              aria-hidden="true"
              className={`absolute -bottom-1 left-0 h-[2px] bg-gradient-to-r from-[#F5821F] to-[#DC2626] transition-all duration-300 ${isIntel ? "w-full" : "w-0 group-hover:w-full"}`}
            ></span>
          </Link>
          <Link
            to="/nivx-forge"
            data-testid="nav-cyberlab"
            onMouseEnter={() => prefetchRoute("/nivx-forge")}
            onFocus={() => prefetchRoute("/nivx-forge")}
            className="group relative inline-flex items-center gap-2 text-sm font-bold transition-all hover:-translate-y-0.5"
          >
            <img
              src="/favicon-32x32.png"
              alt=""
              aria-hidden="true"
              width="18"
              height="18"
              className="shrink-0 rounded-[3px] group-hover:scale-110 transition-transform"
              style={{ marginRight: "0px" }}
            />
            <span
              className="bg-gradient-to-r from-[#2E7DF5] via-[#2E7DF5] to-[#F5821F] bg-clip-text text-transparent bg-[length:200%_100%] bg-[position:0%_50%] group-hover:bg-[position:100%_50%] transition-[background-position] duration-500"
            >
              NivX Forge
            </span>
            <span
              aria-hidden="true"
              className={`absolute -bottom-1 left-0 h-[2px] bg-gradient-to-r from-[#2E7DF5] to-[#F5821F] transition-all duration-300 ${(location.pathname === "/nivx-forge" || location.pathname === "/cyberlab") ? "w-full" : "w-0 group-hover:w-full"}`}
            ></span>
          </Link>
          <Link
            to="/threatbox"
            data-testid="nav-threatbox"
            onMouseEnter={() => prefetchRoute("/threatbox")}
            onFocus={() => prefetchRoute("/threatbox")}
            className="group relative inline-flex items-center gap-1.5 text-sm font-bold transition-all hover:-translate-y-0.5"
          >
            <FileSearch
              className="w-3.5 h-3.5 text-[#DC2626] drop-shadow-[0_0_6px_rgba(220,38,38,0.45)] group-hover:text-[#F5821F] group-hover:drop-shadow-[0_0_8px_rgba(245,130,31,0.55)] transition-all"
              strokeWidth={2.4}
            />
            <span
              className="bg-gradient-to-r from-[#DC2626] via-[#0F172A] to-[#F5821F] bg-clip-text text-transparent bg-[length:200%_100%] bg-[position:0%_50%] group-hover:bg-[position:100%_50%] transition-[background-position] duration-500"
            >
              ThreatBox
            </span>
            <span
              aria-hidden="true"
              className={`absolute -bottom-1 left-0 h-[2px] bg-gradient-to-r from-[#DC2626] to-[#F5821F] transition-all duration-300 ${location.pathname.startsWith("/threatbox") || location.pathname.startsWith("/actors") ? "w-full" : "w-0 group-hover:w-full"}`}
            ></span>
          </Link>
        </div>

        <div className="flex items-center gap-3">
          <Popover>
            <PopoverTrigger asChild>
              <button
                data-testid="nav-more-menu"
                aria-label="More links"
                className="hidden lg:inline-flex items-center justify-center w-9 h-9 rounded-lg border border-slate-200 bg-white text-slate-600 hover:text-slate-900 hover:border-[#2E7DF5] hover:shadow-sm transition-all group"
              >
                <LayoutGrid className="w-4 h-4 group-hover:text-[#2E7DF5] transition-colors" strokeWidth={2.2} />
              </button>
            </PopoverTrigger>
            <PopoverContent align="end" sideOffset={10} className="w-64 p-2 bg-white/95 backdrop-blur-md border-slate-200 shadow-lg">
              <div className="px-2 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-400">More</div>
              <Link
                to="/learn"
                data-testid="more-menu-learn"
                onMouseEnter={() => prefetchRoute("/learn")}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-all ${isLearn ? "bg-blue-50 text-[#2E7DF5]" : "text-slate-700 hover:bg-slate-50 hover:text-slate-900"}`}
              >
                <GraduationCap className="w-4 h-4 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div>Learn</div>
                  <div className="text-[11px] text-slate-400 font-normal">Blog · Cyber 101 · SOC playbooks</div>
                </div>
              </Link>
              <button
                type="button"
                data-testid="more-menu-careers"
                onClick={() => go("careers")}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium text-left text-slate-700 hover:bg-slate-50 hover:text-slate-900 transition-all"
              >
                <Briefcase className="w-4 h-4 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div>Careers</div>
                  <div className="text-[11px] text-slate-400 font-normal">Join the NivX team</div>
                </div>
              </button>
              <button
                type="button"
                data-testid="more-menu-support"
                onClick={() => go("support")}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium text-left text-slate-700 hover:bg-slate-50 hover:text-slate-900 transition-all"
              >
                <LifeBuoy className="w-4 h-4 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div>Support</div>
                  <div className="text-[11px] text-slate-400 font-normal">Get in touch with our team</div>
                </div>
              </button>
            </PopoverContent>
          </Popover>

          {/* Signed-in avatar or Login button — depends on auth state */}
          {signedIn ? (
            <Popover>
              <PopoverTrigger asChild>
                <button
                  data-testid="nav-user-avatar"
                  className="hidden lg:inline-flex items-center gap-2 pl-1 pr-3 py-1 rounded-full border border-slate-200 bg-white hover:border-[#2E7DF5] hover:shadow-sm transition-all"
                >
                  <span className="inline-flex items-center justify-center w-7 h-7 rounded-full bg-gradient-to-br from-[#2E7DF5] to-[#F5821F] text-white text-[11px] font-bold">
                    {initials || <UserIcon className="w-3.5 h-3.5" />}
                  </span>
                  <span className="text-sm font-semibold text-slate-700 max-w-[8rem] truncate">{user.name || user.email}</span>
                </button>
              </PopoverTrigger>
              <PopoverContent align="end" sideOffset={10} className="w-64 p-2 bg-white/95 backdrop-blur-md border-slate-200 shadow-lg">
                <div className="px-3 py-2 border-b border-slate-100 mb-1">
                  <div className="text-sm font-semibold text-slate-900 truncate">{user.name || "NivX user"}</div>
                  <div className="text-xs text-slate-500 truncate">{user.email}</div>
                  <span className={`inline-block mt-1.5 text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${roleTone}`}>{roleBadge}</span>
                </div>
                {roleBadge === "user" && (
                  <>
                    <Link
                      to="/me"
                      data-testid="user-menu-bookmarks"
                      className="flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-slate-700 hover:bg-slate-50 hover:text-slate-900 transition-colors"
                    >
                      <Bookmark className="w-4 h-4" /> My bookmarks
                    </Link>
                    <Link
                      to="/me?tab=watchlist"
                      data-testid="user-menu-watchlist"
                      className="flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-slate-700 hover:bg-slate-50 hover:text-slate-900 transition-colors"
                    >
                      <Eye className="w-4 h-4" /> IOC watchlist
                    </Link>
                  </>
                )}
                {roleBadge === "employee" && (
                  <Link
                    to="/employee"
                    data-testid="user-menu-portal"
                    className="flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-slate-700 hover:bg-slate-50 hover:text-slate-900 transition-colors"
                  >
                    <UserIcon className="w-4 h-4" /> Employee portal
                  </Link>
                )}
                {roleBadge === "admin" && (
                  <Link
                    to="/admin"
                    data-testid="user-menu-admin"
                    className="flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-slate-700 hover:bg-slate-50 hover:text-slate-900 transition-colors"
                  >
                    <ShieldCheck className="w-4 h-4" /> Admin console
                  </Link>
                )}
                <button
                  type="button"
                  onClick={() => { logout(); navigate("/"); }}
                  data-testid="user-menu-logout"
                  className="w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-red-600 hover:bg-red-50 transition-colors text-left"
                >
                  <LogOut className="w-4 h-4" /> Log out
                </button>
              </PopoverContent>
            </Popover>
          ) : (
            <Link
              to="/login"
              data-testid="nav-login-btn"
              onMouseEnter={() => prefetchRoute("/login")}
              onFocus={() => prefetchRoute("/login")}
              className="hidden lg:inline-flex items-center gap-1.5 px-4 py-2 rounded-md bg-slate-900 hover:bg-[#2E7DF5] text-white text-sm font-semibold transition-all hover:shadow-md hover:-translate-y-0.5"
            >
              <LogIn className="w-4 h-4" strokeWidth={2.2} /> Login
            </Link>
          )}

          <button data-testid="mobile-menu-toggle" aria-label={open ? "Close menu" : "Open menu"} className="lg:hidden inline-flex items-center justify-center w-11 h-11 -mr-1 rounded-md text-slate-700 hover:bg-slate-100 transition-colors" onClick={() => setOpen((o) => !o)}>
            {open ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </nav>

      {open && (
        <div className="lg:hidden bg-white border-t border-slate-200 px-6 py-5 flex flex-col gap-4" data-testid="mobile-menu">
          {SECTION_LINKS.map((l) => (
            <button key={l.id} onClick={() => go(l.id)} className="text-left text-sm font-medium text-slate-700">{l.label}</button>
          ))}
          <button data-testid="mobile-nav-careers" onClick={() => { go("careers"); setOpen(false); }} className="text-left text-sm font-medium text-slate-700">Careers</button>
          <button data-testid="mobile-nav-support" onClick={() => { go("support"); setOpen(false); }} className="text-left text-sm font-medium text-slate-700">Support</button>
          <Link to="/learn" onClick={() => setOpen(false)} className="text-left text-sm font-medium text-slate-700">Learn</Link>
          <Link to="/threat-intelligence" onClick={() => setOpen(false)} className="inline-flex items-center gap-2 text-left text-sm font-bold">
            <span className="relative flex h-2 w-2" aria-hidden="true">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-500 opacity-70"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-red-500"></span>
            </span>
            <span className="bg-gradient-to-r from-[#0F172A] to-[#F5821F] bg-clip-text text-transparent">
              Threat Intelligence
            </span>
          </Link>
          <Link to="/nivx-forge" data-testid="mobile-nav-cyberlab" onClick={() => setOpen(false)} className="inline-flex items-center gap-2 text-left text-sm font-bold">
            <img src="/favicon-32x32.png" alt="" aria-hidden="true" width="18" height="18" className="rounded-[3px]" />
            <span className="bg-gradient-to-r from-[#2E7DF5] to-[#F5821F] bg-clip-text text-transparent">
              NivX Forge
            </span>
          </Link>
          <Link to="/threatbox" data-testid="mobile-nav-threatbox" onClick={() => setOpen(false)} className="inline-flex items-center gap-2 text-left text-sm font-bold">
            <FileSearch className="w-4 h-4 text-[#DC2626] drop-shadow-[0_0_6px_rgba(220,38,38,0.45)]" strokeWidth={2.4} />
            <span className="bg-gradient-to-r from-[#DC2626] to-[#F5821F] bg-clip-text text-transparent">
              ThreatBox
            </span>
          </Link>
          <Link to="/login" data-testid="mobile-nav-login" onClick={() => setOpen(false)} className="mt-2 pt-3 border-t border-slate-200 text-left text-sm font-semibold text-[#2E7DF5]">Login / Sign up</Link>
        </div>
      )}
    </header>
  );
}
