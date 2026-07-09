import { useState, useEffect } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { useLenis } from "lenis/react";
import { Menu, X, Phone, ShieldCheck } from "lucide-react";
import { prefetchRoute } from "@/lib/routePrefetch";

const SECTION_LINKS = [
  { label: "About", id: "about" },
  { label: "Services", id: "services" },
  { label: "Gallery", id: "gallery" },
  { label: "Careers", id: "careers" },
  { label: "Support", id: "support" },
];

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const lenis = useLenis();

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
      ["/blog", "/threat-intelligence", "/cybersecurity-101", "/detonate", "/admin"].forEach(prefetchRoute);
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
            to="/blog"
            data-testid="nav-blog"
            onMouseEnter={() => prefetchRoute("/blog")}
            onFocus={() => prefetchRoute("/blog")}
            className={`text-sm font-medium transition-colors ${isBlog ? "text-[#2E7DF5]" : "text-slate-600 hover:text-slate-900"}`}
          >
            Blog
          </Link>
          <Link
            to="/cybersecurity-101"
            data-testid="nav-cyber-101"
            onMouseEnter={() => prefetchRoute("/cybersecurity-101")}
            onFocus={() => prefetchRoute("/cybersecurity-101")}
            className={`text-sm font-medium transition-colors ${isKb ? "text-[#2E7DF5]" : "text-slate-600 hover:text-slate-900"}`}
          >
            Cyber 101
          </Link>
          <Link
            to="/threat-intelligence"
            data-testid="nav-threat-intelligence"
            onMouseEnter={() => prefetchRoute("/threat-intelligence")}
            onFocus={() => prefetchRoute("/threat-intelligence")}
            className={`text-sm font-medium transition-colors ${isIntel ? "text-[#2E7DF5]" : "text-slate-600 hover:text-slate-900"}`}
          >
            Threat Intelligence
          </Link>
        </div>

        <div className="flex items-center gap-3">
          <Link to="/admin" data-testid="nav-admin-link" onMouseEnter={() => prefetchRoute("/admin")} onFocus={() => prefetchRoute("/admin")} className="inline-flex items-center gap-1.5 text-sm font-medium text-slate-500 hover:text-slate-900 transition-colors">
            <ShieldCheck className="w-4 h-4" /> <span className="hidden sm:inline">Admin</span>
          </Link>
          <a href="tel:9059565125" data-testid="nav-contact-cta" className="hidden sm:inline-flex items-center gap-2 bg-[#2E7DF5] hover:bg-[#2563EB] text-white text-sm font-semibold px-4 py-2 rounded-md transition-colors">
            <Phone className="w-4 h-4" strokeWidth={2} /> Get Secured
          </a>
          <button data-testid="mobile-menu-toggle" className="lg:hidden text-slate-700" onClick={() => setOpen((o) => !o)}>
            {open ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </nav>

      {open && (
        <div className="lg:hidden bg-white border-t border-slate-200 px-6 py-5 flex flex-col gap-4" data-testid="mobile-menu">
          {SECTION_LINKS.map((l) => (
            <button key={l.id} onClick={() => go(l.id)} className="text-left text-sm font-medium text-slate-700">{l.label}</button>
          ))}
          <Link to="/blog" onClick={() => setOpen(false)} className="text-left text-sm font-medium text-slate-700">Blog</Link>
          <Link to="/cybersecurity-101" onClick={() => setOpen(false)} className="text-left text-sm font-medium text-slate-700">Cyber 101</Link>
          <Link to="/threat-intelligence" onClick={() => setOpen(false)} className="text-left text-sm font-medium text-[#2E7DF5]">Threat Intelligence</Link>
          <Link to="/admin" data-testid="mobile-nav-admin-link" onClick={() => setOpen(false)} className="inline-flex items-center gap-2 text-left text-sm font-semibold text-slate-700 pt-3 mt-1 border-t border-slate-200">
            <ShieldCheck className="w-4 h-4" /> Admin sign in
          </Link>
        </div>
      )}
    </header>
  );
}
