import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Menu, X, Phone } from "lucide-react";

const LINKS = [
  { label: "About", id: "about" },
  { label: "Services", id: "services" },
  { label: "Threat Report", id: "threats" },
  { label: "Gallery", id: "gallery" },
  { label: "Careers", id: "careers" },
  { label: "Support", id: "support" },
];

export default function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const go = (id) => {
    setOpen(false);
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <header
      data-testid="main-navbar"
      className={`fixed top-0 left-0 right-0 z-50 transition-shadow duration-300 bg-white/90 backdrop-blur-md border-b border-slate-200 ${
        scrolled ? "shadow-sm" : ""
      }`}
    >
      <nav className="mx-auto max-w-7xl px-6 h-16 flex items-center justify-between">
        <button
          data-testid="logo-home"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          className="flex items-center"
        >
          <img src="/nivx-logo-light.png" alt="NivX Machines" className="h-8 w-auto object-contain" />
        </button>

        <div className="hidden lg:flex items-center gap-8">
          {LINKS.map((l) => (
            <button
              key={l.id}
              data-testid={`nav-${l.id}`}
              onClick={() => go(l.id)}
              className="text-sm font-medium text-slate-600 hover:text-slate-900 transition-colors"
            >
              {l.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/admin"
            data-testid="nav-admin-link"
            className="hidden sm:inline-flex text-sm font-medium text-slate-500 hover:text-slate-900 transition-colors"
          >
            Admin
          </Link>
          <a
            href="tel:9059565125"
            data-testid="nav-contact-cta"
            className="hidden sm:inline-flex items-center gap-2 bg-[#2E7DF5] hover:bg-[#2563EB] text-white text-sm font-semibold px-4 py-2 rounded-md transition-colors"
          >
            <Phone className="w-4 h-4" strokeWidth={2} />
            Get Secured
          </a>
          <button
            data-testid="mobile-menu-toggle"
            className="lg:hidden text-slate-700"
            onClick={() => setOpen((o) => !o)}
          >
            {open ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </nav>

      {open && (
        <div className="lg:hidden bg-white border-t border-slate-200 px-6 py-5 flex flex-col gap-4" data-testid="mobile-menu">
          {LINKS.map((l) => (
            <button key={l.id} onClick={() => go(l.id)} className="text-left text-sm font-medium text-slate-700">
              {l.label}
            </button>
          ))}
        </div>
      )}
    </header>
  );
}
