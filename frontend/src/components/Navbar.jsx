import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Menu, X, ShieldHalf } from "lucide-react";

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
    const onScroll = () => setScrolled(window.scrollY > 40);
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
      className={`fixed top-0 left-0 right-0 z-50 transition-[background-color,border-color,padding] duration-500 ${
        scrolled ? "glass py-3 border-b" : "py-5 border-b border-transparent bg-transparent"
      }`}
    >
      <nav className="mx-auto max-w-[1400px] px-6 flex items-center justify-between">
        <button
          data-testid="logo-home"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          className="flex items-center gap-2 group"
        >
          <ShieldHalf className="w-6 h-6 text-[#00F0FF]" strokeWidth={1.5} />
          <span className="font-display font-black text-lg tracking-tighter text-white">
            NIVX<span className="text-[#00F0FF]">.</span>MACHINES
          </span>
        </button>

        <div className="hidden lg:flex items-center gap-9 font-mono-data text-[12px] uppercase tracking-widest">
          {LINKS.map((l) => (
            <button
              key={l.id}
              data-testid={`nav-${l.id}`}
              onClick={() => go(l.id)}
              className="link-underline text-[#A1A1A5] hover:text-white transition-colors duration-300"
            >
              {l.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/admin"
            data-testid="nav-admin-link"
            className="hidden sm:inline-flex font-mono-data text-[11px] uppercase tracking-widest text-[#66666E] hover:text-[#00F0FF] transition-colors"
          >
            Admin
          </Link>
          <a
            href="tel:9059565125"
            data-testid="nav-contact-cta"
            className="hidden sm:inline-flex items-center border border-[#00F0FF]/60 text-[#00F0FF] px-5 py-2 font-mono-data text-[11px] uppercase tracking-widest hover:bg-[#00F0FF] hover:text-black transition-colors duration-300"
          >
            Get Secured
          </a>
          <button
            data-testid="mobile-menu-toggle"
            className="lg:hidden text-white"
            onClick={() => setOpen((o) => !o)}
          >
            {open ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </nav>

      {open && (
        <div className="lg:hidden glass border-t mt-3 px-6 py-6 flex flex-col gap-5" data-testid="mobile-menu">
          {LINKS.map((l) => (
            <button
              key={l.id}
              onClick={() => go(l.id)}
              className="text-left font-mono-data text-sm uppercase tracking-widest text-[#A1A1A5]"
            >
              {l.label}
            </button>
          ))}
        </div>
      )}
    </header>
  );
}
