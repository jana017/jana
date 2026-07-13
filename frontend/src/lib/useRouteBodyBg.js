/**
 * useRouteBodyBg — set the <html> and <body> background based on the current
 * route. Prevents any white/dark "peek" gap on mobile browsers when a
 * dark-themed page (CyberLab / NivX Forge) is displayed on a body that
 * defaults to white (or vice versa).
 *
 * Mount ONCE at the App level, inside <BrowserRouter>.
 *
 * Route -> bg mapping (kept small on purpose):
 *   /cyberlab, /cyberlab/*, /nivx-forge, /nivx-forge/*  → dark (slate-950)
 *   everything else                                     → light (white)
 */
import { useEffect } from "react";
import { useLocation } from "react-router-dom";

const DARK  = "#020617"; // slate-950
const LIGHT = "#ffffff";

function bgForPath(pathname) {
  const p = (pathname || "").toLowerCase();
  if (p.startsWith("/cyberlab") || p.startsWith("/nivx-forge") || p.startsWith("/detonate") || p.startsWith("/payload-lab") || p.startsWith("/console")) {
    return DARK;
  }
  return LIGHT;
}

export default function useRouteBodyBg() {
  const { pathname } = useLocation();
  useEffect(() => {
    const color = bgForPath(pathname);
    document.body.style.backgroundColor = color;
    document.documentElement.style.backgroundColor = color;
    // Also set the meta theme-color so mobile browser chrome (URL bar,
    // status bar tint) matches — eliminates the visible "white gap" the
    // user reported at the top edge of the viewport too.
    let meta = document.querySelector('meta[name="theme-color"]');
    if (!meta) {
      meta = document.createElement("meta");
      meta.setAttribute("name", "theme-color");
      document.head.appendChild(meta);
    }
    meta.setAttribute("content", color);
  }, [pathname]);
}
