/**
 * AnnouncementBanner — top-of-page banner controlled from the Developer tab.
 * Reads /api/cms/announcement and renders when active. Dismissed state is
 * remembered in localStorage keyed by the announcement text (so a new
 * announcement re-shows automatically).
 */
import { useEffect, useState } from "react";
import axios from "axios";
import { X, ExternalLink, Megaphone } from "lucide-react";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || "";
const STORAGE_KEY = "nivx.announcement.dismissed";

const VARIANT_STYLE = {
  info: "bg-blue-600 text-white",
  success: "bg-emerald-600 text-white",
  warning: "bg-amber-500 text-slate-900",
  promo: "bg-gradient-to-r from-purple-600 to-pink-600 text-white",
};

export default function AnnouncementBanner() {
  const [ann, setAnn] = useState(null);
  const [dismissedFor, setDismissedFor] = useState(() => {
    try { return localStorage.getItem(STORAGE_KEY) || ""; }
    catch { return ""; }
  });

  useEffect(() => {
    axios.get(`${BACKEND_URL}/api/cms/announcement`)
      .then(({ data }) => setAnn(data))
      .catch(() => setAnn(null));
  }, []);

  if (!ann || !ann.active || !ann.text) return null;
  if (ann.dismissable && dismissedFor === ann.text) return null;

  const style = VARIANT_STYLE[ann.variant] || VARIANT_STYLE.info;
  const dismiss = () => {
    try { localStorage.setItem(STORAGE_KEY, ann.text); } catch { /* ignore */ }
    setDismissedFor(ann.text);
  };

  return (
    <div className={`w-full ${style}`} data-testid="announcement-banner" role="status">
      <div className="mx-auto max-w-7xl px-6 py-2 flex items-center gap-3 text-sm">
        <Megaphone className="w-4 h-4 shrink-0 opacity-80" />
        <span className="flex-1 font-semibold">{ann.text}</span>
        {ann.href && (
          <a
            href={ann.href}
            target="_blank"
            rel="noreferrer"
            data-testid="announcement-link"
            className="inline-flex items-center gap-1 text-xs font-bold uppercase tracking-wide underline hover:no-underline"
          >
            Learn more <ExternalLink className="w-3 h-3" />
          </a>
        )}
        {ann.dismissable && (
          <button
            onClick={dismiss}
            data-testid="announcement-dismiss"
            className="ml-2 opacity-70 hover:opacity-100"
            aria-label="Dismiss announcement"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
}
