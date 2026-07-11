/**
 * AdminMaster — unified Admin command center.
 *
 * Consolidates all admin sub-features into a single tab with lazy-loaded
 * sub-panels for performance:
 *   • Overview      — Backend HealthBot + UI/UX Scanner (existing hub)
 *   • Settings      — OSINT API keys, community feed sources, cache purge
 *   • NivX Forge    — Global custom detection rules
 *   • EDR / SIEM    — Webhook manager + delivery audit log
 *
 * The underlying components are reused verbatim so their existing endpoints,
 * pytest coverage and behavior are unchanged — this is pure UI consolidation.
 *
 * Selected sub-tab is persisted in localStorage. An `initialTab` prop lets the
 * parent (Admin.jsx) preselect a tab for backward compatibility with legacy
 * sidebar entries and `?view=` URL parameters.
 */
import { useState, useEffect, lazy, Suspense } from "react";
import { Wrench, Activity, Settings as SettingsIcon, Bug, Webhook, Loader2 } from "lucide-react";
import AdminHealthBot from "@/components/AdminHealthBot";
import AdminUiScanner from "@/components/AdminUiScanner";

// Lazy-load heavier sub-panels so switching tabs doesn't cost anything until
// the analyst opens them.
const AdminSettings = lazy(() => import("@/components/AdminSettings"));
const AdminCyberLabRules = lazy(() => import("@/components/AdminCyberLabRules"));
const AdminWebhooks = lazy(() => import("@/components/AdminWebhooks"));

const STORAGE_KEY = "nivx-admin-master-tab";

const TABS = [
  { id: "overview", label: "Overview",         icon: Activity,    testid: "master-tab-overview" },
  { id: "settings", label: "Settings",         icon: SettingsIcon, testid: "master-tab-settings" },
  { id: "rules",    label: "NivX Forge Rules", icon: Bug,          testid: "master-tab-rules" },
  { id: "webhooks", label: "EDR / SIEM",       icon: Webhook,      testid: "master-tab-webhooks" },
];

const VALID_TABS = new Set(TABS.map((t) => t.id));

function LazyFallback({ label }) {
  return (
    <div className="mx-auto max-w-7xl px-6 py-10 flex items-center gap-2 text-sm text-slate-500" data-testid="master-lazy-loading">
      <Loader2 className="w-4 h-4 animate-spin" /> Loading {label}…
    </div>
  );
}

function Overview() {
  return (
    <div className="mx-auto max-w-7xl px-6 py-6" data-testid="master-overview">
      <p className="text-xs text-slate-400 max-w-3xl mb-4">
        <strong className="text-slate-600">Auto-fixed:</strong> Mongo indexes, cron loops, missing viewport / theme-color meta, body/html bg per route.
        &nbsp;<strong className="text-slate-600">Reported for developer review:</strong> tap-target sizing, missing alt text, layout regressions — safe auto-injection could break intentional design.
      </p>

      <section className="mb-6 rounded-xl border border-slate-200 bg-white overflow-hidden" data-testid="master-section-healthbot">
        <div className="px-5 py-3 border-b border-slate-100">
          <div className="text-sm font-bold text-slate-900">Backend Health</div>
          <div className="text-xs text-slate-500 mt-0.5">Mongo indexes, cron loops, config drift. Auto-scans every 2 hours; click Run for an on-demand check + auto-repair.</div>
        </div>
        <div className="[&_main]:pt-2 [&_main]:pb-4 [&_main]:px-4">
          <AdminHealthBot />
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white overflow-hidden" data-testid="master-section-ui-scanner">
        <div className="px-5 py-3 border-b border-slate-100">
          <div className="text-sm font-bold text-slate-900">UI/UX Scanner</div>
          <div className="text-xs text-slate-500 mt-0.5">Deterministic viewport scan across 6 routes × 8 viewports. Findings history + CSV/JSON per-scan download.</div>
        </div>
        <div className="[&_main]:pt-2 [&_main]:pb-4 [&_main]:px-4">
          <AdminUiScanner />
        </div>
      </section>
    </div>
  );
}

export default function AdminMaster({ initialTab }) {
  // Determine the initial tab: explicit prop > localStorage > "overview"
  const [tab, setTab] = useState(() => {
    if (initialTab && VALID_TABS.has(initialTab)) return initialTab;
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved && VALID_TABS.has(saved)) return saved;
    } catch { /* localStorage disabled — fine */ }
    return "overview";
  });

  // If the parent re-mounts with a new initialTab (e.g. sidebar click), honor it.
  useEffect(() => {
    if (initialTab && VALID_TABS.has(initialTab)) setTab(initialTab);
  }, [initialTab]);

  // Persist the analyst's last tab across page loads.
  useEffect(() => {
    try { localStorage.setItem(STORAGE_KEY, tab); } catch { /* ignore */ }
  }, [tab]);

  return (
    <div data-testid="admin-master">
      {/* Header */}
      <div className="mx-auto max-w-7xl px-6 pt-10 pb-4">
        <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 flex items-center gap-2">
          <Wrench className="w-6 h-6 text-[#2E7DF5]" /> Master Command Center
        </h1>
        <p className="mt-1 text-sm text-slate-500 max-w-3xl">
          One hub for all admin operations — diagnostics, OSINT keys, detection rules and outbound integrations. Everything below is deterministic and does not consume LLM credits.
        </p>
      </div>

      {/* Sub-tab navigation */}
      <div className="bg-white border-y border-slate-200 sticky top-16 z-20">
        <div className="mx-auto max-w-7xl px-6 flex gap-1 overflow-x-auto">
          {TABS.map((t) => {
            const Icon = t.icon;
            const active = tab === t.id;
            return (
              <button
                key={t.id}
                data-testid={t.testid}
                onClick={() => setTab(t.id)}
                className={`px-4 py-3 text-sm font-semibold border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap ${
                  active
                    ? "border-[#2E7DF5] text-[#2E7DF5]"
                    : "border-transparent text-slate-500 hover:text-slate-800"
                }`}
              >
                <Icon className="w-4 h-4" /> {t.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Panel — lazy-loaded so switching stays cheap. */}
      <div data-testid={`master-panel-${tab}`}>
        {tab === "overview" && <Overview />}
        {tab === "settings" && (
          <Suspense fallback={<LazyFallback label="Settings" />}>
            <AdminSettings />
          </Suspense>
        )}
        {tab === "rules" && (
          <Suspense fallback={<LazyFallback label="NivX Forge Rules" />}>
            <main className="mx-auto max-w-7xl px-6 py-10">
              <AdminCyberLabRules />
            </main>
          </Suspense>
        )}
        {tab === "webhooks" && (
          <Suspense fallback={<LazyFallback label="EDR / SIEM" />}>
            <AdminWebhooks />
          </Suspense>
        )}
      </div>
    </div>
  );
}
