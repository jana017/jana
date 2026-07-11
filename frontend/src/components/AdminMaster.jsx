/**
 * AdminMaster — unified Health & Fix hub.
 *
 * Consolidates the two existing diagnostic tools (Backend HealthBot + UI/UX
 * Scanner) into one Admin tab. The underlying components (`AdminHealthBot`,
 * `AdminUiScanner`) are reused verbatim so their existing endpoints, pytest
 * coverage and history collections are unchanged — this is a pure UI
 * consolidation, no logic duplication.
 */
import { useState } from "react";
import { Wrench, ChevronDown, ChevronRight } from "lucide-react";
import AdminHealthBot from "@/components/AdminHealthBot";
import AdminUiScanner from "@/components/AdminUiScanner";

function Section({ title, subtitle, defaultOpen = true, testid, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section className="mb-4 rounded-xl border border-slate-200 bg-white overflow-hidden" data-testid={testid}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-5 py-3 text-left hover:bg-slate-50 transition-colors"
        aria-expanded={open}
      >
        <div>
          <div className="text-sm font-bold text-slate-900">{title}</div>
          {subtitle && <div className="text-xs text-slate-500 mt-0.5">{subtitle}</div>}
        </div>
        {open ? <ChevronDown className="w-4 h-4 text-slate-400 shrink-0" /> : <ChevronRight className="w-4 h-4 text-slate-400 shrink-0" />}
      </button>
      {open && <div className="border-t border-slate-100 -mt-px">{children}</div>}
    </section>
  );
}

export default function AdminMaster() {
  return (
    <main className="mx-auto max-w-7xl px-6 py-10">
      <div className="mb-6">
        <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 flex items-center gap-2">
          <Wrench className="w-6 h-6 text-[#2E7DF5]" /> Master Health &amp; Fix
        </h1>
        <p className="mt-1 text-sm text-slate-500 max-w-3xl">
          One hub for all site diagnostics. Run backend checks, UI/UX scans, view history, download reports and auto-apply safe fixes — all deterministic, no LLM.
        </p>
        <p className="mt-2 text-xs text-slate-400 max-w-3xl">
          <strong className="text-slate-600">Auto-fixed:</strong> Mongo indexes, cron loops, missing viewport / theme-color meta, body/html bg per route.
          &nbsp;<strong className="text-slate-600">Reported for developer review:</strong> tap-target sizing, missing alt text, layout regressions — safe auto-injection could break intentional design.
        </p>
      </div>

      <Section
        title="1. Backend Health (Mongo indexes, cron loops, config drift)"
        subtitle="Auto-scans every 2 hours in the background. Click Run for an on-demand check + auto-repair."
        testid="master-section-healthbot"
      >
        <div className="[&_main]:pt-2 [&_main]:pb-4 [&_main]:px-4">
          <AdminHealthBot />
        </div>
      </Section>

      <Section
        title="2. UI/UX Scanner (mobile · tablet · desktop viewports)"
        subtitle="Deterministic viewport scan across 6 routes × 8 viewports. Findings history + CSV/JSON per-scan download."
        testid="master-section-ui-scanner"
      >
        <div className="[&_main]:pt-2 [&_main]:pb-4 [&_main]:px-4">
          <AdminUiScanner />
        </div>
      </Section>
    </main>
  );
}
