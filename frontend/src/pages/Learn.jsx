/**
 * Learn — merged "Blog + Cyber 101" hub. Renders one of two sub-tabs based
 * on the `?tab=` query param, sharing a single Navbar + Contact layout and
 * a single SEO canonical URL. Backward-compat: `/blog` and
 * `/cybersecurity-101` still route here via <Navigate>. Each sub-tab lazily
 * mounts the existing (unchanged) page component so no content regression.
 */
import { lazy, Suspense } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { BookOpen, GraduationCap } from "lucide-react";
import Navbar from "@/components/Navbar";
import useSeo from "@/lib/useSeo";

const BlogIndex = lazy(() => import("@/pages/BlogIndex"));
const KnowledgeBase = lazy(() => import("@/pages/KnowledgeBase"));

const TABS = [
  { id: "blog",     label: "Blog",     icon: BookOpen,        desc: "Long-form NivX threat research, SOC playbooks & DFIR case studies." },
  { id: "cyber101", label: "Cyber 101", icon: GraduationCap,   desc: "Beginner-friendly cybersecurity fundamentals — attacks, defenses, careers." },
];

function TabSwitcher({ active, onChange }) {
  return (
    <div className="border-b border-slate-200 bg-white sticky top-16 z-30 -mt-px" data-testid="learn-tab-switcher">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="flex items-center gap-1 -mb-px overflow-x-auto no-scrollbar">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => onChange(id)}
              data-testid={`learn-tab-${id}`}
              className={`inline-flex items-center gap-1.5 px-4 py-3 text-sm font-semibold whitespace-nowrap border-b-2 transition-colors ${
                active === id
                  ? "border-[#2E7DF5] text-[#2E7DF5]"
                  : "border-transparent text-slate-500 hover:text-slate-800"
              }`}
            >
              <Icon className="w-4 h-4" /> {label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function Learn() {
  const [params, setParams] = useSearchParams();
  const raw = (params.get("tab") || "").toLowerCase();
  const active = TABS.some(t => t.id === raw) ? raw : "blog";

  const meta = TABS.find(t => t.id === active);
  useSeo({
    title: active === "blog"
      ? "Learn · NivX Blogs — Threat Research & SOC Playbooks | NivX Machines"
      : "Learn · Cyber 101 — Cybersecurity Fundamentals | NivX Machines",
    description: meta.desc,
    canonical: `https://nivxmachines.com/learn?tab=${active}`,
  });

  const setTab = (id) => {
    const next = new URLSearchParams(params);
    next.set("tab", id);
    setParams(next, { replace: false });
  };

  return (
    <div className="min-h-screen bg-white text-slate-900 pt-16">
      <Navbar />
      <TabSwitcher active={active} onChange={setTab} />
      <Suspense fallback={
        <div className="min-h-[40vh] flex items-center justify-center">
          <div className="w-8 h-8 border-2 border-slate-200 border-t-[#2E7DF5] rounded-full animate-spin" aria-label="Loading" />
        </div>
      }>
        <div data-testid={`learn-panel-${active}`}>
          {active === "blog" ? <BlogIndex embedded /> : <KnowledgeBase embedded />}
        </div>
      </Suspense>
      {/* Quick cross-link footer nudge */}
      <div className="border-t border-slate-100 bg-slate-50">
        <div className="mx-auto max-w-6xl px-6 py-6 text-sm text-slate-500 flex flex-wrap items-center justify-between gap-3">
          <span>
            {active === "blog"
              ? "Just getting started? Try Cyber 101 fundamentals →"
              : "Want in-depth threat research? Read the Blog →"}
          </span>
          <Link
            to={`/learn?tab=${active === "blog" ? "cyber101" : "blog"}`}
            onClick={() => setTab(active === "blog" ? "cyber101" : "blog")}
            data-testid="learn-cross-link"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-200 bg-white text-slate-700 font-semibold hover:border-slate-400 transition-colors"
          >
            {active === "blog" ? <><GraduationCap className="w-4 h-4" /> Cyber 101</> : <><BookOpen className="w-4 h-4" /> Blog</>}
          </Link>
        </div>
      </div>
    </div>
  );
}
