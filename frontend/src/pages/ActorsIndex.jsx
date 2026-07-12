/**
 * ActorsIndex — /actors landing page.
 * Grid of every tracked threat actor with a quick glance at motivation,
 * region and TTPs. Click any card → /actors/:slug detail.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Loader2, ShieldAlert, Globe2, Target, ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import useSeo from "@/lib/useSeo";
import Navbar from "@/components/Navbar";

const MOTIVATION_TONE = {
  "financial": "bg-emerald-50 text-emerald-700 border-emerald-200",
  "espionage": "bg-sky-50 text-sky-700 border-sky-200",
  "hacktivism": "bg-violet-50 text-violet-700 border-violet-200",
};
function motivationTone(m) {
  const k = (m || "").toLowerCase();
  for (const key of Object.keys(MOTIVATION_TONE)) if (k.includes(key)) return MOTIVATION_TONE[key];
  return "bg-slate-50 text-slate-700 border-slate-200";
}

export default function ActorsIndex() {
  useSeo({
    title: "ThreatBox — Threat Actor Attribution — NivX Machines",
    description: "ThreatBox: curated attribution profiles for tracked threat actor groups — bio, TTPs, timeline and related IOCs.",
  });
  const [actors, setActors] = useState(null);

  useEffect(() => {
    api.get("/actors").then(({ data }) => setActors(data.actors || [])).catch(() => setActors([]));
  }, []);

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <main className="mx-auto max-w-7xl px-6 py-12" data-testid="actors-index">
        <div className="mb-8">
          <div className="text-xs font-mono uppercase tracking-widest text-[#F5821F] mb-2">ThreatBox · Threat Intelligence</div>
          <h1 className="text-3xl sm:text-4xl font-bold text-slate-900 flex items-center gap-3">
            <ShieldAlert className="w-7 h-7 text-red-500" /> ThreatBox
          </h1>
          <p className="mt-2 text-sm sm:text-base text-slate-600 max-w-3xl">
            NivX ThreatBox is a curated intelligence library of actively-tracked adversary groups. Each dossier covers biography, known TTPs (MITRE ATT&amp;CK), an incident timeline and related IOCs — reviewed by NivX analysts and updated as new intelligence emerges.
          </p>
        </div>

        {actors === null ? (
          <div className="flex items-center gap-2 text-slate-500"><Loader2 className="w-4 h-4 animate-spin" /> Loading…</div>
        ) : actors.length === 0 ? (
          <div className="text-slate-500">No tracked actors yet.</div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {actors.map((a) => (
              <Link
                key={a.slug}
                to={`/threatbox/${a.slug}`}
                data-testid={`actor-card-${a.slug}`}
                className="group rounded-xl border border-slate-200 bg-white p-5 hover:border-[#2E7DF5] hover:shadow-md transition-all"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-lg font-bold text-slate-900 truncate">{a.name}</div>
                    {a.aliases?.length > 0 && (
                      <div className="text-[11px] text-slate-500 truncate">a.k.a. {a.aliases.slice(0, 3).join(", ")}</div>
                    )}
                  </div>
                  <ArrowRight className="w-4 h-4 text-slate-300 group-hover:text-[#2E7DF5] group-hover:translate-x-0.5 transition-all" />
                </div>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {a.motivation && (
                    <span className={`text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${motivationTone(a.motivation)}`}>
                      {a.motivation}
                    </span>
                  )}
                  {a.origin_country && (
                    <span className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border bg-slate-50 text-slate-700 border-slate-200 inline-flex items-center gap-1">
                      <Globe2 className="w-3 h-3" /> {a.origin_country}
                    </span>
                  )}
                  {a.first_seen && (
                    <span className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border bg-slate-50 text-slate-700 border-slate-200">
                      since {a.first_seen}
                    </span>
                  )}
                </div>
                {a.targeted_sectors?.length > 0 && (
                  <div className="mt-3 text-xs text-slate-600 flex items-start gap-1.5">
                    <Target className="w-3.5 h-3.5 shrink-0 text-slate-400 mt-0.5" />
                    <span className="line-clamp-2">{a.targeted_sectors.slice(0, 4).join(" · ")}</span>
                  </div>
                )}
                {a.ttps?.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1">
                    {a.ttps.slice(0, 3).map((t) => (
                      <span key={t.id} className="text-[10px] font-mono bg-red-50 text-red-700 border border-red-200 rounded px-1.5 py-0.5">
                        {t.id}
                      </span>
                    ))}
                    {a.ttps.length > 3 && <span className="text-[10px] text-slate-400">+{a.ttps.length - 3}</span>}
                  </div>
                )}
              </Link>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
