/**
 * ActorProfile — /actors/:slug detail page.
 * Sections: Header (bio) → TTPs → Attack Timeline → Related IOCs → References.
 */
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Loader2, ShieldAlert, Globe2, Target, Calendar, ListChecks, Fingerprint, ExternalLink, AlertTriangle, BookOpen, Newspaper } from "lucide-react";
import { api } from "@/lib/api";
import useSeo from "@/lib/useSeo";
import Navbar from "@/components/Navbar";

function Section({ id, icon: Icon, title, children }) {
  return (
    <section id={id} className="rounded-xl border border-slate-200 bg-white p-5 mb-4">
      <div className="flex items-center gap-2 mb-3 text-slate-900">
        <Icon className="w-5 h-5 text-[#2E7DF5]" />
        <h2 className="text-lg font-bold">{title}</h2>
      </div>
      {children}
    </section>
  );
}

export default function ActorProfile() {
  const { slug } = useParams();
  const [actor, setActor] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [err, setErr] = useState(null);

  useSeo({
    title: actor ? `${actor.name} — ThreatBox — NivX Machines` : "ThreatBox — Threat Actor Profile",
    description: actor ? `${actor.name} ThreatBox dossier: bio, TTPs, timeline, and related IOCs.` : "",
  });

  useEffect(() => {
    setActor(null);
    setIncidents([]);
    setErr(null);
    api.get(`/actors/${encodeURIComponent(slug)}`)
       .then(({ data }) => setActor(data))
       .catch((e) => setErr(e.response?.status === 404 ? "notfound" : "error"));
    // Related incidents from NivX Threat Intel — single-source-of-truth join
    // via `actor_slug` FK. Silently no-op if none exist.
    api.get(`/actors/${encodeURIComponent(slug)}/incidents`)
       .then(({ data }) => setIncidents(data.incidents || []))
       .catch(() => setIncidents([]));
  }, [slug]);

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      {/* Sticky left-side back-to-index affordance — always visible on scroll */}
      {actor && (
        <Link
          to="/threatbox"
          data-testid="actor-sticky-back"
          aria-label="Back to ThreatBox"
          className="hidden lg:flex fixed left-6 top-1/2 -translate-y-1/2 z-30 items-center justify-center w-11 h-11 rounded-full bg-white border border-slate-200 shadow-md text-slate-600 hover:text-white hover:bg-gradient-to-br hover:from-[#DC2626] hover:to-[#F5821F] hover:border-transparent hover:shadow-lg hover:-translate-y-[calc(50%+2px)] transition-all group"
        >
          <ArrowLeft className="w-5 h-5" strokeWidth={2.4} />
          <span className="absolute left-full ml-3 px-2 py-1 rounded bg-slate-900 text-white text-[11px] whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">Back to ThreatBox</span>
        </Link>
      )}
      <main className="mx-auto max-w-5xl px-6 py-10" data-testid="actor-profile">
        <Link to="/threatbox" className="inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-[#2E7DF5] mb-4">
          <ArrowLeft className="w-4 h-4" /> All ThreatBox profiles
        </Link>

        {err === "notfound" ? (
          <div className="rounded-xl border border-amber-200 bg-amber-50 p-6 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-amber-900">Actor not found</div>
              <div className="text-sm text-amber-800 mt-1">
                We don&apos;t have a ThreatBox dossier for <code className="font-mono bg-white/60 px-1 rounded">{slug}</code> yet.
                &nbsp;<Link to="/threatbox" className="underline hover:text-amber-900">Browse tracked actors →</Link>
              </div>
            </div>
          </div>
        ) : err === "error" ? (
          <div className="text-sm text-red-600">Failed to load actor profile.</div>
        ) : actor === null ? (
          <div className="flex items-center gap-2 text-slate-500"><Loader2 className="w-4 h-4 animate-spin" /> Loading…</div>
        ) : (
          <>
            {/* Header + Bio */}
            <div className="rounded-xl border border-slate-200 bg-white p-6 mb-4">
              <div className="text-xs font-mono uppercase tracking-widest text-[#F5821F] mb-2">ThreatBox · Threat Actor Attribution</div>
              <h1 className="text-3xl font-bold text-slate-900 flex items-center gap-3">
                <ShieldAlert className="w-7 h-7 text-red-500" /> {actor.name}
              </h1>
              {actor.aliases?.length > 0 && (
                <div className="text-sm text-slate-500 mt-1">a.k.a. {actor.aliases.join(", ")}</div>
              )}

              <div className="mt-4 flex flex-wrap gap-2 text-xs">
                {actor.motivation && (
                  <span className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-50 border border-slate-200 text-slate-700"><Target className="w-3 h-3" /> {actor.motivation}</span>
                )}
                {actor.origin_country && (
                  <span className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-50 border border-slate-200 text-slate-700"><Globe2 className="w-3 h-3" /> {actor.origin_country}</span>
                )}
                {actor.first_seen && (
                  <span className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-50 border border-slate-200 text-slate-700"><Calendar className="w-3 h-3" /> First seen {actor.first_seen}</span>
                )}
              </div>

              {actor.bio && (
                <p className="mt-4 text-sm sm:text-base text-slate-700 leading-relaxed" data-testid="actor-bio">{actor.bio}</p>
              )}

              {(actor.targeted_sectors?.length > 0 || actor.targeted_regions?.length > 0) && (
                <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                  {actor.targeted_sectors?.length > 0 && (
                    <div>
                      <div className="text-[10px] uppercase tracking-wider text-slate-400 mb-1">Targeted sectors</div>
                      <div className="flex flex-wrap gap-1">{actor.targeted_sectors.map((s) => <span key={s} className="text-xs px-1.5 py-0.5 rounded bg-slate-100 text-slate-700">{s}</span>)}</div>
                    </div>
                  )}
                  {actor.targeted_regions?.length > 0 && (
                    <div>
                      <div className="text-[10px] uppercase tracking-wider text-slate-400 mb-1">Targeted regions</div>
                      <div className="flex flex-wrap gap-1">{actor.targeted_regions.map((s) => <span key={s} className="text-xs px-1.5 py-0.5 rounded bg-slate-100 text-slate-700">{s}</span>)}</div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Known TTPs */}
            {actor.ttps?.length > 0 && (
              <Section id="ttps" icon={ListChecks} title={`Known TTPs (${actor.ttps.length})`}>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2" data-testid="actor-ttps">
                  {actor.ttps.map((t) => (
                    <a key={t.id} href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer"
                       className="flex items-center justify-between gap-2 p-2 rounded border border-slate-200 hover:border-[#2E7DF5] bg-slate-50 hover:bg-white transition-colors">
                      <div>
                        <span className="font-mono text-xs bg-red-50 text-red-700 border border-red-200 rounded px-1.5 py-0.5 mr-2">{t.id}</span>
                        <span className="text-sm text-slate-700">{t.name}</span>
                      </div>
                      <ExternalLink className="w-3.5 h-3.5 text-slate-400" />
                    </a>
                  ))}
                </div>
                <div className="mt-3 text-[11px] text-slate-400">Click any technique to open the MITRE ATT&amp;CK reference.</div>
              </Section>
            )}

            {/* Attack Timeline */}
            {actor.timeline?.length > 0 && (
              <Section id="timeline" icon={Calendar} title="Attack Timeline">
                <ol className="relative border-l-2 border-slate-200 ml-2 pl-5 space-y-4" data-testid="actor-timeline">
                  {actor.timeline.map((ev, i) => (
                    <li key={i} className="relative">
                      <span className="absolute -left-[27px] top-1.5 w-3 h-3 rounded-full bg-[#2E7DF5] border-2 border-white"></span>
                      <div className="text-xs font-mono text-[#2E7DF5] font-semibold">{ev.date}</div>
                      <div className="text-sm font-semibold text-slate-900">{ev.title}</div>
                      {ev.description && <div className="text-xs text-slate-600 mt-0.5">{ev.description}</div>}
                      {ev.source_url && (
                        <a href={ev.source_url} target="_blank" rel="noopener noreferrer" className="text-[11px] text-[#2E7DF5] hover:underline inline-flex items-center gap-1 mt-1">Source <ExternalLink className="w-3 h-3" /></a>
                      )}
                    </li>
                  ))}
                </ol>
              </Section>
            )}

            {/* Related IOCs */}
            {actor.related_iocs?.length > 0 && (
              <Section id="iocs" icon={Fingerprint} title={`Related IOCs (${actor.related_iocs.length})`}>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm" data-testid="actor-iocs">
                    <thead>
                      <tr className="text-left text-[10px] uppercase tracking-wider text-slate-500 bg-slate-50 border-b border-slate-200">
                        <th className="px-3 py-2">Type</th>
                        <th className="px-3 py-2">Value</th>
                        <th className="px-3 py-2">Note</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {actor.related_iocs.map((ioc, i) => (
                        <tr key={i}>
                          <td className="px-3 py-2"><span className="text-[10px] font-mono uppercase bg-slate-100 rounded px-1.5 py-0.5">{ioc.type}</span></td>
                          <td className="px-3 py-2"><code className="text-xs font-mono text-slate-800 break-all">{ioc.value}</code></td>
                          <td className="px-3 py-2 text-xs text-slate-600">{ioc.note || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Section>
            )}

            {/* Related Incidents — NivX Threat Intel case studies attributed to this actor */}
            {incidents.length > 0 && (
              <Section id="incidents" icon={Newspaper} title={`Related Incidents from NivX Threat Intel (${incidents.length})`}>
                <div className="space-y-2" data-testid="actor-incidents">
                  {incidents.map((inc) => (
                    <div key={inc.id} className="flex items-start gap-3 p-3 rounded-lg border border-slate-200 hover:border-[#2E7DF5] bg-slate-50 hover:bg-white transition-colors">
                      <span className={`shrink-0 text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded border mt-0.5 ${
                        inc.severity === "critical" ? "bg-red-50 text-red-700 border-red-200" :
                        inc.severity === "high" ? "bg-orange-50 text-orange-700 border-orange-200" :
                        inc.severity === "medium" ? "bg-blue-50 text-blue-700 border-blue-200" :
                        "bg-slate-100 text-slate-600 border-slate-200"
                      }`}>{inc.severity}</span>
                      <div className="min-w-0 flex-1">
                        <div className="text-sm font-semibold text-slate-900">{inc.title}</div>
                        <div className="text-xs text-slate-600 line-clamp-2 mt-0.5">{inc.summary}</div>
                        <div className="text-[11px] text-slate-400 mt-1 font-mono">{inc.category}</div>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="mt-3 text-[11px] text-slate-400">Incident case studies live in NivX Threat Intel, linked to this ThreatBox dossier by <code className="font-mono">actor_slug</code>.</div>
              </Section>
            )}

            {/* References */}
            {actor.references?.length > 0 && (
              <Section id="references" icon={BookOpen} title="References">
                <ul className="space-y-1.5 text-sm">
                  {actor.references.map((r, i) => (
                    <li key={i}>
                      <a href={r.url} target="_blank" rel="noopener noreferrer" className="text-[#2E7DF5] hover:underline inline-flex items-center gap-1">
                        {r.title} <ExternalLink className="w-3 h-3" />
                      </a>
                    </li>
                  ))}
                </ul>
              </Section>
            )}

            {/* Bottom back-to-index navigation */}
            <div className="mt-6 flex items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white p-4">
              <div className="text-xs text-slate-500">
                End of dossier · <span className="font-mono text-slate-700">{actor.name}</span>
              </div>
              <Link
                to="/threatbox"
                data-testid="actor-back-to-threatbox"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-[#DC2626] to-[#F5821F] text-white text-sm font-semibold shadow-sm hover:shadow-md hover:-translate-y-0.5 transition-all"
              >
                <ArrowLeft className="w-4 h-4" /> Back to ThreatBox
              </Link>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
