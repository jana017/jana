/**
 * ActorProfile — /actors/:slug detail page.
 * Sections: Header (bio) → TTPs → Attack Timeline → Related IOCs → References.
 */
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Loader2, ShieldAlert, Globe2, Target, Calendar, ListChecks, Fingerprint, ExternalLink, AlertTriangle, BookOpen } from "lucide-react";
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
  const [err, setErr] = useState(null);

  useSeo({
    title: actor ? `${actor.name} — Threat Actor Profile — NivX Machines` : "Threat Actor Profile",
    description: actor ? `${actor.name} attribution profile: bio, TTPs, timeline, and related IOCs.` : "",
  });

  useEffect(() => {
    setActor(null);
    setErr(null);
    api.get(`/actors/${encodeURIComponent(slug)}`)
       .then(({ data }) => setActor(data))
       .catch((e) => setErr(e.response?.status === 404 ? "notfound" : "error"));
  }, [slug]);

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <main className="mx-auto max-w-5xl px-6 py-10" data-testid="actor-profile">
        <Link to="/actors" className="inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-[#2E7DF5] mb-4">
          <ArrowLeft className="w-4 h-4" /> All threat actor profiles
        </Link>

        {err === "notfound" ? (
          <div className="rounded-xl border border-amber-200 bg-amber-50 p-6 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-amber-900">Actor not found</div>
              <div className="text-sm text-amber-800 mt-1">
                We don&apos;t have an attribution profile for <code className="font-mono bg-white/60 px-1 rounded">{slug}</code> yet.
                &nbsp;<Link to="/actors" className="underline hover:text-amber-900">Browse tracked actors →</Link>
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
              <div className="text-xs font-mono uppercase tracking-widest text-[#F5821F] mb-2">Threat Actor Attribution Profile</div>
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
          </>
        )}
      </main>
    </div>
  );
}
