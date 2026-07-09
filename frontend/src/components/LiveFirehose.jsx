import { useEffect, useMemo, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Radio, RefreshCw, ExternalLink, Loader2 } from "lucide-react";
import { api } from "@/lib/api";

const POLL_MS = 60_000;

const SOURCE_TONE = {
  talos:        { chip: "bg-red-50 text-red-700 border-red-200" },
  unit42:       { chip: "bg-blue-50 text-blue-700 border-blue-200" },
  dfir:         { chip: "bg-amber-50 text-amber-700 border-amber-200" },
  msthreat:     { chip: "bg-emerald-50 text-emerald-700 border-emerald-200" },
  bleeping:     { chip: "bg-orange-50 text-orange-700 border-orange-200" },
  hn:           { chip: "bg-orange-50 text-orange-700 border-orange-200" },
  thn:          { chip: "bg-purple-50 text-purple-700 border-purple-200" },
  krebs:        { chip: "bg-rose-50 text-rose-700 border-rose-200" },
  darkreading:  { chip: "bg-slate-100 text-slate-700 border-slate-200" },
  securityweek: { chip: "bg-indigo-50 text-indigo-700 border-indigo-200" },
  therecord:    { chip: "bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200" },
};

const chipFor = (slug) => SOURCE_TONE[slug]?.chip || "bg-slate-100 text-slate-700 border-slate-200";

function timeAgo(iso) {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  const s = Math.floor((Date.now() - t) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export default function LiveFirehose() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeSlug, setActiveSlug] = useState("all");

  const load = useCallback(async () => {
    try { const { data } = await api.get("/community/firehose?limit=80"); setData(data); }
    catch { /* soft-fail */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  }, [load]);

  const filtered = useMemo(() => {
    if (!data) return [];
    return activeSlug === "all" ? data.articles : data.articles.filter((a) => a.source_slug === activeSlug);
  }, [data, activeSlug]);

  const sourceCounts = useMemo(() => {
    if (!data) return {};
    const c = {};
    for (const a of data.articles) c[a.source_slug] = (c[a.source_slug] || 0) + 1;
    return c;
  }, [data]);

  return (
    <section data-testid="blog-firehose" className="py-14 lg:py-20 bg-slate-50 border-y border-slate-200">
      <div className="mx-auto max-w-7xl px-6">
        <div className="mb-6 flex items-end justify-between flex-wrap gap-4">
          <div>
            <div className="text-xs font-bold uppercase tracking-[0.2em] text-[#F5821F] mb-2 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 pulse-dot" /> Live · Cyber News Firehose
            </div>
            <h2 className="font-heading text-2xl md:text-3xl lg:text-4xl font-semibold tracking-tight text-slate-900">Everything happening in cybersecurity, right now</h2>
            <p className="mt-3 text-base text-slate-600 max-w-3xl leading-relaxed">
              Merged live feed from <strong>{data?.sources?.length || 11} top security sources</strong> — breaches, vulnerabilities, ransomware, nation-state activity and threat research. Sorted newest-first, updated every minute.
            </p>
          </div>
          <button data-testid="firehose-refresh" onClick={load} className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600 hover:text-[#2E7DF5] border border-slate-200 hover:border-[#2E7DF5] rounded-full px-4 py-1.5 bg-white">
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>

        {/* Source filter chips */}
        {data && (
          <div className="mb-6 flex flex-wrap items-center gap-2" data-testid="firehose-source-chips">
            <button data-testid="firehose-chip-all" onClick={() => setActiveSlug("all")} className={`text-xs font-semibold rounded-full px-3 py-1 border transition-colors ${activeSlug === "all" ? "bg-slate-900 text-white border-slate-900" : "bg-white text-slate-600 border-slate-200 hover:border-slate-400"}`}>
              All sources <span className="text-[10px] opacity-70">({data.count})</span>
            </button>
            {data.sources.map((s) => (
              <button
                key={s.slug}
                data-testid={`firehose-chip-${s.slug}`}
                onClick={() => setActiveSlug(s.slug)}
                className={`text-xs font-semibold rounded-full px-3 py-1 border transition-colors ${activeSlug === s.slug ? "bg-slate-900 text-white border-slate-900" : `${chipFor(s.slug)} hover:opacity-80`}`}
              >
                {s.name} <span className="text-[10px] opacity-70">({sourceCounts[s.slug] || 0})</span>
              </button>
            ))}
          </div>
        )}

        {loading && !data && (
          <div className="py-16 flex items-center justify-center text-slate-400 gap-2 text-sm">
            <Loader2 className="w-4 h-4 animate-spin" /> Fetching all feeds…
          </div>
        )}

        {data && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <AnimatePresence mode="popLayout">
              {filtered.map((a, i) => (
                <motion.a
                  key={a.url}
                  layout
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.22, delay: (i % 12) * 0.02 }}
                  href={a.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  data-testid={`firehose-card-${i}`}
                  className="group flex flex-col rounded-xl overflow-hidden border border-slate-200 bg-white hover:border-slate-300 hover:shadow-md transition-all"
                >
                  {a.image && (
                    <div className="aspect-[16/9] bg-slate-100 overflow-hidden">
                      <img src={a.image} alt="" loading="lazy" className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" />
                    </div>
                  )}
                  <div className="p-4 flex-1 flex flex-col">
                    <div className="flex items-center gap-2 mb-2 flex-wrap">
                      <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${chipFor(a.source_slug)}`}>{a.source_name}</span>
                      <span className="text-[10px] text-slate-400">{a.date}{a.iso_date ? ` · ${timeAgo(a.iso_date)}` : ""}</span>
                    </div>
                    <h3 className="font-heading font-semibold text-slate-900 text-sm md:text-base leading-snug group-hover:text-[#2E7DF5] transition-colors line-clamp-3">{a.title}</h3>
                    {a.excerpt && <p className="mt-2 text-xs text-slate-600 leading-relaxed line-clamp-3">{a.excerpt}</p>}
                    <div className="mt-3 text-[11px] font-semibold text-[#2E7DF5] inline-flex items-center gap-1">
                      Read on source <ExternalLink className="w-3 h-3" />
                    </div>
                  </div>
                </motion.a>
              ))}
            </AnimatePresence>
          </div>
        )}

        {data && filtered.length === 0 && (
          <div className="py-14 text-center text-sm text-slate-500">
            No articles from this source right now — try another chip or refresh.
          </div>
        )}

        <div className="mt-6 text-[11px] text-slate-500">
          Content aggregated as metadata (title + excerpt + cover image). Every card links back to the origin. Sources: {data?.sources?.map((s) => s.name).join(" · ") || "loading"}.
        </div>
      </div>
    </section>
  );
}
