import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowLeft, ArrowUpRight, Calendar, ExternalLink, Info, Loader2, Radio } from "lucide-react";
import Navbar from "@/components/Navbar";
import Contact from "@/components/Contact";
import { api } from "@/lib/api";
import useSeo from "@/lib/useSeo";

const SOURCE_META = {
  talos:        { label: "Cisco Talos Intelligence",           tag: "Talos",         tone: "text-red-400",       gradient: "from-red-500/10 to-transparent",       chip: "bg-red-50 text-red-700" },
  unit42:       { label: "Palo Alto Unit 42",                   tag: "Unit42",        tone: "text-blue-400",      gradient: "from-blue-500/10 to-transparent",      chip: "bg-blue-50 text-blue-700" },
  dfir:         { label: "The DFIR Report",                     tag: "DFIR",          tone: "text-amber-400",     gradient: "from-amber-500/10 to-transparent",     chip: "bg-amber-50 text-amber-700" },
  msthreat:     { label: "Microsoft Threat Intelligence",       tag: "MSTI",          tone: "text-emerald-400",   gradient: "from-emerald-500/10 to-transparent",   chip: "bg-emerald-50 text-emerald-700" },
  bleeping:     { label: "BleepingComputer",                    tag: "Bleeping",      tone: "text-orange-400",    gradient: "from-orange-500/10 to-transparent",    chip: "bg-orange-50 text-orange-700" },
  hn:           { label: "Hacker News",                          tag: "HN",            tone: "text-[#F5821F]",     gradient: "from-orange-500/10 to-transparent",    chip: "bg-orange-50 text-orange-700" },
  thn:          { label: "The Hacker News",                     tag: "THN",           tone: "text-purple-400",    gradient: "from-purple-500/10 to-transparent",    chip: "bg-purple-50 text-purple-700" },
  krebs:        { label: "Krebs on Security",                    tag: "Krebs",         tone: "text-rose-400",      gradient: "from-rose-500/10 to-transparent",      chip: "bg-rose-50 text-rose-700" },
  darkreading:  { label: "Dark Reading",                         tag: "Dark Reading",  tone: "text-slate-500",     gradient: "from-slate-500/10 to-transparent",     chip: "bg-slate-100 text-slate-700" },
  securityweek: { label: "SecurityWeek",                         tag: "SecurityWeek",  tone: "text-indigo-400",    gradient: "from-indigo-500/10 to-transparent",    chip: "bg-indigo-50 text-indigo-700" },
  therecord:    { label: "The Record (Recorded Future)",         tag: "The Record",    tone: "text-fuchsia-400",   gradient: "from-fuchsia-500/10 to-transparent",   chip: "bg-fuchsia-50 text-fuchsia-700" },
};

const ORDER = ["talos", "unit42", "dfir", "msthreat", "bleeping", "hn", "thn", "krebs", "darkreading", "securityweek", "therecord"];

export default function CommunityFeed() {
  const { source = "talos" } = useParams();
  const meta = SOURCE_META[source] || SOURCE_META.talos;
  const [feed, setFeed] = useState(null);
  const [err, setErr] = useState("");

  useSeo({
    title: `${meta.label} · Community Threat Intel | NivX Machines`,
    description: `Latest ${meta.label} research aggregated on NivX with links back to source.`,
    canonical: `https://nivxmachines.com/community/${source}`,
  });

  useEffect(() => {
    let live = true;
    setFeed(null);
    setErr("");
    (async () => {
      try {
        const { data } = await api.get(`/community/feed/${source}`);
        if (!live) return;
        setFeed(data);
      } catch (e) {
        if (live) setErr(e.response?.data?.detail || "Could not load feed");
      }
    })();
    return () => { live = false; };
  }, [source]);

  const other = ORDER.filter((s) => s !== source);

  return (
    <div data-testid="community-feed-page" className="bg-white min-h-screen">
      <Navbar />

      <section className={`pt-28 pb-14 lg:pt-32 bg-[#0A1220] relative overflow-hidden border-b border-slate-800 bg-gradient-to-b ${meta.gradient}`}>
        <div className="absolute inset-0 dot-grid opacity-40" aria-hidden="true" />
        <div className="relative mx-auto max-w-7xl px-6">
          <Link to="/threat-intelligence#community" data-testid="feed-back" className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-400 hover:text-[#2E7DF5] mb-6">
            <ArrowLeft className="w-3.5 h-3.5" /> Threat Intelligence
          </Link>
          <div className={`inline-flex items-center gap-2 bg-white/5 border border-white/10 rounded-full px-3 py-1 text-xs font-semibold mb-5 ${meta.tone}`}>
            <Radio className="w-4 h-4" /> Community feed · {meta.tag}
          </div>
          <h1 className="font-heading text-3xl md:text-4xl lg:text-5xl font-bold tracking-tight text-white leading-tight max-w-3xl">
            {meta.label}
          </h1>
          <p className="mt-4 text-base md:text-lg text-slate-400 max-w-2xl leading-relaxed">
            The latest threat research aggregated from {meta.label} — browse the feed inside NivX, click through to read the full article on the source site.
          </p>
        </div>
      </section>

      <section className="py-10 lg:py-14 bg-white">
        <div className="mx-auto max-w-7xl px-6">
          <div className="mb-6 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 flex flex-wrap items-start gap-2 text-sm text-slate-600" data-testid="feed-attribution">
            <Info className="w-4 h-4 mt-0.5 shrink-0 text-slate-400" />
            <span>
              Article previews are <strong>curated from {meta.label}</strong>. We show the title, cover image and a short snippet here; clicking any card opens the full article on the source site so the original authors get proper credit.
            </span>
          </div>

          {!feed && !err && (
            <div className="py-24 flex items-center justify-center text-slate-400 gap-2" data-testid="feed-loading">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading community feed…
            </div>
          )}
          {err && <div className="py-16 text-center text-red-500" data-testid="feed-err">{err}</div>}

          {feed && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" data-testid="feed-grid">
              {(feed.articles || []).map((a, i) => (
                <motion.a
                  key={a.slug + i}
                  href={a.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  initial={{ opacity: 0, y: 14 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.4, delay: (i % 3) * 0.05 }}
                  data-testid={`feed-card-${i}`}
                  className="group flex flex-col rounded-xl border border-slate-200 overflow-hidden bg-white hover:shadow-lg hover:-translate-y-1 hover:border-slate-300 transition-all"
                >
                  {a.image && (
                    <div className="relative aspect-[16/9] overflow-hidden bg-slate-100">
                      <img src={a.image} alt="" loading="lazy" referrerPolicy="no-referrer" className="absolute inset-0 w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" onError={(e) => { e.currentTarget.style.display = "none"; }} />
                    </div>
                  )}
                  <div className="p-5 flex-1 flex flex-col">
                    <span className={`inline-flex w-fit items-center text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded mb-3 ${meta.chip}`}>{a.category || meta.tag}</span>
                    <h3 className="font-semibold text-slate-900 group-hover:text-[#2E7DF5] transition-colors leading-snug line-clamp-3">{a.title}</h3>
                    {a.excerpt && <p className="mt-2 text-sm text-slate-600 leading-relaxed line-clamp-3 flex-1">{a.excerpt}</p>}
                    <div className="mt-4 flex items-center justify-between pt-3 border-t border-slate-100">
                      <div className="flex items-center gap-2 text-[11px] text-slate-500">
                        {a.date && <span className="inline-flex items-center gap-1"><Calendar className="w-3 h-3" /> {a.date}</span>}
                      </div>
                      <span className="inline-flex items-center gap-1 text-xs font-semibold text-[#2E7DF5]">
                        Read on {meta.tag} <ExternalLink className="w-3 h-3" />
                      </span>
                    </div>
                  </div>
                </motion.a>
              ))}
            </div>
          )}

          <div className="mt-10 flex flex-wrap justify-center gap-3" data-testid="feed-source-nav">
            {other.map((s) => (
              <Link key={s} to={`/community/${s}`} className="inline-flex items-center gap-1.5 text-sm font-semibold text-slate-600 hover:text-[#2E7DF5] border border-slate-200 hover:border-[#2E7DF5] rounded-full px-4 py-1.5 transition-colors">
                Switch to {SOURCE_META[s].tag} <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>
            ))}
            <Link to="/community/cd/dfir" className="inline-flex items-center gap-1.5 text-sm font-semibold text-slate-600 hover:text-[#2E7DF5] border border-slate-200 hover:border-[#2E7DF5] rounded-full px-4 py-1.5 transition-colors">
              Switch to CyberDefenders <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </section>

      <Contact />
    </div>
  );
}
