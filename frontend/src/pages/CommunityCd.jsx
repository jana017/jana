import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowLeft, ArrowUpRight, Calendar, ExternalLink, Info, Loader2, BookOpen } from "lucide-react";
import Navbar from "@/components/Navbar";
import Contact from "@/components/Contact";
import { api } from "@/lib/api";
import useSeo from "@/lib/useSeo";

const TOPIC_META = {
  dfir:    { label: "DFIR & Threat Investigations",  tag: "DFIR",    tone: "text-blue-400" },
  malware: { label: "Malware Analysis Case Studies", tag: "Malware", tone: "text-red-400" },
  soc:     { label: "SOC & Threat Hunting Playbooks",tag: "SOC",     tone: "text-emerald-400" },
};

export default function CommunityCd() {
  const { topic = "dfir" } = useParams();
  const meta = TOPIC_META[topic] || TOPIC_META.dfir;
  const [articles, setArticles] = useState(null);
  const [err, setErr] = useState("");

  useSeo({
    title: `${meta.label} · Community Threat Intel | NivX Machines`,
    description: `Curated ${meta.label.toLowerCase()} from the CyberDefenders community, aggregated on NivX Machines with links back to source.`,
    canonical: `https://nivxmachines.com/community/cd/${topic}`,
  });

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const { data } = await api.get(`/community/cd-articles?topic=${topic}`);
        if (!live) return;
        setArticles(data.articles || []);
      } catch (e) {
        if (live) setErr(e.response?.data?.detail || "Could not load community feed");
      }
    })();
    return () => { live = false; };
  }, [topic]);

  return (
    <div data-testid="community-cd-page" className="bg-white min-h-screen">
      <Navbar />

      <section className="pt-28 pb-14 lg:pt-32 bg-[#0A1220] relative overflow-hidden border-b border-slate-800">
        <div className="absolute inset-0 dot-grid opacity-40" aria-hidden="true" />
        <div className="relative mx-auto max-w-7xl px-6">
          <Link
            to="/threat-intelligence"
            data-testid="community-back"
            className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-400 hover:text-[#2E7DF5] mb-6"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Threat Intelligence
          </Link>
          <div className={`inline-flex items-center gap-2 bg-white/5 border border-white/10 rounded-full px-3 py-1 text-xs font-semibold mb-5 ${meta.tone}`}>
            <BookOpen className="w-4 h-4" /> Community · {meta.tag}
          </div>
          <h1 className="font-heading text-3xl md:text-4xl lg:text-5xl font-bold tracking-tight text-white leading-tight max-w-3xl">
            {meta.label}
          </h1>
          <p className="mt-4 text-base md:text-lg text-slate-400 max-w-2xl leading-relaxed">
            The latest {meta.tag.toLowerCase()} writeups curated from the CyberDefenders community — rendered right here on NivX so you can browse without leaving the platform.
          </p>
        </div>
      </section>

      <section className="py-10 lg:py-14 bg-white">
        <div className="mx-auto max-w-7xl px-6">
          <div className="mb-6 rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 flex flex-wrap items-start gap-2 text-sm text-slate-600" data-testid="community-attribution">
            <Info className="w-4 h-4 mt-0.5 shrink-0 text-slate-400" />
            <span>
              These article previews are <strong>curated from CyberDefenders.org</strong> — a community platform for DFIR &amp; SOC training.
              We show the title, cover image and a short snippet here; clicking any card opens the full article on the original site so the authors get proper credit.
            </span>
          </div>

          {!articles && !err && (
            <div className="py-24 flex items-center justify-center text-slate-400 gap-2" data-testid="community-loading">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading community feed…
            </div>
          )}
          {err && <div className="py-16 text-center text-red-500" data-testid="community-err">{err}</div>}
          {articles && articles.length === 0 && (
            <div className="py-16 text-center text-slate-400" data-testid="community-empty">
              No community articles match this topic right now — check back soon or view another topic.
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" data-testid="community-grid">
            {(articles || []).map((a, i) => (
              <motion.a
                key={a.slug}
                href={a.url}
                target="_blank"
                rel="noopener noreferrer"
                initial={{ opacity: 0, y: 14 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: (i % 3) * 0.05 }}
                data-testid={`community-card-${i}`}
                className="group flex flex-col rounded-xl border border-slate-200 overflow-hidden bg-white hover:shadow-lg hover:-translate-y-1 hover:border-slate-300 transition-all"
              >
                <div className="relative aspect-[16/9] overflow-hidden bg-slate-100">
                  {a.image && (
                    <img
                      src={a.image}
                      alt={a.title}
                      loading="lazy"
                      referrerPolicy="no-referrer"
                      className="absolute inset-0 w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                      onError={(e) => { e.currentTarget.style.display = "none"; }}
                    />
                  )}
                  <div className="absolute inset-0 bg-gradient-to-t from-black/30 via-transparent to-transparent" />
                  <div className="absolute top-3 left-3 flex items-center gap-2">
                    <span className="inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider bg-white/95 text-slate-900 px-2 py-0.5 rounded shadow-sm">{a.category}</span>
                  </div>
                </div>
                <div className="p-5 flex-1 flex flex-col">
                  <h3 className="font-semibold text-slate-900 group-hover:text-[#2E7DF5] transition-colors leading-snug line-clamp-3">{a.title}</h3>
                  {a.excerpt && <p className="mt-2 text-sm text-slate-600 leading-relaxed line-clamp-3 flex-1">{a.excerpt}</p>}
                  <div className="mt-4 flex items-center justify-between pt-3 border-t border-slate-100">
                    <div className="flex items-center gap-2 text-[11px] text-slate-500">
                      {a.date && <span className="inline-flex items-center gap-1"><Calendar className="w-3 h-3" /> {a.date}</span>}
                    </div>
                    <span className="inline-flex items-center gap-1 text-xs font-semibold text-[#2E7DF5]">
                      Read on CyberDefenders <ExternalLink className="w-3 h-3" />
                    </span>
                  </div>
                </div>
              </motion.a>
            ))}
          </div>

          <div className="mt-10 flex flex-wrap justify-center gap-3" data-testid="community-topic-nav">
            {Object.entries(TOPIC_META).filter(([k]) => k !== topic).map(([k, m]) => (
              <Link
                key={k}
                to={`/community/cd/${k}`}
                data-testid={`community-topic-${k}`}
                className="inline-flex items-center gap-1.5 text-sm font-semibold text-slate-600 hover:text-[#2E7DF5] border border-slate-200 hover:border-[#2E7DF5] rounded-full px-4 py-1.5 transition-colors"
              >
                Switch to {m.tag} <ArrowUpRight className="w-3.5 h-3.5" />
              </Link>
            ))}
          </div>
        </div>
      </section>

      <Contact />
    </div>
  );
}
