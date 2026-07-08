import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { api } from "@/lib/api";
import Navbar from "@/components/Navbar";
import Contact from "@/components/Contact";
import { FileText, ExternalLink, ShieldAlert, BookOpen, ArrowRight } from "lucide-react";

const CYBERDEFENDERS = [
  { title: "Blue Team Labs & Threat Investigations", desc: "Hands-on DFIR writeups, malware analysis walkthroughs and detection engineering from the CyberDefenders community.", tag: "DFIR", url: "https://cyberdefenders.org/blog/" },
  { title: "Malware Analysis Case Studies", desc: "Step-by-step reverse-engineering of real-world samples with IOCs, YARA rules and TTP mapping.", tag: "Malware", url: "https://cyberdefenders.org/blog/" },
  { title: "SOC & Threat Hunting Playbooks", desc: "Practical guidance on building detections, triaging alerts and hunting adversaries across the enterprise.", tag: "SOC", url: "https://cyberdefenders.org/blog/" },
];

export default function ThreatIntelligence() {
  const [intel, setIntel] = useState(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    let active = true;
    api.get("/intel-feed").then(({ data }) => active && setIntel(data)).catch(() => active && setErr(true));
    window.scrollTo({ top: 0 });
    return () => { active = false; };
  }, []);

  return (
    <div data-testid="threat-intelligence-page" className="bg-white">
      <Navbar />

      {/* Hero */}
      <section className="pt-28 pb-14 lg:pt-32 bg-[#0A1220] relative overflow-hidden">
        <div className="absolute inset-0 dot-grid opacity-40" aria-hidden="true" />
        <div className="relative mx-auto max-w-7xl px-6">
          <div className="inline-flex items-center gap-2 bg-white/5 border border-white/10 text-blue-300 rounded-full px-3 py-1 text-xs font-semibold mb-5">
            <ShieldAlert className="w-4 h-4" /> Threat Intelligence
          </div>
          <h1 className="font-heading text-3xl md:text-4xl font-bold tracking-tight text-white leading-tight max-w-3xl">
            Curated intelligence from the front lines
          </h1>
          <p className="mt-4 text-base md:text-lg text-slate-400 max-w-2xl leading-relaxed">
            Live, published threat research from Palo Alto Unit42 and hand-picked analysis from
            the security community — refreshed automatically.
          </p>
        </div>
      </section>

      {/* Unit42 live intel feed */}
      <section data-testid="intel-feed" className="py-16 lg:py-24 bg-white">
        <div className="mx-auto max-w-7xl px-6">
          <div className="flex flex-wrap items-end justify-between gap-4 mb-10">
            <div className="max-w-2xl">
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-blue-600 mb-3">
                <span className="w-2 h-2 rounded-full bg-green-500 pulse-dot" /> Live · Unit42 Timely Threat Intel
              </div>
              <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-slate-900">Latest published intelligence</h2>
            </div>
            {intel?.repo_url && (
              <a href={intel.repo_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-sm font-semibold text-[#2E7DF5] hover:underline">
                View full source <ExternalLink className="w-4 h-4" />
              </a>
            )}
          </div>

          {err && <div className="text-sm text-red-500">Intel feed temporarily unavailable.</div>}
          {!intel && !err && <div className="text-sm text-slate-400">Loading Unit42 intelligence…</div>}

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {intel?.items?.map((it, i) => (
              <motion.a
                key={it.title + i}
                href={it.url}
                target="_blank"
                rel="noopener noreferrer"
                initial={{ opacity: 0, y: 14 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.45, delay: (i % 3) * 0.07 }}
                data-testid={`intel-card-${i}`}
                className="group flex flex-col rounded-xl border border-slate-200 bg-white shadow-sm hover:shadow-md hover:-translate-y-1 transition-[transform,box-shadow] overflow-hidden"
              >
                <div className="relative h-40 overflow-hidden">
                  <img src={it.image} alt={it.title} loading="lazy" className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-700" />
                  <div className="absolute inset-0 bg-gradient-to-t from-slate-900/60 to-transparent" />
                  <span className="absolute top-3 left-3 inline-flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md bg-white/90 text-slate-800">
                    <FileText className="w-3 h-3" /> {it.source}
                  </span>
                </div>
                <div className="p-5 flex flex-col flex-1">
                  <div className="text-xs text-slate-400 mb-1.5">{it.date}</div>
                  <h3 className="font-heading text-base font-semibold text-slate-900 leading-snug mb-2 group-hover:text-[#2E7DF5] transition-colors line-clamp-2">{it.title}</h3>
                  <p className="text-sm text-slate-600 leading-relaxed line-clamp-3 flex-1">{it.summary}</p>
                  <div className="mt-4 flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-500">{it.ioc_count} IOCs</span>
                    <span className="inline-flex items-center gap-1 text-sm font-semibold text-[#2E7DF5]">Read <ExternalLink className="w-3.5 h-3.5" /></span>
                  </div>
                </div>
              </motion.a>
            ))}
          </div>
        </div>
      </section>

      {/* CyberDefenders blog */}
      <section data-testid="intel-blog" className="py-16 lg:py-24 bg-slate-50">
        <div className="mx-auto max-w-7xl px-6">
          <div className="max-w-2xl mb-10">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-[#F5821F] mb-3">
              <BookOpen className="w-4 h-4" /> From the Community
            </div>
            <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-slate-900">Threat intel blog & writeups</h2>
            <p className="mt-4 text-base text-slate-600 leading-relaxed">
              Deep-dive DFIR and malware-analysis articles curated from CyberDefenders.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {CYBERDEFENDERS.map((b, i) => (
              <motion.a
                key={b.title}
                href={b.url}
                target="_blank"
                rel="noopener noreferrer"
                initial={{ opacity: 0, y: 14 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.45, delay: i * 0.08 }}
                data-testid={`blog-card-${i}`}
                className="group rounded-xl border border-slate-200 bg-white shadow-sm hover:shadow-md hover:-translate-y-1 transition-[transform,box-shadow] p-7 flex flex-col"
              >
                <span className="inline-flex w-fit items-center text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md bg-blue-50 text-blue-700 mb-4">{b.tag}</span>
                <h3 className="font-heading text-lg font-semibold text-slate-900 mb-2 group-hover:text-[#2E7DF5] transition-colors">{b.title}</h3>
                <p className="text-sm text-slate-600 leading-relaxed flex-1">{b.desc}</p>
                <span className="mt-5 inline-flex items-center gap-1.5 text-sm font-semibold text-[#F5821F]">Read on CyberDefenders <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" /></span>
              </motion.a>
            ))}
          </div>
        </div>
      </section>

      <Contact />
    </div>
  );
}
