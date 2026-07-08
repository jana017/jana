import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Skull, ExternalLink, Globe, Building2 } from "lucide-react";
import { api } from "@/lib/api";

function timeAgo(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function AttackFeed() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    let active = true;
    api.get("/attack-feed").then(({ data }) => active && setData(data)).catch(() => active && setErr(true));
    return () => { active = false; };
  }, []);

  const items = data?.items?.slice(0, 9) || [];

  return (
    <section data-testid="attack-feed" className="py-20 lg:py-28 bg-slate-50">
      <div className="mx-auto max-w-7xl px-6">
        <div className="flex flex-wrap items-end justify-between gap-4 mb-10">
          <div className="max-w-2xl">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-red-600 mb-3">
              <span className="w-2 h-2 rounded-full bg-red-500 pulse-dot" /> Live · Real-Time Attack Feed
            </div>
            <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-slate-900">
              Ransomware attacks, as they surface
            </h2>
            <p className="mt-4 text-base text-slate-600 leading-relaxed">
              Newly disclosed victims from active ransomware groups worldwide. Click any card for the full disclosure.
            </p>
          </div>
          <div className="text-sm text-slate-500">{data ? `Source: ${data.source}` : "Connecting…"}</div>
        </div>

        {err && <div className="text-sm text-red-500">Attack feed temporarily unavailable.</div>}
        {!data && !err && <div className="text-sm text-slate-400">Loading live attack feed…</div>}

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {items.map((it, i) => (
            <motion.a
              key={(it.victim || "") + i}
              href={it.url}
              target="_blank"
              rel="noopener noreferrer"
              initial={{ opacity: 0, y: 14 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.45, delay: (i % 3) * 0.07 }}
              data-testid={`attack-card-${i}`}
              className="group rounded-xl border border-slate-200 bg-white shadow-sm hover:shadow-md hover:-translate-y-1 transition-[transform,box-shadow] overflow-hidden"
            >
              <div className="relative h-36 bg-slate-100 overflow-hidden">
                {it.screenshot ? (
                  <img src={it.screenshot} alt={it.victim} loading="lazy" className="w-full h-full object-cover object-top group-hover:scale-105 transition-transform duration-700" onError={(e) => { e.currentTarget.style.display = "none"; }} />
                ) : (
                  <div className="w-full h-full flex items-center justify-center"><Skull className="w-8 h-8 text-slate-300" /></div>
                )}
                <span className="absolute top-3 left-3 inline-flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md bg-red-600 text-white">
                  <Skull className="w-3 h-3" /> {it.group}
                </span>
                <ExternalLink className="absolute top-3 right-3 w-4 h-4 text-white opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>
              <div className="p-5">
                <h3 className="font-heading text-base font-semibold text-slate-900 leading-snug truncate group-hover:text-[#2E7DF5] transition-colors">{it.victim || it.domain || "Undisclosed victim"}</h3>
                <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
                  {it.sector && <span className="inline-flex items-center gap-1"><Building2 className="w-3.5 h-3.5" />{it.sector}</span>}
                  {it.country && <span className="inline-flex items-center gap-1"><Globe className="w-3.5 h-3.5" />{it.country}</span>}
                  <span className="text-slate-400">{timeAgo(it.date)}</span>
                </div>
              </div>
            </motion.a>
          ))}
        </div>
      </div>
    </section>
  );
}
