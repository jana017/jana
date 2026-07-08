import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Activity, ShieldAlert, Database, Radar } from "lucide-react";
import { api } from "@/lib/api";

function Counter({ value }) {
  const [n, setN] = useState(0);
  useEffect(() => {
    if (!value) return;
    let raf;
    const start = performance.now();
    const dur = 1200;
    const tick = (t) => {
      const p = Math.min((t - start) / dur, 1);
      setN(Math.floor(p * value));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);
  return <>{n.toLocaleString()}</>;
}

export default function LiveThreatLandscape() {
  const [feed, setFeed] = useState(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    let active = true;
    api
      .get("/live-feed")
      .then(({ data }) => active && setFeed(data))
      .catch(() => active && setErr(true));
    return () => {
      active = false;
    };
  }, []);

  const stats = [
    { icon: Database, label: "Exploited CVEs Tracked", value: feed?.total_count, testid: "stat-total" },
    { icon: ShieldAlert, label: "Ransomware-Linked", value: feed?.ransomware_linked, testid: "stat-ransomware" },
    { icon: Radar, label: "Feeds Monitored", value: 42, testid: "stat-feeds" },
    { icon: Activity, label: "Uptime SLA %", value: 99, testid: "stat-uptime" },
  ];

  return (
    <section data-testid="live-landscape" className="relative py-24 border-t border-white/5 bg-[#0A1220]">
      <div className="mx-auto max-w-[1400px] px-6">
        <div className="flex flex-wrap items-end justify-between gap-6 mb-14">
          <div>
            <div className="flex items-center gap-3 font-mono-data text-[11px] uppercase tracking-[0.3em] text-[#F5821F] mb-4">
              <span className="w-2 h-2 rounded-full bg-[#35D07F] pulse-dot" />
              Live · Real-Time Threat Landscape
            </div>
            <h2 className="font-display font-black tracking-tighter text-white text-4xl sm:text-5xl">
              The Landscape, Right Now
            </h2>
          </div>
          <div className="font-mono-data text-[11px] text-[#5A6B82] uppercase tracking-widest">
            {feed ? `Source: ${feed.source}` : "Connecting to feed…"}
          </div>
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-12">
          {stats.map((s) => (
            <motion.div
              key={s.testid}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6 }}
              data-testid={s.testid}
              className="glass p-6 hover:-translate-y-1 hover:border-[#F5821F]/40 transition-[transform,border-color] duration-300"
            >
              <s.icon className="w-6 h-6 text-[#F5821F] mb-6" strokeWidth={1.5} />
              <div className="font-display font-black text-3xl md:text-4xl text-white tracking-tighter">
                {s.value != null ? <Counter value={s.value} /> : "—"}
              </div>
              <div className="font-mono-data text-[10px] uppercase tracking-widest text-[#5A6B82] mt-2">
                {s.label}
              </div>
            </motion.div>
          ))}
        </div>

        <div className="glass">
          <div className="flex items-center justify-between px-5 py-3 border-b border-white/10">
            <span className="font-mono-data text-[11px] uppercase tracking-widest text-white">
              Latest Exploited Vulnerabilities
            </span>
            <span className="font-mono-data text-[10px] text-[#35D07F]">● LIVE</span>
          </div>
          <div className="max-h-[360px] overflow-y-auto divide-y divide-white/5">
            {err && (
              <div className="p-6 font-mono-data text-sm text-[#FF3B5C]">Feed temporarily unavailable.</div>
            )}
            {!feed && !err && (
              <div className="p-6 font-mono-data text-sm text-[#5A6B82]">Loading live feed…</div>
            )}
            {feed?.items?.map((it, i) => (
              <div
                key={it.cve + i}
                data-testid={`feed-row-${i}`}
                className="grid grid-cols-[auto_1fr_auto] gap-4 items-center px-5 py-3 hover:bg-white/5 transition-colors"
              >
                <span className="font-mono-data text-[12px] text-[#F5821F] w-32 shrink-0">{it.cve}</span>
                <div className="min-w-0">
                  <div className="text-sm text-white truncate">{it.name}</div>
                  <div className="font-mono-data text-[10px] text-[#5A6B82] uppercase tracking-wider">
                    {it.vendor} · {it.product}
                  </div>
                </div>
                <span
                  className={`font-mono-data text-[10px] uppercase tracking-widest px-2 py-1 border ${
                    it.ransomware === "Known"
                      ? "text-[#FF3B5C] border-[#FF3B5C]/40"
                      : "text-[#5A6B82] border-white/10"
                  }`}
                >
                  {it.ransomware === "Known" ? "Ransomware" : it.dateAdded}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
