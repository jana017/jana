import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Database, ShieldAlert, Radar, Activity, ExternalLink, Search, X } from "lucide-react";
import { api } from "@/lib/api";

function Counter({ value, suffix = "" }) {
  const [n, setN] = useState(0);
  useEffect(() => {
    if (value == null) return;
    let raf;
    const start = performance.now();
    const dur = 1100;
    const tick = (t) => {
      const p = Math.min((t - start) / dur, 1);
      setN(Math.floor(p * value));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);
  return <>{n.toLocaleString()}{suffix}</>;
}

export default function LiveThreatLandscape() {
  const [feed, setFeed] = useState(null);
  const [err, setErr] = useState(false);
  const [query, setQuery] = useState("");

  useEffect(() => {
    let active = true;
    api.get("/live-feed").then(({ data }) => active && setFeed(data)).catch(() => active && setErr(true));
    return () => { active = false; };
  }, []);

  const filtered = useMemo(() => {
    const items = feed?.items || [];
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((it) =>
      (it.cve || "").toLowerCase().includes(q) ||
      (it.name || "").toLowerCase().includes(q) ||
      (it.vendor || "").toLowerCase().includes(q) ||
      (it.product || "").toLowerCase().includes(q)
    );
  }, [feed, query]);

  const stats = [
    { icon: Database, label: "Exploited CVEs tracked", value: feed?.total_count, color: "blue", testid: "stat-total" },
    { icon: ShieldAlert, label: "Ransomware-linked", value: feed?.ransomware_linked, color: "red", testid: "stat-ransomware" },
    { icon: Radar, label: "Feeds monitored", value: 42, color: "orange", testid: "stat-feeds" },
    { icon: Activity, label: "Uptime SLA", value: 99, suffix: "%", color: "green", testid: "stat-uptime" },
  ];
  const colorMap = {
    blue: "bg-blue-50 text-[#2E7DF5]",
    red: "bg-red-50 text-red-500",
    orange: "bg-orange-50 text-[#F5821F]",
    green: "bg-green-50 text-green-600",
  };

  return (
    <section data-testid="live-landscape" className="py-20 lg:py-28 bg-white">
      <div className="mx-auto max-w-7xl px-6">
        <div className="flex flex-wrap items-end justify-between gap-4 mb-10">
          <div className="max-w-2xl">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-blue-600 mb-3">
              <span className="w-2 h-2 rounded-full bg-green-500 pulse-dot" /> Live · Real-Time Threat Landscape
            </div>
            <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-slate-900">
              The threat landscape, right now
            </h2>
          </div>
          <div className="text-sm text-slate-500">{feed ? `Source: ${feed.source}` : "Connecting to feed…"}</div>
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {stats.map((s, i) => (
            <motion.div
              key={s.testid}
              initial={{ opacity: 0, y: 14 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: i * 0.06 }}
              data-testid={s.testid}
              className="rounded-xl border border-slate-200 bg-white shadow-sm p-6"
            >
              <span className={`w-10 h-10 rounded-lg flex items-center justify-center mb-4 ${colorMap[s.color]}`}>
                <s.icon className="w-5 h-5" strokeWidth={1.7} />
              </span>
              <div className="font-heading text-3xl font-bold text-slate-900">
                {s.value != null ? <Counter value={s.value} suffix={s.suffix} /> : "—"}
              </div>
              <div className="text-sm text-slate-500 mt-1">{s.label}</div>
            </motion.div>
          ))}
        </div>

        <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 border-b border-slate-100 bg-slate-50">
            <span className="text-sm font-semibold text-slate-800">Latest exploited vulnerabilities</span>
            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-500 tabular-nums" data-testid="cve-count">
                {feed ? `${filtered.length.toLocaleString()} of ${(feed.items?.length || 0).toLocaleString()}` : "…"}
              </span>
              <span className="flex items-center gap-1.5 text-xs font-semibold text-green-600"><span className="w-1.5 h-1.5 rounded-full bg-green-500 pulse-dot" /> LIVE</span>
            </div>
          </div>

          <div className="px-5 py-3 border-b border-slate-100">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                data-testid="cve-search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search by CVE number or vulnerability name (e.g. CVE-2024-3400 or Chrome)"
                className="w-full bg-white border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none pl-9 pr-9 py-2.5 text-sm text-slate-800 placeholder:text-slate-400 rounded-md transition-shadow"
              />
              {query && (
                <button
                  onClick={() => setQuery("")}
                  data-testid="cve-search-clear"
                  aria-label="Clear search"
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>

          <div className="max-h-[460px] overflow-y-auto divide-y divide-slate-100" data-testid="cve-feed-scroll">
            {err && <div className="p-6 text-sm text-red-500">Feed temporarily unavailable.</div>}
            {!feed && !err && <div className="p-6 text-sm text-slate-400">Loading live feed…</div>}
            {feed && filtered.length === 0 && (
              <div className="p-6 text-sm text-slate-400" data-testid="cve-no-results">No vulnerabilities match “{query}”.</div>
            )}
            {filtered.map((it, i) => (
              <a
                key={it.cve + i}
                href={it.nvd_url}
                target="_blank"
                rel="noopener noreferrer"
                data-testid={`feed-row-${i}`}
                className="grid grid-cols-[auto_1fr_auto] gap-4 items-center px-5 py-3 hover:bg-blue-50/60 transition-colors group"
              >
                <span className="font-mono-data text-xs font-medium text-[#2E7DF5] w-28 shrink-0 group-hover:underline">{it.cve}</span>
                <div className="min-w-0">
                  <div className="text-sm text-slate-800 truncate flex items-center gap-1.5">
                    {it.name}
                    <ExternalLink className="w-3 h-3 text-slate-400 opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
                  </div>
                  <div className="text-xs text-slate-400">{it.vendor} · {it.product}</div>
                </div>
                <span className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md ${it.ransomware === "Known" ? "bg-red-50 text-red-600" : "bg-slate-100 text-slate-500"}`}>
                  {it.ransomware === "Known" ? "Ransomware" : it.dateAdded}
                </span>
              </a>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
