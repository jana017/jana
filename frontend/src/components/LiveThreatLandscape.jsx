import { useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Database, ShieldAlert, Radar, Activity, ExternalLink, Search, X, Zap, Clock } from "lucide-react";
import { api } from "@/lib/api";

// Poll intervals
const LANDSCAPE_POLL_MS = 30_000; // aggregate refresh
const TICK_MS = 1_000;            // "last updated Xs ago" tick

function Counter({ value, suffix = "" }) {
  const [n, setN] = useState(0);
  useEffect(() => {
    if (value == null) return;
    let raf;
    const start = performance.now();
    const dur = 900;
    const from = n;
    const delta = value - from;
    const tick = (t) => {
      const p = Math.min((t - start) / dur, 1);
      setN(Math.round(from + delta * p));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
    // n is intentionally the animation source, not a dep — otherwise every frame retriggers the effect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);
  return <>{n.toLocaleString()}{suffix}</>;
}

function relTime(iso) {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function LiveThreatLandscape() {
  const [feed, setFeed] = useState(null);       // /api/live-feed (full CVE list)
  const [landscape, setLandscape] = useState(null); // /api/threat-landscape/live (aggregate)
  const [err, setErr] = useState(false);
  const [query, setQuery] = useState("");
  const [now, setNow] = useState(Date.now());
  const seenCvesRef = useRef(new Set());
  const [freshCves, setFreshCves] = useState(new Set()); // recently added — highlight

  // Initial load + polling for the aggregate.
  useEffect(() => {
    let active = true;
    const loadLandscape = async () => {
      try {
        const { data } = await api.get("/threat-landscape/live");
        if (!active) return;
        setLandscape(data);
      } catch { if (active) setErr(true); }
    };
    const loadFeed = async () => {
      try {
        const { data } = await api.get("/live-feed");
        if (!active) return;
        // Detect newly-added CVEs on every refresh (skip first).
        const incoming = new Set((data.items || []).map((i) => i.cve));
        if (seenCvesRef.current.size > 0) {
          const fresh = new Set();
          incoming.forEach((cve) => { if (!seenCvesRef.current.has(cve)) fresh.add(cve); });
          if (fresh.size) {
            setFreshCves(fresh);
            setTimeout(() => setFreshCves(new Set()), 8000);
          }
        }
        seenCvesRef.current = incoming;
        setFeed(data);
      } catch { if (active) setErr(true); }
    };
    loadLandscape();
    loadFeed();
    // Poll aggregate every 30s, feed every 60s.
    const iA = setInterval(loadLandscape, LANDSCAPE_POLL_MS);
    const iB = setInterval(loadFeed, LANDSCAPE_POLL_MS * 2);
    // Pause polling when tab hidden — save bandwidth, resume on visible.
    const onVis = () => {
      if (document.visibilityState === "visible") { loadLandscape(); loadFeed(); }
    };
    document.addEventListener("visibilitychange", onVis);
    return () => { active = false; clearInterval(iA); clearInterval(iB); document.removeEventListener("visibilitychange", onVis); };
  }, []);

  // Live "last updated Xs ago" ticker.
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), TICK_MS);
    return () => clearInterval(t);
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

  const s = landscape?.stats || {};
  const stats = [
    { icon: Database, label: "Exploited CVEs tracked", value: s.total_cves, color: "blue", testid: "stat-total" },
    { icon: ShieldAlert, label: "Ransomware-linked CVEs", value: s.ransomware_linked_cves, color: "red", testid: "stat-ransomware" },
    { icon: Zap, label: "New CVEs added (7d)", value: s.cves_last_7d, color: "orange", testid: "stat-recent" },
    { icon: Activity, label: "Curated IOCs", value: s.curated_iocs, color: "green", testid: "stat-iocs" },
  ];
  const colorMap = {
    blue: "bg-blue-50 text-[#2E7DF5]",
    red: "bg-red-50 text-red-500",
    orange: "bg-orange-50 text-[#F5821F]",
    green: "bg-green-50 text-green-600",
  };

  // Suppress unused warning — `now` triggers re-render for relTime.
  void now;

  const updatedRel = relTime(landscape?.updated_at);
  const syncRel = relTime(landscape?.last_synced_at);

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
            <p className="mt-2 text-sm text-slate-500 flex items-center gap-2">
              <Clock className="w-3.5 h-3.5" />
              Refreshed <span data-testid="landscape-updated" className="font-semibold text-slate-700">{updatedRel}</span>
              {landscape?.last_synced_source && (
                <span className="text-slate-400">· last {landscape.last_synced_source} sync {syncRel}</span>
              )}
            </p>
          </div>
          <div className="text-sm text-slate-500">{feed ? `Source: ${feed.source}` : "Connecting to feed…"}</div>
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {stats.map((stat, i) => (
            <motion.div
              key={stat.testid}
              initial={{ opacity: 0, y: 14 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: i * 0.06 }}
              data-testid={stat.testid}
              className="rounded-xl border border-slate-200 bg-white shadow-sm p-6"
            >
              <span className={`w-10 h-10 rounded-lg flex items-center justify-center mb-4 ${colorMap[stat.color]}`}>
                <stat.icon className="w-5 h-5" strokeWidth={1.7} />
              </span>
              <div className="font-heading text-3xl font-bold text-slate-900">
                {stat.value != null ? <Counter value={stat.value} suffix={stat.suffix || ""} /> : "—"}
              </div>
              <div className="text-sm text-slate-500 mt-1">{stat.label}</div>
            </motion.div>
          ))}
        </div>

        {/* Real-time activity ticker — victims last 24h + newest CVE dates */}
        {landscape && (
          <div className="mb-6 rounded-xl border border-slate-200 bg-slate-50/60 px-4 py-3 flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
            <span className="inline-flex items-center gap-1.5 font-semibold text-slate-700">
              <span className="w-2 h-2 rounded-full bg-red-500 pulse-dot" /> Live activity
            </span>
            <span className="text-slate-500">
              <span data-testid="live-victims-24h" className="font-bold text-slate-800">{landscape.stats.victims_24h}</span> ransomware victims disclosed in last 24h
            </span>
            <span className="text-slate-500">
              <span data-testid="live-critical-iocs" className="font-bold text-red-600">{landscape.stats.critical_iocs}</span> critical IOCs in curated DB
            </span>
            {landscape.newest_victims?.[0] && (
              <span className="text-slate-500 truncate max-w-md">
                Most recent: <span className="font-semibold text-slate-700">{landscape.newest_victims[0].group}</span> · {landscape.newest_victims[0].victim}
              </span>
            )}
          </div>
        )}

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
            <AnimatePresence initial={false}>
              {filtered.map((it, i) => {
                const isFresh = freshCves.has(it.cve);
                return (
                  <motion.a
                    key={`${it.cve ?? "item"}-${i}`}
                    initial={isFresh ? { backgroundColor: "#FEF3C7" } : false}
                    animate={{ backgroundColor: isFresh ? "#FEF9E7" : "rgba(255,255,255,0)" }}
                    transition={{ duration: 3.5 }}
                    href={it.nvd_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    data-testid={`feed-row-${i}`}
                    className={`grid grid-cols-[auto_1fr_auto] gap-4 items-center px-5 py-3 hover:bg-blue-50/60 transition-colors group ${isFresh ? "ring-1 ring-amber-300" : ""}`}
                  >
                    <span className="font-mono-data text-xs font-medium text-[#2E7DF5] w-28 shrink-0 group-hover:underline inline-flex items-center gap-1">
                      {it.cve}
                      {isFresh && <span data-testid={`feed-new-${i}`} className="text-[9px] font-bold uppercase tracking-wider bg-amber-500 text-white px-1 py-0.5 rounded">NEW</span>}
                    </span>
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
                  </motion.a>
                );
              })}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </section>
  );
}
