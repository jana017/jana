import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Activity, ShieldCheck, Radio } from "lucide-react";
import { api } from "@/lib/api";
import { COUNTRY_CENTROIDS } from "@/lib/countryCentroids";

const countryName = (() => {
  try {
    const dn = new Intl.DisplayNames(["en"], { type: "region" });
    return (code) => {
      try { return dn.of(code) || code; } catch { return code; }
    };
  } catch {
    return (code) => code;
  }
})();

const project = (lat, lon) => ({
  left: ((lon + 180) / 360) * 100,
  top: ((90 - lat) / 180) * 100,
});

// Static fallback so the map is never empty if the live feed is slow/unreachable.
const FALLBACK = [
  { code: "US", group: "chaos", victim: "Live monitoring" },
  { code: "GB", group: "akira", victim: "Live monitoring" },
  { code: "DE", group: "play", victim: "Live monitoring" },
  { code: "BR", group: "qilin", victim: "Live monitoring" },
  { code: "IN", group: "lockbit", victim: "Live monitoring" },
  { code: "RU", group: "blackcat", victim: "Live monitoring" },
];

export default function LiveThreatMap() {
  const [attacks, setAttacks] = useState([]);
  const [stats, setStats] = useState({ kev: null, ransomware: null, incidents: null, updated: null });
  const [active, setActive] = useState(0);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const [a, l] = await Promise.allSettled([api.get("/attack-feed"), api.get("/live-feed")]);
        if (!alive) return;
        if (a.status === "fulfilled") {
          const items = (a.value.data.items || [])
            .filter((i) => i.country && COUNTRY_CENTROIDS[i.country])
            .map((i) => ({ code: i.country, group: i.group, victim: i.victim }));
          setAttacks(items.length ? items : FALLBACK);
          setStats((s) => ({ ...s, incidents: a.value.data.count, updated: a.value.data.updated }));
        } else {
          setAttacks(FALLBACK);
        }
        if (l.status === "fulfilled") {
          setStats((s) => ({ ...s, kev: l.value.data.total_count, ransomware: l.value.data.ransomware_linked }));
        }
      } catch {
        if (alive) setAttacks(FALLBACK);
      }
    })();
    return () => { alive = false; };
  }, []);

  // Unique markers by country (keep first group seen), capped for a clean look.
  const markers = useMemo(() => {
    const seen = new Map();
    for (const a of attacks) {
      if (!seen.has(a.code)) seen.set(a.code, a);
    }
    return Array.from(seen.values())
      .slice(0, 14)
      .map((a) => {
        const [lat, lon] = COUNTRY_CENTROIDS[a.code];
        return { ...a, ...project(lat, lon), name: countryName(a.code) };
      });
  }, [attacks]);

  // Rotate the highlighted marker for a live feel.
  useEffect(() => {
    if (markers.length < 2) return;
    const t = setInterval(() => setActive((i) => (i + 1) % markers.length), 2600);
    return () => clearInterval(t);
  }, [markers.length]);

  const hub = markers[active];
  const activeMarker = markers[active];

  return (
    <div className="relative" data-testid="live-threat-map">
      <div className="relative rounded-2xl overflow-hidden border border-slate-800 shadow-2xl bg-[#0A1220]">
        {/* World map base */}
        <div className="relative w-full h-[300px] sm:h-[360px] lg:h-[420px]">
          <img
            src="/world-equirect.jpg"
            alt="Global threat activity map"
            className="absolute inset-0 w-full h-full object-cover opacity-[0.28] mix-blend-luminosity"
            style={{ filter: "grayscale(1) brightness(0.55) contrast(1.1)" }}
          />
          <div className="absolute inset-0 bg-gradient-to-b from-[#0A1220]/40 via-transparent to-[#0A1220]/80" />
          <div className="absolute inset-0" style={{ backgroundImage: "radial-gradient(circle, rgba(46,125,245,0.10) 1px, transparent 1px)", backgroundSize: "26px 26px" }} />

          {/* Scan sweep */}
          <div className="absolute inset-0 overflow-hidden">
            <div className="tm-scan absolute inset-y-0 w-1/3 bg-gradient-to-r from-transparent via-[#2E7DF5]/10 to-transparent" />
          </div>

          {/* Attack arcs */}
          <svg className="absolute inset-0 w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
            {hub && markers.map((m, i) => {
              if (i === active) return null;
              const mx = (m.left + hub.left) / 2;
              const my = Math.min(m.top, hub.top) - 12;
              return (
                <path
                  key={`arc-${m.code}-${i}`}
                  d={`M ${hub.left} ${hub.top} Q ${mx} ${my} ${m.left} ${m.top}`}
                  fill="none"
                  stroke="#2E7DF5"
                  strokeWidth="0.4"
                  className="tm-arc"
                  opacity={0.5}
                  vectorEffect="non-scaling-stroke"
                />
              );
            })}
          </svg>

          {/* Markers */}
          {markers.map((m, i) => {
            const isActive = i === active;
            return (
              <div
                key={`${m.code}-${i}`}
                className="absolute -translate-x-1/2 -translate-y-1/2"
                style={{ left: `${m.left}%`, top: `${m.top}%` }}
                data-testid={`threat-marker-${m.code}`}
              >
                <span className={`absolute inset-0 -translate-x-1/2 -translate-y-1/2 left-1/2 top-1/2 w-2.5 h-2.5 rounded-full tm-ping ${isActive ? "bg-[#F5821F]" : "bg-[#2E7DF5]"}`} />
                <span className={`relative block w-2 h-2 rounded-full ${isActive ? "bg-[#F5821F] ring-2 ring-orange-300/40" : "bg-[#4d9bff]"}`} />
              </div>
            );
          })}

          {/* Active marker label */}
          {activeMarker && (
            <motion.div
              key={activeMarker.code + active}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              className="absolute top-4 left-4 bg-[#0f1a2e]/90 backdrop-blur border border-slate-700 rounded-lg px-3 py-2"
              data-testid="threat-map-active-label"
            >
              <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-[#F5821F] font-semibold">
                <Radio className="w-3 h-3" /> Live incident
              </div>
              <div className="text-sm font-semibold text-white mt-0.5">{activeMarker.name}</div>
              <div className="text-[11px] text-slate-400 font-mono-data">{activeMarker.group}{activeMarker.victim && activeMarker.victim !== "Live monitoring" ? ` · ${activeMarker.victim}` : ""}</div>
            </motion.div>
          )}

          {/* Live stat chips */}
          <div className="absolute bottom-3 right-3 flex flex-wrap justify-end gap-2 max-w-[70%]">
            {stats.kev != null && (
              <div className="bg-[#0f1a2e]/85 backdrop-blur border border-slate-700 rounded-md px-2.5 py-1.5" data-testid="threat-stat-kev">
                <div className="text-[9px] uppercase tracking-wide text-slate-400">KEV tracked</div>
                <div className="text-sm font-bold text-white font-mono-data">{stats.kev.toLocaleString()}</div>
              </div>
            )}
            {stats.incidents != null && (
              <div className="bg-[#0f1a2e]/85 backdrop-blur border border-slate-700 rounded-md px-2.5 py-1.5" data-testid="threat-stat-incidents">
                <div className="text-[9px] uppercase tracking-wide text-slate-400">Recent incidents</div>
                <div className="text-sm font-bold text-white font-mono-data">{stats.incidents.toLocaleString()}</div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Floating live badge */}
      <div className="absolute -bottom-5 -left-5 bg-white rounded-xl border border-slate-200 shadow-lg p-4 hidden sm:block" data-testid="threat-monitoring-badge">
        <div className="flex items-center gap-3">
          <span className="w-2.5 h-2.5 rounded-full bg-green-500 pulse-dot" />
          <div>
            <div className="text-xs text-slate-500 flex items-center gap-1.5"><Activity className="w-3 h-3 text-[#2E7DF5]" /> Threat monitoring</div>
            <div className="text-sm font-semibold text-slate-900">
              {stats.incidents != null ? `${stats.incidents} active signals · 24/7 SOC` : "Active · 24/7 SOC"}
            </div>
          </div>
        </div>
      </div>

      {/* Ransomware-linked chip (top-right of card) */}
      {stats.ransomware != null && (
        <div className="absolute -top-3 right-4 bg-white rounded-full border border-slate-200 shadow-md px-3 py-1 hidden sm:flex items-center gap-1.5" data-testid="threat-ransomware-chip">
          <ShieldCheck className="w-3.5 h-3.5 text-[#F5821F]" />
          <span className="text-xs font-semibold text-slate-700">{stats.ransomware} ransomware-linked CVEs</span>
        </div>
      )}
    </div>
  );
}
