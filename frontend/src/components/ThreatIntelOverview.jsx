import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Users, Bug, Radar, Database, ShieldAlert, Activity, ExternalLink, Zap } from "lucide-react";
import { api } from "@/lib/api";
import { severityStyle, TYPE_LABEL } from "@/lib/iocUtils";

const NUM = (n) => (typeof n === "number" ? n.toLocaleString() : "—");

const MODULES = [
  { key: "adversary_intel", title: "Adversary Intelligence", desc: "Track named threat actors and campaigns from OTX pulses, Unit42 and community intel.", icon: Users, tone: "from-red-500 to-orange-500" },
  { key: "malware_analysis", title: "Malware Analysis", desc: "Hybrid Analysis + VirusTotal detonation ratios, malware family attribution and sandbox verdicts.", icon: Bug, tone: "from-blue-500 to-indigo-500" },
  { key: "digital_risk", title: "Digital Risk Protection", desc: "URLScan live page previews, domain impersonation checks and Shodan attack-surface signals.", icon: Radar, tone: "from-emerald-500 to-teal-500" },
  { key: "curated_iocs", title: "Curated IOC Database", desc: "444+ indicators aggregated daily from AlienVault OTX with severity scoring and analyst notes.", icon: Database, tone: "from-slate-700 to-slate-900" },
];

export default function ThreatIntelOverview() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    let alive = true;
    api.get("/threat-intel/overview").then((r) => { if (alive) setData(r.data); }).catch(() => { if (alive) setErr(true); });
    return () => { alive = false; };
  }, []);

  if (err || !data) {
    return <div className="h-72 rounded-2xl bg-slate-50 border border-slate-200 animate-pulse" />;
  }

  const providersUp = Object.values(data.providers || {}).filter(Boolean).length;

  return (
    <section data-testid="ti-overview" className="mt-4 mb-14">
      {/* Header + big stats */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-800/10 bg-gradient-to-br from-slate-950 via-[#0b1b36] to-slate-900 text-white shadow-xl">
        <div className="absolute inset-0 opacity-[0.15]" style={{
          backgroundImage: "radial-gradient(circle at 20% 0%, rgba(255,101,60,.4), transparent 40%), radial-gradient(circle at 80% 80%, rgba(46,125,245,.5), transparent 45%)",
        }} aria-hidden="true" />
        <div className="relative px-6 sm:px-10 py-10 sm:py-14">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-orange-400">
            <Zap className="w-4 h-4" /> NivX Counter Adversary Operations
          </div>
          <h2 className="mt-4 text-3xl sm:text-4xl lg:text-5xl font-bold leading-tight max-w-3xl">
            Know your adversary. Stop the breach.
          </h2>
          <p className="mt-3 text-slate-300 max-w-2xl">
            Unified threat intelligence, malware analysis and IOC hunting — powered by <strong className="text-white">{providersUp}</strong> integrated OSINT feeds and refreshed daily from the front lines.
          </p>

          {/* Big stats row (CrowdStrike-style) */}
          <div className="mt-10 grid grid-cols-2 md:grid-cols-4 gap-4 sm:gap-6">
            <StatTile data-testid="ti-stat-iocs" label="IOCs tracked" value={NUM(data.total_iocs)} sub={`${NUM(data.by_type.hash)} hashes · ${NUM(data.by_type.domain)} domains · ${NUM(data.by_type.ip)} IPs`} accent="text-orange-400" />
            <StatTile data-testid="ti-stat-adversaries" label="Named adversaries" value={NUM(data.adversaries.length)} sub={data.adversaries[0]?.name || "—"} accent="text-red-400" />
            <StatTile data-testid="ti-stat-families" label="Malware families" value={NUM(data.malware_families.length)} sub={data.malware_families[0]?.name || "—"} accent="text-blue-400" />
            <StatTile data-testid="ti-stat-sync" label="OTX last sync" value={data.last_otx_sync ? new Date(data.last_otx_sync.synced_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "—"} sub={data.last_otx_sync ? `${NUM(data.last_otx_sync.pulses)} pulses · ${NUM(data.last_otx_sync.updated)} updated` : "awaiting sync"} accent="text-emerald-400" />
          </div>
        </div>
      </div>

      {/* Module cards */}
      <div className="mt-10 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {MODULES.map((m, i) => (
          <motion.div
            key={m.key}
            initial={{ opacity: 0, y: 12 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.4, delay: i * 0.05 }}
            data-testid={`ti-module-${m.key}`}
            className="group relative overflow-hidden rounded-xl border border-slate-200 bg-white p-5 hover:border-slate-300 hover:shadow-lg transition-all"
          >
            <div className={`inline-flex w-11 h-11 rounded-lg items-center justify-center text-white bg-gradient-to-br ${m.tone} mb-4`}>
              <m.icon className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-slate-900">{m.title}</h3>
            <p className="mt-1.5 text-sm text-slate-600 leading-relaxed">{m.desc}</p>
          </motion.div>
        ))}
      </div>

      {/* Adversaries + Malware families columns */}
      <div className="mt-8 grid grid-cols-1 lg:grid-cols-3 gap-4">
        <ListCard testid="ti-adversaries" title="Top adversaries" subtitle="Named actors from active pulses" icon={Users} tone="text-red-500" items={data.adversaries.slice(0, 8)} empty="No named adversary attribution in current IOCs" />
        <ListCard testid="ti-families" title="Top malware families" subtitle="Grouped by IOC frequency" icon={Bug} tone="text-blue-500" items={data.malware_families.slice(0, 8)} empty="No malware family attribution yet" />
        <ListCard testid="ti-sources" title="Intelligence sources" subtitle="Where your intel comes from" icon={Activity} tone="text-emerald-500" items={data.top_sources.slice(0, 8)} empty="No sources tracked yet" />
      </div>

      {/* Recent intel + campaigns */}
      <div className="mt-8 grid grid-cols-1 lg:grid-cols-5 gap-4">
        <div className="lg:col-span-3 rounded-xl border border-slate-200 bg-white p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-orange-500" />
              <h3 className="font-bold text-slate-900">Recent IOCs on your radar</h3>
            </div>
            <span className="text-xs text-slate-400 uppercase tracking-wide">Last 8</span>
          </div>
          <div className="divide-y divide-slate-100" data-testid="ti-recent">
            {data.recent.map((r, i) => {
              const st = severityStyle(r.severity);
              return (
                <div key={i} className="flex items-center gap-3 py-2.5 text-sm">
                  <span className={`text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded ${st.badge} shrink-0`}>{r.severity}</span>
                  <code className="font-mono-data text-xs text-slate-800 truncate flex-1">{r.value}</code>
                  <span className="text-[10px] font-semibold uppercase text-slate-500 shrink-0">{TYPE_LABEL[r.type] || r.type}</span>
                  <span className="hidden sm:inline text-xs text-slate-400 truncate max-w-[180px] shrink-0">{r.threat_name || r.source || "—"}</span>
                </div>
              );
            })}
            {data.recent.length === 0 && <div className="py-6 text-center text-sm text-slate-400">No IOCs yet — sync OTX or add via the analyzer.</div>}
          </div>
        </div>

        <div className="lg:col-span-2 rounded-xl border border-slate-200 bg-white p-5">
          <div className="flex items-center gap-2 mb-4">
            <ExternalLink className="w-4 h-4 text-indigo-500" />
            <h3 className="font-bold text-slate-900">Top active campaigns</h3>
          </div>
          <div className="space-y-2" data-testid="ti-campaigns">
            {data.top_campaigns.slice(0, 6).map((c, i) => (
              <div key={i} className="flex items-center gap-3 text-sm">
                <span className="w-6 h-6 rounded-md bg-slate-100 text-slate-500 text-[10px] font-bold flex items-center justify-center shrink-0">{i + 1}</span>
                <span className="flex-1 truncate text-slate-700" title={c.name}>{c.name}</span>
                <span className="text-xs font-semibold text-slate-400">{c.count} IOC{c.count > 1 ? "s" : ""}</span>
              </div>
            ))}
            {data.top_campaigns.length === 0 && <div className="py-6 text-center text-sm text-slate-400">No campaigns detected.</div>}
          </div>
        </div>
      </div>
    </section>
  );
}

function StatTile({ label, value, sub, accent = "text-white", ...rest }) {
  return (
    <div {...rest} className="border-l-2 border-white/20 pl-4">
      <div className={`text-3xl sm:text-4xl font-bold tabular-nums ${accent}`}>{value}</div>
      <div className="mt-1 text-[11px] font-semibold uppercase tracking-wider text-slate-300">{label}</div>
      {sub && <div className="mt-1 text-xs text-slate-400 truncate">{sub}</div>}
    </div>
  );
}

function ListCard({ testid, title, subtitle, icon: Icon, tone, items, empty }) {
  const max = Math.max(...(items.map((i) => i.count) || [1]), 1);
  return (
    <div data-testid={testid} className="rounded-xl border border-slate-200 bg-white p-5">
      <div className="flex items-center gap-2">
        <Icon className={`w-4 h-4 ${tone}`} />
        <h3 className="font-bold text-slate-900">{title}</h3>
      </div>
      <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>
      <div className="mt-4 space-y-2.5">
        {items.length === 0 && <div className="py-4 text-sm text-slate-400">{empty}</div>}
        {items.map((it, i) => (
          <div key={i} className="text-sm">
            <div className="flex items-center justify-between">
              <span className="truncate text-slate-700" title={it.name}>{it.name}</span>
              <span className="text-xs font-semibold text-slate-500 tabular-nums ml-2">{it.count}</span>
            </div>
            <div className="mt-1 h-1 rounded-full bg-slate-100 overflow-hidden">
              <div className={`h-full ${tone.replace("text-", "bg-")}`} style={{ width: `${Math.max(6, Math.round((it.count / max) * 100))}%` }} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
