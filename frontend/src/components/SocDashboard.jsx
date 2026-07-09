import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Database, Users, ShieldAlert, Activity, TrendingUp, RefreshCw,
  Loader2, Bug, ExternalLink, CheckCircle2, XCircle, Clock,
} from "lucide-react";
import { api } from "@/lib/api";
import { severityStyle, TYPE_LABEL } from "@/lib/iocUtils";
import LiveThreatsPanel from "@/components/LiveThreatsPanel";

const NUM = (n) => (typeof n === "number" ? n.toLocaleString() : "—");

const STATUS_TONE = {
  new: "bg-blue-50 text-blue-700 border-blue-200",
  contacted: "bg-amber-50 text-amber-700 border-amber-200",
  qualified: "bg-emerald-50 text-emerald-700 border-emerald-200",
  archived: "bg-slate-100 text-slate-500 border-slate-200",
};

const PROVIDER_LABEL = {
  virustotal: "VirusTotal",
  abuseipdb: "AbuseIPDB",
  urlscan: "URLScan",
  otx: "AlienVault OTX",
  hybrid_analysis: "Hybrid Analysis",
  ai_summary: "AI Summary (Gemini)",
};

function timeAgo(iso) {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  const s = Math.floor((Date.now() - t) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export default function SocDashboard() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const load = async () => {
    setRefreshing(true);
    setErr(false);
    try {
      const { data: d } = await api.get("/admin/overview");
      setData(d);
    } catch {
      setErr(true);
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (err) return <div className="p-6 text-center text-red-600 text-sm">Failed to load overview.</div>;
  if (!data) return (
    <div className="p-8 flex items-center justify-center text-slate-400 gap-2 text-sm">
      <Loader2 className="w-4 h-4 animate-spin" /> Loading operational overview…
    </div>
  );

  const iocFlagged = (data.iocs.by_severity.critical || 0) + (data.iocs.by_severity.high || 0);
  const openLeads = (data.leads.by_status.new || 0) + (data.leads.by_status.contacted || 0);

  return (
    <div className="mx-auto max-w-7xl px-6 py-8" data-testid="soc-dashboard">
      {/* Header */}
      <div className="flex flex-wrap items-end justify-between gap-4 mb-6">
        <div>
          <div className="text-xs uppercase tracking-[0.15em] font-semibold text-orange-500">SOC Overview</div>
          <h1 className="mt-1 text-2xl sm:text-3xl font-bold text-slate-900">Operational console</h1>
          <p className="text-sm text-slate-500 mt-1">Live snapshot of your threat intel, pipeline and integrations · updated {timeAgo(data.generated_at)}</p>
        </div>
        <button
          onClick={load}
          disabled={refreshing}
          data-testid="soc-refresh"
          className="inline-flex items-center gap-2 border border-slate-300 hover:border-[#2E7DF5] hover:text-[#2E7DF5] text-slate-700 text-sm font-semibold px-4 py-2 rounded-md transition-colors disabled:opacity-60"
        >
          {refreshing ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />} Refresh
        </button>
      </div>

      {/* Top KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <Kpi testid="soc-kpi-iocs" icon={Database} tone="from-orange-500 to-red-500" label="IOCs tracked" value={NUM(data.iocs.total)} sub={`${NUM(iocFlagged)} high/critical`} />
        <Kpi testid="soc-kpi-leads" icon={Users} tone="from-blue-500 to-indigo-500" label="Open leads" value={NUM(openLeads)} sub={`${NUM(data.leads.last_7_days)} added this week`} />
        <Kpi testid="soc-kpi-reports" icon={ShieldAlert} tone="from-red-500 to-rose-600" label="Threat reports" value={NUM(data.reports.total)} sub="Published to site" />
        <Kpi testid="soc-kpi-otx" icon={TrendingUp} tone="from-emerald-500 to-teal-500" label="OTX last sync" value={data.otx.last_sync ? timeAgo(data.otx.last_sync.synced_at) : "—"} sub={data.otx.last_sync ? `${NUM(data.otx.last_sync.pulses)} pulses` : "awaiting sync"} />
      </div>

      {/* Two-column: IOC breakdown + Lead pipeline */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-8">
        <Panel testid="soc-ioc-breakdown" title="IOC breakdown" icon={Database} iconTone="text-orange-500" subtitle="By severity and indicator type">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">By severity</div>
              {["critical", "high", "medium", "low"].map((s) => {
                const st = severityStyle(s);
                const count = data.iocs.by_severity[s] || 0;
                const pct = data.iocs.total ? Math.round((count / data.iocs.total) * 100) : 0;
                return (
                  <div key={s} className="mb-2.5">
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className={`font-bold uppercase tracking-wide ${st.text}`}>{s}</span>
                      <span className="text-slate-500 tabular-nums">{count.toLocaleString()} · {pct}%</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-slate-100 overflow-hidden">
                      <div className={`h-full ${st.dot}`} style={{ width: `${Math.max(count ? 4 : 0, pct)}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2">By type</div>
              {[["hash", "Hashes"], ["domain", "Domains"], ["ip", "IPs"], ["url", "URLs"]].map(([k, lbl]) => {
                const count = data.iocs.by_type[k] || 0;
                const pct = data.iocs.total ? Math.round((count / data.iocs.total) * 100) : 0;
                return (
                  <div key={k} className="mb-2.5">
                    <div className="flex items-center justify-between text-xs mb-1">
                      <span className="font-semibold text-slate-700">{lbl}</span>
                      <span className="text-slate-500 tabular-nums">{count.toLocaleString()} · {pct}%</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-slate-100 overflow-hidden">
                      <div className="h-full bg-slate-700" style={{ width: `${Math.max(count ? 4 : 0, pct)}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </Panel>

        <Panel testid="soc-lead-pipeline" title="Lead pipeline" icon={Users} iconTone="text-blue-500" subtitle={`${NUM(data.leads.total)} total · ${NUM(data.leads.last_7_days)} in last 7 days`}>
          <div className="grid grid-cols-4 gap-3">
            {["new", "contacted", "qualified", "archived"].map((s) => (
              <div key={s} className={`rounded-lg border p-3 ${STATUS_TONE[s]}`}>
                <div className="text-2xl font-bold tabular-nums">{NUM(data.leads.by_status[s] || 0)}</div>
                <div className="text-[10px] font-bold uppercase tracking-wider mt-1">{s}</div>
              </div>
            ))}
          </div>
          {data.top_families.length > 0 && (
            <div className="mt-5 pt-4 border-t border-slate-100">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
                <Bug className="w-3.5 h-3.5" /> Top malware families in DB
              </div>
              <div className="flex flex-wrap gap-1.5">
                {data.top_families.map((f) => (
                  <span key={f.name} className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-1 rounded-md bg-slate-50 border border-slate-200 text-slate-700">
                    {f.name} <span className="text-slate-400">{f.count}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </Panel>
      </div>

      {/* Recent activity + Providers */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8">
        <Panel testid="soc-recent-leads" title="Recent leads" icon={Users} iconTone="text-blue-500" subtitle="Last 6 submissions" cta={<Link to="#" onClick={(e) => { e.preventDefault(); window.dispatchEvent(new CustomEvent("nivx-admin-goto", { detail: "leads" })); }} className="text-xs font-semibold text-[#2E7DF5] hover:underline">View all →</Link>}>
          <div className="divide-y divide-slate-100">
            {data.recent.leads.length === 0 && <div className="py-4 text-sm text-slate-400">No leads yet.</div>}
            {data.recent.leads.map((l) => (
              <div key={l.id} className="py-2.5 flex items-center justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold text-slate-800 truncate">{l.name || l.email}</div>
                  <div className="text-xs text-slate-500 truncate">{l.company || l.email}</div>
                </div>
                <div className="flex flex-col items-end shrink-0">
                  <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border ${STATUS_TONE[l.status] || STATUS_TONE.archived}`}>{l.status}</span>
                  <span className="text-[10px] text-slate-400 mt-0.5">{timeAgo(l.created_at)}</span>
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel testid="soc-recent-iocs" title="Recent IOCs" icon={ShieldAlert} iconTone="text-orange-500" subtitle="Latest additions" cta={<Link to="/threat-intelligence" className="text-xs font-semibold text-[#2E7DF5] hover:underline">Open DB →</Link>}>
          <div className="divide-y divide-slate-100">
            {data.recent.iocs.length === 0 && <div className="py-4 text-sm text-slate-400">No IOCs yet.</div>}
            {data.recent.iocs.map((r, i) => {
              const st = severityStyle(r.severity);
              return (
                <div key={i} className="py-2.5 flex items-center gap-2">
                  <span className={`text-[9px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded ${st.badge} shrink-0`}>{r.severity}</span>
                  <code className="font-mono text-[11px] text-slate-800 truncate flex-1" title={r.value}>{r.value}</code>
                  <span className="text-[9px] font-bold uppercase text-slate-400 shrink-0">{TYPE_LABEL[r.type] || r.type}</span>
                </div>
              );
            })}
          </div>
        </Panel>

        <Panel testid="soc-providers" title="Integrations" icon={Activity} iconTone="text-emerald-500" subtitle="Connected OSINT & AI feeds">
          <div className="space-y-2">
            {Object.entries(data.providers).map(([k, ok]) => (
              <div key={k} className="flex items-center justify-between text-sm py-1.5">
                <span className="font-medium text-slate-700">{PROVIDER_LABEL[k] || k}</span>
                {ok ? (
                  <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-600"><CheckCircle2 className="w-3.5 h-3.5" /> Connected</span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-xs font-semibold text-slate-400"><XCircle className="w-3.5 h-3.5" /> Not configured</span>
                )}
              </div>
            ))}
          </div>
          {data.otx.last_sync && (
            <div className="mt-4 pt-3 border-t border-slate-100 text-xs text-slate-500 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" /> OTX auto-syncs daily · next in {Math.max(0, 24 - Math.floor((Date.now() - new Date(data.otx.last_sync.synced_at).getTime()) / 3_600_000))}h
            </div>
          )}
        </Panel>
      </div>

      {/* Recent threat reports */}
      {data.recent.reports.length > 0 && (
        <Panel testid="soc-recent-reports" title="Latest threat reports" icon={ShieldAlert} iconTone="text-rose-500" subtitle="Published on the public site" cta={<Link to="#" onClick={(e) => { e.preventDefault(); window.dispatchEvent(new CustomEvent("nivx-admin-goto", { detail: "reports" })); }} className="text-xs font-semibold text-[#2E7DF5] hover:underline">Manage reports →</Link>}>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {data.recent.reports.map((r) => {
              const st = severityStyle(r.severity);
              return (
                <div key={r.id} className="rounded-lg border border-slate-200 p-3 hover:border-slate-300 transition-colors">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className={`text-[9px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded ${st.badge}`}>{r.severity}</span>
                    <span className="text-[10px] text-slate-400">{timeAgo(r.created_at)}</span>
                  </div>
                  <div className="text-sm font-semibold text-slate-800 line-clamp-2">{r.title}</div>
                  <div className="text-xs text-slate-500 mt-1">{r.category}</div>
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      {/* Live cyber threat map — real-time ransomware.live victims + CISA KEV CVEs */}
      <LiveThreatsPanel />
    </div>
  );
}

function Kpi({ icon: Icon, label, value, sub, tone, testid }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      data-testid={testid}
      className="relative overflow-hidden rounded-xl border border-slate-200 bg-white p-4"
    >
      <div className={`inline-flex w-9 h-9 rounded-lg items-center justify-center text-white bg-gradient-to-br ${tone} mb-2.5`}>
        <Icon className="w-4 h-4" />
      </div>
      <div className="text-3xl font-bold text-slate-900 tabular-nums leading-none">{value}</div>
      <div className="mt-1 text-[11px] font-bold uppercase tracking-wider text-slate-500">{label}</div>
      {sub && <div className="mt-1 text-xs text-slate-400 truncate">{sub}</div>}
    </motion.div>
  );
}

function Panel({ title, subtitle, icon: Icon, iconTone, children, cta, testid }) {
  return (
    <div data-testid={testid} className="rounded-xl border border-slate-200 bg-white p-5">
      <div className="flex items-start justify-between mb-4 gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Icon className={`w-4 h-4 ${iconTone}`} />
            <h3 className="font-bold text-slate-900">{title}</h3>
          </div>
          {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
        </div>
        {cta}
      </div>
      {children}
    </div>
  );
}
