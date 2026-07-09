import { useEffect, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Radar, Link2, Network, ExternalLink, RefreshCw, Loader2 } from "lucide-react";
import { api } from "@/lib/api";

const POLL_MS = 60_000;

export default function LiveGlobalAttacks() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try { const { data } = await api.get("/live-attacks"); setData(data); }
    catch { /* soft-fail; keep previous data */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  }, [load]);

  if (!data && loading) {
    return (
      <section data-testid="live-global-attacks-landing" className="py-14 bg-slate-50 border-y border-slate-200">
        <div className="mx-auto max-w-7xl px-6 flex items-center justify-center text-slate-400 gap-2 text-sm">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading global attack telemetry…
        </div>
      </section>
    );
  }
  if (!data) return null;

  return (
    <section data-testid="live-global-attacks-landing" className="py-14 lg:py-20 bg-slate-50 border-y border-slate-200">
      <div className="mx-auto max-w-7xl px-6">
        <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
          <div>
            <div className="text-xs font-bold uppercase tracking-[0.2em] text-[#F5821F] mb-2 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 pulse-dot" /> Live &middot; Global Attack Telemetry
            </div>
            <h2 className="font-heading text-2xl md:text-3xl lg:text-4xl font-semibold tracking-tight text-slate-900">Who&rsquo;s attacking the internet right now</h2>
            <p className="mt-3 text-base text-slate-600 max-w-3xl leading-relaxed">
              Aggregated real-time attack telemetry from the world&rsquo;s largest public honeypot networks and community threat-intel feeds — refreshed every minute.
            </p>
          </div>
          <button data-testid="live-global-refresh" onClick={load} className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600 hover:text-[#2E7DF5] border border-slate-200 hover:border-[#2E7DF5] rounded-full px-4 py-1.5 bg-white">
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          {/* Column 1: DShield top attackers */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm" data-testid="landing-dshield">
            <div className="flex items-center gap-2 mb-1">
              <Radar className="w-4 h-4 text-orange-500" />
              <h3 className="font-heading font-semibold text-slate-900">Top attacker IPs</h3>
            </div>
            <div className="text-[11px] text-slate-500 mb-3">Source: <a href="https://isc.sans.edu/" target="_blank" rel="noopener noreferrer" className="text-[#2E7DF5] hover:underline">SANS Internet Storm Center · DShield</a></div>
            <ol className="space-y-1.5 max-h-[360px] overflow-y-auto pr-1">
              <AnimatePresence>
                {(data.attackers || []).slice(0, 15).map((a) => (
                  <motion.li key={a.ip} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} className="flex items-center gap-2.5 text-xs">
                    <span className="text-slate-400 font-mono tabular-nums w-6 shrink-0">#{a.rank}</span>
                    <code className="font-mono text-slate-800 flex-1 truncate">{a.ip}</code>
                    <span className="tabular-nums text-slate-600 font-semibold shrink-0">{a.reports.toLocaleString()}</span>
                    <span className="text-[10px] text-slate-400 shrink-0">reports</span>
                  </motion.li>
                ))}
              </AnimatePresence>
            </ol>
          </div>

          {/* Column 2: URLhaus live malware URLs */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm" data-testid="landing-urlhaus">
            <div className="flex items-center gap-2 mb-1">
              <Link2 className="w-4 h-4 text-purple-500" />
              <h3 className="font-heading font-semibold text-slate-900">Live malware URLs</h3>
            </div>
            <div className="text-[11px] text-slate-500 mb-3">Source: <a href="https://urlhaus.abuse.ch/" target="_blank" rel="noopener noreferrer" className="text-[#2E7DF5] hover:underline">URLhaus · abuse.ch</a></div>
            <div className="space-y-1.5 max-h-[360px] overflow-y-auto pr-1">
              {(data.malicious_urls || []).slice(0, 15).map((u, i) => (
                <a key={i} href={u.urlhaus_link || u.url} target="_blank" rel="noopener noreferrer" data-testid={`landing-urlhaus-${i}`} className="block group">
                  <div className="flex items-center gap-2 text-xs">
                    <span className="inline-flex text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-red-50 text-red-700 border border-red-200 shrink-0">{(u.threat || "").replace("_", " ") || "malware"}</span>
                    <code className="font-mono text-slate-700 group-hover:text-[#2E7DF5] truncate flex-1" title={u.url}>{u.url}</code>
                    <ExternalLink className="w-3 h-3 text-slate-400 group-hover:text-[#2E7DF5] shrink-0" />
                  </div>
                </a>
              ))}
            </div>
          </div>

          {/* Column 3: Feodo Tracker C2s */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm" data-testid="landing-feodo">
            <div className="flex items-center gap-2 mb-1">
              <Network className="w-4 h-4 text-rose-500" />
              <h3 className="font-heading font-semibold text-slate-900">Active botnet C2s</h3>
            </div>
            <div className="text-[11px] text-slate-500 mb-3">Source: <a href="https://feodotracker.abuse.ch/" target="_blank" rel="noopener noreferrer" className="text-[#2E7DF5] hover:underline">Feodo Tracker · abuse.ch</a></div>
            <div className="space-y-1.5 max-h-[360px] overflow-y-auto pr-1">
              {(data.botnet_c2s || []).slice(0, 25).map((c, i) => (
                <div key={i} data-testid={`landing-c2-${i}`} className="flex items-center gap-2 text-xs">
                  <span className="inline-flex text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 shrink-0">C2</span>
                  <code className="font-mono text-slate-800 truncate flex-1">{c.ip}</code>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="mt-6 text-[11px] text-slate-500">
          Attack telemetry aggregated from public feeds: <strong>SANS DShield</strong> honeypot network, <strong>URLhaus</strong>, and <strong>Feodo Tracker</strong> — updated {data.updated_at ? new Date(data.updated_at).toLocaleTimeString() : "just now"}. No proprietary vendor data; all sources link back to origin.
        </div>
      </div>
    </section>
  );
}
