import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import { Globe2, Loader2, RefreshCw, ExternalLink, MapPin, Users, ShieldAlert, Bug, AlertTriangle, Radar, Link2, Network } from "lucide-react";
import { api } from "@/lib/api";

const POLL_MS = 30_000;

function timeAgo(iso) {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  const s = Math.floor((Date.now() - t) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

const countryName = (() => {
  try {
    const dn = new Intl.DisplayNames(["en"], { type: "region" });
    return (code) => { try { return dn.of(code) || code; } catch { return code; } };
  } catch { return (code) => code; }
})();

const NUM = (n) => (typeof n === "number" ? n.toLocaleString() : "—");

export default function LiveThreatsPanel() {
  const [land, setLand] = useState(null);
  const [victims, setVictims] = useState([]);
  const [cves, setCves] = useState([]);
  const [attacks, setAttacks] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    setErr("");
    try {
      const [l, a, k, la] = await Promise.allSettled([
        api.get("/threat-landscape/live"),
        api.get("/attack-feed"),
        api.get("/live-feed"),
        api.get("/live-attacks"),
      ]);
      if (l.status === "fulfilled") setLand(l.value.data);
      if (a.status === "fulfilled") setVictims(a.value.data.items || []);
      if (k.status === "fulfilled") setCves(k.value.data.items || []);
      if (la.status === "fulfilled") setAttacks(la.value.data);
      if (l.status === "rejected" && a.status === "rejected" && k.status === "rejected" && la.status === "rejected") {
        setErr("Could not load live threat feeds.");
      }
    } catch (e) {
      setErr(e?.response?.data?.detail || "Load failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, POLL_MS);
    const onVis = () => { if (!document.hidden) load(); };
    document.addEventListener("visibilitychange", onVis);
    return () => { clearInterval(t); document.removeEventListener("visibilitychange", onVis); };
  }, [load]);

  const stats = land?.stats || {};
  // Group victims by country for the "attacks by country" table.
  const byCountry = {};
  for (const v of victims) {
    const c = v.country || "??";
    if (!byCountry[c]) byCountry[c] = { code: c, count: 0, groups: new Set(), latestVictim: v.victim };
    byCountry[c].count++;
    if (v.group) byCountry[c].groups.add(v.group);
  }
  const countryRows = Object.values(byCountry).sort((a, b) => b.count - a.count).slice(0, 12);

  // Group victims by threat actor for "top ransomware actors this window"
  const byGroup = {};
  for (const v of victims) {
    const g = v.group || "unknown";
    if (!byGroup[g]) byGroup[g] = { group: g, count: 0, sectors: new Set(), countries: new Set() };
    byGroup[g].count++;
    if (v.sector) byGroup[g].sectors.add(v.sector);
    if (v.country) byGroup[g].countries.add(v.country);
  }
  const groupRows = Object.values(byGroup).sort((a, b) => b.count - a.count).slice(0, 10);

  return (
    <div className="mt-8" data-testid="soc-live-threats">
      <div className="flex items-center justify-between mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Globe2 className="w-4 h-4 text-[#2E7DF5]" />
            <h3 className="font-bold text-slate-900">Live Cyber Threat Map</h3>
            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 inline-flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 pulse-dot" /> Live
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">Real-time ransomware victims + CISA KEV — auto-refreshes every 30s. Sources: ransomware.live · CISA Known Exploited Vulnerabilities.</p>
        </div>
        <button data-testid="live-threats-refresh" onClick={load} className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600 hover:text-[#2E7DF5] border border-slate-200 hover:border-[#2E7DF5] rounded-md px-3 py-1.5">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {err && <div className="text-sm text-red-600 mb-4" data-testid="live-threats-err">{err}</div>}
      {loading && !land && (
        <div className="py-16 flex items-center justify-center text-slate-400 gap-2 text-sm">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading live threat map…
        </div>
      )}

      {land && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5" data-testid="live-threats-kpis">
          <MiniKpi label="Ransomware victims · 24h" value={NUM(stats.victims_24h)} icon={AlertTriangle} tone="text-red-500 bg-red-50 border-red-200" />
          <MiniKpi label="Recent attacks tracked" value={NUM(victims.length)} icon={ShieldAlert} tone="text-orange-500 bg-orange-50 border-orange-200" />
          <MiniKpi label="Exploited CVEs (KEV)" value={NUM(stats.total_cves)} icon={Bug} tone="text-purple-500 bg-purple-50 border-purple-200" />
          <MiniKpi label="Ransomware-linked CVEs" value={NUM(stats.ransomware_cves)} icon={ShieldAlert} tone="text-rose-500 bg-rose-50 border-rose-200" />
        </div>
      )}

      {/* Two-column: Attacks-by-country + Top ransomware actors */}
      {victims.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
          <div className="rounded-xl border border-slate-200 bg-white p-5" data-testid="attacks-by-country">
            <div className="flex items-center gap-2 mb-3">
              <MapPin className="w-4 h-4 text-slate-500" />
              <h4 className="font-semibold text-slate-900">Attacks by country</h4>
              <span className="ml-auto text-xs text-slate-400">Top {countryRows.length}</span>
            </div>
            <div className="space-y-2">
              {countryRows.map((c) => {
                const max = countryRows[0]?.count || 1;
                return (
                  <div key={c.code} className="flex items-center gap-3 text-sm">
                    <span className="font-mono text-xs text-slate-400 w-8">{c.code}</span>
                    <span className="font-medium text-slate-700 flex-1 truncate">{countryName(c.code)}</span>
                    <span className="text-xs text-slate-500">{[...c.groups].slice(0, 2).join(", ") || "—"}</span>
                    <div className="w-24 h-2 bg-slate-100 rounded-full overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-orange-500 to-red-500" style={{ width: `${(c.count / max) * 100}%` }} />
                    </div>
                    <span className="text-sm font-bold text-slate-900 tabular-nums w-6 text-right">{c.count}</span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-5" data-testid="top-actors">
            <div className="flex items-center gap-2 mb-3">
              <Users className="w-4 h-4 text-slate-500" />
              <h4 className="font-semibold text-slate-900">Top ransomware actors</h4>
              <span className="ml-auto text-xs text-slate-400">Recent victims</span>
            </div>
            <div className="space-y-2">
              {groupRows.map((g) => (
                <div key={g.group} className="flex items-center justify-between gap-3 text-sm">
                  <div className="min-w-0">
                    <div className="font-semibold text-slate-800 truncate">{g.group}</div>
                    <div className="text-[11px] text-slate-500 truncate">{g.countries.size} countries · {[...g.sectors].slice(0, 2).join(", ") || "mixed sectors"}</div>
                  </div>
                  <span className="text-sm font-bold text-red-600 tabular-nums">{g.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Recent ransomware victims table */}
      {victims.length > 0 && (
        <div className="rounded-xl border border-slate-200 bg-white overflow-hidden mb-6" data-testid="recent-victims-table">
          <div className="px-5 py-3 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-500" />
              <h4 className="font-semibold text-slate-900">Recent ransomware victims</h4>
            </div>
            <div className="text-xs text-slate-400">{victims.length} attacks · ransomware.live</div>
          </div>
          <div className="overflow-x-auto max-h-[520px] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 border-b border-slate-200 sticky top-0">
                <tr className="text-left text-[10px] font-bold uppercase tracking-wider text-slate-500">
                  <th className="px-4 py-2.5">Victim</th>
                  <th className="px-4 py-2.5">Threat actor</th>
                  <th className="px-4 py-2.5">Country</th>
                  <th className="px-4 py-2.5">Sector</th>
                  <th className="px-4 py-2.5">Date</th>
                  <th className="px-4 py-2.5">Link</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {victims.slice(0, 60).map((v, i) => (
                  <motion.tr key={`${v.victim}-${i}`} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.25, delay: (i % 20) * 0.01 }} data-testid={`victim-row-${i}`} className="hover:bg-slate-50">
                    <td className="px-4 py-2.5">
                      <div className="font-semibold text-slate-800 truncate max-w-[220px]" title={v.victim || ""}>{v.victim || "—"}</div>
                      {v.domain && <div className="text-[11px] text-slate-400 truncate max-w-[220px]">{v.domain}</div>}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded bg-red-50 text-red-700 border border-red-200">{v.group || "unknown"}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="text-xs text-slate-600">{v.country ? countryName(v.country) : "—"}</span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="text-xs text-slate-500 truncate max-w-[160px] block" title={v.sector || ""}>{v.sector || "—"}</span>
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap text-xs text-slate-500">{v.date ? new Date(v.date).toLocaleString() : "—"}</td>
                    <td className="px-4 py-2.5">
                      {v.url ? <a href={v.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs font-semibold text-[#2E7DF5] hover:underline">Post <ExternalLink className="w-3 h-3" /></a> : <span className="text-slate-300 text-xs">—</span>}
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Global live attacks: DShield + URLhaus + Feodo Tracker */}
      {attacks && (
        <div className="mb-6 grid grid-cols-1 lg:grid-cols-3 gap-4" data-testid="live-global-attacks">
          {/* Top attacker IPs from SANS DShield */}
          <div className="rounded-xl border border-slate-200 bg-white p-5" data-testid="dshield-attackers">
            <div className="flex items-center gap-2 mb-3">
              <Radar className="w-4 h-4 text-orange-500" />
              <h4 className="font-semibold text-slate-900">Global attackers</h4>
              <span className="ml-auto text-[10px] font-bold uppercase text-orange-700 bg-orange-50 border border-orange-200 rounded px-1.5 py-0.5">DShield · SANS ISC</span>
            </div>
            <p className="text-[11px] text-slate-500 mb-3">Top attacker IPs seen by the DShield honeypot network in the last 24h.</p>
            <div className="space-y-1.5 max-h-[320px] overflow-y-auto">
              {(attacks.attackers || []).slice(0, 20).map((a) => (
                <div key={a.ip} className="flex items-center gap-2 text-xs">
                  <span className="font-mono text-slate-400 w-6 shrink-0">#{a.rank}</span>
                  <code className="font-mono text-slate-800 truncate flex-1">{a.ip}</code>
                  <span className="text-slate-500 tabular-nums shrink-0">{a.reports.toLocaleString()}</span>
                  <span className="text-[10px] text-slate-400 shrink-0">reports</span>
                </div>
              ))}
              {(!attacks.attackers || attacks.attackers.length === 0) && <div className="text-xs text-slate-400">No DShield data available.</div>}
            </div>
          </div>

          {/* URLhaus live malware URLs */}
          <div className="rounded-xl border border-slate-200 bg-white p-5" data-testid="urlhaus-live">
            <div className="flex items-center gap-2 mb-3">
              <Link2 className="w-4 h-4 text-purple-500" />
              <h4 className="font-semibold text-slate-900">Live malware URLs</h4>
              <span className="ml-auto text-[10px] font-bold uppercase text-purple-700 bg-purple-50 border border-purple-200 rounded px-1.5 py-0.5">URLhaus · abuse.ch</span>
            </div>
            <p className="text-[11px] text-slate-500 mb-3">Malware distribution URLs seen in the last hour — click to see the URLhaus report.</p>
            <div className="space-y-1.5 max-h-[320px] overflow-y-auto">
              {(attacks.malicious_urls || []).slice(0, 20).map((u, i) => (
                <a key={i} href={u.urlhaus_link || u.url} target="_blank" rel="noopener noreferrer" data-testid={`urlhaus-row-${i}`} className="block group">
                  <div className="flex items-center gap-2 text-xs">
                    <span className="inline-flex text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-red-50 text-red-700 border border-red-200 shrink-0">{u.threat.replace("_", " ")}</span>
                    <code className="font-mono text-slate-700 group-hover:text-[#2E7DF5] truncate flex-1" title={u.url}>{u.url}</code>
                    <ExternalLink className="w-3 h-3 text-slate-400 group-hover:text-[#2E7DF5] shrink-0" />
                  </div>
                </a>
              ))}
              {(!attacks.malicious_urls || attacks.malicious_urls.length === 0) && <div className="text-xs text-slate-400">No URLhaus data available.</div>}
            </div>
          </div>

          {/* Feodo Tracker botnet C2s */}
          <div className="rounded-xl border border-slate-200 bg-white p-5" data-testid="feodo-c2s">
            <div className="flex items-center gap-2 mb-3">
              <Network className="w-4 h-4 text-rose-500" />
              <h4 className="font-semibold text-slate-900">Active botnet C2s</h4>
              <span className="ml-auto text-[10px] font-bold uppercase text-rose-700 bg-rose-50 border border-rose-200 rounded px-1.5 py-0.5">Feodo · abuse.ch</span>
            </div>
            <p className="text-[11px] text-slate-500 mb-3">Active banking-trojan command-and-control IPs (Emotet, Dridex, TrickBot family).</p>
            <div className="space-y-1.5 max-h-[320px] overflow-y-auto">
              {(attacks.botnet_c2s || []).slice(0, 30).map((c, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span className="inline-flex text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 shrink-0">C2</span>
                  <code className="font-mono text-slate-800 truncate flex-1">{c.ip}</code>
                </div>
              ))}
              {(!attacks.botnet_c2s || attacks.botnet_c2s.length === 0) && <div className="text-xs text-slate-400">No Feodo Tracker data available.</div>}
            </div>
          </div>
        </div>
      )}

      {/* CISA KEV — Live Exploited CVE feed */}
      {cves.length > 0 && (
        <div className="rounded-xl border border-slate-200 bg-white overflow-hidden" data-testid="cves-table">
          <div className="px-5 py-3 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Bug className="w-4 h-4 text-purple-500" />
              <h4 className="font-semibold text-slate-900">Recently added exploited CVEs</h4>
            </div>
            <div className="text-xs text-slate-400">Source: CISA KEV · updated {land?.updated_at ? timeAgo(land.updated_at) : "—"}</div>
          </div>
          <div className="overflow-x-auto max-h-[520px] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 border-b border-slate-200 sticky top-0">
                <tr className="text-left text-[10px] font-bold uppercase tracking-wider text-slate-500">
                  <th className="px-4 py-2.5">CVE</th>
                  <th className="px-4 py-2.5">Vendor / Product</th>
                  <th className="px-4 py-2.5">Vulnerability</th>
                  <th className="px-4 py-2.5">Ransomware</th>
                  <th className="px-4 py-2.5">Added by CISA</th>
                  <th className="px-4 py-2.5">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {cves.slice(0, 60).map((c, i) => (
                  <tr key={c.cveID + i} data-testid={`cve-row-${i}`} className="hover:bg-slate-50">
                    <td className="px-4 py-2.5 font-mono text-xs font-bold text-slate-800 whitespace-nowrap">{c.cveID}</td>
                    <td className="px-4 py-2.5">
                      <div className="text-sm font-semibold text-slate-800 truncate max-w-[220px]" title={`${c.vendorProject || ""} · ${c.product || ""}`}>{c.vendorProject || "—"}</div>
                      <div className="text-[11px] text-slate-500 truncate max-w-[220px]">{c.product || ""}</div>
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="text-xs text-slate-700 line-clamp-2 max-w-[320px]" title={c.vulnerabilityName || ""}>{c.vulnerabilityName || "—"}</div>
                    </td>
                    <td className="px-4 py-2.5">
                      {c.knownRansomwareCampaignUse && String(c.knownRansomwareCampaignUse).toLowerCase() === "known"
                        ? <span className="inline-flex items-center gap-1 text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-red-50 text-red-700 border border-red-200">Known</span>
                        : <span className="text-xs text-slate-400">—</span>}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap text-xs text-slate-500">{c.dateAdded ? new Date(c.dateAdded).toLocaleDateString() : "—"}</td>
                    <td className="px-4 py-2.5">
                      <a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.cveID)}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs font-semibold text-[#2E7DF5] hover:underline">NVD <ExternalLink className="w-3 h-3" /></a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function MiniKpi({ label, value, icon: Icon, tone }) {
  return (
    <div className={`rounded-lg border p-3 ${tone.split(" ")[1]} ${tone.split(" ")[2]}`}>
      <div className={`flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider ${tone.split(" ")[0]}`}>
        <Icon className="w-3 h-3" /> {label}
      </div>
      <div className="mt-1 text-2xl font-bold text-slate-900 tabular-nums">{value}</div>
    </div>
  );
}
