import { useEffect, useState, useCallback, useRef } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { api } from "@/lib/api";
import Navbar from "@/components/Navbar";
import Contact from "@/components/Contact";
import IntelReader from "@/components/IntelReader";
import IocAnalyzer from "@/components/IocAnalyzer";
import ThreatIntelOverview from "@/components/ThreatIntelOverview";
import IocDatabase from "@/components/IocDatabase";
import { FileText, ExternalLink, ShieldAlert, BookOpen, ArrowRight, Search, Globe, Database } from "lucide-react";
import useSeo from "@/lib/useSeo";

const OSINT_TOOLS = [
  { name: "VirusTotal", domain: "virustotal.com", url: "https://www.virustotal.com/gui/home/search", desc: "Files, URLs, hashes & domains across 70+ engines" },
  { name: "urlscan.io", domain: "urlscan.io", url: "https://urlscan.io/", desc: "Sandbox & analyze suspicious URLs" },
  { name: "AbuseIPDB", domain: "abuseipdb.com", url: "https://www.abuseipdb.com/", desc: "Check IP reputation & abuse reports" },
  { name: "Cisco Talos", domain: "talosintelligence.com", url: "https://talosintelligence.com/reputation_center", desc: "IP/domain reputation & threat intel" },
  { name: "IBM X-Force Exchange", domain: "exchange.xforce.ibmcloud.com", url: "https://exchange.xforce.ibmcloud.com/", desc: "Threat intelligence sharing platform" },
  { name: "Shodan", domain: "shodan.io", url: "https://www.shodan.io/", desc: "Search exposed hosts, ports & services on the internet" },
  { name: "Censys", domain: "censys.io", url: "https://platform.censys.io/home", desc: "Attack-surface & internet asset discovery" },
  { name: "CyberChef", domain: "gchq.github.io", url: "https://gchq.github.io/CyberChef/", desc: "Decode, decrypt & transform data — the cyber Swiss-army knife" },
  { name: "MITRE ATT&CK", domain: "attack.mitre.org", url: "https://attack.mitre.org/", desc: "Adversary tactics, techniques & procedures (TTPs) knowledge base" },
  { name: "MITRE D3FEND", domain: "d3fend.mitre.org", url: "https://d3fend.mitre.org/", desc: "Countermeasure & defensive technique knowledge graph" },
];

const CYBERDEFENDERS = [
  { title: "Blue Team Labs & Threat Investigations", desc: "Curated DFIR writeups and threat investigations — full article previews rendered on NivX.",                                             tag: "DFIR",       url: "/community/cd/dfir",    slug: "cyberdefenders" },
  { title: "Malware Analysis Case Studies",          desc: "Step-by-step reverse-engineering of real-world samples with IOCs and TTP mapping.",                                                       tag: "Malware",    url: "/community/cd/malware", slug: "cyberdefenders" },
  { title: "SOC & Threat Hunting Playbooks",         desc: "Practical guidance on building detections, triaging alerts and hunting adversaries.",                                                     tag: "SOC",        url: "/community/cd/soc",     slug: "cyberdefenders" },
  { title: "Vendor Threat Advisories",               desc: "Latest APT tracking, malware research and 0-day disclosures aggregated from top security teams — refreshed every 30 minutes.",             tag: "Vendors",    url: "/community/talos",      slug: "talos"          },
  { title: "Adversary Deep-Dives",                   desc: "Deep-dive threat research, incident response case studies and vulnerability write-ups.",                                                   tag: "Research",   url: "/community/unit42",     slug: "unit42"         },
  { title: "Incident Response Reports",              desc: "Real-world intrusion timelines, attacker TTPs and detection opportunities from published incidents.",                                     tag: "IR",         url: "/community/dfir",       slug: "dfir"           },
  { title: "Nation-State Threat Intelligence",       desc: "Tracking of state-aligned adversaries, emerging malware and defender guidance.",                                                          tag: "APT",        url: "/community/msthreat",   slug: "msthreat"       },
  { title: "Breaking Security News",                 desc: "Ransomware coverage, breach disclosures and technical explainers — updated live throughout the day.",                                     tag: "News",       url: "/community/bleeping",   slug: "bleeping"       },
  { title: "Community Signals",                      desc: "Real-time top stories from the wider tech & security community, ranked by readers.",                                                       tag: "Signals",    url: "/community/hn",         slug: "hn"             },
];

const DATE_RANGES = [
  { label: "All time", value: "" },
  { label: "Last 90 days", value: 90 },
  { label: "Last 12 months", value: 365 },
];

function sinceDate(days) {
  if (!days) return "";
  const d = new Date();
  d.setDate(d.getDate() - days);
  return d.toISOString().slice(0, 10);
}

const PAGE_SIZE = 9;

export default function ThreatIntelligence() {
  useSeo({
    title: "Threat Intelligence · Live IOC Analyzer & OSINT | NivX Machines",
    description: "Search hundreds of curated threat reports, run bulk IOC analysis across leading OSINT sources, and browse the NivX-curated IOC database.",
    canonical: "https://nivxmachines.com/threat-intelligence",
  });
  const [items, setItems] = useState([]);
  const [types, setTypes] = useState([]);
  const [total, setTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(false);
  const [repoUrl, setRepoUrl] = useState("");
  const [activeName, setActiveName] = useState(null);
  const [enabledSources, setEnabledSources] = useState(null);

  useEffect(() => {
    let live = true;
    api.get("/community/enabled-sources")
      .then(({ data }) => { if (live) setEnabledSources(data.enabled || null); })
      .catch(() => { if (live) setEnabledSources(null); });
    return () => { live = false; };
  }, []);

  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [dateDays, setDateDays] = useState("");
  const debounceRef = useRef();

  const fetchFeed = useCallback(async (nextPage, append) => {
    setLoading(true);
    setErr(false);
    try {
      const { data } = await api.get("/intel-feed", {
        params: { page: nextPage, page_size: PAGE_SIZE, q: query, type: typeFilter, since: sinceDate(dateDays) },
      });
      setItems((prev) => (append ? [...prev, ...data.items] : data.items));
      setTypes(data.types || []);
      setTotal(data.total);
      setHasMore(data.has_more);
      setRepoUrl(data.repo_url);
      setPage(data.page);
    } catch {
      setErr(true);
    } finally {
      setLoading(false);
    }
  }, [query, typeFilter, dateDays]);

  // Refetch (page 1) whenever filters change, debounced for query
  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, []);

  useEffect(() => {
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => fetchFeed(1, false), 300);
    return () => clearTimeout(debounceRef.current);
  }, [fetchFeed]);

  return (
    <div data-testid="threat-intelligence-page" className="bg-white">
      <Navbar />

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
            Live threat research and hand-picked analysis curated by the NivX intel team —
            searchable across {total || "hundreds of"} reports.
          </p>
        </div>
      </section>

      {/* Threat Intel Overview */}
      <section className="bg-white pt-14 lg:pt-16">
        <div className="mx-auto max-w-7xl px-6">
          <ThreatIntelOverview />
        </div>
      </section>

      {/* OSINT quick-access */}
      <section data-testid="osint-section" className="py-16 lg:py-20 bg-white border-b border-slate-100">
        <div className="mx-auto max-w-7xl px-6">
          <div className="max-w-2xl mb-8">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-[#F5821F] mb-3">
              <Globe className="w-4 h-4" /> OSINT · IOC Analysis
            </div>
            <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-slate-900">Investigate indicators in one click</h2>
            <p className="mt-4 text-base text-slate-600 leading-relaxed">
              Jump straight to the industry&apos;s leading OSINT platforms to enrich and validate IOCs — hashes, URLs, IPs and domains.
            </p>
          </div>

          <IocAnalyzer />

          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            {OSINT_TOOLS.map((t, i) => (
              <a
                key={t.name}
                href={t.url}
                target="_blank"
                rel="noopener noreferrer"
                data-testid={`osint-${i}`}
                className="group rounded-xl border border-slate-200 bg-white shadow-sm hover:shadow-md hover:-translate-y-1 hover:border-[#2E7DF5]/40 transition-[transform,box-shadow,border-color] p-5 flex flex-col items-start"
              >
                <div className="w-11 h-11 rounded-lg bg-slate-50 border border-slate-100 flex items-center justify-center mb-4 overflow-hidden">
                  <img
                    src={`https://www.google.com/s2/favicons?domain=${t.domain}&sz=64`}
                    alt={t.name}
                    className="w-6 h-6"
                    onError={(e) => { e.currentTarget.style.display = "none"; }}
                  />
                </div>
                <div className="font-heading text-sm font-semibold text-slate-900 group-hover:text-[#2E7DF5] transition-colors">{t.name}</div>
                <div className="text-xs text-slate-500 mt-1 mb-3 leading-snug flex-1">{t.desc}</div>
                <span className="inline-flex items-center gap-1 text-xs font-semibold text-[#2E7DF5]">Open <ExternalLink className="w-3 h-3" /></span>
              </a>
            ))}
          </div>
        </div>
      </section>

      {/* Curated IOC Database */}
      <section data-testid="ioc-database-section" className="py-16 lg:py-20 bg-slate-50 border-b border-slate-100">
        <div className="mx-auto max-w-7xl px-6">
          <div className="max-w-2xl mb-2">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-[#F5821F] mb-3">
              <Database className="w-4 h-4" /> Threat Intel · IOC Database
            </div>
            <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-slate-900">Our curated indicator database</h2>
            <p className="mt-4 text-base text-slate-600 leading-relaxed">
              Newly discovered indicators are catalogued here and automatically flagged inside the analyzer above whenever a match is found.
            </p>
          </div>
          <IocDatabase />
        </div>
      </section>

      <section data-testid="intel-feed" className="py-16 lg:py-24 bg-white">
        <div className="mx-auto max-w-7xl px-6">
          <div className="flex flex-wrap items-end justify-between gap-4 mb-6">
            <div className="max-w-2xl">
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-blue-600 mb-3">
                <span className="w-2 h-2 rounded-full bg-green-500 pulse-dot" /> Live · Timely Threat Intel
              </div>
              <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-slate-900">Latest published intelligence</h2>
              <p className="mt-1 text-sm text-slate-500 max-w-xl">Fresh reports and adversary research — updated continuously by the NivX intel team.</p>
            </div>
            {repoUrl && (
              <a href={repoUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 text-sm font-semibold text-[#2E7DF5] hover:underline">
                View full source <ExternalLink className="w-4 h-4" />
              </a>
            )}
          </div>

          {/* Filters */}
          <div className="flex flex-col lg:flex-row lg:items-center gap-3 mb-6">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                data-testid="intel-search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search reports by keyword, malware, date…"
                className="w-full bg-white border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none pl-10 pr-4 py-2.5 text-sm text-slate-800 placeholder:text-slate-400 rounded-md transition-shadow"
              />
            </div>
            <select
              data-testid="intel-date-filter"
              value={dateDays}
              onChange={(e) => setDateDays(e.target.value)}
              className="bg-white border border-slate-300 focus:border-[#2E7DF5] outline-none px-3.5 py-2.5 text-sm text-slate-700 rounded-md"
            >
              {DATE_RANGES.map((r) => (
                <option key={r.label} value={r.value}>{r.label}</option>
              ))}
            </select>
          </div>

          {/* Type facets */}
          <div className="flex flex-wrap gap-2 mb-8" data-testid="intel-type-facets">
            {["", ...types].map((t) => (
              <button
                key={t || "all"}
                data-testid={`facet-${t || "all"}`}
                onClick={() => setTypeFilter(t)}
                className={`text-xs font-semibold px-3 py-1.5 rounded-full border transition-colors ${
                  typeFilter === t ? "bg-[#2E7DF5] border-[#2E7DF5] text-white" : "bg-white border-slate-300 text-slate-600 hover:border-[#2E7DF5] hover:text-[#2E7DF5]"
                }`}
              >
                {t || "All"}
              </button>
            ))}
          </div>

          {err && <div className="text-sm text-red-500">Intel feed temporarily unavailable.</div>}
          {loading && items.length === 0 && <div className="text-sm text-slate-400">Loading intelligence…</div>}
          {!loading && items.length === 0 && !err && (
            <div data-testid="intel-no-results" className="text-sm text-slate-500">No reports match your filters.</div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {items.map((it, i) => (
              <motion.button
                key={it.name + i}
                type="button"
                onClick={() => setActiveName(it.name)}
                initial={{ opacity: 0, y: 14 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4 }}
                data-testid={`intel-card-${i}`}
                className="group text-left flex flex-col rounded-xl border border-slate-200 bg-white shadow-sm hover:shadow-md hover:-translate-y-1 transition-[transform,box-shadow] overflow-hidden"
              >
                <div className="relative h-40 overflow-hidden">
                  <img src={it.image} alt={it.title} loading="lazy" className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-700" />
                  <div className="absolute inset-0 bg-gradient-to-t from-slate-900/60 to-transparent" />
                  <span className="absolute top-3 left-3 inline-flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md bg-white/90 text-slate-800">
                    <FileText className="w-3 h-3" /> {it.source}
                  </span>
                  <span className="absolute top-3 right-3 text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md bg-[#2E7DF5] text-white">{it.type}</span>
                </div>
                <div className="p-5 flex flex-col flex-1">
                  <div className="text-xs text-slate-400 mb-1.5">{it.date}</div>
                  <h3 className="font-heading text-base font-semibold text-slate-900 leading-snug mb-2 group-hover:text-[#2E7DF5] transition-colors line-clamp-2">{it.title}</h3>
                  <p className="text-sm text-slate-600 leading-relaxed line-clamp-3 flex-1">{it.summary}</p>
                  <div className="mt-4 flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-500">{it.ioc_count} IOCs</span>
                    <span className="inline-flex items-center gap-1 text-sm font-semibold text-[#2E7DF5]">Read report <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" /></span>
                  </div>
                </div>
              </motion.button>
            ))}
          </div>

          {hasMore && (
            <div className="flex justify-center mt-10">
              <button
                data-testid="intel-load-more"
                disabled={loading}
                onClick={() => fetchFeed(page + 1, true)}
                className="inline-flex items-center gap-2 border border-slate-300 hover:border-[#2E7DF5] hover:text-[#2E7DF5] text-slate-700 text-sm font-semibold px-6 py-3 rounded-md transition-colors disabled:opacity-60"
              >
                {loading ? "Loading…" : `Load more (${total - items.length} remaining)`}
              </button>
            </div>
          )}
        </div>
      </section>

      <section id="community" data-testid="intel-blog" className="py-16 lg:py-24 bg-slate-50 scroll-mt-24">
        <div className="mx-auto max-w-7xl px-6">
          <div className="max-w-2xl mb-10">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-[#F5821F] mb-3">
              <BookOpen className="w-4 h-4" /> Community Signals
            </div>
            <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-slate-900">Threat intel blog &amp; writeups</h2>
            <p className="mt-4 text-base text-slate-600 leading-relaxed">
              DFIR, malware analysis, SOC playbooks and breaking security news curated live by NivX analysts — refreshed every 30 minutes.
              Click any card to jump straight to the full report.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-3 gap-6">
            {CYBERDEFENDERS.filter((b) => enabledSources === null || enabledSources.includes(b.slug)).map((b, i) => (
              <motion.div
                key={b.title}
                initial={{ opacity: 0, y: 14 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.45, delay: i * 0.08 }}
              >
                <Link
                  to={b.url}
                  data-testid={`blog-card-${i}`}
                  className="group h-full rounded-xl border border-slate-200 bg-white shadow-sm hover:shadow-md hover:-translate-y-1 transition-[transform,box-shadow] p-7 flex flex-col"
                >
                  <span className="inline-flex w-fit items-center text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md bg-blue-50 text-blue-700 mb-4">{b.tag}</span>
                  <h3 className="font-heading text-lg font-semibold text-slate-900 mb-2 group-hover:text-[#2E7DF5] transition-colors">{b.title}</h3>
                  <p className="text-sm text-slate-600 leading-relaxed flex-1">{b.desc}</p>
                  <span className="mt-5 inline-flex items-center gap-1.5 text-sm font-semibold text-[#F5821F]">Browse feed on NivX <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" /></span>
                </Link>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      <Contact />
      <IntelReader name={activeName} onClose={() => setActiveName(null)} />
    </div>
  );
}
