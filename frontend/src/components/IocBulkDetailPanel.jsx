/**
 * IocBulkDetailPanel — full OSINT dossier for a single bulk-analyzed row.
 *
 * Rendered as an expandable section beneath each IocBulkTable row. Aggregates
 * every source we've already enriched with — geo, Shodan, VirusTotal,
 * AbuseIPDB, MalwareBazaar, urlscan.io, CIRCL — into a single dossier so the
 * analyst never has to click 8 tabs to see the picture.
 *
 * Kept lean: pure presentation, no API calls of its own — everything comes
 * from the `enrichment` + `reputation` fields already on the row.
 */
import { Globe2, Network, ShieldAlert, Server, Tag, Fingerprint, ExternalLink, FileWarning } from "lucide-react";

function Section({ icon: Icon, title, children, testid }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-3" data-testid={testid}>
      <div className="text-[11px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5 mb-2">
        <Icon className="w-3.5 h-3.5 text-[#2E7DF5]" /> {title}
      </div>
      <div className="text-sm text-slate-700">{children}</div>
    </div>
  );
}

function KV({ k, v }) {
  if (v === null || v === undefined || v === "") return null;
  return (
    <div className="flex gap-2 text-xs">
      <span className="text-slate-400 min-w-[70px]">{k}</span>
      <span className="text-slate-800 font-medium break-all">{v}</span>
    </div>
  );
}

function ChipList({ items, tone = "slate", testid }) {
  if (!items || items.length === 0) return <span className="text-xs text-slate-400">—</span>;
  const toneCls = {
    slate:   "bg-slate-100 text-slate-700 border-slate-200",
    red:     "bg-red-50 text-red-700 border-red-200",
    amber:   "bg-amber-50 text-amber-700 border-amber-200",
    emerald: "bg-emerald-50 text-emerald-700 border-emerald-200",
    sky:     "bg-sky-50 text-sky-700 border-sky-200",
  }[tone];
  return (
    <div className="flex flex-wrap gap-1" data-testid={testid}>
      {items.map((it, i) => (
        <span key={i} className={`inline-flex items-center text-[11px] font-mono px-1.5 py-0.5 rounded border ${toneCls}`}>
          {String(it)}
        </span>
      ))}
    </div>
  );
}

export default function IocBulkDetailPanel({ row }) {
  const en = row?.enrichment || {};
  const rep = row?.reputation || {};
  const vt  = rep.vt || {};
  const ab  = rep.abuseipdb || {};
  const kind = en.kind || row?.type;

  const isIp = kind === "ip";
  const isWeb = kind === "web" || kind === "url" || kind === "domain";
  const isFile = kind === "file" || kind === "hash";

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 p-4 bg-slate-50/60" data-testid="ioc-bulk-detail">
      {/* Geolocation / Network — for IPs and web hosts */}
      {(isIp || isWeb) && en.geo && (
        <Section icon={Globe2} title="Geolocation & Network" testid="dossier-geo">
          <div className="space-y-1">
            <KV k="Country" v={en.geo.country} />
            <KV k="City"    v={en.geo.city} />
            <KV k="ISP"     v={en.geo.isp} />
            <KV k="Org"     v={en.geo.org} />
            <KV k="ASN"     v={en.geo.asn} />
            {en.resolved_ip && <KV k="Resolved" v={en.resolved_ip} />}
          </div>
        </Section>
      )}

      {/* Shodan — open ports, CPEs, tags, vulns */}
      {isIp && (
        <Section icon={Server} title="Shodan — Attack surface" testid="dossier-shodan">
          <div className="space-y-2">
            <div>
              <div className="text-[10px] uppercase text-slate-400 mb-0.5">Open ports</div>
              <ChipList items={en.open_ports} tone={en.open_ports?.length > 3 ? "amber" : "sky"} testid="dossier-ports" />
            </div>
            {en.cpes?.length > 0 && (
              <div>
                <div className="text-[10px] uppercase text-slate-400 mb-0.5 flex items-center gap-1"><Fingerprint className="w-3 h-3" /> Software fingerprint (CPE)</div>
                <ChipList items={en.cpes.map((c) => c.replace(/^cpe:\/[oa]:/, ""))} tone="slate" testid="dossier-cpes" />
              </div>
            )}
            {en.hostnames?.length > 0 && (
              <div>
                <div className="text-[10px] uppercase text-slate-400 mb-0.5">Hostnames</div>
                <ChipList items={en.hostnames} tone="slate" />
              </div>
            )}
            {en.tags?.length > 0 && (
              <div>
                <div className="text-[10px] uppercase text-slate-400 mb-0.5 flex items-center gap-1"><Tag className="w-3 h-3" /> Tags</div>
                <ChipList items={en.tags} tone="amber" />
              </div>
            )}
            <div>
              <div className="text-[10px] uppercase text-slate-400 mb-0.5 flex items-center gap-1"><FileWarning className="w-3 h-3" /> Known vulnerabilities (CVE)</div>
              <ChipList items={en.vulns} tone="red" testid="dossier-vulns" />
              <div className="text-[10px] text-slate-400 mt-1">
                Empty = InternetDB has no CVE flag. For full CVE coverage, add a paid Shodan key.
              </div>
            </div>
          </div>
        </Section>
      )}

      {/* VirusTotal */}
      {vt.found !== undefined && (
        <Section icon={ShieldAlert} title="VirusTotal reputation" testid="dossier-vt">
          <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
            <div><span className="text-slate-400">Malicious</span> <strong className="text-red-600">{vt.malicious ?? 0}</strong></div>
            <div><span className="text-slate-400">Suspicious</span> <strong className="text-amber-600">{vt.suspicious ?? 0}</strong></div>
            <div><span className="text-slate-400">Harmless</span> <strong className="text-emerald-600">{vt.harmless ?? 0}</strong></div>
            <div><span className="text-slate-400">Undetected</span> <strong className="text-slate-500">{vt.undetected ?? 0}</strong></div>
          </div>
          {vt.categories && Object.keys(vt.categories).length > 0 && (
            <div className="mt-2">
              <div className="text-[10px] uppercase text-slate-400 mb-0.5">Categories</div>
              <ChipList items={Object.values(vt.categories).slice(0, 6)} tone="slate" />
            </div>
          )}
        </Section>
      )}

      {/* AbuseIPDB — only for IPs */}
      {isIp && ab.abuseConfidenceScore !== undefined && (
        <Section icon={Network} title="AbuseIPDB" testid="dossier-abuseipdb">
          <div className="space-y-1 text-xs">
            <div>
              <span className="text-slate-400">Abuse confidence</span>{" "}
              <strong className={ab.abuseConfidenceScore >= 75 ? "text-red-600" : ab.abuseConfidenceScore >= 25 ? "text-amber-600" : "text-emerald-600"}>
                {ab.abuseConfidenceScore}%
              </strong>
            </div>
            <KV k="Total reports"   v={ab.totalReports} />
            <KV k="Distinct users"  v={ab.numDistinctUsers} />
            <KV k="Country"         v={ab.countryCode} />
            <KV k="Usage type"      v={ab.usageType} />
            <KV k="Last reported"   v={ab.lastReportedAt} />
          </div>
        </Section>
      )}

      {/* urlscan.io — web only */}
      {isWeb && (en.preview || en.recent_scans?.length > 0 || en.fresh_scan) && (
        <Section icon={Globe2} title="urlscan.io" testid="dossier-urlscan">
          {en.preview?.screenshot && (
            <a href={en.preview.result_url || en.preview.screenshot} target="_blank" rel="noopener noreferrer" className="block mb-2">
              <img src={en.preview.screenshot} alt="urlscan preview" className="w-full rounded border border-slate-200 max-h-40 object-cover" onError={(e) => { e.currentTarget.style.display = "none"; }} />
            </a>
          )}
          <KV k="Scans"    v={en.scan_count} />
          {en.fresh_scan?.result_url && (
            <a href={en.fresh_scan.result_url} target="_blank" rel="noopener noreferrer" className="text-[11px] text-cyan-700 hover:underline inline-flex items-center gap-1 mt-1">
              Fresh scan submitted <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </Section>
      )}

      {/* Local DB — known IOC */}
      {row?.local_db && (
        <Section icon={ShieldAlert} title="NivX Curated DB — Known IOC" testid="dossier-local">
          <div className="space-y-1 text-xs">
            <KV k="Threat"    v={row.local_db.threat_name} />
            <KV k="Severity"  v={String(row.local_db.severity || "").toUpperCase()} />
            <KV k="Category"  v={row.local_db.category} />
            <KV k="Source"    v={row.local_db.source} />
            <KV k="Added"     v={row.local_db.created_at} />
            {row.local_db.notes && <KV k="Notes" v={row.local_db.notes} />}
          </div>
        </Section>
      )}

      {/* Sources footer + investigate deep-links */}
      <Section icon={ExternalLink} title="Investigate deeper" testid="dossier-links">
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(row?.links || {}).map(([name, url]) => (
            <a key={name} href={url} target="_blank" rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-1 rounded border border-slate-200 hover:border-[#2E7DF5] hover:text-[#2E7DF5] bg-white transition-colors">
              {name} <ExternalLink className="w-3 h-3" />
            </a>
          ))}
        </div>
        {en.sources?.length > 0 && (
          <div className="text-[10px] text-slate-400 mt-2">
            Sources: {en.sources.join(" · ")}
          </div>
        )}
      </Section>
    </div>
  );
}
