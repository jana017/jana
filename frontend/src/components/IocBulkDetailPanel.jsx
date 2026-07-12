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
import { Globe2, Network, ShieldAlert, Server, Tag, Fingerprint, ExternalLink, FileWarning, Download, Radar, Flame } from "lucide-react";

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
  const gn  = en.greynoise || null;
  const otx = en.otx || null;
  const cves = en.cves_by_cpe || [];

  const isIp = kind === "ip";
  const isWeb = kind === "web" || kind === "url" || kind === "domain";
  const isFile = kind === "file" || kind === "hash";
  void isFile;

  // Per-row download — captures everything (row + enrichment + reputation
  // + local_db + all deep-links) as a JSON dossier the analyst can attach
  // to a ticket or share.  Uses the value + timestamp as the filename.
  const downloadDossier = (fmt) => {
    const safeName = (row?.value || "ioc").replace(/[^a-z0-9.-]+/gi, "_").slice(0, 60);
    const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    if (fmt === "json") {
      const blob = new Blob([JSON.stringify(row, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `nivx-dossier-${safeName}-${ts}.json`; a.click();
      URL.revokeObjectURL(url);
      return;
    }
    // Markdown
    const lines = [`# NivX Dossier — \`${row?.value}\``, "",
      `**Type**: ${kind}   **Generated**: ${new Date().toISOString()}`, ""];
    if (en.geo) lines.push("## Geolocation", `- Country: ${en.geo.country || "—"}`, `- City: ${en.geo.city || "—"}`, `- ISP: ${en.geo.isp || "—"}`, `- ASN: ${en.geo.asn || "—"}`, "");
    if (en.open_ports?.length) lines.push("## Shodan Attack Surface", `Open ports: ${en.open_ports.join(", ")}`, `CPEs: ${(en.cpes||[]).join(", ") || "—"}`, `Vulns (InternetDB): ${(en.vulns||[]).join(", ") || "—"}`, "");
    if (cves.length) { lines.push("## Known CVEs (CIRCL)"); cves.forEach((c) => lines.push(`- **${c.id}** (${c.product}) CVSS ${c.cvss ?? "?"} — ${c.summary}`)); lines.push(""); }
    if (gn) lines.push("## GreyNoise", `- Classification: ${gn.classification || "unknown"}`, `- Name: ${gn.name || "—"}`, `- Last seen: ${gn.last_seen || "—"}`, `- Noise: ${gn.noise ? "yes" : "no"} · RIOT: ${gn.riot ? "yes" : "no"}`, "");
    if (otx) { lines.push("## AlienVault OTX", `- Pulse count: ${otx.pulse_count || 0}`); (otx.pulses||[]).forEach((p) => lines.push(`  - ${p.name}${p.adversary?` (adversary: ${p.adversary})`:""}`)); lines.push(""); }
    if (vt.found !== undefined) lines.push("## VirusTotal", `- Malicious: **${vt.malicious ?? 0}**  Suspicious: ${vt.suspicious ?? 0}  Harmless: ${vt.harmless ?? 0}  Undetected: ${vt.undetected ?? 0}`, "");
    if (ab.abuseConfidenceScore !== undefined) lines.push("## AbuseIPDB", `- Confidence: **${ab.abuseConfidenceScore}%**  Reports: ${ab.totalReports ?? 0}  Users: ${ab.numDistinctUsers ?? 0}`, `- Country: ${ab.countryCode || "—"}  Usage: ${ab.usageType || "—"}`, "");
    if (row?.local_db) lines.push("## NivX Curated DB", `- Threat: ${row.local_db.threat_name}`, `- Severity: **${row.local_db.severity}**`, `- Source: ${row.local_db.source}`, "");
    if (row?.links) { lines.push("## Investigate deeper"); Object.entries(row.links).forEach(([n, u]) => lines.push(`- [${n}](${u})`)); }
    const blob = new Blob([lines.join("\n")], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `nivx-dossier-${safeName}-${ts}.md`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-4 bg-slate-50/60" data-testid="ioc-bulk-detail">
      <div className="mb-3 flex items-center justify-end gap-2">
        <button onClick={() => downloadDossier("md")} data-testid="dossier-download-md"
          className="text-xs font-semibold text-slate-600 hover:text-[#2E7DF5] inline-flex items-center gap-1 border border-slate-200 hover:border-[#2E7DF5] bg-white px-2 py-1 rounded">
          <Download className="w-3 h-3" /> Markdown
        </button>
        <button onClick={() => downloadDossier("json")} data-testid="dossier-download-json"
          className="text-xs font-semibold text-slate-600 hover:text-[#2E7DF5] inline-flex items-center gap-1 border border-slate-200 hover:border-[#2E7DF5] bg-white px-2 py-1 rounded">
          <Download className="w-3 h-3" /> JSON
        </button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
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
              <div className="text-[10px] uppercase text-slate-400 mb-0.5 flex items-center gap-1"><FileWarning className="w-3 h-3" /> InternetDB vulnerability flags</div>
              <ChipList items={en.vulns} tone="red" testid="dossier-vulns" />
            </div>
          </div>
        </Section>
      )}

      {/* CIRCL CVE — real CVE lookup by CPE */}
      {isIp && cves.length > 0 && (
        <Section icon={FileWarning} title={`Known CVEs (${cves.length})`} testid="dossier-cves">
          <div className="space-y-1.5 max-h-52 overflow-y-auto pr-1">
            {cves.map((c) => (
              <div key={c.id} className="text-xs border-l-2 border-red-300 pl-2">
                <div className="font-mono font-semibold text-red-700">
                  {c.id}{" "}
                  {c.cvss != null && <span className="text-slate-500 font-normal">CVSS {c.cvss}</span>}
                </div>
                <div className="text-slate-500 text-[10px] mb-0.5">{c.product}</div>
                <div className="text-slate-700 leading-snug">{c.summary || "—"}</div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* GreyNoise Community */}
      {isIp && gn && (
        <Section icon={Radar} title="GreyNoise (Community)" testid="dossier-greynoise">
          <div className="space-y-1 text-xs">
            <div>
              <span className="text-slate-400">Classification</span>{" "}
              <strong className={gn.classification === "malicious" ? "text-red-600" : gn.classification === "benign" ? "text-emerald-600" : "text-slate-700"}>
                {gn.classification || "unknown"}
              </strong>
            </div>
            <KV k="Name"      v={gn.name} />
            <KV k="Last seen" v={gn.last_seen} />
            <div>
              <span className="text-slate-400">Noise</span> <strong>{gn.noise ? "yes" : "no"}</strong>
              <span className="mx-2 text-slate-300">·</span>
              <span className="text-slate-400">RIOT</span> <strong>{gn.riot ? "yes" : "no"}</strong>
            </div>
            {gn.link && <a href={gn.link} target="_blank" rel="noopener noreferrer" className="text-[11px] text-[#2E7DF5] hover:underline inline-flex items-center gap-1">View on GreyNoise <ExternalLink className="w-3 h-3" /></a>}
          </div>
        </Section>
      )}

      {/* AlienVault OTX */}
      {isIp && otx && (
        <Section icon={Flame} title="AlienVault OTX" testid="dossier-otx">
          <div className="space-y-1 text-xs">
            <div>
              <span className="text-slate-400">Pulse count</span>{" "}
              <strong className={otx.pulse_count >= 5 ? "text-red-600" : otx.pulse_count >= 1 ? "text-amber-600" : "text-slate-700"}>
                {otx.pulse_count}
              </strong>
            </div>
            {otx.pulses?.length > 0 && (
              <div className="max-h-24 overflow-y-auto pr-1">
                {otx.pulses.map((p, i) => (
                  <div key={i} className="text-[11px] text-slate-700 truncate" title={p.name}>
                    · {p.name}{p.adversary ? ` (${p.adversary})` : ""}
                  </div>
                ))}
              </div>
            )}
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
    </div>
  );
}
