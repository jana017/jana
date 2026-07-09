export const FAVICON = {
  "VirusTotal": "virustotal.com",
  "AbuseIPDB": "abuseipdb.com",
  "Cisco Talos": "talosintelligence.com",
  "IBM X-Force": "exchange.xforce.ibmcloud.com",
  "urlscan.io": "urlscan.io",
  "MalwareBazaar": "abuse.ch",
  "ThreatFox": "threatfox.abuse.ch",
  "Hybrid Analysis": "hybrid-analysis.com",
  "Shodan": "shodan.io",
  "GreyNoise": "greynoise.io",
};

export const TYPE_LABEL = {
  md5: "MD5 Hash", sha1: "SHA1 Hash", sha256: "SHA256 Hash",
  ip: "IP Address", domain: "Domain", url: "URL", unknown: "Unrecognized",
};

export const SEVERITY_STYLE = {
  critical: { badge: "bg-red-600 text-white", ring: "border-red-300 bg-red-50", text: "text-red-700", dot: "bg-red-600" },
  high: { badge: "bg-orange-500 text-white", ring: "border-orange-300 bg-orange-50", text: "text-orange-700", dot: "bg-orange-500" },
  medium: { badge: "bg-amber-400 text-amber-950", ring: "border-amber-300 bg-amber-50", text: "text-amber-700", dot: "bg-amber-400" },
  low: { badge: "bg-slate-400 text-white", ring: "border-slate-300 bg-slate-50", text: "text-slate-600", dot: "bg-slate-400" },
};
export const severityStyle = (s) => SEVERITY_STYLE[(s || "medium").toLowerCase()] || SEVERITY_STYLE.medium;

// Short human summary of the free-source enrichment for a result row.
export function iocSummary(r) {
  const en = r?.enrichment;
  if (r?.type === "unknown") return "Not a valid IOC";
  if (!en) return "—";
  if (en.kind === "ip") {
    const parts = [];
    const geo = en.geo ? [en.geo.city, en.geo.country].filter(Boolean).join(", ") : "";
    if (geo) parts.push(geo);
    parts.push(`${en.open_ports?.length || 0} ports`);
    if (en.vulns?.length) parts.push(`${en.vulns.length} CVEs`);
    return parts.join(" · ");
  }
  if (en.kind === "web") {
    const parts = [];
    if (en.geo) {
      const loc = [en.geo.city, en.geo.country].filter(Boolean).join(", ");
      if (loc) parts.push(loc);
    }
    if (en.open_ports?.length) parts.push(`${en.open_ports.length} ports`);
    parts.push(`${(en.scan_count || 0).toLocaleString()} scans`);
    return parts.join(" · ");
  }
  if (en.kind === "hash") {
    if (en.found) return en.known_malicious ? "Known malicious" : "Known good file";
    return "Not in known-file DB";
  }
  return "—";
}

const VT_ERR = { unauthorized: "key invalid", rate_limited: "quota reached", request_failed: "unavailable" };

// Returns { text, tone } for a VirusTotal reputation object, or null.
export function vtVerdict(vt) {
  if (!vt) return null;
  if (vt.error) return { text: `VT ${VT_ERR[vt.error] || vt.error}`, tone: "muted" };
  if (vt.found === false) return { text: "VT: no data", tone: "muted" };
  const flagged = (vt.malicious || 0) + (vt.suspicious || 0);
  return { text: `${vt.malicious || 0}/${vt.total || 0}`, tone: flagged > 0 ? "bad" : "good" };
}

// Returns { text, tone } for an AbuseIPDB reputation object, or null.
export function abuseVerdict(ab) {
  if (!ab) return null;
  if (ab.error) return { text: `Abuse ${VT_ERR[ab.error] || ab.error}`, tone: "muted" };
  const score = ab.score ?? 0;
  const tone = score >= 50 ? "bad" : score > 0 ? "warn" : "good";
  return { text: `${score}%`, tone };
}

// Returns { text, tone } for a Hybrid Analysis reputation object, or null.
export function haVerdict(ha) {
  if (!ha) return null;
  if (ha.skipped) return null; // sha256 required — hide badge silently
  if (ha.error) return { text: `HA ${VT_ERR[ha.error] || ha.error}`, tone: "muted" };
  if (ha.found === false) return { text: "HA: no data", tone: "muted" };
  // URL quick-scan shape has verdict + malicious_scanners + total_scanners.
  if (ha.total_scanners != null) {
    const flagged = ha.malicious_scanners || 0;
    const verdict = (ha.verdict || "").toLowerCase();
    const tone = verdict === "malicious" || flagged > 2 ? "bad" : verdict === "suspicious" || flagged > 0 ? "warn" : "good";
    const label = verdict ? verdict.charAt(0).toUpperCase() + verdict.slice(1) : `${flagged}/${ha.total_scanners}`;
    return { text: `${label} · ${flagged}/${ha.total_scanners}`, tone };
  }
  const score = ha.threat_score ?? 0;
  const verdict = (ha.verdict || "").toLowerCase();
  const tone = verdict === "malicious" || score >= 70 ? "bad" : verdict === "suspicious" || score >= 30 ? "warn" : "good";
  const label = verdict ? verdict.charAt(0).toUpperCase() + verdict.slice(1) : `${score}/100`;
  return { text: `${label}${ha.threat_score != null ? ` · ${score}` : ""}`, tone };
}

// Returns { text, tone } for a MalwareBazaar reputation object, or null.
export function mbVerdict(mb) {
  if (!mb) return null;
  if (mb.skipped) return null;
  if (mb.error) return { text: `MB ${VT_ERR[mb.error] || mb.error}`, tone: "muted" };
  if (mb.found === false) return { text: "MB: no data", tone: "muted" };
  const sig = mb.signature;
  return { text: sig ? sig : "Known sample", tone: "bad" };
}

function csvCell(v) {
  const s = v == null ? "" : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function resultsToCSV(results) {
  const header = ["IOC", "Type", "Summary", "VT_Flagged", "VT_Total", "AbuseIPDB_Score", "AbuseIPDB_Reports", "Sources"];
  const rows = results.map((r) => {
    const vt = r.reputation?.vt;
    const ab = r.reputation?.abuseipdb;
    const vtOk = vt && !vt.error && vt.found !== false;
    const abOk = ab && !ab.error;
    return [
      r.value,
      TYPE_LABEL[r.type] || r.type,
      iocSummary(r),
      vtOk ? (vt.malicious || 0) + (vt.suspicious || 0) : "",
      vtOk ? vt.total : "",
      abOk ? (ab.score ?? "") : "",
      abOk ? (ab.reports ?? "") : "",
      Object.keys(r.links || {}).join(" | "),
    ];
  });
  return [header, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
}

export function downloadCSV(csv, filename = "ioc-analysis.csv") {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
