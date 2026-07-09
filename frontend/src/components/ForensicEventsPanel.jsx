/**
 * ForensicEventsPanel — renders the full forensic record handed off from
 * CyberLab's Sysmon parser. Displays every field the DFIR analyst needs
 * (src/dst IP:port, protocol, process names, hashes, MITRE, ...) and
 * offers CSV / JSON / Markdown downloads that include ALL columns.
 */
import { useState, useMemo, useRef, useEffect } from "react";
import { toast } from "sonner";
import { Download, ChevronDown, FileSpreadsheet, FileJson, FileText, Search, ShieldAlert } from "lucide-react";

const RISK_CHIP = {
  info:     "bg-emerald-100 text-emerald-800 border-emerald-200",
  low:      "bg-blue-100 text-blue-800 border-blue-200",
  medium:   "bg-amber-100 text-amber-800 border-amber-200",
  high:     "bg-orange-100 text-orange-800 border-orange-200",
  critical: "bg-red-100 text-red-800 border-red-200",
};

const COLUMNS = [
  ["timestamp", "Time"],
  ["event_id", "EID"],
  ["event_type", "Event"],
  ["action", "Action"],
  ["category", "Category"],
  ["host", "Host"],
  ["user", "User"],
  ["integrity_level", "Integrity"],
  ["process_name", "Process"],
  ["process_id", "PID"],
  ["process_image", "Image path"],
  ["command_line", "Command line"],
  ["parent_process_name", "Parent"],
  ["parent_process_id", "PPID"],
  ["parent_image", "Parent image"],
  ["parent_command_line", "Parent cmdline"],
  ["file_path", "File / Target"],
  ["file_hash_md5", "MD5"],
  ["file_hash_sha1", "SHA1"],
  ["file_hash_sha256", "SHA256"],
  ["parent_file_hash", "Parent hash"],
  ["src_ip", "Src IP"],
  ["src_port", "Src port"],
  ["dst_ip", "Dst IP"],
  ["dst_port", "Dst port"],
  ["protocol", "Protocol"],
  ["domain", "Domain"],
  ["url", "URL"],
  ["dns_query", "DNS query"],
  ["dns_answer", "DNS answer"],
  ["registry_key", "Registry key"],
  ["registry_value", "Registry value"],
  ["mitre_techniques", "MITRE"],
  ["risk", "Risk"],
];

function csvCell(v) {
  const s = v == null ? "" : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function toCSV(events) {
  const headers = COLUMNS.map(([, label]) => label);
  const rows = events.map((e) =>
    COLUMNS.map(([field]) => {
      const v = e[field];
      if (field === "mitre_techniques") {
        return (v || []).map((t) => `${t.id}:${t.name}`).join(" | ");
      }
      return v ?? "";
    }),
  );
  return [headers, ...rows].map((row) => row.map(csvCell).join(",")).join("\n");
}

function toMarkdown(forensic) {
  const events = forensic.events || [];
  const lines = [
    "# NivX Machines · Forensic Event Report",
    `_Generated ${new Date().toISOString()}_`,
    "",
    `**Source:** ${forensic.source || "CyberLab"} · **Format:** \`${forensic.format || "?"}\` · **Events:** ${events.length}`,
    "",
  ];
  const cols = COLUMNS.filter(([f]) => f !== "mitre_techniques").map(([, l]) => l);
  cols.push("MITRE");
  lines.push(`| ${cols.join(" | ")} |`);
  lines.push(`|${cols.map(() => "---").join("|")}|`);
  for (const e of events) {
    const row = COLUMNS.filter(([f]) => f !== "mitre_techniques").map(([f]) => {
      const v = e[f];
      return String(v ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
    });
    const techniques = (e.mitre_techniques || []).map((t) => t.id).join(", ");
    row.push(techniques);
    lines.push(`| ${row.join(" | ")} |`);
  }
  return lines.join("\n");
}

function download(text, mime, name) {
  const blob = new Blob([text], { type: mime + ";charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export default function ForensicEventsPanel({ forensic }) {
  const [q, setQ] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");
  const [actionFilter, setActionFilter] = useState("all");
  const [menu, setMenu] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setMenu(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);

  const events = forensic?.events || [];
  const actions = useMemo(() => [...new Set(events.map((e) => e.action))], [events]);

  const filtered = useMemo(() => {
    let out = events;
    if (riskFilter !== "all") out = out.filter((e) => e.risk === riskFilter);
    if (actionFilter !== "all") out = out.filter((e) => e.action === actionFilter);
    const term = q.trim().toLowerCase();
    if (term) {
      out = out.filter((e) =>
        Object.values(e).some((v) => {
          if (v == null) return false;
          if (Array.isArray(v)) return v.some((t) => String(t.id || t).toLowerCase().includes(term));
          return String(v).toLowerCase().includes(term);
        }),
      );
    }
    return out;
  }, [events, q, riskFilter, actionFilter]);

  const stamp = () => new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const doCSV = () => { download(toCSV(filtered), "text/csv", `nivx-forensic-${stamp()}.csv`); toast.success("CSV downloaded"); setMenu(false); };
  const doJSON = () => {
    const payload = { generated_at: new Date().toISOString(), source: forensic.source, format: forensic.format, count: filtered.length, events: filtered };
    download(JSON.stringify(payload, null, 2), "application/json", `nivx-forensic-${stamp()}.json`);
    toast.success("JSON downloaded"); setMenu(false);
  };
  const doMD = () => { download(toMarkdown({ ...forensic, events: filtered }), "text/markdown", `nivx-forensic-${stamp()}.md`); toast.success("Markdown downloaded"); setMenu(false); };

  if (!events.length) return null;

  return (
    <div className="mb-6 rounded-xl border border-slate-200 bg-white overflow-hidden" data-testid="analyzer-forensic-panel">
      <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-slate-200 bg-slate-50 flex-wrap">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-cyan-600" />
          <h3 className="font-semibold text-slate-900 text-sm">Forensic Events</h3>
          <span className="text-xs text-slate-500">
            {filtered.length} / {events.length} shown · source: <code className="font-mono text-slate-700">{forensic.source}</code>
          </span>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <div className="relative">
            <Search className="w-3 h-3 absolute left-2 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              data-testid="forensic-search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Filter…"
              className="w-40 pl-7 pr-2 py-1 text-xs border border-slate-300 rounded outline-none focus:border-[#2E7DF5]"
            />
          </div>
          <select
            data-testid="forensic-risk-filter"
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="text-xs border border-slate-300 rounded px-2 py-1 outline-none"
          >
            <option value="all">All risks</option>
            {["critical", "high", "medium", "low", "info"].map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <select
            data-testid="forensic-action-filter"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="text-xs border border-slate-300 rounded px-2 py-1 outline-none"
          >
            <option value="all">All actions</option>
            {actions.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
          <div className="relative" ref={ref}>
            <button
              data-testid="forensic-export-btn"
              onClick={() => setMenu((v) => !v)}
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-white bg-[#2E7DF5] hover:bg-[#2563EB] rounded px-3 py-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5" /> Download report
              <ChevronDown className={`w-3 h-3 transition-transform ${menu ? "rotate-180" : ""}`} />
            </button>
            {menu && (
              <div data-testid="forensic-export-menu" className="absolute right-0 mt-1 w-56 rounded-md border border-slate-200 bg-white shadow-lg z-30 py-1">
                <button onClick={doCSV} data-testid="forensic-export-csv" className="w-full text-left px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 inline-flex items-center gap-2">
                  <FileSpreadsheet className="w-4 h-4 text-emerald-600" /> CSV (all {COLUMNS.length} columns)
                </button>
                <button onClick={doJSON} data-testid="forensic-export-json" className="w-full text-left px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 inline-flex items-center gap-2">
                  <FileJson className="w-4 h-4 text-blue-600" /> JSON (full nested)
                </button>
                <button onClick={doMD} data-testid="forensic-export-md" className="w-full text-left px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 inline-flex items-center gap-2">
                  <FileText className="w-4 h-4 text-fuchsia-600" /> Markdown report
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
      <div className="overflow-x-auto max-h-96 overflow-y-auto">
        <table className="w-full text-[11px]">
          <thead className="sticky top-0 bg-slate-100 z-10">
            <tr className="text-left text-[9px] uppercase tracking-widest text-slate-500 border-b border-slate-200">
              {COLUMNS.map(([f, label]) => (
                <th key={f} className="px-2 py-1.5 font-semibold whitespace-nowrap">{label}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {filtered.slice(0, 500).map((e, i) => (
              <tr key={i} data-testid={`analyzer-forensic-row-${i}`} className="hover:bg-slate-50">
                {COLUMNS.map(([f]) => {
                  const v = e[f];
                  if (f === "risk") {
                    return (
                      <td key={f} className="px-2 py-1">
                        <span className={`inline-flex items-center text-[9px] font-bold px-1.5 py-0.5 rounded border ${RISK_CHIP[v] || RISK_CHIP.info}`}>
                          {v}
                        </span>
                      </td>
                    );
                  }
                  if (f === "mitre_techniques") {
                    return (
                      <td key={f} className="px-2 py-1 whitespace-nowrap">
                        {(v || []).slice(0, 4).map((t) => (
                          <span key={t.id} title={`${t.name} · ${t.tactic}`} className="mr-1 text-[9px] font-mono px-1 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200">{t.id}</span>
                        ))}
                      </td>
                    );
                  }
                  const s = v == null ? "" : String(v);
                  const displayValue = s.length > 60 ? s.slice(0, 60) + "…" : s;
                  const isMono = ["file_hash_md5","file_hash_sha1","file_hash_sha256","parent_file_hash","src_ip","dst_ip","command_line","parent_command_line","url","domain","dns_query","registry_key","file_path","parent_image","process_image","process_guid","parent_process_guid"].includes(f);
                  return (
                    <td key={f} className={`px-2 py-1 ${isMono ? "font-mono text-slate-700" : "text-slate-700"} whitespace-nowrap max-w-[200px] truncate`} title={s}>
                      {displayValue}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {filtered.length > 500 && (
        <div className="px-3 py-2 text-[11px] text-slate-500 border-t border-slate-200 bg-slate-50">
          Showing first 500 of {filtered.length} filtered events. All {events.length} events are included in downloads.
        </div>
      )}
    </div>
  );
}
