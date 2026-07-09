/**
 * Investigation Timeline — chronological Gantt-style visualization
 * of forensic events. One lane per host or user. Events colored by risk.
 * Hover a marker to see the full record.
 */
import { useMemo, useState } from "react";
import { Clock, Server, User, RefreshCw } from "lucide-react";

const RISK_HEX = {
  info:     "#10b981",
  low:      "#3b82f6",
  medium:   "#f59e0b",
  high:     "#ea580c",
  critical: "#dc2626",
};

const ACTION_ICON = {
  process_create:   "▶",
  process_terminate:"■",
  network_connect:  "↔",
  dns_query:        "?",
  file_create:      "+",
  file_delete:      "×",
  image_load:       "↓",
  registry_set:     "⚙",
  registry_create:  "⚙",
};

function _ts(e) {
  const t = e.timestamp || "";
  const d = new Date(t);
  return isNaN(d.getTime()) ? null : d.getTime();
}

export default function InvestigationTimeline({ events = [] }) {
  const [laneKey, setLaneKey] = useState("host"); // "host" | "user"
  const [hovered, setHovered] = useState(null);

  const parsed = useMemo(() => {
    const rows = events
      .map((e) => ({ ...e, _t: _ts(e) }))
      .filter((e) => e._t !== null);
    return rows.sort((a, b) => a._t - b._t);
  }, [events]);

  const [tMin, tMax] = useMemo(() => {
    if (parsed.length === 0) return [0, 1];
    const first = parsed[0]._t;
    const last = parsed[parsed.length - 1]._t;
    const span = Math.max(last - first, 1000);
    return [first, first + span];
  }, [parsed]);

  const lanes = useMemo(() => {
    const map = new Map();
    for (const e of parsed) {
      const key = (laneKey === "host" ? e.host : e.user) || "(unknown)";
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(e);
    }
    return [...map.entries()];
  }, [parsed, laneKey]);

  if (parsed.length === 0) {
    return (
      <div className="p-6 text-center text-xs text-slate-500 italic border border-dashed border-slate-300 rounded-md">
        No events with parseable timestamps. Timeline requires an `@timestamp` / `UtcTime` / `ts` field on each event.
      </div>
    );
  }

  const totalMs = tMax - tMin;
  const humanSpan = _fmtDuration(totalMs);

  return (
    <div data-testid="investigation-timeline" className="border border-slate-200 rounded-md bg-white overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 border-b border-slate-200 bg-slate-50">
        <div className="flex items-center gap-2 text-xs">
          <Clock className="w-3.5 h-3.5 text-cyan-600" />
          <span className="font-semibold text-slate-900">Investigation Timeline</span>
          <span className="text-slate-500">
            {parsed.length} events · {lanes.length} lanes · {humanSpan}
          </span>
        </div>
        <div className="inline-flex rounded border border-slate-200 bg-white p-0.5">
          {[
            { id: "host", label: "By host", icon: Server },
            { id: "user", label: "By user", icon: User },
          ].map((o) => (
            <button
              key={o.id}
              data-testid={`timeline-lane-${o.id}`}
              onClick={() => setLaneKey(o.id)}
              className={`inline-flex items-center gap-1 px-2 py-1 text-[11px] font-semibold rounded transition-colors ${
                laneKey === o.id ? "bg-[#2E7DF5] text-white" : "text-slate-600 hover:bg-slate-100"
              }`}
            >
              <o.icon className="w-3 h-3" /> {o.label}
            </button>
          ))}
        </div>
      </div>

      <div className="overflow-x-auto p-3">
        {/* Axis */}
        <div className="flex ml-32 text-[10px] text-slate-500 mb-1 select-none">
          {[0, 0.25, 0.5, 0.75, 1].map((f, i) => (
            <div key={i} style={{ flex: 1 }} className="text-left">
              {new Date(tMin + f * totalMs).toISOString().slice(11, 19)}
            </div>
          ))}
        </div>

        {lanes.map(([lane, laneEvents]) => (
          <div key={lane} className="flex items-center mb-1.5" data-testid={`timeline-lane-row-${lane}`}>
            <div className="w-32 shrink-0 pr-2 text-[10px] text-slate-700 font-mono truncate" title={lane}>
              {lane}
            </div>
            <div className="relative flex-1 h-7 rounded bg-slate-50 border border-slate-200">
              {laneEvents.map((e, i) => {
                const pct = ((e._t - tMin) / totalMs) * 100;
                const color = RISK_HEX[e.risk] || RISK_HEX.info;
                const isHigh = e.risk === "high" || e.risk === "critical";
                return (
                  <div
                    key={i}
                    onMouseEnter={() => setHovered({ e, pct, lane })}
                    onMouseLeave={() => setHovered(null)}
                    className={`absolute top-1/2 -translate-y-1/2 -translate-x-1/2 flex items-center justify-center rounded-full font-mono text-white cursor-pointer transition-transform hover:scale-125 ${
                      isHigh ? "w-5 h-5 text-[10px]" : "w-4 h-4 text-[9px]"
                    }`}
                    style={{ left: `${pct}%`, background: color, boxShadow: isHigh ? "0 0 0 2px rgba(220,38,38,0.35)" : "none" }}
                    title={`${e.action} · ${e.process_name || e.dst_ip || e.domain || e.file_path || ''} @ ${new Date(e._t).toISOString().slice(11, 19)}`}
                    data-testid={`timeline-marker-${e.event_id}-${i}`}
                  >
                    {ACTION_ICON[e.action] || "·"}
                  </div>
                );
              })}
            </div>
          </div>
        ))}

        {/* Hover card */}
        {hovered && (
          <div className="mt-3 p-3 rounded-md border border-slate-200 bg-slate-50 text-[11px]" data-testid="timeline-hover-card">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[9px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded text-white"
                style={{ background: RISK_HEX[hovered.e.risk] || RISK_HEX.info }}>
                {hovered.e.action}
              </span>
              <span className="font-mono text-slate-500">{new Date(hovered.e._t).toISOString()}</span>
              <span className="ml-auto text-slate-500">{hovered.lane}</span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-0.5 text-slate-700">
              {["process_name","process_id","parent_process_name","user","file_path","file_hash_sha256","src_ip","dst_ip","dst_port","protocol","domain","url"].map((f) => {
                const v = hovered.e[f];
                if (!v) return null;
                return (
                  <div key={f} className="truncate">
                    <span className="text-slate-400 text-[9px] uppercase mr-1">{f}:</span>
                    <span className="font-mono">{String(v).slice(0, 40)}{String(v).length > 40 ? "…" : ""}</span>
                  </div>
                );
              })}
            </div>
            {(hovered.e.mitre_techniques || []).length > 0 && (
              <div className="mt-1.5 flex flex-wrap gap-1">
                {(hovered.e.mitre_techniques || []).map((t) => (
                  <span key={t.id} title={`${t.name} · ${t.tactic}`}
                    className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200">
                    {t.id}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function _fmtDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h`;
  return `${Math.round(hr / 24)}d`;
}
