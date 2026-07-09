/**
 * Attack Chain visualizer for CyberLab.
 * Uses reactflow to render the decoding pipeline as a horizontal DAG, then
 * hangs the detected MITRE techniques off the final node as leaf nodes.
 */
import { useMemo } from "react";
import ReactFlow, { Background, MiniMap, Controls, Handle, Position } from "reactflow";
import "reactflow/dist/style.css";

const CATEGORY_COLOR = {
  Encoding:      "#60a5fa",
  Compression:   "#34d399",
  Cryptography:  "#fbbf24",
  Deobfuscation: "#e879f9",
  Extractors:    "#fb7185",
  Utilities:     "#94a3b8",
  Hashing:       "#818cf8",
};

const TACTIC_COLOR = {
  Execution:              "#f87171",
  Persistence:            "#fb923c",
  "Defense Evasion":      "#facc15",
  "Privilege Escalation": "#f472b6",
  Discovery:              "#38bdf8",
  "Credential Access":    "#a78bfa",
  "Command and Control":  "#ef4444",
  Impact:                 "#dc2626",
  "Lateral Movement":     "#22d3ee",
};

function StepNode({ data }) {
  const color = CATEGORY_COLOR[data.category] || "#94a3b8";
  return (
    <div
      className="rounded-md border shadow-lg px-3 py-2 min-w-[170px]"
      style={{ background: "#0f172a", borderColor: color }}
    >
      <Handle type="target" position={Position.Left} style={{ background: color }} />
      <div className="flex items-center gap-1.5 mb-0.5">
        <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
        <span className="text-[9px] font-bold uppercase tracking-wider" style={{ color }}>
          {data.category}
        </span>
      </div>
      <div className="text-xs font-semibold text-white leading-tight">{data.name}</div>
      {typeof data.confidence === "number" && (
        <div className="text-[9px] text-emerald-400 font-mono mt-0.5">conf {data.confidence}</div>
      )}
      <Handle type="source" position={Position.Right} style={{ background: color }} />
    </div>
  );
}

function InputNode({ data }) {
  return (
    <div className="rounded-md border border-cyan-400 bg-slate-900 shadow-lg px-3 py-2 min-w-[130px]">
      <div className="text-[9px] font-bold uppercase tracking-wider text-cyan-300 mb-0.5">Input</div>
      <div className="text-xs font-mono text-slate-300 truncate max-w-[130px]">{data.label}</div>
      <Handle type="source" position={Position.Right} style={{ background: "#22d3ee" }} />
    </div>
  );
}

function OutputNode({ data }) {
  return (
    <div className="rounded-md border border-emerald-400 bg-slate-900 shadow-lg px-3 py-2 min-w-[150px]">
      <Handle type="target" position={Position.Left} style={{ background: "#34d399" }} />
      <div className="text-[9px] font-bold uppercase tracking-wider text-emerald-300 mb-0.5">Decoded</div>
      <div className="text-xs font-mono text-emerald-200 truncate max-w-[150px]">{data.label}</div>
      <Handle type="source" position={Position.Right} style={{ background: "#34d399" }} />
    </div>
  );
}

function TechniqueNode({ data }) {
  const color = TACTIC_COLOR[data.tactic] || "#ef4444";
  return (
    <div className="rounded-md border shadow-lg px-2 py-1.5 min-w-[150px]"
      style={{ background: "#1e293b", borderColor: color }}>
      <Handle type="target" position={Position.Left} style={{ background: color }} />
      <div className="text-[9px] font-bold uppercase tracking-wider mb-0.5" style={{ color }}>
        {data.tactic}
      </div>
      <div className="text-[11px] font-bold text-white font-mono">{data.id}</div>
      <div className="text-[10px] text-slate-300 leading-tight">{data.name}</div>
    </div>
  );
}

const NODE_TYPES = { step: StepNode, input: InputNode, output: OutputNode, technique: TechniqueNode };

export default function AttackChainViewer({ input, output, trace = [], mitre = [] }) {
  const { nodes, edges } = useMemo(() => {
    const n = []; const e = [];
    const xStep = 210; const y0 = 200;

    // Input node
    n.push({
      id: "input", type: "input",
      position: { x: 0, y: y0 },
      data: { label: (input || "").slice(0, 20) + ((input || "").length > 20 ? "…" : "") },
    });

    // Step nodes chained
    let prev = "input";
    trace.forEach((step, i) => {
      const id = `step-${i}`;
      n.push({
        id, type: "step",
        position: { x: xStep * (i + 1), y: y0 },
        data: step,
      });
      e.push({ id: `e-${prev}-${id}`, source: prev, target: id, animated: true, style: { stroke: "#22d3ee" } });
      prev = id;
    });

    // Output node
    const outX = xStep * (trace.length + 1);
    n.push({
      id: "output", type: "output",
      position: { x: outX, y: y0 },
      data: { label: (output || "").slice(0, 30) + ((output || "").length > 30 ? "…" : "") },
    });
    e.push({ id: `e-${prev}-output`, source: prev, target: "output", animated: true, style: { stroke: "#34d399" } });

    // MITRE technique nodes hanging off the output
    mitre.forEach((m, i) => {
      const id = `t-${m.id}`;
      const yOffset = y0 + (i - (mitre.length - 1) / 2) * 90;
      n.push({
        id, type: "technique",
        position: { x: outX + 220, y: yOffset },
        data: m,
      });
      e.push({
        id: `e-output-${id}`, source: "output", target: id,
        style: { stroke: TACTIC_COLOR[m.tactic] || "#ef4444", strokeDasharray: "5 5" },
      });
    });
    return { nodes: n, edges: e };
  }, [input, output, trace, mitre]);

  if (trace.length === 0 && mitre.length === 0) {
    return (
      <div className="h-72 flex items-center justify-center text-xs text-slate-500 italic border border-dashed border-slate-800 rounded-md">
        Run auto-decode or analyze to see the attack chain visualized.
      </div>
    );
  }

  return (
    <div className="h-96 rounded-md border border-slate-800 bg-slate-950" data-testid="attack-chain-viewer">
      <ReactFlow
        nodes={nodes} edges={edges} nodeTypes={NODE_TYPES}
        fitView fitViewOptions={{ padding: 0.2, minZoom: 0.4, maxZoom: 1.2 }}
        proOptions={{ hideAttribution: true }}
        panOnDrag zoomOnScroll zoomOnPinch
      >
        <Background color="#334155" gap={20} size={1} />
        <MiniMap style={{ background: "#020617", border: "1px solid #1e293b" }} nodeColor={(n) =>
          n.type === "technique" ? (TACTIC_COLOR[n.data?.tactic] || "#ef4444")
          : n.type === "step" ? (CATEGORY_COLOR[n.data?.category] || "#94a3b8")
          : n.type === "input" ? "#22d3ee" : "#34d399"
        } maskColor="rgba(0,0,0,0.6)" />
        <Controls className="[&_button]:!bg-slate-800 [&_button]:!border-slate-700 [&_button]:!text-slate-200" />
      </ReactFlow>
    </div>
  );
}
