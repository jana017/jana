import { Terminal, AlertTriangle } from "lucide-react";

function flatten(tree) {
  const rows = [];
  const stack = [{ node: tree, depth: 0 }];
  while (stack.length) {
    const { node, depth } = stack.shift();
    if (!node) continue;
    rows.push({ node, depth });
    const kids = node.children || [];
    for (let i = kids.length - 1; i >= 0; i--) stack.unshift({ node: kids[i], depth: depth + 1 });
  }
  return rows;
}

export default function ProcessTree({ tree }) {
  if (!tree) return null;
  const rows = flatten(tree);
  return (
    <div data-testid="process-tree" className="rounded-lg bg-slate-50 border border-slate-200 p-4">
      {rows.map(({ node, depth }, idx) => (
        <div key={idx} style={{ marginLeft: depth * 18 }}>
          <div className={`flex items-start gap-2.5 py-1.5 pl-3 border-l-2 ${node.malicious ? "border-red-400" : "border-slate-300"}`}>
            {node.malicious ? (
              <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5 shrink-0" />
            ) : (
              <Terminal className="w-4 h-4 text-slate-400 mt-0.5 shrink-0" />
            )}
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`font-mono-data text-sm font-medium ${node.malicious ? "text-red-600" : "text-slate-800"}`}>{node.name}</span>
                {node.pid && <span className="font-mono-data text-[10px] text-slate-400">PID {node.pid}</span>}
              </div>
              {node.cmd && <code className="font-mono-data text-[11px] text-slate-500 block mt-0.5 break-all">$ {node.cmd}</code>}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
