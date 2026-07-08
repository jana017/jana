import { Terminal, AlertTriangle } from "lucide-react";

function flatten(tree) {
  const rows = [];
  const stack = [{ node: tree, depth: 0 }];
  while (stack.length) {
    const { node, depth } = stack.shift();
    if (!node) continue;
    rows.push({ node, depth });
    const kids = node.children || [];
    for (let i = kids.length - 1; i >= 0; i--) {
      stack.unshift({ node: kids[i], depth: depth + 1 });
    }
  }
  return rows;
}

export default function ProcessTree({ tree }) {
  if (!tree) return null;
  const rows = flatten(tree);
  return (
    <div data-testid="process-tree" className="bg-black/40 border border-white/10 p-4">
      {rows.map(({ node, depth }, idx) => (
        <div key={idx} style={{ marginLeft: depth * 18 }}>
          <div
            className={`flex items-start gap-3 py-2 pl-3 border-l-2 ${
              node.malicious ? "border-[#FF3B5C]" : "border-white/15"
            }`}
          >
            {node.malicious ? (
              <AlertTriangle className="w-4 h-4 text-[#FF3B5C] mt-0.5 shrink-0" />
            ) : (
              <Terminal className="w-4 h-4 text-[#F5821F] mt-0.5 shrink-0" />
            )}
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`font-mono-data text-sm ${node.malicious ? "text-[#FF3B5C]" : "text-white"}`}>
                  {node.name}
                </span>
                {node.pid && <span className="font-mono-data text-[10px] text-[#5A6B82]">PID {node.pid}</span>}
              </div>
              {node.cmd && (
                <code className="font-mono-data text-[11px] text-[#9AA6B8] block mt-1 break-all">$ {node.cmd}</code>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
