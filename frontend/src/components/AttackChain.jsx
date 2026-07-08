import { ChevronRight } from "lucide-react";

const MITRE = {
  "reconnaissance": "TA0043",
  "resource development": "TA0042",
  "initial access": "TA0001",
  "execution": "TA0002",
  "persistence": "TA0003",
  "privilege escalation": "TA0004",
  "defense evasion": "TA0005",
  "credential access": "TA0006",
  "discovery": "TA0007",
  "lateral movement": "TA0008",
  "collection": "TA0009",
  "command & control": "TA0011",
  "command and control": "TA0011",
  "exfiltration": "TA0010",
  "impact": "TA0040",
};

export function mitreId(step) {
  return MITRE[step.trim().toLowerCase()] || "TAxxxx";
}

export default function AttackChain({ steps = [], showIds = false }) {
  if (!steps.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5" data-testid="attack-chain">
      {steps.map((s, i) => {
        const last = i === steps.length - 1;
        return (
          <div key={i} className="flex items-center gap-1.5">
            <span
              className={`rounded-md border px-2.5 py-1.5 flex flex-col leading-tight ${
                last ? "border-red-200 bg-red-50 text-red-700" : "border-blue-200 bg-blue-50 text-blue-700"
              }`}
            >
              {showIds && <span className="font-mono-data text-[9px] tracking-wider text-slate-400">{mitreId(s)}</span>}
              <span className="text-[11px] font-semibold uppercase tracking-wide">{s}</span>
            </span>
            {!last && <ChevronRight className="w-3.5 h-3.5 text-slate-300 shrink-0" />}
          </div>
        );
      })}
    </div>
  );
}
