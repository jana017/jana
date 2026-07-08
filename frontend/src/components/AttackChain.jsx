import { ChevronRight } from "lucide-react";

// MITRE ATT&CK Enterprise tactic IDs
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

export default function AttackChain({ steps = [], compact = false, showIds = false }) {
  if (!steps.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5" data-testid="attack-chain">
      {steps.map((s, i) => (
        <div key={i} className="flex items-center gap-1.5">
          <span
            className={`font-mono-data uppercase tracking-wider border px-2 py-1 flex flex-col leading-tight ${
              compact ? "text-[9px]" : "text-[10px]"
            } ${
              i === steps.length - 1
                ? "text-[#FF3B5C] border-[#FF3B5C]/50 bg-[#FF3B5C]/5"
                : "text-[#F5821F] border-[#F5821F]/30"
            }`}
          >
            {showIds && <span className="text-[#5A6B82] text-[8px] tracking-widest">{mitreId(s)}</span>}
            {s}
          </span>
          {i < steps.length - 1 && <ChevronRight className="w-3 h-3 text-[#5A6B82] shrink-0" />}
        </div>
      ))}
    </div>
  );
}
