import { ChevronRight } from "lucide-react";

export default function AttackChain({ steps = [], compact = false }) {
  if (!steps.length) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5" data-testid="attack-chain">
      {steps.map((s, i) => (
        <div key={i} className="flex items-center gap-1.5">
          <span
            className={`font-mono-data uppercase tracking-wider border px-2 py-1 ${
              compact ? "text-[9px]" : "text-[10px]"
            } ${
              i === steps.length - 1
                ? "text-[#FF3B5C] border-[#FF3B5C]/50 bg-[#FF3B5C]/5"
                : "text-[#F5821F] border-[#F5821F]/30"
            }`}
          >
            {s}
          </span>
          {i < steps.length - 1 && <ChevronRight className="w-3 h-3 text-[#5A6B82]" />}
        </div>
      ))}
    </div>
  );
}
