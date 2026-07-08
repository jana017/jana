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
                ? "text-[#FF0055] border-[#FF0055]/50 bg-[#FF0055]/5"
                : "text-[#00F0FF] border-[#00F0FF]/30"
            }`}
          >
            {s}
          </span>
          {i < steps.length - 1 && <ChevronRight className="w-3 h-3 text-[#66666E]" />}
        </div>
      ))}
    </div>
  );
}
