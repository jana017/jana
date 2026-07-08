import { ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import { vtVerdict, abuseVerdict } from "@/lib/iocUtils";

const TONE = {
  bad: "bg-red-50 border-red-200 text-red-700",
  warn: "bg-orange-50 border-orange-200 text-orange-700",
  good: "bg-green-50 border-green-200 text-green-700",
  muted: "bg-slate-50 border-slate-200 text-slate-500",
};

const Icon = ({ tone }) => {
  if (tone === "bad") return <ShieldAlert className="w-3.5 h-3.5" />;
  if (tone === "good") return <ShieldCheck className="w-3.5 h-3.5" />;
  return <ShieldQuestion className="w-3.5 h-3.5" />;
};

// Compact inline reputation badges for VT + AbuseIPDB. Renders nothing if no keys/data.
export default function ReputationBadges({ reputation, size = "sm" }) {
  if (!reputation) return null;
  const vt = vtVerdict(reputation.vt);
  const ab = abuseVerdict(reputation.abuseipdb);
  if (!vt && !ab) return null;
  const pad = size === "sm" ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-1 text-xs";
  return (
    <div className="flex flex-wrap items-center gap-1.5" data-testid="ioc-reputation">
      {vt && (
        <span data-testid="ioc-rep-vt" className={`inline-flex items-center gap-1 font-semibold rounded-md border ${pad} ${TONE[vt.tone]}`}>
          <Icon tone={vt.tone} /> VirusTotal {vt.text}
        </span>
      )}
      {ab && (
        <span data-testid="ioc-rep-abuseipdb" className={`inline-flex items-center gap-1 font-semibold rounded-md border ${pad} ${TONE[ab.tone]}`}>
          <Icon tone={ab.tone} /> AbuseIPDB {ab.text}
        </span>
      )}
    </div>
  );
}
