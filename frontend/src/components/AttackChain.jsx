import { ChevronRight } from "lucide-react";

const MITRE = {
  "reconnaissance": { ta: "TA0043", tech: "T1595", tname: "Active Scanning" },
  "resource development": { ta: "TA0042", tech: "T1583", tname: "Acquire Infrastructure" },
  "initial access": { ta: "TA0001", tech: "T1566", tname: "Phishing" },
  "execution": { ta: "TA0002", tech: "T1059", tname: "Command & Scripting" },
  "persistence": { ta: "TA0003", tech: "T1547", tname: "Boot/Logon Autostart" },
  "privilege escalation": { ta: "TA0004", tech: "T1055", tname: "Process Injection" },
  "defense evasion": { ta: "TA0005", tech: "T1070", tname: "Indicator Removal" },
  "credential access": { ta: "TA0006", tech: "T1003", tname: "OS Credential Dumping" },
  "discovery": { ta: "TA0007", tech: "T1087", tname: "Account Discovery" },
  "lateral movement": { ta: "TA0008", tech: "T1021", tname: "Remote Services" },
  "collection": { ta: "TA0009", tech: "T1005", tname: "Data from Local System" },
  "command & control": { ta: "TA0011", tech: "T1071", tname: "App Layer Protocol" },
  "command and control": { ta: "TA0011", tech: "T1071", tname: "App Layer Protocol" },
  "exfiltration": { ta: "TA0010", tech: "T1041", tname: "Exfil Over C2" },
  "impact": { ta: "TA0040", tech: "T1486", tname: "Data Encrypted for Impact" },
};

export function mitreInfo(step) {
  return MITRE[step.trim().toLowerCase()] || { ta: "TAxxxx", tech: "Txxxx", tname: "Technique" };
}

export default function AttackChain({ steps = [], showIds = false }) {
  if (!steps.length) return null;
  return (
    <div className="flex flex-wrap items-stretch gap-1.5" data-testid="attack-chain">
      {steps.map((s, i) => {
        const last = i === steps.length - 1;
        const info = mitreInfo(s);
        return (
          <div key={i} className="flex items-center gap-1.5">
            <span
              className={`rounded-md border px-2.5 py-1.5 flex flex-col leading-tight ${
                last ? "border-red-200 bg-red-50 text-red-700" : "border-blue-200 bg-blue-50 text-blue-700"
              }`}
            >
              {showIds && <span className="font-mono-data text-[9px] tracking-wider text-slate-400">{info.ta}</span>}
              <span className="text-[11px] font-semibold uppercase tracking-wide">{s}</span>
              {showIds && (
                <span className="font-mono-data text-[9px] tracking-wide text-slate-400 mt-0.5">
                  {info.tech} · {info.tname}
                </span>
              )}
            </span>
            {!last && <ChevronRight className="w-3.5 h-3.5 text-slate-300 shrink-0" />}
          </div>
        );
      })}
    </div>
  );
}
