import Marquee from "react-fast-marquee";

const ITEMS = [
  "REAL-TIME THREAT LANDSCAPE",
  "ZERO-TRUST ARCHITECTURE",
  "AI THREAT DETECTION",
  "INCIDENT RESPONSE",
  "MITRE ATT&CK MAPPING",
  "MANAGED DETECTION & RESPONSE",
];

export default function EditorialMarquee() {
  return (
    <div data-testid="marquee" className="py-8 border-y border-white/10 bg-[#0A0A0B] overflow-hidden">
      <Marquee speed={35} gradient={false}>
        {ITEMS.concat(ITEMS).map((t, i) => (
          <span
            key={i}
            className="mx-8 font-mono-data uppercase tracking-[0.25em] text-2xl md:text-4xl text-white/70 flex items-center gap-8"
          >
            {t}
            <span className="text-[#00F0FF]">✦</span>
          </span>
        ))}
      </Marquee>
    </div>
  );
}
