import { motion } from "framer-motion";
import { ArrowUpRight, MapPin } from "lucide-react";

const JOBS = [
  { title: "Senior Threat Intelligence Analyst", type: "Full-time", loc: "Hyderabad / Remote", team: "Research" },
  { title: "AI/ML Security Engineer", type: "Full-time", loc: "Remote", team: "Engineering" },
  { title: "SOC Analyst (Tier 2)", type: "Full-time", loc: "Hyderabad", team: "Operations" },
  { title: "Offensive Security Consultant", type: "Contract", loc: "Remote", team: "Red Team" },
  { title: "Incident Response Lead", type: "Full-time", loc: "Hyderabad", team: "IR" },
];

export default function Careers() {
  return (
    <section id="careers" data-testid="careers-section" className="relative py-28 border-t border-white/5 bg-[#0A0A0B]">
      <div className="mx-auto max-w-[1400px] px-6">
        <div className="max-w-3xl mb-16">
          <div className="font-mono-data text-[11px] uppercase tracking-[0.3em] text-[#00F0FF] mb-6">/ Careers</div>
          <h2 className="font-display font-black tracking-tighter text-white text-4xl sm:text-5xl lg:text-6xl leading-[0.95]">
            Defend the frontier.
          </h2>
          <p className="text-[#A1A1A5] mt-6 text-lg">Open roles — apply directly via email with your résumé.</p>
        </div>

        <div className="space-y-px">
          {JOBS.map((j, i) => {
            const mailto = `mailto:info@nivxmachines.com?subject=${encodeURIComponent(
              `Application: ${j.title}`
            )}&body=${encodeURIComponent(`Hi NivX team,\n\nI'd like to apply for the ${j.title} role.\n\n`)}`;
            return (
              <motion.a
                key={j.title}
                href={mailto}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: i * 0.05 }}
                data-testid={`career-${i}`}
                className="group grid grid-cols-1 md:grid-cols-[1fr_auto_auto] gap-4 md:items-center py-7 border-t border-white/10 hover:bg-white/[0.02] px-2 transition-colors"
              >
                <div>
                  <div className="font-mono-data text-[10px] uppercase tracking-widest text-[#66666E] mb-1">{j.team}</div>
                  <h3 className="font-display font-semibold text-xl md:text-2xl text-white group-hover:text-[#00F0FF] transition-colors tracking-tight">
                    {j.title}
                  </h3>
                </div>
                <div className="flex items-center gap-4 font-mono-data text-[11px] uppercase tracking-widest text-[#A1A1A5]">
                  <span className="flex items-center gap-1.5"><MapPin className="w-3.5 h-3.5" />{j.loc}</span>
                  <span className="text-[#66666E]">{j.type}</span>
                </div>
                <span className="inline-flex items-center gap-1.5 font-mono-data text-[11px] uppercase tracking-widest text-[#00F0FF]">
                  Apply <ArrowUpRight className="w-4 h-4 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                </span>
              </motion.a>
            );
          })}
        </div>
      </div>
    </section>
  );
}
