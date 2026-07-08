import { motion } from "framer-motion";
import { MapPin, ArrowUpRight } from "lucide-react";

const JOBS = [
  { title: "Senior Threat Intelligence Analyst", type: "Full-time", loc: "Hyderabad / Remote", team: "Research" },
  { title: "AI/ML Security Engineer", type: "Full-time", loc: "Remote", team: "Engineering" },
  { title: "SOC Analyst (Tier 2)", type: "Full-time", loc: "Hyderabad", team: "Operations" },
  { title: "Offensive Security Consultant", type: "Contract", loc: "Remote", team: "Red Team" },
  { title: "Incident Response Lead", type: "Full-time", loc: "Hyderabad", team: "IR" },
];

export default function Careers() {
  return (
    <section id="careers" data-testid="careers-section" className="py-20 lg:py-28 bg-slate-50">
      <div className="mx-auto max-w-7xl px-6">
        <div className="max-w-2xl mb-12">
          <div className="text-xs font-bold uppercase tracking-[0.2em] text-blue-600 mb-3">Careers</div>
          <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-slate-900">
            Defend the frontier with us
          </h2>
          <p className="mt-4 text-base text-slate-600">Open roles — apply directly via email with your résumé.</p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white shadow-sm divide-y divide-slate-100 overflow-hidden">
          {JOBS.map((j, i) => {
            const mailto = `mailto:info@nivxmachines.com?subject=${encodeURIComponent(`Application: ${j.title}`)}&body=${encodeURIComponent(`Hi NivX team,\n\nI'd like to apply for the ${j.title} role.\n\n`)}`;
            return (
              <motion.a
                key={j.title}
                href={mailto}
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: i * 0.05 }}
                data-testid={`career-${i}`}
                className="group flex flex-col md:flex-row md:items-center justify-between gap-3 p-6 hover:bg-slate-50 transition-colors"
              >
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wider text-blue-600 mb-1">{j.team}</div>
                  <h3 className="font-heading text-lg font-semibold text-slate-900 group-hover:text-[#2E7DF5] transition-colors">{j.title}</h3>
                </div>
                <div className="flex items-center gap-5">
                  <span className="flex items-center gap-1.5 text-sm text-slate-500"><MapPin className="w-4 h-4" />{j.loc}</span>
                  <span className="text-sm text-slate-400">{j.type}</span>
                  <span className="inline-flex items-center gap-1 text-sm font-semibold text-[#2E7DF5]">
                    Apply <ArrowUpRight className="w-4 h-4 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                  </span>
                </div>
              </motion.a>
            );
          })}
        </div>
      </div>
    </section>
  );
}
