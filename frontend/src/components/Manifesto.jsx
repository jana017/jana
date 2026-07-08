import { motion } from "framer-motion";
import { ShieldCheck, Cpu, Zap } from "lucide-react";

const PILLARS = [
  { n: "01", icon: ShieldCheck, title: "Assume breach", body: "We architect from the premise that adversaries are already inside — zero-trust segmentation and least-privilege access contain the blast radius." },
  { n: "02", icon: Cpu, title: "Weaponize intelligence", body: "Our AI models ingest telemetry at machine speed, correlating signals across endpoints, identity and network to surface what humans miss." },
  { n: "03", icon: Zap, title: "Respond at machine speed", body: "Automated playbooks isolate, remediate and recover — collapsing dwell time from weeks to minutes." },
];

const fade = {
  hidden: { opacity: 0, y: 14 },
  show: { opacity: 1, y: 0, transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] } },
};

export default function About() {
  return (
    <section id="about" data-testid="about-section" className="py-20 lg:py-28 bg-white">
      <div className="mx-auto max-w-7xl px-6">
        <motion.div initial="hidden" whileInView="show" viewport={{ once: true }} variants={fade} className="max-w-2xl mb-14">
          <div className="text-xs font-bold uppercase tracking-[0.2em] text-blue-600 mb-3">About Us</div>
          <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-slate-900">
            Defense is a discipline, not a product
          </h2>
          <p className="mt-4 text-base text-slate-600 leading-relaxed">
            NivX Machines is a cybersecurity, AI and technology firm helping enterprises
            build resilient, intelligent defenses. Three principles guide everything we build.
          </p>
        </motion.div>

        <div className="grid md:grid-cols-3 gap-6">
          {PILLARS.map((p) => (
            <motion.div
              key={p.n}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true }}
              variants={fade}
              data-testid={`about-pillar-${p.n}`}
              className="rounded-xl border border-slate-200 bg-white shadow-sm hover:shadow-md transition-shadow p-8"
            >
              <div className="flex items-center justify-between mb-6">
                <span className="w-11 h-11 rounded-lg bg-blue-50 flex items-center justify-center">
                  <p.icon className="w-5 h-5 text-[#2E7DF5]" strokeWidth={1.6} />
                </span>
                <span className="font-heading text-3xl font-bold text-slate-100">{p.n}</span>
              </div>
              <h3 className="font-heading text-lg font-semibold text-slate-900 mb-2">{p.title}</h3>
              <p className="text-sm text-slate-600 leading-relaxed">{p.body}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
