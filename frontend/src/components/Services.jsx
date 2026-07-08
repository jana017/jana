import { motion } from "framer-motion";
import { ShieldCheck, BrainCircuit, Radar, Lock, ServerCog, Bug } from "lucide-react";

const SERVICES = [
  { icon: Radar, title: "Managed Detection & Response", desc: "24/7 SOC monitoring with AI-triaged alerts and human-led threat hunting.", span: "md:col-span-7", big: true },
  { icon: BrainCircuit, title: "AI Security Engineering", desc: "Custom ML models for anomaly detection, fraud, and behavioral analytics.", span: "md:col-span-5" },
  { icon: Lock, title: "Zero-Trust Architecture", desc: "Identity-first segmentation and least-privilege design.", span: "md:col-span-4" },
  { icon: Bug, title: "Offensive Security", desc: "Red teaming, pentesting, and adversary emulation.", span: "md:col-span-4" },
  { icon: ServerCog, title: "Cloud & Infra Hardening", desc: "CSPM, container security, and secure DevOps pipelines.", span: "md:col-span-4" },
  { icon: ShieldCheck, title: "Incident Response & Forensics", desc: "Rapid containment, root-cause forensics, and recovery orchestration.", span: "md:col-span-12", big: true },
];

export default function Services() {
  return (
    <section id="services" data-testid="services-section" className="relative py-28 border-t border-white/5">
      <div className="mx-auto max-w-[1400px] px-6">
        <div className="max-w-3xl mb-16">
          <div className="font-mono-data text-[11px] uppercase tracking-[0.3em] text-[#F5821F] mb-6">/ Services</div>
          <h2 className="font-display font-black tracking-tighter text-white text-4xl sm:text-5xl lg:text-6xl leading-[0.95]">
            Full-spectrum defense.
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
          {SERVICES.map((s, i) => (
            <motion.div
              key={s.title}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6, delay: (i % 3) * 0.08 }}
              data-testid={`service-${i}`}
              className={`group glass p-8 hover:-translate-y-2 hover:border-[#F5821F]/40 transition-[transform,border-color] duration-400 ${s.span} ${
                s.big ? "min-h-[220px] flex flex-col justify-between" : ""
              }`}
            >
              <s.icon className="w-8 h-8 text-[#F5821F] mb-8" strokeWidth={1.4} />
              <div>
                <h3 className={`font-display font-semibold text-white mb-3 tracking-tight ${s.big ? "text-2xl md:text-3xl" : "text-xl"}`}>
                  {s.title}
                </h3>
                <p className="text-[#9AA6B8] leading-relaxed">{s.desc}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
