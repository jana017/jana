import { motion } from "framer-motion";
import { Radar, BrainCircuit, Lock, Bug, ServerCog, ShieldCheck, ArrowRight } from "lucide-react";

const SERVICES = [
  { icon: Radar, title: "Managed Detection & Response", desc: "24/7 SOC monitoring with AI-triaged alerts and human-led threat hunting." },
  { icon: BrainCircuit, title: "AI Security Engineering", desc: "Custom ML models for anomaly detection, fraud, and behavioral analytics." },
  { icon: Lock, title: "Zero-Trust Architecture", desc: "Identity-first segmentation and least-privilege access design." },
  { icon: Bug, title: "Offensive Security", desc: "Red teaming, penetration testing, and adversary emulation." },
  { icon: ServerCog, title: "Cloud & Infra Hardening", desc: "CSPM, container security, and secure DevOps pipelines." },
  { icon: ShieldCheck, title: "Incident Response & Forensics", desc: "Rapid containment, root-cause forensics, and recovery orchestration." },
];

export default function Services() {
  return (
    <section id="services" data-testid="services-section" className="py-20 lg:py-28 bg-slate-50">
      <div className="mx-auto max-w-7xl px-6">
        <div className="max-w-2xl mb-14">
          <div className="text-xs font-bold uppercase tracking-[0.2em] text-blue-600 mb-3">Services</div>
          <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-slate-900">
            Full-spectrum defense
          </h2>
          <p className="mt-4 text-base text-slate-600 leading-relaxed">
            End-to-end cybersecurity, AI and technology services engineered for enterprise resilience.
          </p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {SERVICES.map((s, i) => (
            <motion.div
              key={s.title}
              initial={{ opacity: 0, y: 14 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: (i % 3) * 0.08 }}
              data-testid={`service-${i}`}
              className="group rounded-xl border border-slate-200 bg-white shadow-sm hover:shadow-md transition-shadow p-7"
            >
              <span className="w-11 h-11 rounded-lg bg-blue-50 flex items-center justify-center mb-5">
                <s.icon className="w-5 h-5 text-[#2E7DF5]" strokeWidth={1.6} />
              </span>
              <h3 className="font-heading text-lg font-semibold text-slate-900 mb-2">{s.title}</h3>
              <p className="text-sm text-slate-600 leading-relaxed mb-4">{s.desc}</p>
              <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-[#2E7DF5] opacity-0 group-hover:opacity-100 transition-opacity">
                Learn more <ArrowRight className="w-4 h-4" />
              </span>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
