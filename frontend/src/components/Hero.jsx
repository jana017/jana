import { motion } from "framer-motion";
import { Phone, Mail, ShieldCheck, ArrowRight } from "lucide-react";

const fade = {
  hidden: { opacity: 0, y: 12 },
  show: (i) => ({ opacity: 1, y: 0, transition: { duration: 0.6, delay: i * 0.1, ease: [0.16, 1, 0.3, 1] } }),
};

export default function Hero() {
  return (
    <section id="home" data-testid="hero-section" className="relative pt-28 pb-20 lg:pt-36 lg:pb-28 overflow-hidden">
      <div className="absolute inset-0 dot-grid-light opacity-60" aria-hidden="true" />
      <div className="absolute top-0 right-0 w-1/2 h-full bg-gradient-to-l from-blue-50/70 to-transparent" aria-hidden="true" />

      <div className="relative mx-auto max-w-7xl px-6 grid lg:grid-cols-[1.05fr_0.95fr] gap-12 lg:gap-16 items-center">
        <div>
          <motion.div
            custom={0}
            variants={fade}
            initial="hidden"
            animate="show"
            className="inline-flex items-center gap-2 bg-blue-50 border border-blue-100 text-blue-700 rounded-full px-3 py-1 text-xs font-semibold mb-6"
          >
            <ShieldCheck className="w-4 h-4" strokeWidth={2} />
            Cybersecurity · Artificial Intelligence · Tech
          </motion.div>

          <motion.h1
            custom={1}
            variants={fade}
            initial="hidden"
            animate="show"
            className="font-heading text-3xl md:text-4xl lg:text-5xl font-bold tracking-tight text-slate-900 leading-[1.1]"
          >
            Engineering digital immunity for the modern enterprise
          </motion.h1>

          <motion.p
            custom={2}
            variants={fade}
            initial="hidden"
            animate="show"
            className="mt-5 text-base md:text-lg text-slate-600 leading-relaxed max-w-xl"
          >
            NivX Machines defends your business with AI-driven threat detection,
            zero-trust architecture, and real-time intelligence — turning raw
            signal into decisive defense.
          </motion.p>

          <motion.div
            custom={3}
            variants={fade}
            initial="hidden"
            animate="show"
            className="mt-8 flex flex-wrap items-center gap-3"
          >
            <a
              href="#threats"
              data-testid="hero-primary-cta"
              onClick={(e) => { e.preventDefault(); document.getElementById("threats")?.scrollIntoView({ behavior: "smooth" }); }}
              className="inline-flex items-center gap-2 bg-[#2E7DF5] hover:bg-[#2563EB] text-white text-sm font-semibold px-5 py-3 rounded-md transition-colors"
            >
              View Threat Reports <ArrowRight className="w-4 h-4" />
            </a>
            <a
              href="#services"
              onClick={(e) => { e.preventDefault(); document.getElementById("services")?.scrollIntoView({ behavior: "smooth" }); }}
              className="inline-flex items-center gap-2 border border-slate-300 hover:bg-slate-50 text-slate-700 text-sm font-semibold px-5 py-3 rounded-md transition-colors"
            >
              Explore Services
            </a>
          </motion.div>

          <motion.div
            custom={4}
            variants={fade}
            initial="hidden"
            animate="show"
            className="mt-10 flex flex-wrap gap-6"
          >
            <a href="tel:9059565125" data-testid="hero-phone" className="flex items-center gap-3 group">
              <span className="w-10 h-10 rounded-lg bg-orange-50 border border-orange-100 flex items-center justify-center">
                <Phone className="w-4 h-4 text-[#F5821F]" strokeWidth={2} />
              </span>
              <span>
                <span className="block text-xs text-slate-500">Mobile</span>
                <span className="block text-sm font-semibold text-slate-900 group-hover:text-[#2E7DF5] transition-colors">+91 90595 65125</span>
              </span>
            </a>
            <a href="mailto:info@nivxmachines.com" data-testid="hero-email" className="flex items-center gap-3 group">
              <span className="w-10 h-10 rounded-lg bg-blue-50 border border-blue-100 flex items-center justify-center">
                <Mail className="w-4 h-4 text-[#2E7DF5]" strokeWidth={2} />
              </span>
              <span>
                <span className="block text-xs text-slate-500">Email</span>
                <span className="block text-sm font-semibold text-slate-900 group-hover:text-[#2E7DF5] transition-colors">info@nivxmachines.com</span>
              </span>
            </a>
          </motion.div>
        </div>

        <motion.div
          initial={{ opacity: 0, scale: 0.97 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          className="relative"
        >
          <div className="relative rounded-2xl overflow-hidden border border-slate-200 shadow-xl">
            <img
              src="https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=1200&q=80"
              alt="Global real-time threat network"
              className="w-full h-[420px] object-cover"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-[#0A1220]/50 to-transparent" />
          </div>
          <div className="absolute -bottom-5 -left-5 bg-white rounded-xl border border-slate-200 shadow-lg p-4 hidden sm:block">
            <div className="flex items-center gap-3">
              <span className="w-2.5 h-2.5 rounded-full bg-green-500 pulse-dot" />
              <div>
                <div className="text-xs text-slate-500">Threat monitoring</div>
                <div className="text-sm font-semibold text-slate-900">Active · 24/7 SOC</div>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
