import { motion } from "framer-motion";
import { Phone, Mail, ArrowDown } from "lucide-react";

const line = {
  hidden: { y: "110%" },
  show: (i) => ({
    y: "0%",
    transition: { duration: 1, ease: [0.16, 1, 0.3, 1], delay: 0.2 + i * 0.12 },
  }),
};

const LINES = ["ENGINEERING", "DIGITAL", "IMMUNITY"];

export default function Hero() {
  return (
    <section
      id="home"
      data-testid="hero-section"
      className="relative min-h-screen flex flex-col justify-center overflow-hidden pt-28 pb-16"
    >
      <div className="absolute inset-0 hero-grid-bg" aria-hidden="true" />
      <div className="absolute -top-40 -right-40 w-[520px] h-[520px] rounded-full bg-[#00F0FF]/10 blur-[120px]" aria-hidden="true" />
      <div className="absolute bottom-0 left-1/4 w-[380px] h-[380px] rounded-full bg-[#FF0055]/5 blur-[120px]" aria-hidden="true" />

      <div className="relative mx-auto max-w-[1400px] w-full px-6">
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
          className="flex items-center gap-3 mb-8 font-mono-data text-[11px] uppercase tracking-[0.3em] text-[#00F0FF]"
        >
          <span className="w-2 h-2 rounded-full bg-[#00F0FF] pulse-dot" />
          Cybersecurity · Artificial Intelligence · Tech
        </motion.div>

        <h1 className="font-display font-black tracking-tighter leading-[0.92] text-white text-5xl sm:text-7xl lg:text-[8.5rem]">
          {LINES.map((t, i) => (
            <span key={t} className="block overflow-hidden">
              <motion.span
                custom={i}
                variants={line}
                initial="hidden"
                animate="show"
                className={`block ${i === 2 ? "text-[#00F0FF] text-glow" : ""}`}
              >
                {t}
              </motion.span>
            </span>
          ))}
        </h1>

        <div className="mt-10 grid lg:grid-cols-[1.2fr_1fr] gap-10 items-end">
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.9, duration: 0.8 }}
            className="max-w-xl text-[#A1A1A5] text-base sm:text-lg leading-relaxed"
          >
            NivX Machines defends the enterprise with AI-driven threat detection,
            zero-trust architecture, and real-time intelligence — turning raw signal
            into decisive defense.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 1.05, duration: 0.8 }}
            className="flex flex-col gap-3"
          >
            <a
              href="tel:9059565125"
              data-testid="hero-phone"
              className="glass flex items-center gap-4 px-5 py-4 hover:border-[#00F0FF]/50 transition-colors group"
            >
              <Phone className="w-5 h-5 text-[#00F0FF]" />
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-[#66666E]">Mobile</div>
                <div className="text-white font-medium group-hover:text-[#00F0FF] transition-colors">+91 90595 65125</div>
              </div>
            </a>
            <a
              href="mailto:info@nivxmachines.com"
              data-testid="hero-email"
              className="glass flex items-center gap-4 px-5 py-4 hover:border-[#00F0FF]/50 transition-colors group"
            >
              <Mail className="w-5 h-5 text-[#00F0FF]" />
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-[#66666E]">Email</div>
                <div className="text-white font-medium group-hover:text-[#00F0FF] transition-colors">info@nivxmachines.com</div>
              </div>
            </a>
          </motion.div>
        </div>
      </div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 1.4 }}
        className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2 text-[#66666E]"
      >
        <span className="font-mono-data text-[10px] uppercase tracking-widest">Scroll</span>
        <ArrowDown className="w-4 h-4 animate-bounce" />
      </motion.div>
    </section>
  );
}
