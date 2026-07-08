import { motion } from "framer-motion";
import { ArrowRight, Globe, ShieldCheck } from "lucide-react";
import LiveThreatMap from "./LiveThreatMap";

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
            className="mt-10"
          >
            <div className="flex items-center gap-3" data-testid="hero-socials">
              {/* WhatsApp */}
              <a
                href="#"
                aria-label="WhatsApp"
                data-testid="hero-social-whatsapp"
                className="w-11 h-11 rounded-full bg-white border border-slate-200 hover:border-[#25D366] hover:bg-[#25D366]/5 flex items-center justify-center transition-colors group"
              >
                <svg viewBox="0 0 24 24" className="w-5 h-5 text-slate-500 group-hover:text-[#25D366] transition-colors" fill="currentColor" aria-hidden="true">
                  <path d="M17.472 14.382c-.297-.149-1.758-.867-2.031-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/>
                </svg>
              </a>
              {/* Twitter / X */}
              <a
                href="#"
                aria-label="Twitter"
                data-testid="hero-social-twitter"
                className="w-11 h-11 rounded-full bg-white border border-slate-200 hover:border-slate-900 hover:bg-slate-900/5 flex items-center justify-center transition-colors group"
              >
                <svg viewBox="0 0 24 24" className="w-5 h-5 text-slate-500 group-hover:text-slate-900 transition-colors" fill="currentColor" aria-hidden="true">
                  <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/>
                </svg>
              </a>
              {/* LinkedIn */}
              <a
                href="#"
                aria-label="LinkedIn"
                data-testid="hero-social-linkedin"
                className="w-11 h-11 rounded-full bg-white border border-slate-200 hover:border-[#0A66C2] hover:bg-[#0A66C2]/5 flex items-center justify-center transition-colors group"
              >
                <svg viewBox="0 0 24 24" className="w-5 h-5 text-slate-500 group-hover:text-[#0A66C2] transition-colors" fill="currentColor" aria-hidden="true">
                  <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 01-2.063-2.065 2.063 2.063 0 112.063 2.065zm1.777 13.019H3.555V9h3.559v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0z"/>
                </svg>
              </a>
            </div>
            <a
              href="https://nivxmachines.com"
              data-testid="hero-website"
              className="mt-4 inline-flex items-center gap-2 text-sm font-semibold text-slate-500 hover:text-[#2E7DF5] transition-colors"
            >
              <Globe className="w-4 h-4" strokeWidth={2} />
              nivxmachines.com
            </a>
          </motion.div>
        </div>

        <motion.div
          initial={{ opacity: 0, scale: 0.97 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          className="relative"
        >
          <LiveThreatMap />
        </motion.div>
      </div>
    </section>
  );
}
