import { motion } from "framer-motion";
import { Phone, Mail, ArrowRight } from "lucide-react";

export default function Contact() {
  return (
    <footer id="support" data-testid="support-section" className="bg-[#0A1220]">
      <div className="mx-auto max-w-7xl px-6 py-20 lg:py-24">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-start">
          <div>
            <div className="text-xs font-bold uppercase tracking-[0.2em] text-[#F5821F] mb-3">Support</div>
            <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-white">
              Under attack? Talk to us.
            </h2>
            <p className="mt-4 text-base text-slate-400 leading-relaxed max-w-md">
              Our team is on standby for incident response and consultation.
              Reach out directly — we answer fast.
            </p>
          </div>

          <div className="grid sm:grid-cols-2 gap-4">
            <motion.a
              href="tel:9059565125"
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5 }}
              data-testid="support-phone"
              className="group rounded-xl border border-slate-700 bg-slate-800/40 hover:border-[#F5821F]/50 p-6 transition-colors"
            >
              <span className="w-10 h-10 rounded-lg bg-orange-500/10 flex items-center justify-center mb-4">
                <Phone className="w-5 h-5 text-[#F5821F]" strokeWidth={1.8} />
              </span>
              <div className="text-xs text-slate-400">Mobile</div>
              <div className="text-lg font-semibold text-white group-hover:text-[#F5821F] transition-colors">+91 90595 65125</div>
            </motion.a>

            <motion.a
              href="mailto:info@nivxmachines.com"
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: 0.1 }}
              data-testid="support-email"
              className="group rounded-xl border border-slate-700 bg-slate-800/40 hover:border-[#2E7DF5]/50 p-6 transition-colors"
            >
              <span className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center mb-4">
                <Mail className="w-5 h-5 text-[#2E7DF5]" strokeWidth={1.8} />
              </span>
              <div className="text-xs text-slate-400">Email</div>
              <div className="text-lg font-semibold text-white group-hover:text-[#2E7DF5] transition-colors break-all">info@nivxmachines.com</div>
            </motion.a>
          </div>
        </div>

        <div className="mt-16 pt-8 border-t border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4">
          <img src="/nivx-logo.webp" alt="NivX Machines" className="h-9 w-auto object-contain rounded-md" />
          <p className="text-sm text-slate-500">© {new Date().getFullYear()} NivX Machines · Cybersecurity · AI · Tech</p>
        </div>
      </div>
    </footer>
  );
}
