import { motion } from "framer-motion";
import { Phone, Mail } from "lucide-react";

export default function Contact() {
  return (
    <footer id="support" data-testid="support-section" className="relative pt-28 pb-12 border-t border-white/5">
      <div className="mx-auto max-w-[1400px] px-6">
        <div className="grid lg:grid-cols-2 gap-16 mb-24">
          <div>
            <div className="font-mono-data text-[11px] uppercase tracking-[0.3em] text-[#F5821F] mb-6">/ Support</div>
            <h2 className="font-display font-black tracking-tighter text-white text-4xl sm:text-5xl lg:text-6xl leading-[0.92]">
              Under attack?
              <br />
              <span className="text-[#F5821F] text-glow">Talk to us.</span>
            </h2>
            <p className="text-[#9AA6B8] mt-6 max-w-md text-lg leading-relaxed">
              Our team is on standby for incident response and consultation. Reach out
              directly — we answer fast.
            </p>
          </div>

          <div className="flex flex-col gap-4 justify-center">
            <motion.a
              href="tel:9059565125"
              initial={{ opacity: 0, x: 20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6 }}
              data-testid="support-phone"
              className="group glass flex items-center gap-5 p-6 hover:border-[#F5821F]/50 transition-colors"
            >
              <div className="w-12 h-12 flex items-center justify-center border border-[#F5821F]/30 group-hover:bg-[#F5821F] transition-colors">
                <Phone className="w-5 h-5 text-[#F5821F] group-hover:text-black transition-colors" />
              </div>
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-[#5A6B82]">Mobile</div>
                <div className="text-white text-xl font-medium">+91 90595 65125</div>
              </div>
            </motion.a>

            <motion.a
              href="mailto:info@nivxmachines.com"
              initial={{ opacity: 0, x: 20 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6, delay: 0.1 }}
              data-testid="support-email"
              className="group glass flex items-center gap-5 p-6 hover:border-[#F5821F]/50 transition-colors"
            >
              <div className="w-12 h-12 flex items-center justify-center border border-[#F5821F]/30 group-hover:bg-[#F5821F] transition-colors">
                <Mail className="w-5 h-5 text-[#F5821F] group-hover:text-black transition-colors" />
              </div>
              <div>
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-[#5A6B82]">Email</div>
                <div className="text-white text-xl font-medium">info@nivxmachines.com</div>
              </div>
            </motion.a>
          </div>
        </div>

        <div className="flex flex-col md:flex-row items-center justify-between gap-6 pt-8 border-t border-white/10">
          <div className="flex items-center gap-2">
            <img src="/nivx-logo.webp" alt="NivX Machines" className="h-9 w-auto object-contain" />
          </div>
          <p className="font-mono-data text-[11px] uppercase tracking-widest text-[#5A6B82]">
            © {new Date().getFullYear()} NivX Machines · Cybersecurity · AI · Tech
          </p>
        </div>
      </div>
    </footer>
  );
}
