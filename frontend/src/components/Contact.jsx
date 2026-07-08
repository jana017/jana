import { useState } from "react";
import { motion } from "framer-motion";
import { toast } from "sonner";
import { Phone, Mail, Send, CheckCircle2 } from "lucide-react";
import { api, formatApiErrorDetail } from "@/lib/api";

const EMPTY = { name: "", email: "", company: "", phone: "", company_size: "", interest: "Managed Detection & Response", message: "" };

const field = "w-full bg-white border border-slate-300 focus:border-[#2E7DF5] focus:ring-2 focus:ring-blue-100 outline-none px-3.5 py-2.5 text-sm text-slate-800 placeholder:text-slate-400 rounded-md transition-shadow";

export default function Contact() {
  const [form, setForm] = useState(EMPTY);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await api.post("/leads", form);
      setDone(true);
      setForm(EMPTY);
      toast.success("Request received — our team will reach out shortly.");
    } catch (err) {
      toast.error(formatApiErrorDetail(err.response?.data?.detail) || "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

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
              Our team is on standby for incident response and consultation. Reach out
              directly, or request a free security assessment.
            </p>

            <div className="mt-8 grid sm:grid-cols-2 gap-4">
              <a href="tel:9059565125" data-testid="support-phone" className="group rounded-xl border border-slate-700 bg-slate-800/40 hover:border-[#F5821F]/50 p-5 transition-colors">
                <span className="w-10 h-10 rounded-lg bg-orange-500/10 flex items-center justify-center mb-3">
                  <Phone className="w-5 h-5 text-[#F5821F]" strokeWidth={1.8} />
                </span>
                <div className="text-xs text-slate-400">Mobile</div>
                <div className="text-base font-semibold text-white group-hover:text-[#F5821F] transition-colors">+91 90595 65125</div>
              </a>
              <a href="mailto:info@nivxmachines.com" data-testid="support-email" className="group rounded-xl border border-slate-700 bg-slate-800/40 hover:border-[#2E7DF5]/50 p-5 transition-colors">
                <span className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center mb-3">
                  <Mail className="w-5 h-5 text-[#2E7DF5]" strokeWidth={1.8} />
                </span>
                <div className="text-xs text-slate-400">Email</div>
                <div className="text-base font-semibold text-white group-hover:text-[#2E7DF5] transition-colors break-all">info@nivxmachines.com</div>
              </a>
            </div>
          </div>

          <motion.div
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="rounded-2xl bg-white shadow-xl p-7 lg:p-8"
          >
            {done ? (
              <div data-testid="lead-success" className="flex flex-col items-center text-center py-10">
                <CheckCircle2 className="w-12 h-12 text-green-500 mb-4" strokeWidth={1.6} />
                <h3 className="font-heading text-lg font-semibold text-slate-900">Request received</h3>
                <p className="text-sm text-slate-500 mt-2 max-w-xs">Thanks — a NivX security specialist will contact you within one business day.</p>
                <button onClick={() => setDone(false)} className="mt-6 text-sm font-semibold text-[#2E7DF5]">Submit another request</button>
              </div>
            ) : (
              <form onSubmit={submit} data-testid="lead-form" className="space-y-3.5">
                <div>
                  <h3 className="font-heading text-lg font-semibold text-slate-900">Request a security assessment</h3>
                  <p className="text-sm text-slate-500 mt-1">Free, no-obligation review of your security posture.</p>
                </div>
                <div className="grid sm:grid-cols-2 gap-3">
                  <input data-testid="lead-name" required placeholder="Full name" value={form.name} onChange={set("name")} className={field} />
                  <input data-testid="lead-email" required type="email" placeholder="Work email" value={form.email} onChange={set("email")} className={field} />
                </div>
                <div className="grid sm:grid-cols-2 gap-3">
                  <input data-testid="lead-company" placeholder="Company" value={form.company} onChange={set("company")} className={field} />
                  <input data-testid="lead-phone" placeholder="Phone" value={form.phone} onChange={set("phone")} className={field} />
                </div>
                <div className="grid sm:grid-cols-2 gap-3">
                  <select data-testid="lead-size" value={form.company_size} onChange={set("company_size")} className={field}>
                    <option value="">Company size</option>
                    <option>1–50</option>
                    <option>51–200</option>
                    <option>201–1000</option>
                    <option>1000+</option>
                  </select>
                  <select data-testid="lead-interest" value={form.interest} onChange={set("interest")} className={field}>
                    <option>Managed Detection & Response</option>
                    <option>AI Security Engineering</option>
                    <option>Zero-Trust Architecture</option>
                    <option>Offensive Security</option>
                    <option>Incident Response</option>
                  </select>
                </div>
                <textarea data-testid="lead-message" placeholder="Tell us about your environment (optional)" value={form.message} onChange={set("message")} rows={3} className={field} />
                <button data-testid="lead-submit" disabled={loading} className="w-full inline-flex items-center justify-center gap-2 bg-[#F5821F] hover:bg-[#EA580C] text-white text-sm font-semibold py-3 rounded-md transition-colors disabled:opacity-60">
                  <Send className="w-4 h-4" /> {loading ? "Sending…" : "Request assessment"}
                </button>
              </form>
            )}
          </motion.div>
        </div>

        <div className="mt-16 pt-8 border-t border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4">
          <img src="/nivx-logo-transparent.png" alt="NivX Machines" className="h-8 w-auto object-contain" />
          <p className="text-sm text-slate-500">© {new Date().getFullYear()} NivX Machines · Cybersecurity · AI · Tech</p>
        </div>
      </div>
    </footer>
  );
}
