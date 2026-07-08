import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { api } from "@/lib/api";
import AttackChain from "@/components/AttackChain";
import ProcessTree from "@/components/ProcessTree";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

const SEV = {
  critical: "text-[#FF0055] border-[#FF0055]/50 bg-[#FF0055]/10",
  high: "text-[#FFB800] border-[#FFB800]/50 bg-[#FFB800]/10",
  medium: "text-[#00F0FF] border-[#00F0FF]/50 bg-[#00F0FF]/10",
  low: "text-[#A1A1A5] border-white/20 bg-white/5",
};

export default function ThreatDashboard() {
  const [reports, setReports] = useState([]);
  const [active, setActive] = useState(null);

  useEffect(() => {
    api.get("/threats").then(({ data }) => setReports(data)).catch(() => {});
  }, []);

  return (
    <section id="threats" data-testid="threats-section" className="relative py-28 border-t border-white/5">
      <div className="mx-auto max-w-[1400px] px-6">
        <div className="max-w-3xl mb-16">
          <div className="font-mono-data text-[11px] uppercase tracking-[0.3em] text-[#00F0FF] mb-6">
            / Threat Report
          </div>
          <h2 className="font-display font-black tracking-tighter text-white text-4xl sm:text-5xl lg:text-6xl leading-[0.95]">
            Attack chains, dissected.
          </h2>
          <p className="text-[#A1A1A5] mt-6 text-lg leading-relaxed">
            Curated intelligence from the NivX research team — full kill-chain mapping,
            process-tree forensics, and indicators of compromise.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {reports.map((r, i) => (
            <motion.button
              key={r.id}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.6, delay: (i % 3) * 0.08 }}
              data-testid={`threat-card-${i}`}
              onClick={() => setActive(r)}
              className="group text-left glass overflow-hidden hover:-translate-y-2 hover:border-[#00F0FF]/40 transition-[transform,border-color] duration-400"
            >
              <div className="relative h-40 overflow-hidden">
                {r.image_url && (
                  <img
                    src={r.image_url}
                    alt={r.title}
                    className="w-full h-full object-cover grayscale group-hover:grayscale-0 scale-105 group-hover:scale-110 transition-[filter,transform] duration-700"
                  />
                )}
                <div className="absolute inset-0 bg-gradient-to-t from-[#050505] via-[#050505]/30 to-transparent" />
                <span
                  className={`absolute top-3 left-3 font-mono-data text-[10px] uppercase tracking-widest px-2 py-1 border ${
                    SEV[r.severity] || SEV.low
                  }`}
                >
                  {r.severity}
                </span>
              </div>
              <div className="p-5">
                <div className="font-mono-data text-[10px] uppercase tracking-widest text-[#66666E] mb-2">
                  {r.category}
                </div>
                <h3 className="font-display font-semibold text-lg text-white leading-tight mb-3 group-hover:text-[#00F0FF] transition-colors">
                  {r.title}
                </h3>
                <p className="text-sm text-[#A1A1A5] leading-relaxed line-clamp-2 mb-4">{r.summary}</p>
                <AttackChain steps={r.attack_chain?.slice(0, 3)} compact />
              </div>
            </motion.button>
          ))}
        </div>
      </div>

      <Dialog open={!!active} onOpenChange={(o) => !o && setActive(null)}>
        <DialogContent
          data-testid="threat-detail-dialog"
          className="max-w-3xl bg-[#0A0A0B] border-white/10 text-white max-h-[88vh] overflow-y-auto"
        >
          {active && (
            <>
              <DialogHeader>
                <div className="flex items-center gap-3 mb-2">
                  <span className={`font-mono-data text-[10px] uppercase tracking-widest px-2 py-1 border ${SEV[active.severity] || SEV.low}`}>
                    {active.severity}
                  </span>
                  <span className="font-mono-data text-[10px] uppercase tracking-widest text-[#66666E]">
                    {active.category}
                  </span>
                </div>
                <DialogTitle className="font-display font-black text-2xl tracking-tight text-white text-left">
                  {active.title}
                </DialogTitle>
              </DialogHeader>

              {active.image_url && (
                <img src={active.image_url} alt={active.title} className="w-full h-52 object-cover border border-white/10" />
              )}

              <p className="text-[#A1A1A5] leading-relaxed">{active.summary}</p>

              {active.threat_actor && (
                <div className="font-mono-data text-sm">
                  <span className="text-[#66666E] uppercase tracking-widest text-[11px]">Threat Actor: </span>
                  <span className="text-[#FFB800]">{active.threat_actor}</span>
                </div>
              )}

              <div>
                <div className="font-mono-data text-[11px] uppercase tracking-widest text-[#00F0FF] mb-3">
                  Attack Chain / MITRE ATT&CK
                </div>
                <AttackChain steps={active.attack_chain} />
              </div>

              {active.process_tree && (
                <div>
                  <div className="font-mono-data text-[11px] uppercase tracking-widest text-[#00F0FF] mb-3">
                    Process Tree
                  </div>
                  <ProcessTree tree={active.process_tree} />
                </div>
              )}

              {active.iocs?.length > 0 && (
                <div>
                  <div className="font-mono-data text-[11px] uppercase tracking-widest text-[#00F0FF] mb-3">
                    Indicators of Compromise
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {active.iocs.map((ioc, i) => (
                      <code key={i} className="font-mono-data text-[11px] text-[#A1A1A5] bg-black/40 border border-white/10 px-2 py-1">
                        {ioc}
                      </code>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </DialogContent>
      </Dialog>
    </section>
  );
}
