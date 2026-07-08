import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { api } from "@/lib/api";
import AttackChain from "@/components/AttackChain";
import ProcessTree from "@/components/ProcessTree";
import { GitBranch, Crosshair, Fingerprint, ArrowUpRight } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";

const SEV = {
  critical: "text-[#FF3B5C] border-[#FF3B5C]/50 bg-[#FF3B5C]/10",
  high: "text-[#FFB800] border-[#FFB800]/50 bg-[#FFB800]/10",
  medium: "text-[#F5821F] border-[#F5821F]/50 bg-[#F5821F]/10",
  low: "text-[#9AA6B8] border-white/20 bg-white/5",
};

function Panel({ label, icon: Icon, children }) {
  return (
    <div className="border border-white/10 bg-black/30">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-white/10">
        <Icon className="w-4 h-4 text-[#F5821F]" strokeWidth={1.6} />
        <span className="font-mono-data text-[11px] uppercase tracking-widest text-white">{label}</span>
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

function FeaturedBrief({ r }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 40 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }}
      transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
      data-testid="featured-brief"
      className="border border-white/10 bg-[#0A1220] mb-8"
    >
      <div className="grid lg:grid-cols-[1.1fr_1fr]">
        {/* Left: identity */}
        <div className="p-8 border-b lg:border-b-0 lg:border-r border-white/10">
          <div className="flex items-center gap-3 mb-5">
            <span className="font-mono-data text-[10px] uppercase tracking-widest text-[#F5821F] border border-[#F5821F]/40 px-2 py-1">
              Featured Brief
            </span>
            <span className={`font-mono-data text-[10px] uppercase tracking-widest px-2 py-1 border ${SEV[r.severity] || SEV.low}`}>
              {r.severity}
            </span>
          </div>
          <h3 className="font-display font-bold text-2xl md:text-3xl text-white tracking-tight leading-tight mb-4">
            {r.title}
          </h3>
          <p className="text-[#9AA6B8] leading-relaxed mb-6">{r.summary}</p>
          {r.threat_actor && (
            <div className="font-mono-data text-sm mb-6">
              <span className="text-[#5A6B82] uppercase tracking-widest text-[11px]">Attributed to: </span>
              <span className="text-[#FFB800]">{r.threat_actor}</span>
            </div>
          )}
          {r.image_url && (
            <div className="relative overflow-hidden border border-white/10">
              <img src={r.image_url} alt={r.title} className="w-full h-40 object-cover grayscale" />
              <div className="absolute inset-0 bg-gradient-to-t from-[#0A1220] to-transparent" />
            </div>
          )}
        </div>

        {/* Right: analysis */}
        <div className="p-8 space-y-5">
          <Panel label="MITRE ATT&CK · Kill Chain" icon={Crosshair}>
            <AttackChain steps={r.attack_chain} showIds />
          </Panel>
          {r.process_tree && (
            <Panel label="Process Tree · Execution Forensics" icon={GitBranch}>
              <ProcessTree tree={r.process_tree} />
            </Panel>
          )}
          {r.iocs?.length > 0 && (
            <Panel label="Indicators of Compromise" icon={Fingerprint}>
              <div className="flex flex-wrap gap-2">
                {r.iocs.map((ioc, i) => (
                  <code key={i} className="font-mono-data text-[11px] text-[#9AA6B8] bg-black/40 border border-white/10 px-2 py-1">
                    {ioc}
                  </code>
                ))}
              </div>
            </Panel>
          )}
        </div>
      </div>
    </motion.div>
  );
}

export default function ThreatDashboard() {
  const [reports, setReports] = useState([]);
  const [active, setActive] = useState(null);

  useEffect(() => {
    api.get("/threats").then(({ data }) => setReports(data)).catch(() => {});
  }, []);

  const featured = reports[0];
  const rest = reports.slice(1);

  return (
    <section id="threats" data-testid="threats-section" className="relative py-28 border-t border-white/5">
      <div className="mx-auto max-w-[1400px] px-6">
        <div className="max-w-3xl mb-14">
          <div className="font-mono-data text-[11px] uppercase tracking-[0.3em] text-[#F5821F] mb-6">
            / Threat Report
          </div>
          <h2 className="font-display font-black tracking-tighter text-white text-4xl sm:text-5xl lg:text-6xl leading-[0.95]">
            Attack chains, dissected.
          </h2>
          <p className="text-[#9AA6B8] mt-6 text-lg leading-relaxed">
            Every brief is mapped to the <span className="text-white">MITRE ATT&CK</span> framework with
            full process-tree forensics and indicators of compromise.
          </p>
        </div>

        {featured && <FeaturedBrief r={featured} />}

        {rest.length > 0 && (
          <>
            <div className="font-mono-data text-[11px] uppercase tracking-widest text-[#5A6B82] mb-4">
              More Intelligence Briefs
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {rest.map((r, i) => (
                <motion.button
                  key={r.id}
                  initial={{ opacity: 0, y: 30 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.6, delay: (i % 3) * 0.08 }}
                  data-testid={`threat-card-${i}`}
                  onClick={() => setActive(r)}
                  className="group text-left border border-white/10 bg-[#0A1220] overflow-hidden hover:-translate-y-2 hover:border-[#F5821F]/40 transition-[transform,border-color] duration-400"
                >
                  <div className="relative h-36 overflow-hidden">
                    {r.image_url && (
                      <img
                        src={r.image_url}
                        alt={r.title}
                        className="w-full h-full object-cover grayscale group-hover:grayscale-0 scale-105 group-hover:scale-110 transition-[filter,transform] duration-700"
                      />
                    )}
                    <div className="absolute inset-0 bg-gradient-to-t from-[#0A1220] via-[#0A1220]/30 to-transparent" />
                    <span className={`absolute top-3 left-3 font-mono-data text-[10px] uppercase tracking-widest px-2 py-1 border ${SEV[r.severity] || SEV.low}`}>
                      {r.severity}
                    </span>
                    <span className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity">
                      <ArrowUpRight className="w-4 h-4 text-[#F5821F]" />
                    </span>
                  </div>
                  <div className="p-5">
                    <div className="font-mono-data text-[10px] uppercase tracking-widest text-[#5A6B82] mb-2">{r.category}</div>
                    <h3 className="font-display font-semibold text-lg text-white leading-tight mb-3 group-hover:text-[#F5821F] transition-colors">
                      {r.title}
                    </h3>
                    <div className="font-mono-data text-[9px] uppercase tracking-widest text-[#5A6B82] mb-2">MITRE ATT&CK</div>
                    <AttackChain steps={r.attack_chain?.slice(0, 3)} compact />
                  </div>
                </motion.button>
              ))}
            </div>
          </>
        )}
      </div>

      <Dialog open={!!active} onOpenChange={(o) => !o && setActive(null)}>
        <DialogContent
          data-testid="threat-detail-dialog"
          className="max-w-3xl bg-[#0A1220] border-white/10 text-white max-h-[88vh] overflow-y-auto"
        >
          {active && (
            <>
              <DialogHeader>
                <div className="flex items-center gap-3 mb-2">
                  <span className={`font-mono-data text-[10px] uppercase tracking-widest px-2 py-1 border ${SEV[active.severity] || SEV.low}`}>
                    {active.severity}
                  </span>
                  <span className="font-mono-data text-[10px] uppercase tracking-widest text-[#5A6B82]">
                    {active.category}
                  </span>
                </div>
                <DialogTitle className="font-display font-black text-2xl tracking-tight text-white text-left">
                  {active.title}
                </DialogTitle>
                <DialogDescription className="sr-only">
                  Full threat intelligence report including MITRE ATT&CK attack chain, process tree, and indicators of compromise.
                </DialogDescription>
              </DialogHeader>

              {active.image_url && (
                <img src={active.image_url} alt={active.title} className="w-full h-52 object-cover border border-white/10" />
              )}

              <p className="text-[#9AA6B8] leading-relaxed">{active.summary}</p>

              {active.threat_actor && (
                <div className="font-mono-data text-sm">
                  <span className="text-[#5A6B82] uppercase tracking-widest text-[11px]">Threat Actor: </span>
                  <span className="text-[#FFB800]">{active.threat_actor}</span>
                </div>
              )}

              <Panel label="MITRE ATT&CK · Kill Chain" icon={Crosshair}>
                <AttackChain steps={active.attack_chain} showIds />
              </Panel>

              {active.process_tree && (
                <Panel label="Process Tree · Execution Forensics" icon={GitBranch}>
                  <ProcessTree tree={active.process_tree} />
                </Panel>
              )}

              {active.iocs?.length > 0 && (
                <Panel label="Indicators of Compromise" icon={Fingerprint}>
                  <div className="flex flex-wrap gap-2">
                    {active.iocs.map((ioc, i) => (
                      <code key={i} className="font-mono-data text-[11px] text-[#9AA6B8] bg-black/40 border border-white/10 px-2 py-1">
                        {ioc}
                      </code>
                    ))}
                  </div>
                </Panel>
              )}
            </>
          )}
        </DialogContent>
      </Dialog>
    </section>
  );
}
