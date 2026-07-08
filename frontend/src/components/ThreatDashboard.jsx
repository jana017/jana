import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { api } from "@/lib/api";
import AttackChain from "@/components/AttackChain";
import KillChainDiagram from "@/components/KillChainDiagram";
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
  critical: "bg-red-50 text-red-700 border-red-200",
  high: "bg-orange-50 text-orange-700 border-orange-200",
  medium: "bg-blue-50 text-blue-700 border-blue-200",
  low: "bg-slate-100 text-slate-600 border-slate-200",
};

function Panel({ label, icon: Icon, children }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-slate-100">
        <Icon className="w-4 h-4 text-[#2E7DF5]" strokeWidth={1.7} />
        <span className="text-xs font-semibold uppercase tracking-wide text-slate-700">{label}</span>
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

function FeaturedBrief({ r }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      data-testid="featured-brief"
      className="rounded-2xl border border-slate-200 bg-white shadow-sm overflow-hidden mb-8"
    >
      <div className="grid lg:grid-cols-[1fr_1fr]">
        <div className="p-8 border-b lg:border-b-0 lg:border-r border-slate-100">
          <div className="flex items-center gap-2 mb-4">
            <span className="text-[11px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md bg-blue-600 text-white">Featured Brief</span>
            <span className={`text-[11px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md border ${SEV[r.severity] || SEV.low}`}>{r.severity}</span>
          </div>
          <h3 className="font-heading text-xl md:text-2xl font-semibold text-slate-900 leading-tight mb-3">{r.title}</h3>
          <p className="text-sm text-slate-600 leading-relaxed mb-5">{r.summary}</p>
          {r.threat_actor && (
            <div className="text-sm mb-5">
              <span className="text-slate-400">Attributed to: </span>
              <span className="font-semibold text-[#F5821F]">{r.threat_actor}</span>
            </div>
          )}
          {r.image_url && (
            <div className="rounded-lg overflow-hidden border border-slate-200">
              <img src={r.image_url} alt={r.title} className="w-full h-40 object-cover" />
            </div>
          )}
        </div>
        <div className="p-8 space-y-4 bg-slate-50/50">
          <Panel label="MITRE ATT&CK · Kill Chain" icon={Crosshair}>
            <KillChainDiagram steps={r.attack_chain} />
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
                  <code key={i} className="font-mono-data text-[11px] text-slate-600 bg-slate-100 border border-slate-200 px-2 py-1 rounded">{ioc}</code>
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
    <section id="threats" data-testid="threats-section" className="py-20 lg:py-28 bg-slate-50">
      <div className="mx-auto max-w-7xl px-6">
        <div className="max-w-2xl mb-12">
          <div className="text-xs font-bold uppercase tracking-[0.2em] text-blue-600 mb-3">Threat Report</div>
          <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-slate-900">
            Attack chains, dissected
          </h2>
          <p className="mt-4 text-base text-slate-600 leading-relaxed">
            Every brief is mapped to the <span className="font-semibold text-slate-900">MITRE ATT&CK</span> framework
            with full process-tree forensics and indicators of compromise.
          </p>
        </div>

        {featured && <FeaturedBrief r={featured} />}

        {rest.length > 0 && (
          <>
            <div className="text-sm font-semibold text-slate-500 mb-4">More intelligence briefs</div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {rest.map((r, i) => (
                <motion.button
                  key={r.id}
                  initial={{ opacity: 0, y: 16 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.5, delay: (i % 3) * 0.08 }}
                  data-testid={`threat-card-${i}`}
                  onClick={() => setActive(r)}
                  className="group text-left rounded-xl border border-slate-200 bg-white shadow-sm hover:shadow-md hover:-translate-y-1 transition-[transform,box-shadow] overflow-hidden"
                >
                  <div className="relative h-40 overflow-hidden">
                    {r.image_url && <img src={r.image_url} alt={r.title} className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-700" />}
                    <div className="absolute inset-0 bg-gradient-to-t from-slate-900/50 to-transparent" />
                    <span className={`absolute top-3 left-3 text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md border ${SEV[r.severity] || SEV.low}`}>{r.severity}</span>
                    <ArrowUpRight className="absolute top-3 right-3 w-5 h-5 text-white opacity-0 group-hover:opacity-100 transition-opacity" />
                  </div>
                  <div className="p-5">
                    <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">{r.category}</div>
                    <h3 className="font-heading text-base font-semibold text-slate-900 leading-snug mb-3 group-hover:text-[#2E7DF5] transition-colors">{r.title}</h3>
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 mb-2">MITRE ATT&CK</div>
                    <AttackChain steps={r.attack_chain?.slice(0, 3)} />
                  </div>
                </motion.button>
              ))}
            </div>
          </>
        )}
      </div>

      <Dialog open={!!active} onOpenChange={(o) => !o && setActive(null)}>
        <DialogContent data-testid="threat-detail-dialog" className="max-w-2xl bg-white max-h-[88vh] overflow-y-auto">
          {active && (
            <>
              <DialogHeader>
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-1 rounded-md border ${SEV[active.severity] || SEV.low}`}>{active.severity}</span>
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">{active.category}</span>
                </div>
                <DialogTitle className="font-heading text-xl font-semibold text-slate-900 text-left">{active.title}</DialogTitle>
                <DialogDescription className="sr-only">Full threat intelligence report including MITRE ATT&CK chain, process tree and indicators of compromise.</DialogDescription>
              </DialogHeader>

              {active.image_url && <img src={active.image_url} alt={active.title} className="w-full h-48 object-cover rounded-lg border border-slate-200" />}
              <p className="text-sm text-slate-600 leading-relaxed">{active.summary}</p>
              {active.threat_actor && (
                <div className="text-sm"><span className="text-slate-400">Threat actor: </span><span className="font-semibold text-[#F5821F]">{active.threat_actor}</span></div>
              )}
              <Panel label="MITRE ATT&CK · Kill Chain" icon={Crosshair}><KillChainDiagram steps={active.attack_chain} /></Panel>
              {active.process_tree && <Panel label="Process Tree · Execution Forensics" icon={GitBranch}><ProcessTree tree={active.process_tree} /></Panel>}
              {active.iocs?.length > 0 && (
                <Panel label="Indicators of Compromise" icon={Fingerprint}>
                  <div className="flex flex-wrap gap-2">
                    {active.iocs.map((ioc, i) => (
                      <code key={i} className="font-mono-data text-[11px] text-slate-600 bg-slate-100 border border-slate-200 px-2 py-1 rounded">{ioc}</code>
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
