import { motion } from "framer-motion";
import { mitreInfo } from "@/components/AttackChain";

export default function KillChainDiagram({ steps = [] }) {
  if (!steps.length) return null;
  return (
    <div data-testid="killchain-diagram" className="overflow-x-auto pb-2">
      <div className="flex items-start min-w-max gap-0">
        {steps.map((s, i) => {
          const last = i === steps.length - 1;
          const info = mitreInfo(s);
          return (
            <div key={i} className="flex items-start">
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: i * 0.12 }}
                className="flex flex-col items-center w-[132px]"
              >
                <div
                  className={`relative w-11 h-11 rounded-full flex items-center justify-center text-sm font-bold border-2 ${
                    last
                      ? "bg-red-500 border-red-500 text-white"
                      : "bg-white border-[#2E7DF5] text-[#2E7DF5]"
                  }`}
                >
                  {i + 1}
                  {!last && <span className="absolute -inset-1 rounded-full border border-blue-100 animate-none" />}
                </div>
                <div className="mt-2.5 text-center px-1">
                  <div className="font-mono-data text-[9px] tracking-wider text-slate-400">{info.ta}</div>
                  <div className={`text-[11px] font-semibold leading-tight ${last ? "text-red-600" : "text-slate-800"}`}>{s}</div>
                  <div className="font-mono-data text-[9px] text-slate-400 mt-0.5">{info.tech}</div>
                </div>
              </motion.div>

              {!last && (
                <motion.div
                  initial={{ scaleX: 0 }}
                  whileInView={{ scaleX: 1 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.3, delay: i * 0.12 + 0.1 }}
                  style={{ transformOrigin: "left" }}
                  className="h-0.5 w-8 bg-gradient-to-r from-[#2E7DF5] to-blue-200 mt-[21px]"
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
