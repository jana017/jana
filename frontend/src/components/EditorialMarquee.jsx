import { motion } from "framer-motion";

const STATS = [
  { value: "24/7", label: "SOC monitoring" },
  { value: "<15min", label: "Mean response time" },
  { value: "99.9%", label: "Uptime SLA" },
  { value: "500+", label: "Threats neutralized / day" },
];

export default function StatsBand() {
  return (
    <section data-testid="stats-band" className="bg-[#0A1220] py-14">
      <div className="mx-auto max-w-7xl px-6 grid grid-cols-2 md:grid-cols-4 gap-8">
        {STATS.map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 12 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: i * 0.08 }}
            className="text-center md:text-left"
          >
            <div className="font-heading text-3xl md:text-4xl font-bold text-white">{s.value}</div>
            <div className="mt-1 text-sm text-slate-400">{s.label}</div>
          </motion.div>
        ))}
      </div>
    </section>
  );
}
