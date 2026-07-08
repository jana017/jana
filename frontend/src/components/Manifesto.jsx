import { motion } from "framer-motion";

const CHAPTERS = [
  {
    n: "01",
    title: "Assume Breach",
    body: "We architect from the premise that adversaries are already inside. Zero-trust segmentation, continuous verification, and least-privilege access contain the blast radius before it spreads.",
  },
  {
    n: "02",
    title: "Weaponize Intelligence",
    body: "Our AI models ingest telemetry at machine speed — correlating signals across endpoints, identity, and network to surface the anomaly that human analysts would miss.",
  },
  {
    n: "03",
    title: "Respond at Machine Speed",
    body: "Detection without response is theatre. Automated playbooks isolate, remediate, and recover — collapsing dwell time from weeks to minutes.",
  },
];

const reveal = {
  hidden: { y: 40, opacity: 0 },
  show: { y: 0, opacity: 1, transition: { duration: 0.8, ease: [0.16, 1, 0.3, 1] } },
};

export default function Manifesto() {
  return (
    <section id="about" data-testid="about-section" className="relative py-28 lg:py-40 border-t border-white/5">
      <div className="mx-auto max-w-[1400px] px-6">
        <motion.div
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-100px" }}
          variants={reveal}
          className="max-w-3xl mb-20"
        >
          <div className="font-mono-data text-[11px] uppercase tracking-[0.3em] text-[#F5821F] mb-6">
            / About Us — The Manifesto
          </div>
          <h2 className="font-display font-black tracking-tighter text-white text-4xl sm:text-5xl lg:text-6xl leading-[0.95]">
            Defense is not a product. <span className="text-[#5A6B82]">It&apos;s a discipline.</span>
          </h2>
        </motion.div>

        <div className="space-y-px">
          {CHAPTERS.map((c) => (
            <motion.div
              key={c.n}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true, margin: "-80px" }}
              variants={reveal}
              data-testid={`manifesto-${c.n}`}
              className="grid md:grid-cols-[auto_1fr] gap-6 md:gap-14 py-10 border-t border-white/10 group"
            >
              <div className="font-display font-black text-6xl md:text-8xl text-white/10 group-hover:text-[#F5821F]/40 transition-colors duration-500 leading-none">
                {c.n}
              </div>
              <div className="max-w-2xl">
                <h3 className="font-display font-semibold text-2xl md:text-3xl text-white mb-4 tracking-tight">
                  {c.title}
                </h3>
                <p className="text-[#9AA6B8] leading-relaxed text-base md:text-lg">{c.body}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
