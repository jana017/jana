import { motion } from "framer-motion";

const IMAGES = [
  { url: "https://images.unsplash.com/photo-1680992046626-418f7e910589?crop=entropy&cs=srgb&fm=jpg&q=85&w=1200", label: "Network Operations Center", span: "md:col-span-8 md:row-span-2" },
  { url: "https://images.unsplash.com/photo-1644088379091-d574269d422f?crop=entropy&cs=srgb&fm=jpg&q=85&w=800", label: "Neural Threat Mesh", span: "md:col-span-4" },
  { url: "https://images.unsplash.com/photo-1555066931-4365d14bab8c?crop=entropy&cs=srgb&fm=jpg&q=85&w=800", label: "Red Team Terminal", span: "md:col-span-4" },
  { url: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?crop=entropy&cs=srgb&fm=jpg&q=85&w=1200", label: "Datacenter Spine", span: "md:col-span-5" },
  { url: "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?crop=entropy&cs=srgb&fm=jpg&q=85&w=1200", label: "Signal Analysis", span: "md:col-span-7" },
];

export default function Gallery() {
  return (
    <section id="gallery" data-testid="gallery-section" className="relative py-28 border-t border-white/5 bg-[#0A0A0B]">
      <div className="mx-auto max-w-[1400px] px-6">
        <div className="max-w-3xl mb-16">
          <div className="font-mono-data text-[11px] uppercase tracking-[0.3em] text-[#00F0FF] mb-6">/ Gallery</div>
          <h2 className="font-display font-black tracking-tighter text-white text-4xl sm:text-5xl lg:text-6xl leading-[0.95]">
            Inside the machine.
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-4 auto-rows-[220px]">
          {IMAGES.map((img, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, scale: 0.96 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.7, delay: i * 0.06 }}
              data-testid={`gallery-item-${i}`}
              className={`group relative overflow-hidden border border-white/10 ${img.span}`}
            >
              <img
                src={img.url}
                alt={img.label}
                className="w-full h-full object-cover grayscale group-hover:grayscale-0 group-hover:scale-105 transition-[filter,transform] duration-700"
              />
              <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-transparent to-transparent" />
              <div className="absolute bottom-4 left-4 font-mono-data text-[11px] uppercase tracking-widest text-white/80 group-hover:text-[#00F0FF] transition-colors">
                {img.label}
              </div>
              <div className="absolute inset-0 ring-1 ring-inset ring-[#00F0FF]/0 group-hover:ring-[#00F0FF]/40 transition-[box-shadow] duration-500" />
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
