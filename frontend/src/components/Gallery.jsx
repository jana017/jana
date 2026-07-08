import { motion } from "framer-motion";

const IMAGES = [
  { url: "https://images.pexels.com/photos/37730212/pexels-photo-37730212.jpeg", label: "Enterprise Data Center", span: "md:col-span-2 md:row-span-2" },
  { url: "https://images.unsplash.com/photo-1674027444636-ce7379d51252?w=800", label: "AI Threat Mesh" },
  { url: "https://images.pexels.com/photos/5483240/pexels-photo-5483240.jpeg", label: "Security Operations" },
  { url: "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=1200", label: "Network Infrastructure", span: "md:col-span-2" },
];

export default function Gallery() {
  return (
    <section id="gallery" data-testid="gallery-section" className="py-20 lg:py-28 bg-white">
      <div className="mx-auto max-w-7xl px-6">
        <div className="max-w-2xl mb-14">
          <div className="text-xs font-bold uppercase tracking-[0.2em] text-blue-600 mb-3">Gallery</div>
          <h2 className="font-heading text-2xl md:text-3xl font-semibold tracking-tight text-slate-900">
            Inside the operation
          </h2>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 auto-rows-[200px]">
          {IMAGES.map((img, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, scale: 0.97 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 0.55, delay: i * 0.06 }}
              data-testid={`gallery-item-${i}`}
              className={`group relative overflow-hidden rounded-xl border border-slate-200 shadow-sm ${img.span || ""}`}
            >
              <img src={img.url} alt={img.label} className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-700" />
              <div className="absolute inset-0 bg-gradient-to-t from-[#0A1220]/70 via-transparent to-transparent" />
              <div className="absolute bottom-3 left-4 text-sm font-semibold text-white">{img.label}</div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
