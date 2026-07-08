import { motion } from "framer-motion";
import { CheckCircle2, ExternalLink, Award, Twitter, Globe } from "lucide-react";

const LEGENDS = [
  {
    name: "Kevin Mitnick",
    title: "The Pioneer of Social Engineering",
    intro: "The world's most legendary hacker turned white-hat consultant, who proved human psychology is the weakest link in every security programme.",
    achievements: [
      "Authored the iconic bestseller The Art of Deception.",
      "Trained Fortune 500 companies for decades against social engineering.",
      "Founded Mitnick Security Consulting — a benchmark in enterprise red-team services.",
    ],
    image: "https://upload.wikimedia.org/wikipedia/commons/thumb/d/d5/Kevin_Mitnick_ex_hacker_y_ahora_famoso_consultor_en_redes_en_Campus_Party_M%C3%A9xico_2010.jpg/500px-Kevin_Mitnick_ex_hacker_y_ahora_famoso_consultor_en_redes_en_Campus_Party_M%C3%A9xico_2010.jpg",
    initials: "KM",
    accent: "from-red-500 to-orange-500",
    link: { label: "Mitnick Security", href: "https://www.mitnicksecurity.com/" },
  },
  {
    name: "Bruce Schneier",
    title: "The Father of Modern Cryptography",
    intro: "A world-renowned security philosopher, cryptographer, and champion of public privacy rights whose books have shaped generations of defenders.",
    achievements: [
      "Designed the foundational Blowfish and Twofish encryption algorithms.",
      "Wrote Applied Cryptography — the definitive textbook for global security engineering.",
      "Fellow at the Berkman Klein Center for Internet & Society at Harvard.",
    ],
    image: "https://upload.wikimedia.org/wikipedia/commons/thumb/f/fc/Bruce_Schneier_at_CoPS2013-IMG_9174.jpg/500px-Bruce_Schneier_at_CoPS2013-IMG_9174.jpg",
    initials: "BS",
    accent: "from-blue-500 to-indigo-600",
    link: { label: "schneier.com", href: "https://www.schneier.com/" },
  },
  {
    name: "Troy Hunt",
    title: "The Web Security Authority",
    intro: "A Microsoft Regional Director and international speaker dedicated to exposing mass data breaches and lifting the security floor for every developer online.",
    achievements: [
      "Created \"Have I Been Pwned?\" — the internet's primary data-breach tracking service.",
      "Educated millions of software developers through globally standard security courses.",
      "Regularly briefs governments and Fortune 100 boards on breach response.",
    ],
    image: "https://upload.wikimedia.org/wikipedia/commons/thumb/2/2f/Troy_Hunt_LM-0059_%28square%29.jpg/500px-Troy_Hunt_LM-0059_%28square%29.jpg",
    initials: "TH",
    accent: "from-emerald-500 to-teal-600",
    link: { label: "haveibeenpwned.com", href: "https://haveibeenpwned.com/" },
  },
  {
    name: "Brian Krebs",
    title: "The Legendary Cybercrime Journalist",
    intro: "An investigative reporter who risks his safety to expose international cybercrime syndicates and massive corporate data leaks — often before the victims know they've been hit.",
    achievements: [
      "Authored the New York Times bestseller Spam Nation.",
      "Broke the news of the massive Target and Home Depot data breaches.",
      "Publishes Krebs on Security — required reading for every SOC on the planet.",
    ],
    image: "https://champions-speakers.co.uk/sites/default/files/2021-06/brian-krebs-hero.jpg",
    initials: "BK",
    accent: "from-slate-800 to-slate-950",
    link: { label: "krebsonsecurity.com", href: "https://krebsonsecurity.com/" },
  },
];

function Portrait({ legend }) {
  if (legend.image) {
    return (
      <div className="relative w-full h-full overflow-hidden bg-slate-100">
        <img
          src={legend.image}
          alt={legend.name}
          loading="lazy"
          className="absolute inset-0 w-full h-full object-cover object-top grayscale-[15%] group-hover:grayscale-0 group-hover:scale-105 transition-all duration-500"
        />
        <div className={`absolute inset-0 bg-gradient-to-t ${legend.accent} opacity-20 mix-blend-multiply`} />
        <div className="absolute inset-x-0 bottom-0 h-1/3 bg-gradient-to-t from-black/60 to-transparent" />
      </div>
    );
  }
  // Monogram fallback
  return (
    <div className={`relative w-full h-full flex items-center justify-center bg-gradient-to-br ${legend.accent} overflow-hidden`}>
      <div className="absolute inset-0 opacity-20" style={{
        backgroundImage: "radial-gradient(circle at 20% 20%, rgba(255,255,255,.3), transparent 60%)",
      }} aria-hidden="true" />
      <div className="relative text-white font-heading font-bold tracking-tight" style={{ fontSize: "6rem", lineHeight: 1 }}>
        {legend.initials}
      </div>
    </div>
  );
}

export default function Gallery() {
  return (
    <section id="gallery" data-testid="gallery-section" className="py-20 lg:py-28 bg-white">
      <div className="mx-auto max-w-7xl px-6">
        {/* Header */}
        <div className="max-w-3xl mb-14">
          <div className="text-xs font-bold uppercase tracking-[0.2em] text-orange-500 mb-3 flex items-center gap-2">
            <Award className="w-3.5 h-3.5" /> Hall of Legends
          </div>
          <h2 className="font-heading text-3xl md:text-4xl lg:text-5xl font-semibold tracking-tight text-slate-900">
            The people who shaped the discipline we defend.
          </h2>
          <p className="mt-5 text-base md:text-lg text-slate-600 leading-relaxed">
            Four absolute giants of the cybersecurity world — pioneers whose work forms the foundation of modern defence. Every SOC playbook, cryptography choice and breach-response instinct in our practice can be traced back to one of them.
          </p>
        </div>

        {/* Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 lg:gap-8" data-testid="gallery-cards">
          {LEGENDS.map((l, i) => (
            <motion.article
              key={l.name}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: (i % 2) * 0.08 }}
              data-testid={`gallery-legend-${i}`}
              className="group grid grid-cols-1 sm:grid-cols-[220px_1fr] gap-0 rounded-2xl border border-slate-200 bg-white overflow-hidden hover:shadow-2xl hover:border-slate-300 transition-all"
            >
              <div className="relative aspect-square sm:aspect-auto sm:h-full min-h-[260px]">
                <Portrait legend={l} />
                {/* Number badge */}
                <div className="absolute top-4 left-4">
                  <span className="inline-flex items-center justify-center w-8 h-8 rounded-full bg-white/95 text-slate-900 font-bold text-sm shadow-md">
                    {i + 1}
                  </span>
                </div>
              </div>
              <div className="p-6 lg:p-8 flex flex-col">
                <h3 className="font-heading text-2xl font-semibold text-slate-900 leading-tight">{l.name}</h3>
                <div className={`mt-1.5 text-sm font-semibold bg-gradient-to-r ${l.accent} bg-clip-text text-transparent`}>{l.title}</div>
                <p className="mt-4 text-slate-600 leading-relaxed text-sm">{l.intro}</p>

                <div className="mt-5 pt-5 border-t border-slate-100">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-2.5">Key achievements</div>
                  <ul className="space-y-2">
                    {l.achievements.map((a) => (
                      <li key={a} className="flex items-start gap-2 text-sm text-slate-700 leading-snug">
                        <CheckCircle2 className="w-4 h-4 text-[#2E7DF5] shrink-0 mt-0.5" />
                        <span>{a}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                {l.link && (
                  <a
                    href={l.link.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    data-testid={`gallery-link-${i}`}
                    className="mt-5 inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600 hover:text-[#2E7DF5] transition-colors"
                  >
                    <Globe className="w-3.5 h-3.5" /> {l.link.label} <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            </motion.article>
          ))}
        </div>

        {/* Attribution */}
        <p className="mt-10 text-center text-xs text-slate-400">
          Portraits sourced from Wikimedia Commons under Creative Commons licenses where available. All credit to the original photographers.
        </p>
      </div>
    </section>
  );
}
