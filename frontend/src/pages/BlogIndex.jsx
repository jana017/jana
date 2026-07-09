import { Link, useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Calendar, ArrowUpRight, Tag, Clock, BookOpen, X } from "lucide-react";
import Navbar from "@/components/Navbar";
import Contact from "@/components/Contact";
import LiveFirehose from "@/components/LiveFirehose";
import { BLOG_POSTS } from "@/lib/blogPosts";
import useSeo from "@/lib/useSeo";

// Map "topic" query param → set of blog categories to show.
const TOPIC_MAP = {
  dfir:    { label: "DFIR & Threat Investigations",    cats: ["Forensics", "Case Study", "APT Deep Dive", "Threat Actor Insight", "SOC Playbook"] },
  malware: { label: "Malware Analysis Case Studies",    cats: ["Case Study", "APT Deep Dive", "Threat Actor Insight", "SOC Playbook"] },
  soc:     { label: "SOC & Threat Hunting Playbooks",   cats: ["SOC Playbook", "Case Study", "Forensics"] },
};

export default function BlogIndex() {
  const [params, setParams] = useSearchParams();
  const topic = (params.get("topic") || "").toLowerCase();
  const filter = TOPIC_MAP[topic];

  useSeo({
    title: filter
      ? `${filter.label} · NivX Blogs | NivX Machines`
      : "NivX Blogs · Threats, Attacks & SOC Playbooks | NivX Machines",
    description: "Long-form cybersecurity intelligence from the NivX SOC — LOLBAs, ransomware, cloud security, detection engineering and incident response playbooks.",
    canonical: filter ? `https://nivxmachines.com/blog?topic=${topic}` : "https://nivxmachines.com/blog",
  });

  const posts = filter ? BLOG_POSTS.filter((p) => filter.cats.includes(p.category)) : BLOG_POSTS;
  const [featured, ...rest] = posts;

  const clearFilter = () => {
    const next = new URLSearchParams(params);
    next.delete("topic");
    setParams(next);
  };

  return (
    <div data-testid="blog-index-page" className="bg-white min-h-screen">
      <Navbar />

      <section className="pt-28 pb-14 lg:pt-32 bg-[#0A1220] relative overflow-hidden border-b border-slate-800">
        <div className="absolute inset-0 dot-grid opacity-40" aria-hidden="true" />
        <div className="relative mx-auto max-w-7xl px-6">
          <div className="inline-flex items-center gap-2 bg-white/5 border border-white/10 text-orange-300 rounded-full px-3 py-1 text-xs font-semibold mb-5">
            <BookOpen className="w-4 h-4" /> NivX Blogs {filter && <span className="text-orange-200/80">· {filter.label}</span>}
          </div>
          <h1 className="font-heading text-3xl md:text-4xl lg:text-5xl font-bold tracking-tight text-white leading-tight max-w-3xl">
            {filter ? filter.label : "Threats & Attacks · articles from the field"}
          </h1>
          <p className="mt-4 text-base md:text-lg text-slate-400 max-w-2xl leading-relaxed">
            {filter
              ? "Curated writeups from the NivX SOC covering this topic."
              : "Dive into the world of cybersecurity with NivX Blogs — SOC playbooks, live threat analysis, detection engineering and hands-on IR walkthroughs."}
          </p>
          <div className="mt-3 flex items-center gap-3 text-sm text-slate-500">
            <span><span className="font-semibold text-slate-300">{posts.length}</span> article{posts.length === 1 ? "" : "s"}{filter ? ` matching "${filter.label}"` : ""} · updated regularly by the NivX editorial team.</span>
            {filter && (
              <button onClick={clearFilter} data-testid="blog-clear-filter" className="inline-flex items-center gap-1 text-xs font-semibold text-orange-300 hover:text-orange-200">
                <X className="w-3 h-3" /> Show all articles
              </button>
            )}
          </div>
        </div>
      </section>

      <LiveFirehose />

      <section className="py-14 lg:py-20 bg-white">
        <div className="mx-auto max-w-7xl px-6">
          {posts.length === 0 && (
            <div data-testid="blog-empty" className="text-center py-16 text-slate-500">
              No articles match this topic yet.
              <button onClick={clearFilter} className="ml-2 text-[#2E7DF5] font-semibold hover:underline">Show all articles</button>
            </div>
          )}
          {featured && (
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
            >
              <Link
                to={`/blog/${featured.slug}`}
                data-testid="blog-featured"
                className="group grid grid-cols-1 lg:grid-cols-[1.35fr_1fr] gap-0 rounded-2xl border border-slate-200 overflow-hidden hover:shadow-xl hover:border-slate-300 transition-all mb-14 bg-white"
              >
                <div className="relative aspect-[16/10] lg:aspect-auto overflow-hidden bg-slate-100">
                  <img src={featured.image} alt={featured.title} loading="lazy" className="absolute inset-0 w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" />
                  <div className="absolute inset-0 bg-gradient-to-t from-black/40 via-transparent to-transparent" />
                  <div className="absolute top-4 left-4">
                    <span className="inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider bg-white/95 text-slate-900 px-2.5 py-1 rounded shadow-sm">
                      <Tag className="w-3 h-3" /> {featured.category}
                    </span>
                  </div>
                </div>
                <div className="p-8 lg:p-10 flex flex-col justify-center bg-white">
                  <div className="text-xs font-semibold uppercase tracking-wider text-orange-500 mb-3">Featured</div>
                  <h3 className="font-heading text-2xl md:text-3xl font-semibold text-slate-900 group-hover:text-[#2E7DF5] transition-colors leading-snug">
                    {featured.title}
                  </h3>
                  <p className="mt-4 text-slate-600 leading-relaxed">{featured.excerpt}</p>
                  <div className="mt-6 flex items-center justify-between">
                    <div className="flex items-center gap-3 text-xs text-slate-500">
                      <span className="inline-flex items-center gap-1.5"><Calendar className="w-3.5 h-3.5" /> {featured.date}</span>
                      <span className="inline-flex items-center gap-1.5"><Clock className="w-3.5 h-3.5" /> {featured.read_mins} min read</span>
                    </div>
                    <span className="inline-flex items-center gap-1 text-sm font-semibold text-[#2E7DF5] group-hover:gap-2 transition-all">
                      Read article <ArrowUpRight className="w-4 h-4" />
                    </span>
                  </div>
                </div>
              </Link>
            </motion.div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" data-testid="blog-grid">
            {rest.map((p, i) => (
              <motion.div
                key={p.slug}
                initial={{ opacity: 0, y: 14 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: (i % 3) * 0.05 }}
              >
                <Link
                  to={`/blog/${p.slug}`}
                  data-testid={`blog-card-${i}`}
                  className="group flex flex-col rounded-xl border border-slate-200 overflow-hidden bg-white hover:shadow-lg hover:-translate-y-1 hover:border-slate-300 transition-all h-full"
                >
                  <div className="relative aspect-[16/9] overflow-hidden bg-slate-100">
                    <img src={p.image} alt={p.title} loading="lazy" className="absolute inset-0 w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" />
                    <div className="absolute inset-0 bg-gradient-to-t from-black/30 via-transparent to-transparent" />
                    <div className="absolute top-3 left-3">
                      <span className="inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider bg-white/95 text-slate-900 px-2 py-0.5 rounded shadow-sm">
                        {p.category}
                      </span>
                    </div>
                  </div>
                  <div className="p-5 flex-1 flex flex-col">
                    <h3 className="font-semibold text-slate-900 group-hover:text-[#2E7DF5] transition-colors leading-snug line-clamp-3">
                      {p.title}
                    </h3>
                    <p className="mt-2 text-sm text-slate-600 leading-relaxed line-clamp-3 flex-1">{p.excerpt}</p>
                    <div className="mt-4 flex items-center justify-between pt-3 border-t border-slate-100">
                      <div className="flex items-center gap-2 text-[11px] text-slate-500">
                        <span className="inline-flex items-center gap-1"><Calendar className="w-3 h-3" /> {p.date}</span>
                        <span className="inline-flex items-center gap-1"><Clock className="w-3 h-3" /> {p.read_mins}m</span>
                      </div>
                      <ArrowUpRight className="w-4 h-4 text-slate-400 group-hover:text-[#2E7DF5] group-hover:-translate-y-0.5 group-hover:translate-x-0.5 transition-all" />
                    </div>
                  </div>
                </Link>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      <Contact />
    </div>
  );
}
