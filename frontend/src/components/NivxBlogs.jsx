import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Calendar, ArrowUpRight, Tag, Clock } from "lucide-react";
import { BLOG_POSTS } from "@/lib/blogPosts";

export default function NivxBlogs() {
  const featured = BLOG_POSTS[0];
  const rest = BLOG_POSTS.slice(1);

  return (
    <section id="blog" data-testid="nivx-blogs" className="py-20 lg:py-28 bg-white border-t border-slate-100">
      <div className="mx-auto max-w-7xl px-6">
        <div className="max-w-3xl mb-12">
          <div className="text-xs font-bold uppercase tracking-[0.2em] text-orange-500 mb-3">NivX Blogs</div>
          <h2 className="font-heading text-3xl md:text-4xl lg:text-5xl font-semibold tracking-tight text-slate-900">
            Threats & Attacks · articles from the field
          </h2>
          <p className="mt-5 text-base md:text-lg text-slate-600 leading-relaxed">
            Dive into the world of cybersecurity with NivX Blogs. Explore informative articles, insights, and expert perspectives on the latest trends, best practices, and cutting-edge technologies in the field. Stay updated, enhance your knowledge, and empower yourself to defend against cyber threats.
          </p>
        </div>

        {/* Featured */}
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

        {/* Grid */}
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
  );
}
