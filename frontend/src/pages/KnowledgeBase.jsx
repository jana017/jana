import { useParams, Link } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowLeft, Clock, Calendar, BookOpen, ChevronRight, ShieldCheck } from "lucide-react";
import Navbar from "@/components/Navbar";
import Contact from "@/components/Contact";
import { KB_ARTICLES, findArticle } from "@/lib/knowledgeArticles";
import useSeo from "@/lib/useSeo";
import useActorLinker from "@/lib/useActorLinker";

function IndexView({ embedded = false }) {
  useSeo({
    title: "Cybersecurity 101 · Knowledge Base | NivX Machines",
    description: "In-depth explainers on malware analysis, advanced persistent threats (APT), incident response and man-in-the-middle attacks — the fundamentals every defender should know.",
    canonical: "https://nivxmachines.com/cybersecurity-101",
  });
  return (
    <div className="min-h-screen bg-white">
      {!embedded && <Navbar />}
      <section className={`${embedded ? "pt-10 pb-14 lg:pt-14 lg:pb-20" : "pt-28 pb-14 lg:pt-32 lg:pb-20"} bg-gradient-to-b from-slate-50 to-white border-b border-slate-100`}>
        <div className="mx-auto max-w-5xl px-6">
          <div className="text-xs font-bold uppercase tracking-[0.2em] text-orange-500 mb-3">Cybersecurity 101</div>
          <h1 className="font-heading text-4xl md:text-5xl lg:text-6xl font-semibold tracking-tight text-slate-900 max-w-3xl">
            Fundamentals every defender should know.
          </h1>
          <p className="mt-5 text-lg text-slate-600 leading-relaxed max-w-3xl">
            NivX Machines&rsquo; knowledge base — practical, long-form explainers on the concepts and attack patterns that show up in real SOC operations. No product pitches, just craft.
          </p>
        </div>
      </section>

      <section className="py-14 lg:py-20" data-testid="kb-index">
        <div className="mx-auto max-w-5xl px-6 grid grid-cols-1 md:grid-cols-2 gap-6">
          {KB_ARTICLES.map((a, i) => (
            <motion.div
              key={a.slug}
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.4, delay: i * 0.05 }}
            >
              <Link
                to={`/cybersecurity-101/${a.slug}`}
                data-testid={`kb-card-${a.slug}`}
                className="group flex flex-col rounded-2xl border border-slate-200 bg-white hover:shadow-xl hover:-translate-y-1 hover:border-slate-300 transition-all overflow-hidden h-full"
              >
                <div className="relative aspect-[16/9] overflow-hidden bg-slate-100">
                  <img src={a.cover} alt={a.title} loading="lazy" className="absolute inset-0 w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" />
                  <div className={`absolute inset-0 bg-gradient-to-t ${a.cover_tone} opacity-60 mix-blend-multiply`} />
                  <div className="absolute top-4 left-4">
                    <span className="inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider bg-white/95 text-slate-900 px-2.5 py-1 rounded shadow-sm">
                      {a.category}
                    </span>
                  </div>
                </div>
                <div className="p-6 flex-1 flex flex-col">
                  <h2 className="font-heading text-xl font-semibold text-slate-900 group-hover:text-[#2E7DF5] transition-colors leading-snug">
                    {a.title}
                  </h2>
                  <p className="mt-3 text-sm text-slate-600 leading-relaxed line-clamp-3 flex-1">{a.tagline}</p>
                  <div className="mt-5 flex items-center justify-between pt-4 border-t border-slate-100">
                    <div className="flex items-center gap-3 text-[11px] text-slate-500">
                      <span className="inline-flex items-center gap-1"><Clock className="w-3 h-3" /> {a.read_mins} min read</span>
                      <span className="inline-flex items-center gap-1"><Calendar className="w-3 h-3" /> Updated {a.updated}</span>
                    </div>
                    <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-[#2E7DF5] group-hover:translate-x-0.5 transition-all" />
                  </div>
                </div>
              </Link>
            </motion.div>
          ))}
        </div>
      </section>

      <Contact />
    </div>
  );
}

function ArticleView({ slug }) {
  const article = findArticle(slug);
  const linkify = useActorLinker();
  useSeo({
    title: article ? `${article.title} | NivX Cybersecurity 101` : "Article not found",
    description: article?.tagline || "NivX Cybersecurity 101 article.",
    canonical: article ? `https://nivxmachines.com/cybersecurity-101/${article.slug}` : undefined,
  });

  if (!article) {
    return (
      <div className="min-h-screen bg-white">
        <Navbar />
        <div className="pt-32 pb-20 mx-auto max-w-3xl px-6 text-center">
          <h1 className="font-heading text-3xl font-semibold text-slate-900">Article not found</h1>
          <p className="mt-3 text-slate-500">The article you&rsquo;re looking for doesn&rsquo;t exist.</p>
          <Link to="/cybersecurity-101" className="mt-6 inline-flex items-center gap-2 text-sm font-semibold text-[#2E7DF5] hover:underline">
            <ArrowLeft className="w-4 h-4" /> Back to Cybersecurity 101
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-white">
      <Navbar />
      {/* Hero */}
      <section className="relative pt-28 pb-16 lg:pt-32 lg:pb-20 overflow-hidden border-b border-slate-100">
        <div className="absolute inset-0">
          <img src={article.cover} alt={article.title} className="w-full h-full object-cover opacity-20" />
          <div className={`absolute inset-0 bg-gradient-to-br ${article.cover_tone} opacity-30`} />
          <div className="absolute inset-0 bg-gradient-to-t from-white via-white/70 to-white/30" />
        </div>
        <div className="relative mx-auto max-w-4xl px-6">
          <Link to="/cybersecurity-101" data-testid="kb-back" className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500 hover:text-[#2E7DF5] mb-6">
            <ArrowLeft className="w-3.5 h-3.5" /> Cybersecurity 101
          </Link>
          <div className="text-xs font-bold uppercase tracking-[0.2em] text-orange-500 mb-3">{article.category}</div>
          <h1 className="font-heading text-3xl md:text-4xl lg:text-5xl font-semibold tracking-tight text-slate-900 leading-tight">
            {article.title}
          </h1>
          <p className="mt-5 text-lg text-slate-600 leading-relaxed max-w-3xl">{linkify(article.tagline)}</p>
          <div className="mt-6 flex items-center gap-4 text-xs text-slate-500">
            <span className="inline-flex items-center gap-1.5"><Clock className="w-3.5 h-3.5" /> {article.read_mins} min read</span>
            <span className="inline-flex items-center gap-1.5"><Calendar className="w-3.5 h-3.5" /> Updated {article.updated}</span>
            <span className="inline-flex items-center gap-1.5"><ShieldCheck className="w-3.5 h-3.5" /> NivX Editorial</span>
          </div>
        </div>
      </section>

      {/* Body */}
      <article className="py-14 lg:py-20" data-testid="kb-article">
        <div className="mx-auto max-w-3xl px-6">
          {/* Summary */}
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-6 mb-12">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">
              <BookOpen className="w-3.5 h-3.5" /> Executive summary
            </div>
            <p className="text-slate-700 leading-relaxed">{linkify(article.summary)}</p>
          </div>

          {/* Sections */}
          {article.sections.map((s, si) => (
            <section key={si} className="mb-12">
              <h2 className="font-heading text-2xl md:text-3xl font-semibold text-slate-900 tracking-tight mb-5">{s.heading}</h2>

              {s.image && (
                <figure className="mb-6 rounded-xl overflow-hidden border border-slate-200 shadow-sm">
                  <img src={s.image} alt={s.heading} loading="lazy" className="w-full aspect-[16/8] object-cover" />
                </figure>
              )}

              {s.body && s.body.map((p, pi) => (
                <p key={pi} className="text-slate-700 leading-relaxed mb-4">{linkify(p)}</p>
              ))}

              {s.subs && (
                <div className="space-y-8 mt-6">
                  {s.subs.map((sub, sbi) => (
                    <div key={sbi}>
                      <h3 className="font-heading text-lg font-semibold text-slate-900 mb-2">{sub.title}</h3>
                      {sub.body.map((p, pi) => (
                        <p key={pi} className="text-slate-700 leading-relaxed mb-3">{linkify(p)}</p>
                      ))}
                    </div>
                  ))}
                </div>
              )}

              {s.list && (
                <ul className="space-y-3 mt-4">
                  {s.list.map((li, lii) => (
                    <li key={lii} className="flex gap-3 items-start">
                      <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-orange-500 shrink-0" />
                      <div>
                        <div className="font-semibold text-slate-900">{linkify(li.t)}</div>
                        <div className="text-slate-600 leading-relaxed mt-0.5">{linkify(li.d)}</div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          ))}

          {/* Related */}
          <div className="mt-16 pt-10 border-t border-slate-200">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-4">Continue learning</div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {KB_ARTICLES.filter((a) => a.slug !== article.slug).slice(0, 3).map((a) => (
                <Link key={a.slug} to={`/cybersecurity-101/${a.slug}`} className="group rounded-lg border border-slate-200 hover:border-slate-300 hover:shadow-md p-4 transition-all">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-orange-500 mb-1.5">{a.category}</div>
                  <div className="font-semibold text-sm text-slate-900 group-hover:text-[#2E7DF5] transition-colors leading-snug">{a.title}</div>
                </Link>
              ))}
            </div>
          </div>
        </div>
      </article>

      <Contact />
    </div>
  );
}

export default function KnowledgeBase({ embedded = false }) {
  const { slug } = useParams();
  return slug ? <ArticleView slug={slug} /> : <IndexView embedded={embedded} />;
}
