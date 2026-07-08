import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Clock, Calendar, BookOpen, ShieldCheck } from "lucide-react";
import Navbar from "@/components/Navbar";
import Contact from "@/components/Contact";
import { BLOG_POSTS, findBlogPost } from "@/lib/blogPosts";
import useSeo from "@/lib/useSeo";

export default function BlogPost() {
  const { slug } = useParams();
  const article = findBlogPost(slug);

  useSeo({
    title: article ? `${article.title} | NivX Machines Blog` : "Article not found",
    description: article?.excerpt || "NivX Machines blog article.",
    canonical: article ? `https://nivxmachines.com/blog/${article.slug}` : undefined,
  });

  if (!article) {
    return (
      <div className="min-h-screen bg-white">
        <Navbar />
        <div className="pt-32 pb-20 mx-auto max-w-3xl px-6 text-center">
          <h1 className="font-heading text-3xl font-semibold text-slate-900">Article not found</h1>
          <p className="mt-3 text-slate-500">The article you&rsquo;re looking for doesn&rsquo;t exist.</p>
          <Link to="/#blog" className="mt-6 inline-flex items-center gap-2 text-sm font-semibold text-[#2E7DF5] hover:underline">
            <ArrowLeft className="w-4 h-4" /> Back to NivX Blogs
          </Link>
        </div>
      </div>
    );
  }

  const related = BLOG_POSTS.filter((p) => p.slug !== article.slug).slice(0, 3);

  return (
    <div className="min-h-screen bg-white">
      <Navbar />

      {/* Hero */}
      <section className="relative pt-28 pb-16 lg:pt-32 lg:pb-20 overflow-hidden border-b border-slate-100">
        <div className="absolute inset-0">
          <img src={article.image} alt={article.title} className="w-full h-full object-cover opacity-25" />
          <div className="absolute inset-0 bg-gradient-to-t from-white via-white/85 to-white/50" />
        </div>
        <div className="relative mx-auto max-w-4xl px-6">
          <Link to="/#blog" data-testid="blog-back" className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-500 hover:text-[#2E7DF5] mb-6">
            <ArrowLeft className="w-3.5 h-3.5" /> NivX Blogs
          </Link>
          <div className="text-xs font-bold uppercase tracking-[0.2em] text-orange-500 mb-3">{article.category}</div>
          <h1 className="font-heading text-3xl md:text-4xl lg:text-5xl font-semibold tracking-tight text-slate-900 leading-tight">
            {article.title}
          </h1>
          <p className="mt-5 text-lg text-slate-600 leading-relaxed max-w-3xl">{article.excerpt}</p>
          <div className="mt-6 flex items-center gap-4 text-xs text-slate-500 flex-wrap">
            <span className="inline-flex items-center gap-1.5"><Calendar className="w-3.5 h-3.5" /> {article.date}</span>
            <span className="inline-flex items-center gap-1.5"><Clock className="w-3.5 h-3.5" /> {article.read_mins} min read</span>
            <span className="inline-flex items-center gap-1.5"><ShieldCheck className="w-3.5 h-3.5" /> NivX Editorial</span>
          </div>
        </div>
      </section>

      {/* Body */}
      <article className="py-14 lg:py-20" data-testid="blog-article">
        <div className="mx-auto max-w-3xl px-6">
          {/* At-a-glance */}
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-6 mb-12">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">
              <BookOpen className="w-3.5 h-3.5" /> At a glance
            </div>
            <p className="text-slate-700 leading-relaxed">{article.excerpt}</p>
          </div>

          {article.sections.map((s, si) => (
            <section key={si} className="mb-12">
              <h2 className="font-heading text-2xl md:text-3xl font-semibold text-slate-900 tracking-tight mb-5">{s.heading}</h2>
              {s.body && s.body.map((p, pi) => (
                <p key={pi} className="text-slate-700 leading-relaxed mb-4">{p}</p>
              ))}
              {s.list && (
                <ul className="space-y-3 mt-4">
                  {s.list.map((li, lii) => (
                    <li key={lii} className="flex gap-3 items-start">
                      <span className="mt-1.5 w-1.5 h-1.5 rounded-full bg-orange-500 shrink-0" />
                      <div>
                        <div className="font-semibold text-slate-900">{li.t}</div>
                        <div className="text-slate-600 leading-relaxed mt-0.5">{li.d}</div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          ))}

          {/* Related */}
          <div className="mt-16 pt-10 border-t border-slate-200">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-4">Keep reading</div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {related.map((a) => (
                <Link key={a.slug} to={`/blog/${a.slug}`} className="group rounded-lg border border-slate-200 hover:border-slate-300 hover:shadow-md p-4 transition-all">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-orange-500 mb-1.5">{a.category}</div>
                  <div className="font-semibold text-sm text-slate-900 group-hover:text-[#2E7DF5] transition-colors leading-snug">{a.title}</div>
                  <div className="mt-2 text-[11px] text-slate-500 inline-flex items-center gap-1"><Clock className="w-3 h-3" /> {a.read_mins} min read</div>
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
