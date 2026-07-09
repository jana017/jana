import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Clock, Calendar, BookOpen, ShieldCheck, AlertTriangle, Terminal, Network } from "lucide-react";
import Navbar from "@/components/Navbar";
import Contact from "@/components/Contact";
import { BLOG_POSTS, findBlogPost } from "@/lib/blogPosts";
import useSeo from "@/lib/useSeo";

// --- Rich section blocks --------------------------------------------------
function CodeBlock({ language, code }) {
  return (
    <div className="my-4 rounded-lg overflow-hidden border border-slate-800 bg-[#0d1424]" data-testid="code-block">
      {language && (
        <div className="flex items-center justify-between px-3 py-1.5 border-b border-slate-800 bg-[#0a1120]">
          <span className="inline-flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400">
            <Terminal className="w-3 h-3" /> {language}
          </span>
        </div>
      )}
      <pre className="px-4 py-3 text-[12.5px] leading-relaxed text-slate-200 overflow-x-auto font-mono-data whitespace-pre">
{code}
      </pre>
    </div>
  );
}

function DataTable({ headers, rows }) {
  return (
    <div className="my-5 overflow-x-auto rounded-lg border border-slate-200" data-testid="data-table">
      <table className="w-full text-sm">
        <thead className="bg-slate-100 text-slate-700">
          <tr>
            {headers.map((h, i) => (
              <th key={i} className="px-3 py-2.5 text-left font-semibold text-xs uppercase tracking-wider">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, ri) => (
            <tr key={ri} className={ri % 2 === 0 ? "bg-white" : "bg-slate-50/50"}>
              {r.map((c, ci) => (
                <td key={ci} className="px-3 py-2.5 text-slate-700 align-top">
                  {typeof c === "string" && c.startsWith("mono:") ? (
                    <span className="font-mono-data text-[12.5px]">{c.slice(5)}</span>
                  ) : (
                    c
                  )}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Callout({ tone = "warn", title, body }) {
  const toneMap = {
    warn:   { wrap: "border-orange-200 bg-orange-50", title: "text-orange-700", body: "text-orange-900" },
    danger: { wrap: "border-red-200 bg-red-50",       title: "text-red-700",   body: "text-red-900" },
    info:   { wrap: "border-blue-200 bg-blue-50",     title: "text-blue-700",  body: "text-blue-900" },
  }[tone] || {};
  return (
    <div className={`my-5 rounded-lg border ${toneMap.wrap} p-4 flex gap-3`} data-testid={`callout-${tone}`}>
      <AlertTriangle className={`w-5 h-5 shrink-0 ${toneMap.title}`} />
      <div>
        {title && <div className={`text-sm font-bold uppercase tracking-wider mb-1 ${toneMap.title}`}>{title}</div>}
        <div className={`text-sm leading-relaxed ${toneMap.body}`}>{body}</div>
      </div>
    </div>
  );
}

function ProcessTree({ title, nodes }) {
  // nodes: [{ p: "winword.exe", label?: "Office parent", suspect?: true, children: [...] }]
  const renderNode = (n, depth = 0, isLast = true, prefix = "") => {
    const connector = depth === 0 ? "" : (isLast ? "└─ " : "├─ ");
    const linePrefix = prefix + connector;
    return (
      <div key={`${n.p}-${depth}-${Math.random()}`} className="whitespace-pre">
        <span className="text-slate-500">{linePrefix}</span>
        <span className={n.suspect ? "text-orange-400 font-semibold" : "text-slate-200"}>{n.p}</span>
        {n.label && <span className="text-slate-500 ml-2 italic">— {n.label}</span>}
        {n.children && n.children.map((c, i) =>
          renderNode(c, depth + 1, i === n.children.length - 1, prefix + (isLast ? "   " : "│  "))
        )}
      </div>
    );
  };
  return (
    <div className="my-5 rounded-lg overflow-hidden border border-slate-800 bg-[#0d1424]" data-testid="process-tree">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-slate-800 bg-[#0a1120]">
        <span className="inline-flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400">
          <Network className="w-3 h-3" /> {title || "Process tree"}
        </span>
      </div>
      <div className="px-4 py-3 text-[13px] leading-6 font-mono-data">
        {nodes.map((n, i) => renderNode(n, 0, i === nodes.length - 1))}
      </div>
    </div>
  );
}

function SectionImage({ src, alt, caption }) {
  return (
    <figure className="my-6" data-testid="section-image">
      <img src={src} alt={alt} loading="lazy" className="w-full rounded-lg border border-slate-200" />
      {caption && <figcaption className="mt-2 text-xs text-slate-500 text-center italic">{caption}</figcaption>}
    </figure>
  );
}

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

  const related = BLOG_POSTS.filter((p) => p.slug !== article.slug && !p.hidden_from_landing).slice(0, 3);

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
              {s.image && <SectionImage {...s.image} />}
              {s.callout && <Callout {...s.callout} />}
              {s.code && <CodeBlock {...s.code} />}
              {s.tree && <ProcessTree {...s.tree} />}
              {s.table && <DataTable {...s.table} />}
              {s.blocks && s.blocks.map((b, bi) => {
                if (b.type === "p") return <p key={bi} className="text-slate-700 leading-relaxed mb-4">{b.text}</p>;
                if (b.type === "code") return <CodeBlock key={bi} language={b.language} code={b.code} />;
                if (b.type === "callout") return <Callout key={bi} tone={b.tone} title={b.title} body={b.body} />;
                if (b.type === "tree") return <ProcessTree key={bi} title={b.title} nodes={b.nodes} />;
                if (b.type === "table") return <DataTable key={bi} headers={b.headers} rows={b.rows} />;
                if (b.type === "image") return <SectionImage key={bi} src={b.src} alt={b.alt} caption={b.caption} />;
                if (b.type === "h3") return <h3 key={bi} className="font-heading text-xl font-semibold text-slate-900 mt-6 mb-3">{b.text}</h3>;
                if (b.type === "list") return (
                  <ul key={bi} className="space-y-2 mt-3 mb-3">
                    {b.items.map((it, ii) => (
                      <li key={ii} className="flex gap-3 items-start">
                        <span className="mt-2 w-1.5 h-1.5 rounded-full bg-orange-500 shrink-0" />
                        <div className="text-slate-700 leading-relaxed">{typeof it === "string" ? it : <><span className="font-semibold text-slate-900">{it.t}</span>{it.d && <> — {it.d}</>}</>}</div>
                      </li>
                    ))}
                  </ul>
                );
                return null;
              })}
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
