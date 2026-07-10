/**
 * CmsPage — public renderer for custom Markdown pages created in the
 * Developer admin tab. Fetches /api/cms/pages/:slug and injects the
 * pre-rendered HTML (server sanitizes + converts markdown → HTML).
 */
import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import axios from "axios";
import Navbar from "@/components/Navbar";
import { ArrowLeft } from "lucide-react";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || "";

export default function CmsPage() {
  const { slug } = useParams();
  const [page, setPage] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setPage(null);
    setError(null);
    axios
      .get(`${BACKEND_URL}/api/cms/pages/${slug}`)
      .then(({ data }) => setPage(data))
      .catch((e) => setError(e.response?.status === 404 ? "not_found" : "error"));
  }, [slug]);

  return (
    <div className="min-h-screen bg-white text-slate-900" data-testid="cms-page">
      <Navbar />
      <main className="mx-auto max-w-3xl px-6 py-16">
        <Link to="/" className="inline-flex items-center gap-1 text-xs font-semibold text-slate-500 hover:text-[#2E7DF5] mb-6">
          <ArrowLeft className="w-3 h-3" /> Home
        </Link>
        {error === "not_found" && (
          <div className="py-16 text-center">
            <h1 className="text-4xl font-heading font-bold text-slate-800">404</h1>
            <p className="text-sm text-slate-500 mt-2">
              No page found at <code className="text-slate-700 font-mono">/pages/{slug}</code>.
            </p>
          </div>
        )}
        {error === "error" && (
          <div className="py-16 text-center text-sm text-rose-500">
            Failed to load page.
          </div>
        )}
        {!error && !page && (
          <div className="py-16 text-center text-sm text-slate-400">Loading…</div>
        )}
        {page && (
          <article className="prose prose-slate max-w-none prose-headings:font-heading prose-a:text-[#2E7DF5] prose-code:before:hidden prose-code:after:hidden prose-code:bg-slate-100 prose-code:px-1 prose-code:py-0.5 prose-code:rounded">
            <h1 className="mb-6 font-heading text-4xl font-bold">{page.title}</h1>
            <div
              data-testid="cms-page-content"
              dangerouslySetInnerHTML={{ __html: page.html_body }}
            />
          </article>
        )}
      </main>
    </div>
  );
}
