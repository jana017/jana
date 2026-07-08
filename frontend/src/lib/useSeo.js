import { useEffect } from "react";

// Lightweight per-page SEO manager (no react-helmet dependency).
// Sets <title>, <meta name="description">, canonical, OG title/desc, and robots noindex
// tags directly on document.head. Safe for SPA route changes.

function upsertMeta(selector, createEl, apply) {
  let el = document.head.querySelector(selector);
  if (!el) {
    el = createEl();
    document.head.appendChild(el);
  }
  apply(el);
}

export default function useSeo({ title, description, canonical, noindex = false }) {
  useEffect(() => {
    if (title) document.title = title;

    if (description) {
      upsertMeta(
        'meta[name="description"]',
        () => Object.assign(document.createElement("meta"), { name: "description" }),
        (el) => el.setAttribute("content", description),
      );
      upsertMeta(
        'meta[property="og:description"]',
        () => { const m = document.createElement("meta"); m.setAttribute("property", "og:description"); return m; },
        (el) => el.setAttribute("content", description),
      );
    }

    if (title) {
      upsertMeta(
        'meta[property="og:title"]',
        () => { const m = document.createElement("meta"); m.setAttribute("property", "og:title"); return m; },
        (el) => el.setAttribute("content", title),
      );
    }

    if (canonical) {
      upsertMeta(
        'link[rel="canonical"]',
        () => Object.assign(document.createElement("link"), { rel: "canonical" }),
        (el) => el.setAttribute("href", canonical),
      );
    }

    upsertMeta(
      'meta[name="robots"]',
      () => Object.assign(document.createElement("meta"), { name: "robots" }),
      (el) => el.setAttribute("content", noindex ? "noindex,nofollow" : "index,follow"),
    );
  }, [title, description, canonical, noindex]);
}
