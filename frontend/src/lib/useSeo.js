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

export default function useSeo({ title, description, canonical, noindex = false, ogImage, ogType, twitterCard }) {
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
      upsertMeta(
        'meta[name="twitter:description"]',
        () => Object.assign(document.createElement("meta"), { name: "twitter:description" }),
        (el) => el.setAttribute("content", description),
      );
    }

    if (title) {
      upsertMeta(
        'meta[property="og:title"]',
        () => { const m = document.createElement("meta"); m.setAttribute("property", "og:title"); return m; },
        (el) => el.setAttribute("content", title),
      );
      upsertMeta(
        'meta[name="twitter:title"]',
        () => Object.assign(document.createElement("meta"), { name: "twitter:title" }),
        (el) => el.setAttribute("content", title),
      );
    }

    if (canonical) {
      upsertMeta(
        'link[rel="canonical"]',
        () => Object.assign(document.createElement("link"), { rel: "canonical" }),
        (el) => el.setAttribute("href", canonical),
      );
      upsertMeta(
        'meta[property="og:url"]',
        () => { const m = document.createElement("meta"); m.setAttribute("property", "og:url"); return m; },
        (el) => el.setAttribute("content", canonical),
      );
    }

    if (ogImage) {
      upsertMeta(
        'meta[property="og:image"]',
        () => { const m = document.createElement("meta"); m.setAttribute("property", "og:image"); return m; },
        (el) => el.setAttribute("content", ogImage),
      );
      upsertMeta(
        'meta[property="og:image:width"]',
        () => { const m = document.createElement("meta"); m.setAttribute("property", "og:image:width"); return m; },
        (el) => el.setAttribute("content", "1200"),
      );
      upsertMeta(
        'meta[property="og:image:height"]',
        () => { const m = document.createElement("meta"); m.setAttribute("property", "og:image:height"); return m; },
        (el) => el.setAttribute("content", "630"),
      );
      upsertMeta(
        'meta[name="twitter:image"]',
        () => Object.assign(document.createElement("meta"), { name: "twitter:image" }),
        (el) => el.setAttribute("content", ogImage),
      );
    }

    if (ogType) {
      upsertMeta(
        'meta[property="og:type"]',
        () => { const m = document.createElement("meta"); m.setAttribute("property", "og:type"); return m; },
        (el) => el.setAttribute("content", ogType),
      );
    }

    if (twitterCard) {
      upsertMeta(
        'meta[name="twitter:card"]',
        () => Object.assign(document.createElement("meta"), { name: "twitter:card" }),
        (el) => el.setAttribute("content", twitterCard),
      );
    }

    upsertMeta(
      'meta[name="robots"]',
      () => Object.assign(document.createElement("meta"), { name: "robots" }),
      (el) => el.setAttribute("content", noindex ? "noindex,nofollow" : "index,follow"),
    );
  }, [title, description, canonical, noindex, ogImage, ogType, twitterCard]);
}
