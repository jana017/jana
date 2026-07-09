// Route chunk prefetchers — imported by the Navbar to warm up lazy chunks
// on hover / focus, so the actual click navigation is near-instant.
// Uses the same dynamic import as App.js so webpack dedupes to a single chunk.

const prefetchers = {
  "/": () => import(/* webpackPrefetch: true */ "@/pages/Landing"),
  "/threat-intelligence": () => import(/* webpackPrefetch: true */ "@/pages/ThreatIntelligence"),
  "/cybersecurity-101": () => import(/* webpackPrefetch: true */ "@/pages/KnowledgeBase"),
  "/blog": () => import(/* webpackPrefetch: true */ "@/pages/BlogIndex"),
  "/blog/:slug": () => import(/* webpackPrefetch: true */ "@/pages/BlogPost"),
  "/admin": () => import(/* webpackPrefetch: true */ "@/pages/Admin"),
};

const warmed = new Set();

export function prefetchRoute(path) {
  const fn = prefetchers[path] || prefetchers[Object.keys(prefetchers).find((k) => path.startsWith(k))];
  if (!fn || warmed.has(path)) return;
  warmed.add(path);
  fn().catch(() => warmed.delete(path));
}
