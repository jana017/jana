/**
 * useActorLinker — hook that returns a `linkify(text)` function which auto-
 * detects ThreatBox actor names and aliases in a string and returns JSX with
 * <Link to={`/threatbox/${slug}`}> wrapping each match.
 *
 * Fetches the actor list once and memoises the compiled regex + slug map so
 * it stays in sync with ThreatBox additions without needing to touch Learn
 * articles.
 */
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "@/lib/api";

let CACHE = null;   // process-wide cache — one fetch per SPA session

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export default function useActorLinker() {
  const [actors, setActors] = useState(CACHE);

  useEffect(() => {
    if (CACHE) return;
    api.get("/actors")
      .then(({ data }) => { CACHE = data.actors || []; setActors(CACHE); })
      .catch(() => { CACHE = []; setActors([]); });
  }, []);

  // Build a canonical-name -> slug map. Include primary name + all aliases.
  // Longest tokens first so "APT41 (Double Dragon)" matches before "APT41".
  const { regex, slugMap } = useMemo(() => {
    if (!actors || actors.length === 0) return { regex: null, slugMap: {} };
    const map = {};
    const tokens = new Set();
    for (const a of actors) {
      const primaries = [a.name, ...(a.aliases || [])].filter(Boolean);
      for (const t of primaries) {
        // Skip generic aliases likely to overmatch inside common prose
        if (t.length < 3) continue;
        if (["APT", "FIN", "TA", "UNC"].includes(t.toUpperCase())) continue;
        map[t.toLowerCase()] = a.slug;
        tokens.add(t);
      }
    }
    const sorted = Array.from(tokens).sort((a, b) => b.length - a.length);
    if (sorted.length === 0) return { regex: null, slugMap: map };
    // Word-boundary regex; case-insensitive. Escapes special regex chars.
    const pattern = new RegExp(`\\b(${sorted.map(escapeRegExp).join("|")})\\b`, "gi");
    return { regex: pattern, slugMap: map };
  }, [actors]);

  const linkify = useMemo(() => {
    return function linkify(text) {
      if (!text || !regex) return text;
      const parts = [];
      let lastIdx = 0;
      let m;
      // Reset lastIndex to be safe when regex is reused across renders
      regex.lastIndex = 0;
      const seen = new Set();  // Only link the FIRST occurrence per article per actor
      while ((m = regex.exec(text)) !== null) {
        const matched = m[0];
        const slug = slugMap[matched.toLowerCase()];
        if (!slug || seen.has(slug)) {
          if (m.index === regex.lastIndex) regex.lastIndex++;
          continue;
        }
        seen.add(slug);
        if (m.index > lastIdx) parts.push(text.slice(lastIdx, m.index));
        parts.push(
          <Link
            key={`${slug}-${m.index}`}
            to={`/threatbox/${slug}`}
            data-testid={`learn-actor-link-${slug}`}
            className="text-[#2E7DF5] hover:text-[#DC2626] hover:underline font-medium"
            title={`View ${matched} dossier in ThreatBox`}
          >
            {matched}
          </Link>
        );
        lastIdx = m.index + matched.length;
      }
      if (lastIdx < text.length) parts.push(text.slice(lastIdx));
      return parts.length > 1 ? parts : text;
    };
  }, [regex, slugMap]);

  return linkify;
}
