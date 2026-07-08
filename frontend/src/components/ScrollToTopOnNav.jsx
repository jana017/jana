import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { useLenis } from "lenis/react";

// Resets scroll to top on every route change. Works with Lenis smooth scroll.
export default function ScrollToTopOnNav() {
  const { pathname } = useLocation();
  const lenis = useLenis();

  useEffect(() => {
    // Instant jump (no smooth animation) so users land at the top of the article.
    if (lenis) lenis.scrollTo(0, { immediate: true });
    else window.scrollTo(0, 0);
  }, [pathname, lenis]);

  return null;
}
