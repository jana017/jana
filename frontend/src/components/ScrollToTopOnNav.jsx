import { useEffect } from "react";
import { useLocation } from "react-router-dom";
import { useLenis } from "lenis/react";

// Resets scroll on every route change.
// - If a hash is present (e.g. /#blog), scroll to that element instead of the top.
// - Otherwise, jump to the top of the page (works with Lenis smooth scroll).
export default function ScrollToTopOnNav() {
  const { pathname, hash } = useLocation();
  const lenis = useLenis();

  useEffect(() => {
    if (hash) {
      // Poll for the target element since the destination route may be lazy-loaded,
      // then re-scroll a few times to compensate for late layout shifts (images/lazy sections).
      const id = hash.replace("#", "");
      let attempts = 0;
      const maxAttempts = 40; // ~2s to find element
      const timers = [];
      const doScroll = () => {
        const el = document.getElementById(id);
        if (!el) return;
        if (lenis) lenis.scrollTo(el, { immediate: true, offset: -80 });
        else el.scrollIntoView({ block: "start" });
      };
      const tryScroll = () => {
        const el = document.getElementById(id);
        if (el) {
          doScroll();
          // Re-scroll after likely layout shifts (images, lazy sections).
          [150, 400, 800, 1400].forEach((ms) => {
            timers.push(setTimeout(doScroll, ms));
          });
          return;
        }
        if (attempts++ < maxAttempts) {
          timers.push(setTimeout(tryScroll, 50));
        } else if (lenis) {
          lenis.scrollTo(0, { immediate: true });
        } else {
          window.scrollTo(0, 0);
        }
      };
      timers.push(setTimeout(tryScroll, 30));
      return () => timers.forEach(clearTimeout);
    }

    // No hash → instant jump to the top.
    if (lenis) lenis.scrollTo(0, { immediate: true });
    else window.scrollTo(0, 0);
  }, [pathname, hash, lenis]);

  return null;
}
