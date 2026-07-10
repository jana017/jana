/**
 * useBrandingInjection — public hook that fetches CMS branding on app load
 * and injects `custom_css` + `custom_js` into the document. Also sets the
 * favicon when configured. Cheap, cached, and safe to call from App.js.
 */
import { useEffect } from "react";
import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || "";

export default function useBrandingInjection() {
  useEffect(() => {
    let cssEl, jsEl;
    let cancelled = false;
    axios
      .get(`${BACKEND_URL}/api/cms/branding`)
      .then(({ data }) => {
        if (cancelled) return;
        // Site title
        if (data.site_title) document.title = data.site_title;
        // Favicon
        if (data.favicon_url) {
          const href = data.favicon_url.startsWith("http") ? data.favicon_url : BACKEND_URL + data.favicon_url;
          let link = document.querySelector('link[rel="icon"]');
          if (!link) {
            link = document.createElement("link");
            link.rel = "icon";
            document.head.appendChild(link);
          }
          link.href = href;
        }
        // Custom CSS
        if (data.custom_css) {
          cssEl = document.createElement("style");
          cssEl.setAttribute("data-nivx-custom", "css");
          cssEl.textContent = data.custom_css;
          document.head.appendChild(cssEl);
        }
        // Custom JS — appended at end of body so DOM is ready
        if (data.custom_js) {
          jsEl = document.createElement("script");
          jsEl.setAttribute("data-nivx-custom", "js");
          jsEl.textContent = data.custom_js;
          document.body.appendChild(jsEl);
        }
      })
      .catch(() => { /* silent — branding is optional */ });
    return () => {
      cancelled = true;
      cssEl?.remove();
      jsEl?.remove();
    };
  }, []);
}
