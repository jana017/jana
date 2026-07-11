// ESLint flat config used by the HealthBot's `frontend_lint` check.
// Kept lean & deterministic — only enables page-breaking rules
// (`no-undef`, `react/jsx-no-undef`). Style rules are intentionally out of
// scope: the goal is to catch runtime crashes like the one that
// white-screened /threat-intelligence in production (Feb 2026:
// `ReferenceError: exportRef is not defined`).
import react from "/app/frontend/node_modules/eslint-plugin-react/index.js";

export default [
  {
    files: ["**/*.{js,jsx}"],
    // Skip vendored/built code — HealthBot only cares about our own source.
    ignores: [
      "**/node_modules/**",
      "**/build/**",
      "**/dist/**",
      "**/public/**",
      "**/*.min.js",
    ],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: {
        // DOM / BOM
        window: "readonly", document: "readonly", navigator: "readonly",
        location: "readonly", history: "readonly", performance: "readonly",
        console: "readonly", alert: "readonly", confirm: "readonly", prompt: "readonly",
        localStorage: "readonly", sessionStorage: "readonly",
        // Timers
        setTimeout: "readonly", clearTimeout: "readonly",
        setInterval: "readonly", clearInterval: "readonly",
        requestAnimationFrame: "readonly", cancelAnimationFrame: "readonly",
        requestIdleCallback: "readonly", cancelIdleCallback: "readonly",
        // Fetch/URL/network
        fetch: "readonly", URL: "readonly", URLSearchParams: "readonly",
        AbortController: "readonly", Headers: "readonly", Request: "readonly",
        Response: "readonly", WebSocket: "readonly", EventSource: "readonly",
        // Types & platform APIs
        Blob: "readonly", File: "readonly", FileReader: "readonly", FormData: "readonly",
        Image: "readonly", HTMLElement: "readonly", HTMLInputElement: "readonly",
        HTMLDivElement: "readonly", HTMLAnchorElement: "readonly",
        Event: "readonly", CustomEvent: "readonly", MouseEvent: "readonly",
        KeyboardEvent: "readonly", DragEvent: "readonly",
        // Encoding
        atob: "readonly", btoa: "readonly", TextEncoder: "readonly", TextDecoder: "readonly",
        // Crypto & misc
        crypto: "readonly", queueMicrotask: "readonly", structuredClone: "readonly",
        // Build env
        process: "readonly",
      },
    },
    plugins: { react },
    settings: { react: { version: "detect" } },
    rules: {
      "no-undef": "error",
      "react/jsx-no-undef": "error",
    },
  },
];
