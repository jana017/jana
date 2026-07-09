/**
 * Client-side payload operations for the NivX Payload Lab.
 * Every operation is a pure function: (input: string, params: object) => string
 * All processing stays in the browser — malware payloads NEVER leave the page.
 */
import CryptoJS from "crypto-js";

/* --------------------------------- helpers --------------------------------- */
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: false });
const utf16leDecoder = new TextDecoder("utf-16le", { fatal: false });

/* Score a decoded string by how many printable-ish chars it contains.
 * Higher = better. Used to auto-pick between UTF-8 and UTF-16LE. */
const printableScore = (s) => {
  if (!s) return 0;
  let ok = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 160) ok++;
  }
  return ok / s.length;
};

/* Decode a byte array as either UTF-8 or UTF-16LE — whichever yields more
 * printable text. Also considers an "ASCII-only" fallback that filters out
 * nulls and non-ASCII bytes, which repairs *corrupted* UTF-16LE payloads
 * (common when a PowerShell `-EncodedCommand` was mangled during copy/paste
 * and one byte got dropped, shifting the alignment and producing CJK glyphs). */
const bytesToBestText = (bytes) => {
  // Trim trailing NULs
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0) end--;
  const trimmed = bytes.subarray(0, end);
  const utf8 = decoder.decode(trimmed);
  // UTF-16LE requires even byte length; if odd, drop the last byte.
  const evenLen = trimmed.length - (trimmed.length % 2);
  const utf16 = evenLen > 0 ? utf16leDecoder.decode(trimmed.subarray(0, evenLen)) : "";
  // ASCII-only fallback — keep printable ASCII + tab/CR/LF, drop everything else.
  // Repairs corrupted UTF-16LE where alignment slipped by one byte.
  let asciiOnly = "";
  for (let i = 0; i < trimmed.length; i++) {
    const b = trimmed[i];
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127)) asciiOnly += String.fromCharCode(b);
  }
  const s8  = printableScore(utf8);
  const s16 = printableScore(utf16);
  const sa  = printableScore(asciiOnly);
  // Detect "corrupted UTF-16LE" — high overall score but with rogue non-Latin
  // codepoints (CJK / symbols) sprinkled between ASCII. In that case the
  // ASCII-only fallback recovers the intended string cleanly.
  const utf16NonLatin = utf16 ? [...utf16].filter((ch) => ch.charCodeAt(0) > 0x02FF).length : 0;
  const utf16LatinRatio = utf16 ? (utf16.length - utf16NonLatin) / utf16.length : 0;
  const utf16LooksCorrupt = utf16 && utf16NonLatin > 0 && utf16LatinRatio > 0.6 && sa >= 0.9;
  if (utf16LooksCorrupt && asciiOnly.length >= utf16.length * 0.8) return asciiOnly;
  if (sa > Math.max(s8, s16) + 0.1 && asciiOnly.length >= trimmed.length * 0.3) return asciiOnly;
  return s16 > s8 + 0.05 ? utf16 : utf8;
};

const bufToHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const hexToBytes = (hex) => {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
};
const b64ToBytes = (b64) => {
  // Lenient: strip non-Base64 chars, trim to nearest multiple of 4, then pad.
  // This survives real-world corruption from copy-paste (PowerShell payloads
  // from PDFs / terminals often gain/lose a character mid-blob).
  let clean = String(b64).replace(/[^A-Za-z0-9+/_=-]/g, "").replace(/-/g, "+").replace(/_/g, "/");
  // Strip trailing equals then re-pad correctly.
  clean = clean.replace(/=+$/g, "");
  const rem = clean.length % 4;
  if (rem === 1) clean = clean.slice(0, -1);          // 4k+1 is impossible; drop 1 char
  clean = clean + "=".repeat((4 - (clean.length % 4)) % 4);
  try {
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    // Second-chance: decode in blocks, skip broken ones.
    const chunks = [];
    for (let i = 0; i < clean.length; i += 4) {
      const chunk = clean.substr(i, 4).padEnd(4, "=");
      try {
        const bin = atob(chunk);
        for (let j = 0; j < bin.length; j++) chunks.push(bin.charCodeAt(j));
      } catch { /* skip broken block */ }
    }
    return new Uint8Array(chunks);
  }
};
const bytesToB64 = (bytes) => btoa(String.fromCharCode(...bytes));
const asyncHash = async (algo, input) => bufToHex(await crypto.subtle.digest(algo, encoder.encode(input)));

/* --------------------------------- ops ------------------------------------- */
/* Extract the longest run of Base64-looking chars from a mixed string —
 * lets "From Base64" work on command lines that contain a Base64 blob
 * (like PowerShell `-EncodedCommand …` or Windows exec strings). */
const findB64Blob = (s) => {
  const matches = String(s).match(/[A-Za-z0-9+/=_-]{16,}/g) || [];
  if (!matches.length) return null;
  return matches.reduce((a, b) => (b.length > a.length ? b : a));
};

const ops = {
  /* ---------- Encoding ---------- */
  "base64-encode": {
    name: "To Base64", category: "Encoding",
    desc: "Encode UTF-8 text or bytes as standard Base64.",
    async run(input) { return btoa(unescape(encodeURIComponent(input))); },
  },
  "base64-decode": {
    name: "From Base64", category: "Encoding",
    desc: "Decode standard or URL-safe Base64. Auto-detects UTF-8 vs UTF-16LE (Windows strings), and auto-extracts the Base64 blob if the input contains surrounding text.",
    async run(input) {
      const raw = input.trim().replace(/\s+/g, "");
      const looksClean = /^[A-Za-z0-9+/_=-]+$/.test(raw) && raw.length > 0;
      const decodeSmart = (s) => {
        const bytes = b64ToBytes(s.replace(/-/g, "+").replace(/_/g, "/"));
        return bytesToBestText(bytes);
      };
      if (looksClean) return decodeSmart(raw);
      const blob = findB64Blob(input.replace(/\s+/g, ""));
      if (!blob) throw new Error("No Base64 substring found in input.");
      return decodeSmart(blob);
    },
  },
  "base64-decode-utf16": {
    name: "From Base64 · UTF-16LE (forced)", category: "Encoding",
    desc: "Decode Base64 → UTF-16 Little Endian. Use when auto-detect picks the wrong encoding (common for Windows registry strings and .exe SESSION tokens).",
    async run(input) {
      const raw = input.trim().replace(/\s+/g, "");
      const b64 = /^[A-Za-z0-9+/_=-]+$/.test(raw) ? raw : (findB64Blob(input.replace(/\s+/g, "")) || raw);
      const bytes = b64ToBytes(b64.replace(/-/g, "+").replace(/_/g, "/"));
      // Trim trailing NULs and enforce even length.
      let end = bytes.length;
      while (end > 0 && bytes[end - 1] === 0) end--;
      const even = end - (end % 2);
      return utf16leDecoder.decode(bytes.subarray(0, even));
    },
  },
  "url-encode": {
    name: "URL Encode", category: "Encoding",
    desc: "Percent-encode reserved characters for use in URLs.",
    async run(input) { return encodeURIComponent(input); },
  },
  "url-decode": {
    name: "URL Decode", category: "Encoding",
    desc: "Reverse percent-encoding.",
    async run(input) { try { return decodeURIComponent(input); } catch { return input; } },
  },
  "hex-encode": {
    name: "To Hex", category: "Encoding",
    desc: "Convert UTF-8 text to hexadecimal (no delimiter).",
    async run(input) { return bufToHex(encoder.encode(input)); },
  },
  "hex-decode": {
    name: "From Hex", category: "Encoding",
    desc: "Convert hex string back to text. Auto-detects UTF-8 vs UTF-16LE. Non-hex chars are ignored.",
    async run(input) { return bytesToBestText(hexToBytes(input)); },
  },
  "html-entity-decode": {
    name: "HTML Entity Decode", category: "Encoding",
    desc: "Decode HTML entities like &amp; &#x41; &#65;",
    async run(input) {
      const t = document.createElement("textarea"); t.innerHTML = input; return t.value;
    },
  },
  "unicode-escape-decode": {
    name: "Unicode Escape Decode", category: "Encoding",
    desc: "Decode \\uXXXX and \\xXX escape sequences.",
    async run(input) {
      return input
        .replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
        .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    },
  },
  "charcode-to-string": {
    name: "CharCode → String", category: "Encoding",
    desc: "Convert decimal char codes separated by spaces/commas/newlines to text.",
    async run(input) {
      return input.split(/[\s,]+/).filter(Boolean).map((n) => String.fromCharCode(parseInt(n, 10))).join("");
    },
  },

  /* ---------- Cryptography ---------- */
  "xor-single": {
    name: "XOR (single byte key)", category: "Cryptography",
    desc: "XOR every byte with a single hex key (e.g. 0x2A).",
    params: { key: "2A" },
    async run(input, { key }) {
      const k = parseInt(String(key).replace(/^0x/, ""), 16) & 0xff;
      const bytes = encoder.encode(input);
      const out = new Uint8Array(bytes.length);
      for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ k;
      return decoder.decode(out);
    },
  },
  "xor-key": {
    name: "XOR (repeating key)", category: "Cryptography",
    desc: "XOR the input against a repeating ASCII key.",
    params: { key: "" },
    async run(input, { key }) {
      if (!key) return input;
      const bytes = encoder.encode(input);
      const kb = encoder.encode(key);
      const out = new Uint8Array(bytes.length);
      for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ kb[i % kb.length];
      return decoder.decode(out);
    },
  },
  "rot13": {
    name: "ROT13", category: "Cryptography",
    desc: "Rotate letters by 13 positions.",
    async run(input) { return input.replace(/[a-zA-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + (c.toLowerCase() < "n" ? 13 : -13))); },
  },
  "rot47": {
    name: "ROT47", category: "Cryptography",
    desc: "Rotate printable ASCII (33-126) by 47.",
    async run(input) {
      return [...input].map((ch) => { const c = ch.charCodeAt(0); return (c >= 33 && c <= 126) ? String.fromCharCode(33 + ((c + 14) % 94)) : ch; }).join("");
    },
  },
  "caesar": {
    name: "Caesar cipher", category: "Cryptography",
    desc: "Shift letters by N positions.",
    params: { shift: 3 },
    async run(input, { shift }) {
      const s = ((parseInt(shift, 10) || 0) % 26 + 26) % 26;
      return input.replace(/[a-zA-Z]/g, (c) => { const base = c < "a" ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - base + s) % 26) + base); });
    },
  },
  "aes-decrypt-b64": {
    name: "AES-CBC decrypt (Base64)", category: "Cryptography",
    desc: "Decrypt Base64 ciphertext with a passphrase (OpenSSL-compatible AES-256-CBC).",
    params: { passphrase: "" },
    async run(input, { passphrase }) {
      if (!passphrase) return "[AES] Passphrase required.";
      try { const bytes = CryptoJS.AES.decrypt(input.trim(), passphrase); return bytes.toString(CryptoJS.enc.Utf8) || "[AES] Empty or wrong key."; }
      catch (e) { return `[AES] ${e.message}`; }
    },
  },

  /* ---------- Compression ---------- */
  "gzip-decompress-hex": {
    name: "Gzip decompress (from Hex)", category: "Compression",
    desc: "Decompress a gzip payload provided as hex. Uses native DecompressionStream.",
    async run(input) {
      try {
        const bytes = hexToBytes(input);
        const ds = new DecompressionStream("gzip");
        const stream = new Blob([bytes]).stream().pipeThrough(ds);
        return await new Response(stream).text();
      } catch (e) { return `[Gzip] ${e.message}`; }
    },
  },
  "gzip-decompress-b64": {
    name: "Gzip decompress (from Base64)", category: "Compression",
    desc: "Decompress a gzip payload provided as Base64. Auto-extracts the Base64 blob if the input contains surrounding text. Common in PowerShell payloads.",
    async run(input) {
      try {
        const clean = input.trim().replace(/\s+/g, "");
        const b64 = /^[A-Za-z0-9+/_=-]+$/.test(clean) ? clean : (findB64Blob(clean) || clean);
        const bytes = b64ToBytes(b64);
        const ds = new DecompressionStream("gzip");
        const stream = new Blob([bytes]).stream().pipeThrough(ds);
        return await new Response(stream).text();
      } catch (e) { return `[Gzip] ${e.message}`; }
    },
  },
  "zlib-decompress-b64": {
    name: "Zlib inflate (from Base64)", category: "Compression",
    desc: "Inflate a raw-deflate/zlib payload provided as Base64. Auto-extracts the Base64 blob if the input contains surrounding text.",
    async run(input) {
      try {
        const clean = input.trim().replace(/\s+/g, "");
        const b64 = /^[A-Za-z0-9+/_=-]+$/.test(clean) ? clean : (findB64Blob(clean) || clean);
        const bytes = b64ToBytes(b64);
        const ds = new DecompressionStream("deflate");
        const stream = new Blob([bytes]).stream().pipeThrough(ds);
        return await new Response(stream).text();
      } catch (e) { return `[Zlib] ${e.message}`; }
    },
  },

  /* ---------- Hashing ---------- */
  "hash-md5":    { name: "MD5",    category: "Hashing", desc: "Compute MD5 hash of input.",    async run(input) { return CryptoJS.MD5(input).toString(); } },
  "hash-sha1":   { name: "SHA-1",  category: "Hashing", desc: "Compute SHA-1 hash of input.",  async run(input) { return asyncHash("SHA-1",   input); } },
  "hash-sha256": { name: "SHA-256",category: "Hashing", desc: "Compute SHA-256 hash of input.",async run(input) { return asyncHash("SHA-256", input); } },
  "hash-sha512": { name: "SHA-512",category: "Hashing", desc: "Compute SHA-512 hash of input.",async run(input) { return asyncHash("SHA-512", input); } },

  /* ---------- Extractors ---------- */
  "extract-urls": {
    name: "Extract URLs", category: "Extractors",
    desc: "Pull all http/https/hxxp URLs out of the input (defanged variants included).",
    async run(input) {
      const re = /(?:h(?:ttps?|xxps?))(?::|\[:\])\/\/[^\s"'<>`]+/gi;
      return [...new Set(input.match(re) || [])].join("\n");
    },
  },
  "extract-ips": {
    name: "Extract IPs (IPv4)", category: "Extractors",
    desc: "Extract all IPv4 addresses (including defanged like 1[.]2[.]3[.]4).",
    async run(input) {
      const re = /\b(?:\d{1,3}[.[\](){}]{1,3}){3}\d{1,3}\b/g;
      const raw = input.match(re) || [];
      const cleaned = raw.map((s) => s.replace(/[\[\](){}]/g, "."));
      return [...new Set(cleaned.filter((s) => s.split(".").every((o) => +o <= 255)))].join("\n");
    },
  },
  "extract-domains": {
    name: "Extract domains", category: "Extractors",
    desc: "Extract every domain-looking token (excludes bare IPs).",
    async run(input) {
      const re = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;
      return [...new Set(input.match(re) || [])].join("\n");
    },
  },
  "extract-emails": {
    name: "Extract emails", category: "Extractors",
    desc: "Extract every RFC-ish email address.",
    async run(input) {
      const re = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
      return [...new Set(input.match(re) || [])].join("\n");
    },
  },
  "extract-hashes": {
    name: "Extract hashes (MD5 / SHA1 / SHA256)", category: "Extractors",
    desc: "Extract all 32 / 40 / 64-char hex hashes.",
    async run(input) {
      const md5 = input.match(/\b[a-f0-9]{32}\b/gi) || [];
      const sha1 = input.match(/\b[a-f0-9]{40}\b/gi) || [];
      const sha256 = input.match(/\b[a-f0-9]{64}\b/gi) || [];
      return [...new Set([...md5, ...sha1, ...sha256])].join("\n");
    },
  },

  /* ---------- Utilities ---------- */
  "defang": {
    name: "Defang", category: "Utilities",
    desc: "Wrap dots / colons / http so IOCs don't accidentally get clicked.",
    async run(input) {
      return input.replace(/https?/gi, (m) => m.replace("t", "x")).replace(/\./g, "[.]").replace(/(?<!\[):(?!\])/g, "[:]");
    },
  },
  "refang": {
    name: "Refang", category: "Utilities",
    desc: "Reverse Defang.",
    async run(input) {
      return input.replace(/\[\.\]/g, ".").replace(/\[:\]/g, ":").replace(/hxxp/gi, "http").replace(/hxxps/gi, "https");
    },
  },
  "reverse": { name: "Reverse", category: "Utilities", desc: "Reverse the string.", async run(input) { return [...input].reverse().join(""); } },
  "remove-whitespace": { name: "Remove whitespace", category: "Utilities", desc: "Strip all whitespace.", async run(input) { return input.replace(/\s+/g, ""); } },
  "to-upper": { name: "To upper case", category: "Utilities", desc: "UPPERCASE all letters.", async run(input) { return input.toUpperCase(); } },
  "to-lower": { name: "To lower case", category: "Utilities", desc: "lowercase all letters.", async run(input) { return input.toLowerCase(); } },
  "json-beautify": {
    name: "JSON beautify", category: "Utilities",
    desc: "Pretty-print JSON (2-space indent).",
    async run(input) { try { return JSON.stringify(JSON.parse(input), null, 2); } catch (e) { return `[JSON] ${e.message}`; } },
  },
  "hex-dump": {
    name: "Hex dump", category: "Utilities",
    desc: "Classic hex dump (offset · 16 bytes hex · ASCII).",
    async run(input) {
      const bytes = encoder.encode(input);
      const rows = [];
      for (let i = 0; i < bytes.length; i += 16) {
        const chunk = bytes.slice(i, i + 16);
        const hex = [...chunk].map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(48, " ");
        const ascii = [...chunk].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
        rows.push(`${i.toString(16).padStart(8, "0")}  ${hex}  ${ascii}`);
      }
      return rows.join("\n");
    },
  },
  "split-lines": {
    name: "Split by delimiter", category: "Utilities",
    desc: "Split input by a delimiter and put each piece on its own line.",
    params: { delimiter: "," },
    async run(input, { delimiter }) { return input.split(delimiter || ",").join("\n"); },
  },

  /* ---------- Auto ---------- */
  "magic": {
    name: "🪄 Magic (auto-decode)", category: "Auto",
    desc: "Try common decode chains (Base64, hex, URL, HTML, Unicode) and return the first result that looks like clean text.",
    async run(input) {
      const looksTexty = (s) => {
        if (!s || s.length < 4) return false;
        const printable = [...s].filter((ch) => { const c = ch.charCodeAt(0); return c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 160; }).length;
        return printable / s.length > 0.85;
      };
      const attempts = [
        { label: "Base64 → text", fn: () => ops["base64-decode"].run(input) },
        { label: "Hex → text", fn: () => ops["hex-decode"].run(input) },
        { label: "URL → text", fn: () => ops["url-decode"].run(input) },
        { label: "HTML entity → text", fn: () => ops["html-entity-decode"].run(input) },
        { label: "Unicode escape → text", fn: () => ops["unicode-escape-decode"].run(input) },
        { label: "Base64 → Gzip", fn: () => ops["gzip-decompress-b64"].run(input) },
        { label: "Hex → Gzip", fn: () => ops["gzip-decompress-hex"].run(input) },
        { label: "ROT13", fn: () => ops["rot13"].run(input) },
      ];
      const lines = ["Auto-decode attempts (candidates that produced clean text):", ""];
      for (const a of attempts) {
        try {
          const out = await a.fn();
          if (looksTexty(out) && out !== input) lines.push(`── ${a.label} ──`, out.slice(0, 4000), "");
        } catch { /* ignore */ }
      }
      return lines.length > 2 ? lines.join("\n") : "No candidate decoders produced readable text. Try adding operations manually.";
    },
  },
};

export const OP_CATEGORIES = ["Auto", "Encoding", "Cryptography", "Compression", "Hashing", "Extractors", "Utilities"];
export const OPS = ops;

export async function runRecipe(input, recipe) {
  let cur = input;
  const trace = [];
  for (const step of recipe) {
    const op = ops[step.id];
    if (!op) continue;
    try {
      cur = await op.run(cur, step.params || {});
      trace.push({ id: step.id, name: op.name, ok: true, size: cur.length });
    } catch (e) {
      cur = `[${op.name}] ${e.message}`;
      trace.push({ id: step.id, name: op.name, ok: false, error: e.message });
      break;
    }
  }
  return { output: cur, trace };
}

/* ---------- Auto Decode — recursive multi-encoding chain search ---------- */
/* Which ops the auto-decoder is allowed to chain. Kept lean so the search
 * stays fast and results stay meaningful. */
const AUTO_OP_IDS = [
  "base64-decode",
  "base64-decode-utf16",
  "hex-decode",
  "url-decode",
  "html-entity-decode",
  "unicode-escape-decode",
  "gzip-decompress-b64",
  "zlib-decompress-b64",
  "rot13",
  "refang",
  "charcode-to-string",
];

/* Score a candidate: 0.0 (binary/gibberish) → 1.0 (clean human-readable text).
 * Rewards printable ASCII + spaces; penalises replacement chars, nulls,
 * and pure-hex/pure-base64 outputs (that just means we haven't decoded yet). */
function scoreText(s) {
  if (!s || s.length < 3) return 0;
  // Ignore our own error markers so Auto Decode doesn't "win" with a graceful failure.
  if (/^\[(Gzip|Zlib|AES|JSON|Base64)]/.test(s.trim())) return 0;
  let printable = 0, letters = 0, digits = 0, punct = 0, spaces = 0, replacement = 0;
  for (let i = 0; i < Math.min(s.length, 4000); i++) {
    const c = s.charCodeAt(i);
    if (c === 0xfffd) replacement++;
    else if (c === 9 || c === 10 || c === 13 || c === 32) spaces++;
    else if (c >= 65 && c <= 90) { letters++; printable++; }
    else if (c >= 97 && c <= 122) { letters++; printable++; }
    else if (c >= 48 && c <= 57) { digits++; printable++; }
    else if (c >= 33 && c < 127) { punct++; printable++; }
    else if (c >= 160 && c < 65533) printable++;
  }
  const n = Math.min(s.length, 4000);
  const printableRatio = printable / n;
  const spaceRatio = spaces / n;
  const replPenalty = replacement / n;
  // Bonus for having real words (letters + spaces present in balance)
  const wordBonus = (letters > n * 0.3 && spaceRatio > 0.02 && spaceRatio < 0.35) ? 0.1 : 0;
  // Penalty if output is pure hex or pure base64 (means we haven't finished decoding)
  const looksHex = /^[0-9a-fA-F\s]+$/.test(s.slice(0, 200)) && letters === 0;
  const looksB64 = /^[A-Za-z0-9+/=_-]+$/.test(s.slice(0, 200).replace(/\s+/g, "")) && punct === 0;
  const purePenalty = (looksHex || looksB64) ? 0.4 : 0;
  return Math.max(0, Math.min(1, printableRatio - replPenalty * 2 + wordBonus - purePenalty));
}

/* Recursive best-first search over decode chains up to max-depth.
 * Returns { output, chain, score, trace } for the best candidate found,
 * or null if the input already scores high enough (nothing to decode). */
export async function autoDecode(input, { maxDepth = 4, minGain = 0.05 } = {}) {
  const baseScore = scoreText(input);
  let best = { output: input, chain: [], score: baseScore, note: "already looks like plain text" };

  const seen = new Set([input]);
  const queue = [{ cur: input, chain: [], depth: 0 }];

  // Special seed: if the input contains a big Base64-looking substring, try
  // decoding just that first. This covers mixed inputs like "powershell.exe -e <blob>".
  // We ALWAYS prefer a good embedded-blob decode over the raw input, because
  // the user explicitly asked us to "auto-decode" — the whole point is to
  // reveal what's hidden inside, even when the wrapper is plain English.
  const EMBED_ACCEPT = 0.5;
  const b64Match = String(input).match(/[A-Za-z0-9+/=_-]{40,}/g);
  if (b64Match) {
    const longest = b64Match.reduce((a, b) => (b.length > a.length ? b : a));
    for (const opId of ["base64-decode", "base64-decode-utf16", "gzip-decompress-b64"]) {
      try {
        const out = await ops[opId].run(longest);
        if (out && !seen.has(out)) {
          seen.add(out);
          const s = scoreText(out);
          // Force-adopt any embedded-blob decode above EMBED_ACCEPT — user
          // explicitly wants to see what's hidden inside the wrapper.
          if (s >= EMBED_ACCEPT && (best.embedded ? s > best.score : true)) {
            best = { output: out, chain: [opId], score: s, embedded: true };
          }
          queue.push({ cur: out, chain: [opId], depth: 1 });
        }
      } catch { /* ignore */ }
    }
  }

  while (queue.length) {
    const node = queue.shift();
    if (node.depth >= maxDepth) continue;
    for (const opId of AUTO_OP_IDS) {
      const op = ops[opId];
      let next;
      try { next = await op.run(node.cur); }
      catch { continue; }
      if (!next || typeof next !== "string") continue;
      if (next.length < 3 || next.length > 200_000) continue;
      if (seen.has(next)) continue;
      // Skip obvious junk (very high replacement-char ratio)
      if ((next.match(/\ufffd/g) || []).length / next.length > 0.15) continue;
      seen.add(next);
      const s = scoreText(next);
      const chain = [...node.chain, opId];
      if (s > best.score + minGain) {
        best = { output: next, chain, score: s };
      }
      // Only continue expanding if this step improved things (or barely broke even)
      if (s + 0.05 >= scoreText(node.cur)) {
        queue.push({ cur: next, chain, depth: node.depth + 1 });
      }
    }
  }

  return {
    output: best.output,
    chain: best.chain,
    score: best.score,
    baseScore,
    improved: best.chain.length > 0 && (best.embedded || best.score > baseScore + minGain),
    embedded: !!best.embedded,
    steps: best.chain.map((id) => ({ id, name: ops[id].name })),
  };
}
