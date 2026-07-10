/**
 * Client-side PowerShell payload detector + decoder.
 *
 * Purpose: give the analyst instant visual feedback ("PowerShell Payload
 * Detected") the moment they paste a `powershell -enc <b64>` command, and a
 * quick-preview of the decoded text — no round-trip to the backend needed.
 *
 * Handles:
 *   • All PS flag spellings: -e, -en, -enc, -EncodedCommand (case-insensitive)
 *   • PowerShell 5 (`powershell.exe`) AND 7 (`pwsh`)
 *   • Quoted payloads: -enc "AAAB..." / -enc 'AAAB...'
 *   • URL-safe base64 (`-`/`_` variants)
 *   • Missing / partial padding
 *   • UTF-16LE (PS default) with junk-prefix recovery via string extraction
 *   • Falls back to UTF-8 when the output isn't UTF-16LE (rare but happens
 *     with Linux `pwsh -enc` invocations).
 */

// PS + flag + b64. Matches `powershell -e`, `pwsh -EncodedCommand`, etc.
// Base64 body accepts both standard and URL-safe alphabets — we normalize
// before decoding.
const PS_ENC_RE =
  /(?:powershell|pwsh)(?:\.exe)?[^\r\n]*?\s-e(?:c|nc|ncodedcommand)?\s+['"]?([A-Za-z0-9+/=_-]{8,})['"]?/i;

// -----------------------------------------------------------------------------
// Input normalization — fold typographic punctuation (en-dash, em-dash, curly
// quotes, non-breaking space, zero-width chars) that email clients / Word /
// PDFs / rich-text editors silently substitute for ASCII. Without this, an
// analyst pasting a `powershell –enc …` command (with an en-dash) from a
// phishing email would be invisible to every flag-based extractor.
// -----------------------------------------------------------------------------
const UNICODE_PUNCT_MAP = {
  // dashes → ASCII hyphen-minus
  "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",
  "\u2015": "-", "\u2212": "-", "\uFE58": "-", "\uFE63": "-", "\uFF0D": "-",
  // smart quotes → ASCII
  "\u2018": "'", "\u2019": "'", "\u201A": "'", "\u201B": "'",
  "\u201C": '"', "\u201D": '"', "\u201E": '"', "\u201F": '"',
  // NBSP + narrow spaces → regular space
  "\u00A0": " ", "\u2009": " ", "\u200A": " ", "\u202F": " ",
  // zero-width chars → strip
  "\u200B": "", "\u200C": "", "\u200D": "", "\uFEFF": "",
};

export function normalizeInput(text) {
  if (!text || typeof text !== "string") return "";
  let out = "";
  for (const ch of text) out += UNICODE_PUNCT_MAP[ch] ?? ch;
  return out;
}

/**
 * Return true when the input contains a PowerShell -enc/-e/-EncodedCommand
 * argument followed by a base64-looking payload.
 */
export function isPowerShellPayload(text) {
  if (!text || typeof text !== "string") return false;
  return PS_ENC_RE.test(normalizeInput(text));
}

/**
 * Extract the base64 payload that follows a PowerShell -e/-enc flag.
 * Returns the raw base64 string (with quotes stripped) or null.
 */
export function extractPowerShellBase64(text) {
  if (!text || typeof text !== "string") return null;
  const m = normalizeInput(text).match(PS_ENC_RE);
  return m ? m[1] : null;
}

// -----------------------------------------------------------------------------
// Base64 → bytes  (browser-friendly, tolerant of urlsafe + missing padding)
// -----------------------------------------------------------------------------
function base64ToBytes(input) {
  // Normalize URL-safe alphabet.
  let b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  // Strip whitespace + trailing junk padding, then re-pad to multiple of 4.
  b64 = b64.replace(/\s+/g, "").replace(/=+$/g, "");
  const rem = b64.length % 4;
  if (rem === 1) b64 = b64.slice(0, -1); // 1 leftover char is impossible → drop it
  b64 += "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// -----------------------------------------------------------------------------
// Encoding detection  (UTF-16LE vs UTF-8)
// -----------------------------------------------------------------------------
function looksUtf16LE(bytes) {
  if (bytes.length < 6) return false;
  // In UTF-16LE ASCII text, every second byte is 0x00.
  let zeros = 0;
  const sample = Math.min(bytes.length, 200);
  for (let i = 1; i < sample; i += 2) if (bytes[i] === 0) zeros++;
  return zeros / Math.floor(sample / 2) >= 0.6;
}

function decodeUtf16LE(bytes) {
  // TextDecoder handles UTF-16LE natively in every modern browser.
  const trimmed = bytes.length % 2 === 0 ? bytes : bytes.slice(0, bytes.length - 1);
  return new TextDecoder("utf-16le", { fatal: false }).decode(trimmed);
}

function decodeUtf8(bytes) {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

// Recover embedded printable UTF-16LE / ASCII strings from noisy bytes
// (matches the backend `extract-strings` plugin behavior).
function extractPrintableStrings(bytes) {
  const parts = [];
  // UTF-16LE runs: pattern `[\x20-\x7e]\x00` repeated 4+ times.
  {
    let run = [];
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      const lo = bytes[i], hi = bytes[i + 1];
      if (hi === 0 && lo >= 0x20 && lo <= 0x7e) {
        run.push(lo);
      } else {
        if (run.length >= 4) parts.push(String.fromCharCode(...run));
        run = [];
      }
    }
    if (run.length >= 4) parts.push(String.fromCharCode(...run));
  }
  // ASCII runs (8+ chars).
  {
    let run = [];
    for (const b of bytes) {
      if (b >= 0x20 && b <= 0x7e) run.push(b);
      else if (b === 9 || b === 10 || b === 13) run.push(b);
      else {
        if (run.length >= 8) parts.push(String.fromCharCode(...run));
        run = [];
      }
    }
    if (run.length >= 8) parts.push(String.fromCharCode(...run));
  }
  return parts.filter((s) => s.trim().length > 0);
}

// -----------------------------------------------------------------------------
// Top-level: decode a full PS command line
// -----------------------------------------------------------------------------
/**
 * Decode a full PowerShell command line.
 * Returns:
 *   { detected, error?, b64?, encoding?, decoded?, byteLength?, snippet? }
 *
 * When `detected` is true and no error occurred, `decoded` is the readable
 * text (UTF-16LE-decoded by default, falling back to UTF-8 or extracted
 * printable strings when the bytes look mixed/noisy).
 */
export function decodePowerShellCommand(text) {
  if (!isPowerShellPayload(text)) {
    return { detected: false };
  }
  const b64 = extractPowerShellBase64(text);
  if (!b64) {
    return { detected: true, error: "Detected PS flag but no base64 payload." };
  }
  let bytes;
  try {
    bytes = base64ToBytes(b64);
  } catch (e) {
    return { detected: true, b64, error: `Base64 decode failed: ${e.message}` };
  }

  const encoding = looksUtf16LE(bytes) ? "utf-16le" : "utf-8";
  let decoded = encoding === "utf-16le" ? decodeUtf16LE(bytes) : decodeUtf8(bytes);

  // If the primary decode is majority non-printable, try the alternate
  // encoding and finally the strings-extractor fallback.
  const nonPrintableRatio = (() => {
    if (!decoded) return 1;
    let np = 0;
    for (const ch of decoded) {
      const cp = ch.codePointAt(0);
      if (cp < 0x20 && cp !== 9 && cp !== 10 && cp !== 13) np++;
      else if (cp > 0x7e && cp < 0xa0) np++;
    }
    return np / decoded.length;
  })();

  if (nonPrintableRatio > 0.35) {
    const alt = encoding === "utf-16le" ? decodeUtf8(bytes) : decodeUtf16LE(bytes);
    const strings = extractPrintableStrings(bytes);
    if (strings.length > 0) {
      decoded = strings.join("\n");
    } else if (alt && alt.length > decoded.length) {
      decoded = alt;
    }
  }

  return {
    detected: true,
    b64,
    encoding,
    decoded,
    byteLength: bytes.length,
    snippet: decoded ? decoded.slice(0, 400) : "",
  };
}
