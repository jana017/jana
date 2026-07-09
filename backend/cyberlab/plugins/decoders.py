"""Core decoder / transformer plugins for CyberLab.

All plugins operate on bytes for chainability. Each plugin also implements a
`detect()` heuristic that scores 0.0–1.0 for use by the auto-decoder.
"""
from __future__ import annotations
import base64
import binascii
import codecs
import gzip
import re
import zlib
from html import unescape
from typing import Dict, Any
from urllib.parse import unquote_to_bytes

from .base import Plugin, register


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_B64_ALPHA = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n \t")
_B64URL_ALPHA = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=\r\n \t")


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    ok = 0
    for b in data:
        if b in (9, 10, 13) or 32 <= b < 127:
            ok += 1
    return ok / len(data)


def _looks_utf16le(data: bytes) -> bool:
    if len(data) < 4 or len(data) % 2 != 0:
        return False
    # Every second byte should be near-zero for Latin-heavy UTF-16LE.
    zeros = sum(1 for i in range(1, len(data), 2) if data[i] == 0)
    return zeros / (len(data) // 2) > 0.7


def _to_best_text(data: bytes) -> str:
    """Decode bytes preferring the encoding that yields most printable text.
    Handles: UTF-8, UTF-16LE, and 'ASCII-only fallback' for corrupted UTF-16LE
    payloads (mangled during PowerShell copy/paste)."""
    if not data:
        return ""
    # Trim trailing NULs
    end = len(data)
    while end > 0 and data[end - 1] == 0:
        end -= 1
    trimmed = data[:end]

    utf8 = trimmed.decode("utf-8", errors="replace")
    utf16 = ""
    if len(trimmed) >= 2:
        even = trimmed[: len(trimmed) - (len(trimmed) % 2)]
        try:
            utf16 = even.decode("utf-16le", errors="replace")
        except Exception:
            utf16 = ""
    ascii_only = "".join(chr(b) for b in trimmed if b in (9, 10, 13) or 32 <= b < 127)

    def score(s: str) -> float:
        if not s:
            return 0.0
        ok = sum(1 for c in s if c in "\t\r\n" or 32 <= ord(c) < 127 or ord(c) >= 160)
        return ok / len(s)

    s8, s16, sa = score(utf8), score(utf16), score(ascii_only)
    # Corrupted UTF-16LE detection: many CJK/non-Latin glyphs mixed with ASCII.
    if utf16:
        non_latin = sum(1 for c in utf16 if ord(c) > 0x02FF)
        latin_ratio = (len(utf16) - non_latin) / len(utf16)
        if non_latin > 0 and latin_ratio > 0.6 and sa >= 0.9 and len(ascii_only) >= len(utf16) * 0.8:
            return ascii_only
    if sa > max(s8, s16) + 0.1 and len(ascii_only) >= len(trimmed) * 0.3:
        return ascii_only
    return utf16 if s16 > s8 + 0.05 else utf8


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------
def _b64_decode_lenient(data: bytes, urlsafe: bool = False) -> bytes:
    text = data.decode("ascii", errors="ignore")
    # Strip anything that isn't base64
    if urlsafe:
        text = re.sub(r"[^A-Za-z0-9\-_=]", "", text)
        text = text.replace("-", "+").replace("_", "/")
    else:
        text = re.sub(r"[^A-Za-z0-9+/=]", "", text)
    # Strip trailing =, re-pad
    text = text.rstrip("=")
    rem = len(text) % 4
    if rem == 1:
        text = text[:-1]
    text += "=" * ((4 - (len(text) % 4)) % 4)
    return base64.b64decode(text, validate=False)


def _detect_base64(data: bytes) -> float:
    if len(data) < 16:
        return 0.0
    # Consider the longest CONTIGUOUS run of base64 alphabet chars.
    # This prevents matching strings like "powershell.exe -e JABv..." where
    # only the b64 tail is real base64. Auto-decoder should use the
    # extract-encoded-command plugin first for those cases.
    text = data.decode("latin-1", errors="ignore")
    best = ""
    for m in re.finditer(r"[A-Za-z0-9+/=]{16,}", text):
        if len(m.group(0)) > len(best):
            best = m.group(0)
    if not best:
        return 0.0
    # The b64 blob must dominate the input (>= 92% of non-space chars)
    non_space_len = len(re.sub(r"\s", "", text))
    if non_space_len == 0 or len(best) / non_space_len < 0.92:
        return 0.0
    conf = 0.85
    if len(best) % 4 == 0:
        conf += 0.05
    if re.search(r"[A-Z]", best) and re.search(r"[a-z]", best):
        conf += 0.05
    return min(conf, 0.98)


register(Plugin(
    id="base64-decode",
    name="Base64 Decode",
    category="Encoding",
    description="Decode Base64 (standard alphabet). Lenient: strips noise & re-pads.",
    run=lambda data, params: _b64_decode_lenient(data, urlsafe=False),
    detect=_detect_base64,
))

register(Plugin(
    id="base64url-decode",
    name="Base64 URL Decode",
    category="Encoding",
    description="Decode URL-safe Base64 (- and _ instead of + and /).",
    run=lambda data, params: _b64_decode_lenient(data, urlsafe=True),
    detect=lambda data: _detect_base64(data) if b"-" in data or b"_" in data else 0.0,
))

register(Plugin(
    id="base64-encode",
    name="Base64 Encode",
    category="Encoding",
    description="Encode to Base64.",
    run=lambda data, params: base64.b64encode(data),
    auto=False,
))


# ---------------------------------------------------------------------------
# Hex
# ---------------------------------------------------------------------------
def _hex_decode(data: bytes, params: Dict[str, Any]) -> bytes:
    text = data.decode("ascii", errors="ignore")
    text = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(text) % 2 == 1:
        text = text[:-1]
    return bytes.fromhex(text)


def _detect_hex(data: bytes) -> float:
    if len(data) < 6:
        return 0.0
    stripped = re.sub(rb"[\s:,\-]", b"", data)
    if len(stripped) < 6:
        return 0.0
    hex_chars = sum(1 for b in stripped if b in b"0123456789abcdefABCDEF")
    ratio = hex_chars / len(stripped)
    if ratio < 0.95 or len(stripped) % 2 != 0:
        return 0.0
    return min(0.95, ratio)


register(Plugin(
    id="hex-decode",
    name="Hex Decode",
    category="Encoding",
    description="Convert hex string to bytes. Strips whitespace & separators.",
    run=_hex_decode,
    detect=_detect_hex,
))

register(Plugin(
    id="hex-encode",
    name="Hex Encode",
    category="Encoding",
    description="Convert bytes to hex string.",
    run=lambda data, params: data.hex().encode("ascii"),
    auto=False,
))


# ---------------------------------------------------------------------------
# URL / percent encoding
# ---------------------------------------------------------------------------
def _detect_url(data: bytes) -> float:
    if b"%" not in data:
        return 0.0
    matches = len(re.findall(rb"%[0-9a-fA-F]{2}", data))
    if matches == 0:
        return 0.0
    return min(0.9, 0.5 + matches / max(len(data), 1) * 2)


register(Plugin(
    id="url-decode",
    name="URL Decode",
    category="Encoding",
    description="Percent-decode URL-encoded bytes (%XX).",
    run=lambda data, params: unquote_to_bytes(data.decode("latin-1")),
    detect=_detect_url,
))

register(Plugin(
    id="url-encode",
    name="URL Encode",
    category="Encoding",
    description="Percent-encode bytes for URL usage.",
    run=lambda data, params: "".join(
        c if c.isalnum() or c in "-_.~" else f"%{ord(c):02X}"
        for c in data.decode("latin-1")
    ).encode("ascii"),
    auto=False,
))


# ---------------------------------------------------------------------------
# HTML entities
# ---------------------------------------------------------------------------
def _detect_html_entities(data: bytes) -> float:
    text = data.decode("utf-8", errors="ignore")
    matches = len(re.findall(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);", text))
    if matches == 0:
        return 0.0
    return min(0.85, 0.5 + matches * 0.05)


register(Plugin(
    id="html-entity-decode",
    name="HTML Entity Decode",
    category="Encoding",
    description="Decode HTML entities (&amp;, &#65;, &#x41;) to their characters.",
    run=lambda data, params: unescape(data.decode("utf-8", errors="replace")).encode("utf-8"),
    detect=_detect_html_entities,
))


# ---------------------------------------------------------------------------
# Unicode escape
# ---------------------------------------------------------------------------
def _detect_unicode_escape(data: bytes) -> float:
    text = data.decode("utf-8", errors="ignore")
    matches = len(re.findall(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", text))
    if matches == 0:
        return 0.0
    return min(0.85, 0.5 + matches * 0.04)


def _unicode_escape_decode(data: bytes, params: Dict[str, Any]) -> bytes:
    text = data.decode("utf-8", errors="replace")
    try:
        return codecs.decode(text, "unicode_escape").encode("utf-8", errors="replace")
    except Exception:
        return text.encode("utf-8", errors="replace")


register(Plugin(
    id="unicode-escape-decode",
    name="Unicode Escape Decode",
    category="Encoding",
    description=r"Decode \uXXXX and \xXX escape sequences.",
    run=_unicode_escape_decode,
    detect=_detect_unicode_escape,
))


# ---------------------------------------------------------------------------
# Compression: gzip, zlib
# ---------------------------------------------------------------------------
def _detect_gzip(data: bytes) -> float:
    return 0.95 if data[:2] == b"\x1f\x8b" else 0.0


def _detect_zlib(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    if data[0] in (0x78,) and data[1] in (0x01, 0x5E, 0x9C, 0xDA):
        return 0.9
    return 0.0


register(Plugin(
    id="gzip-decompress",
    name="Gzip Decompress",
    category="Compression",
    description="Decompress gzip-compressed bytes (magic 1F 8B).",
    run=lambda data, params: gzip.decompress(data),
    detect=_detect_gzip,
))

register(Plugin(
    id="zlib-decompress",
    name="Zlib Decompress",
    category="Compression",
    description="Decompress zlib-compressed bytes (magic 78 9C / 78 DA).",
    run=lambda data, params: zlib.decompress(data),
    detect=_detect_zlib,
))

register(Plugin(
    id="gzip-decompress-b64",
    name="Base64 → Gzip Decompress",
    category="Compression",
    description="One-shot: base64 decode then gzip decompress.",
    run=lambda data, params: gzip.decompress(_b64_decode_lenient(data)),
    auto=False,
))


# ---------------------------------------------------------------------------
# Cryptography: XOR, ROT13, Reverse
# ---------------------------------------------------------------------------
def _xor(data: bytes, params: Dict[str, Any]) -> bytes:
    key = params.get("key", "").encode("utf-8") if isinstance(params.get("key"), str) else params.get("key", b"")
    if not key:
        return data
    if isinstance(key, str):
        key = key.encode("utf-8")
    key = bytes(key)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


register(Plugin(
    id="xor",
    name="XOR",
    category="Cryptography",
    description="XOR bytes with a repeating key. Provide `key` param.",
    run=_xor,
    params=[{"name": "key", "type": "string", "default": ""}],
    auto=False,
))


def _rot13(data: bytes, params: Dict[str, Any]) -> bytes:
    text = data.decode("utf-8", errors="replace")
    return codecs.encode(text, "rot_13").encode("utf-8")


register(Plugin(
    id="rot13",
    name="ROT13",
    category="Cryptography",
    description="Caesar cipher, shift 13.",
    run=_rot13,
    detect=lambda data: 0.0,  # never auto-select
    auto=False,
))


register(Plugin(
    id="reverse",
    name="Reverse",
    category="Utilities",
    description="Reverse the byte sequence.",
    run=lambda data, params: data[::-1],
    auto=False,
))


# ---------------------------------------------------------------------------
# UTF-16LE / UTF-16BE explicit decode
# ---------------------------------------------------------------------------
def _utf16le_decode(data: bytes, params: Dict[str, Any]) -> bytes:
    even = data[: len(data) - (len(data) % 2)]
    return even.decode("utf-16le", errors="replace").encode("utf-8", errors="replace")


def _detect_utf16le(data: bytes) -> float:
    return 0.92 if _looks_utf16le(data) else 0.0


register(Plugin(
    id="utf16le-decode",
    name="UTF-16LE Decode",
    category="Encoding",
    description="Decode bytes as UTF-16 Little Endian to UTF-8 text.",
    run=_utf16le_decode,
    detect=_detect_utf16le,
))

register(Plugin(
    id="utf16be-decode",
    name="UTF-16BE Decode",
    category="Encoding",
    description="Decode bytes as UTF-16 Big Endian to UTF-8 text.",
    run=lambda data, params: (
        data[: len(data) - (len(data) % 2)]
        .decode("utf-16be", errors="replace")
        .encode("utf-8", errors="replace")
    ),
    auto=False,
))


# ---------------------------------------------------------------------------
# PowerShell -EncodedCommand extractor (auto-triggered pre-processor)
# ---------------------------------------------------------------------------
_PS_ENC_RE = re.compile(
    r"powershell(?:\.exe)?[^\r\n]*?\s-e(?:c|nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})",
    re.IGNORECASE,
)


def _detect_ps_encoded(data: bytes) -> float:
    text = data.decode("utf-8", errors="ignore")
    return 0.97 if _PS_ENC_RE.search(text) else 0.0


def _extract_ps_encoded(data: bytes, params: Dict[str, Any]) -> bytes:
    text = data.decode("utf-8", errors="replace")
    m = _PS_ENC_RE.search(text)
    if m:
        return m.group(1).encode("ascii")
    return data


register(Plugin(
    id="extract-powershell-encoded",
    name="Extract PowerShell Encoded Command",
    category="Extractors",
    description="Find `powershell -e/-enc/-EncodedCommand <base64>` and extract just the payload.",
    run=_extract_ps_encoded,
    detect=_detect_ps_encoded,
))


# ---------------------------------------------------------------------------
# PowerShell cleanup + defang / refang
# ---------------------------------------------------------------------------
def _powershell_deobfuscate(data: bytes, params: Dict[str, Any]) -> bytes:
    text = _to_best_text(data)
    # Remove PS escape chars
    text = text.replace("`", "").replace("^", "")
    # Collapse concat like 'aaa'+'bbb'
    text = re.sub(r"['\"]\s*\+\s*['\"]", "", text)
    # Strip surrounding quotes on tokens
    text = text.replace('""', '"')
    return text.encode("utf-8", errors="replace")


register(Plugin(
    id="powershell-deobfuscate",
    name="PowerShell Deobfuscate",
    category="Deobfuscation",
    description="Strip PS escape chars (` and ^), collapse string concat, un-double quotes.",
    run=_powershell_deobfuscate,
    auto=False,
))


def _refang(data: bytes, params: Dict[str, Any]) -> bytes:
    text = data.decode("utf-8", errors="replace")
    text = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    text = re.sub(r"\[?\bhxxp(s?)\b\]?://", r"http\1://", text, flags=re.IGNORECASE)
    text = re.sub(r"\[?\bfxp\b\]?://", "ftp://", text, flags=re.IGNORECASE)
    text = text.replace("[at]", "@").replace("(at)", "@").replace("[@]", "@")
    text = text.replace("[://]", "://")
    return text.encode("utf-8", errors="replace")


register(Plugin(
    id="refang",
    name="Refang IOCs",
    category="Deobfuscation",
    description="Reverse common IOC defanging (hxxp → http, [.] → ., [at] → @).",
    run=_refang,
    auto=False,
))


def _defang(data: bytes, params: Dict[str, Any]) -> bytes:
    text = data.decode("utf-8", errors="replace")
    text = re.sub(r"https?://", lambda m: m.group(0).replace("http", "hxxp"), text)
    text = re.sub(r"\.(?=[a-zA-Z])", "[.]", text)
    text = text.replace("@", "[at]")
    return text.encode("utf-8", errors="replace")


register(Plugin(
    id="defang",
    name="Defang IOCs",
    category="Deobfuscation",
    description="Neutralize URLs/emails so they aren't clickable (http → hxxp, . → [.]).",
    run=_defang,
    auto=False,
))


# ---------------------------------------------------------------------------
# Strings extraction (binary → printable strings)
# ---------------------------------------------------------------------------
def _extract_strings(data: bytes, params: Dict[str, Any]) -> bytes:
    min_len = int(params.get("min_length", 4))
    out = []
    # ASCII strings
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append(m.group(0).decode("ascii"))
    # UTF-16LE strings (Windows binaries)
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data):
        try:
            out.append(m.group(0).decode("utf-16le"))
        except Exception:
            pass
    return "\n".join(out).encode("utf-8")


register(Plugin(
    id="extract-strings",
    name="Extract Strings",
    category="Extractors",
    description="Extract printable ASCII + UTF-16LE strings (like `strings` binary tool).",
    run=_extract_strings,
    params=[{"name": "min_length", "type": "number", "default": 4}],
    auto=False,
))


# ---------------------------------------------------------------------------
# Text utils: normalize whitespace, lowercase, remove nulls
# ---------------------------------------------------------------------------
register(Plugin(
    id="remove-nulls",
    name="Remove Null Bytes",
    category="Utilities",
    description="Strip all null (0x00) bytes.",
    run=lambda data, params: data.replace(b"\x00", b""),
    auto=False,
))

register(Plugin(
    id="normalize-whitespace",
    name="Normalize Whitespace",
    category="Utilities",
    description="Collapse repeated whitespace into single spaces.",
    run=lambda data, params: re.sub(rb"\s+", b" ", data).strip(),
    auto=False,
))

register(Plugin(
    id="lowercase",
    name="To Lowercase",
    category="Utilities",
    description="Lowercase all text.",
    run=lambda data, params: data.lower(),
    auto=False,
))


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------
import hashlib as _hashlib


def _hash(algo: str):
    def _run(data: bytes, params: Dict[str, Any]) -> bytes:
        return _hashlib.new(algo, data).hexdigest().encode("ascii")
    return _run


for _algo in ("md5", "sha1", "sha256", "sha512"):
    register(Plugin(
        id=f"hash-{_algo}",
        name=f"Hash ({_algo.upper()})",
        category="Hashing",
        description=f"Compute {_algo.upper()} digest of input.",
        run=_hash(_algo),
        auto=False,
    ))


__all__ = ["_to_best_text"]
