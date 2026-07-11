"""Input Refine / Repair — deterministic, offline, no-LLM.

Runs a chain of pure-Python fixes an analyst commonly needs before hitting
Auto Investigate: normalize typographic Unicode, strip CMD-caret escapes and
email quote markers, clean & re-pad base64 blobs, remove ellipses, etc.

Every fix is reported (id + description + before/after preview) so the analyst
can audit what changed. Zero dependencies beyond the standard library — this
module continues to work identically after the app is transferred to any VPS
without an Emergent LLM key.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Fix records
# ---------------------------------------------------------------------------
@dataclass
class Fix:
    id: str                # short machine identifier
    label: str             # human readable label
    detail: str            # what was changed, in one sentence
    count: int = 1         # occurrences fixed
    before_preview: Optional[str] = None
    after_preview: Optional[str] = None


@dataclass
class RefineResult:
    refined: str
    fixes: List[Fix] = field(default_factory=list)
    original_length: int = 0
    refined_length: int = 0
    changed: bool = False

    def summary(self) -> str:
        if not self.fixes:
            return "No repairs needed — input is clean."
        parts = [f"{f.count}× {f.label}" for f in self.fixes]
        return "Repaired: " + ", ".join(parts)


# ---------------------------------------------------------------------------
# Individual repairs — each returns (new_text, fix_or_None)
# ---------------------------------------------------------------------------
_UNICODE_DASHES = "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\uFE58\uFE63\uFF0D"
_SMART_QUOTES_SINGLE = "\u2018\u2019\u201A\u201B"
_SMART_QUOTES_DOUBLE = "\u201C\u201D\u201E\u201F"
_NBSP_SPACES = "\u00A0\u2009\u200A\u202F\u205F\u3000"
_ZERO_WIDTH = "\u200B\u200C\u200D\u2060\uFEFF"


def _sample(text: str, needle_pos: int, span: int = 24) -> str:
    """Small snippet around `needle_pos` — for previews."""
    lo = max(0, needle_pos - span // 2)
    hi = min(len(text), lo + span)
    return text[lo:hi]


def _fix_dashes(text: str) -> tuple[str, Optional[Fix]]:
    count = sum(1 for ch in text if ch in _UNICODE_DASHES)
    if count == 0:
        return text, None
    new = text
    for d in _UNICODE_DASHES:
        new = new.replace(d, "-")
    return new, Fix(
        id="unicode_dash",
        label="Unicode dash → -",
        detail="Replaced en-dash / em-dash / minus with ASCII hyphen (Word/email autoformat).",
        count=count,
    )


def _fix_smart_quotes(text: str) -> tuple[str, Optional[Fix]]:
    count = sum(1 for ch in text if ch in _SMART_QUOTES_SINGLE + _SMART_QUOTES_DOUBLE)
    if count == 0:
        return text, None
    new = text
    for q in _SMART_QUOTES_SINGLE:
        new = new.replace(q, "'")
    for q in _SMART_QUOTES_DOUBLE:
        new = new.replace(q, '"')
    return new, Fix(
        id="smart_quote", label="Smart quote → ASCII",
        detail="Replaced curly / typographic quotes with straight ASCII quotes.",
        count=count,
    )


def _fix_nbsp(text: str) -> tuple[str, Optional[Fix]]:
    count = sum(1 for ch in text if ch in _NBSP_SPACES)
    if count == 0:
        return text, None
    new = text
    for s in _NBSP_SPACES:
        new = new.replace(s, " ")
    return new, Fix(
        id="nbsp", label="Non-breaking space → space",
        detail="Replaced NBSP / narrow / ideographic spaces with regular space.",
        count=count,
    )


def _fix_zero_width(text: str) -> tuple[str, Optional[Fix]]:
    count = sum(1 for ch in text if ch in _ZERO_WIDTH)
    if count == 0:
        return text, None
    new = text
    for z in _ZERO_WIDTH:
        new = new.replace(z, "")
    return new, Fix(
        id="zero_width", label="Zero-width char stripped",
        detail="Removed invisible ZWSP / ZWNJ / ZWJ / BOM characters.",
        count=count,
    )


def _fix_control_chars(text: str) -> tuple[str, Optional[Fix]]:
    """Strip C0/C1 control chars (except \\t \\n \\r) — often leftover from
    binary-in-text pastes."""
    def _bad(ch: str) -> bool:
        cp = ord(ch)
        return (cp < 0x20 and cp not in (9, 10, 13)) or (0x7F <= cp <= 0x9F)
    count = sum(1 for ch in text if _bad(ch))
    if count == 0:
        return text, None
    new = "".join(ch for ch in text if not _bad(ch))
    return new, Fix(
        id="control_chars", label="Control character stripped",
        detail="Removed non-printable control bytes.",
        count=count,
    )


_EMAIL_QUOTE_RE = re.compile(r"^\s*>+\s?", re.MULTILINE)


def _fix_email_quote(text: str) -> tuple[str, Optional[Fix]]:
    matches = _EMAIL_QUOTE_RE.findall(text)
    if not matches:
        return text, None
    new = _EMAIL_QUOTE_RE.sub("", text)
    return new, Fix(
        id="email_quote", label="Email quote marker stripped",
        detail="Removed leading `> ` reply markers on each line.",
        count=len(matches),
    )


_ELLIPSIS_RE = re.compile(r"\u2026|\.{3,}")


def _fix_ellipsis(text: str) -> tuple[str, Optional[Fix]]:
    matches = _ELLIPSIS_RE.findall(text)
    if not matches:
        return text, None
    new = _ELLIPSIS_RE.sub("", text)
    return new, Fix(
        id="ellipsis", label="Ellipsis (…) removed",
        detail="Stripped ellipsis / `...` truncation markers that break base64.",
        count=len(matches),
    )


_CARET_RE = re.compile(r"(?<=[A-Za-z0-9])\^(?=[A-Za-z0-9])")


def _fix_cmd_carets(text: str) -> tuple[str, Optional[Fix]]:
    matches = _CARET_RE.findall(text)
    if len(matches) < 2:  # 2+ intra-token carets = CMD obfuscation, not XOR
        return text, None
    new = _CARET_RE.sub("", text)
    return new, Fix(
        id="cmd_caret", label="CMD caret escape stripped",
        detail="Removed `^` intra-token escapes (`p^o^w^ershell`).",
        count=len(matches),
    )


_LINE_BREAK_IN_B64_RE = re.compile(r"(?<=[A-Za-z0-9+/])[\r\n]+(?=[A-Za-z0-9+/=])")


def _fix_b64_line_wraps(text: str) -> tuple[str, Optional[Fix]]:
    """Some sources wrap long base64 blobs across newlines — this breaks the
    contiguous-run detector. Rejoin adjacent b64-alphabet chunks."""
    matches = _LINE_BREAK_IN_B64_RE.findall(text)
    if not matches:
        return text, None
    new = _LINE_BREAK_IN_B64_RE.sub("", text)
    return new, Fix(
        id="b64_line_wrap", label="Base64 line wrap unfolded",
        detail="Joined base64 fragments that were split across newlines.",
        count=len(matches),
    )


_B64_URLSAFE_RE = re.compile(r"[-_]")


def _fix_b64_urlsafe(text: str) -> tuple[str, Optional[Fix]]:
    """Only convert when the input LOOKS like a b64 blob (>= 24 chars b64
    alphabet with -/_). This avoids clobbering command-line flags with `-`."""
    if not re.search(r"[A-Za-z0-9]{20,}", text):
        return text, None
    # Heuristic: only fold if the input is >80% b64-urlsafe alphabet AND
    # contains at least one `-` or `_` inside a long alnum run.
    long_run_m = re.search(r"[A-Za-z0-9_\-]{40,}", text)
    if not long_run_m:
        return text, None
    run = long_run_m.group(0)
    if ("-" not in run and "_" not in run) or re.search(r"[A-Za-z]", run) is None:
        return text, None
    # Skip if the input contains PS-style flags (`-enc`) — those `-` are real.
    if re.search(r"\s-[a-zA-Z]", text):
        return text, None
    count = sum(run.count(c) for c in "-_")
    new = text[:long_run_m.start()] + run.replace("-", "+").replace("_", "/") + text[long_run_m.end():]
    return new, Fix(
        id="b64_urlsafe", label="URL-safe base64 alphabet normalized",
        detail="Converted `-`/`_` to `+`/`/` inside long base64 runs.",
        count=count,
    )


def _fix_b64_padding(text: str) -> tuple[str, Optional[Fix]]:
    """Detect trailing base64 blobs missing `=` padding and add it. Only
    touches contiguous base64 runs 24+ chars long."""
    changed = 0

    def _repair(m: re.Match) -> str:
        nonlocal changed
        blob = m.group(0)
        # `blob` may include existing `=` padding at the tail. Compute the
        # payload length (chars minus trailing `=`) and add the exact number
        # of `=` needed to bring it to a multiple of 4.
        payload_len = len(blob.rstrip("="))
        needed = (4 - (payload_len % 4)) % 4
        existing_pad = len(blob) - payload_len
        if needed <= existing_pad:
            # Already correctly padded (or over-padded — leave alone).
            return blob
        add = needed - existing_pad
        changed += 1
        return blob + ("=" * add)

    # IMPORTANT: include `={0,3}` in the match so we consume any *existing*
    # padding as part of the blob. Without this, the regex would backtrack
    # into the middle of a valid base64 string (Feb 2026 bug — corrupted
    # payloads with `===` injected mid-string).
    new = re.sub(r"[A-Za-z0-9+/]{24,}={0,3}", _repair, text)
    if changed == 0:
        return text, None
    return new, Fix(
        id="b64_padding", label="Base64 padding restored",
        detail="Added missing `=` padding to base64 blobs.",
        count=changed,
    )


def _fix_trim(text: str) -> tuple[str, Optional[Fix]]:
    stripped = text.strip()
    if stripped == text:
        return text, None
    return stripped, Fix(
        id="trim", label="Leading/trailing whitespace trimmed",
        detail="Removed surrounding whitespace and newlines.",
        count=1,
    )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
# Order matters: normalize characters first, then structural repairs
# (email-quote → line-wrap → padding). Trim happens last so it always applies
# to the fully-cleaned string.
_PIPELINE = [
    _fix_zero_width,
    _fix_nbsp,
    _fix_dashes,
    _fix_smart_quotes,
    _fix_control_chars,
    _fix_email_quote,
    _fix_ellipsis,
    _fix_cmd_carets,
    _fix_b64_line_wraps,
    _fix_b64_urlsafe,
    _fix_b64_padding,
    _fix_trim,
]

# Human-facing description for each fixer id.  Used by `diagnose()` to
# tell the analyst *what* Troubleshoot can fix, before it actually touches
# their payload.  Keep these one line and analyst-friendly (no jargon).
# Keys MUST match the `id` field emitted by each `_fix_*` function.
_FIXER_META = {
    "zero_width":    ("Invisible zero-width characters (U+200B/U+200C/U+FEFF)",
                      "Malware and copy-paste from chat apps often smuggle "
                      "invisible chars into the payload. Removing them lets "
                      "regex-based extractors match properly."),
    "nbsp":          ("Non-breaking / narrow spaces",
                      "Word/PDF pastes replace spaces with U+00A0. Base64 "
                      "chunks with these characters cannot be decoded."),
    "unicode_dash":  ("Typographic Unicode dashes (em/en/minus)",
                      "PDFs and email clients auto-substitute `-` with `—`. "
                      "Command-line flags won't be recognized."),
    "smart_quote":   ("Curly / smart quotes",
                      "Word turns `'` and `\"` into curly quotes. Python "
                      "string literals inside the payload can't be parsed."),
    "control_chars": ("Non-printable ASCII control characters",
                      "Terminal / log copies drop invisible \\r, \\b, etc. "
                      "Removing them restores clean whitespace layout."),
    "email_quote":   ("Email quote markers (`>` prefix per line)",
                      "Forwarded phishing emails prefix every line with `>`. "
                      "Stripping them recovers the original commandline."),
    "ellipsis":      ("Truncation ellipsis (`…` or `...`)",
                      "The paste looks truncated — the payload may be "
                      "incomplete. Removing the ellipsis marker at least "
                      "lets the rest decode."),
    "cmd_caret":     ("Windows CMD caret escapes (`p^o^w^e^r^shell`)",
                      "Adversary CMD obfuscation. Removing the `^` between "
                      "characters restores the real command name so "
                      "downstream regex rules fire."),
    "b64_line_wrap": ("Base64 blob with hard line-wraps (76-column email)",
                     "Emails wrap base64 blobs every 76 chars. Joining "
                     "the lines makes it decodable."),
    "b64_urlsafe":   ("URL-safe base64 (- and _ instead of + and /)",
                      "JWT tokens and some malware use URL-safe alphabet. "
                      "Translating restores the standard alphabet decoder."),
    "b64_padding":   ("Base64 missing `=` padding",
                      "Truncated / manually-typed base64 lacks trailing `=`. "
                      "Adding the correct amount fixes the decode."),
    "trim":          ("Leading / trailing whitespace",
                      "Off-by-one whitespace bytes at the ends of the paste."),
}


def diagnose(text: str) -> dict:
    """Dry-run diagnostic pass — analyze the payload, list every issue
    Troubleshoot *could* fix, and note whether the auto-decoder already
    succeeds without any repair.

    Returns a JSON-serializable report the frontend renders as a
    "here's what I found; click Proceed to apply" confirmation modal.
    """
    if not isinstance(text, str):
        text = str(text)

    findings: List[dict] = []
    # Dry-run: run each fixer over the ORIGINAL text in isolation. We do
    # not chain them, because we want the analyst to see every distinct
    # issue independently (chaining would mask which fixer contributed
    # what). A separate `refine()` call does the actual repair.
    for step in _PIPELINE:
        _new, fix = step(text)
        if fix is None:
            continue
        title, description = _FIXER_META.get(
            fix.id, (fix.label, fix.detail),
        )
        findings.append({
            "id": fix.id,
            "label": fix.label,
            "title": title,
            "description": description,
            "count": fix.count,
            "sample_before": (text[:80] if len(text) else ""),
            "sample_after":  (_new[:80] if _new else ""),
            "has_fix": True,
        })

    # Also detect known "no plugin will match this" anomalies. These are
    # things Troubleshoot cannot repair itself — they need a developer to
    # add a new decoder plugin. We surface them so the analyst knows to
    # pin the sample to the Regression Suite.
    anomalies: List[dict] = []
    # Presence of a large base64-looking blob (200+ chars) that Auto
    # Investigate's normal extractors don't recognize means we're likely
    # missing an extractor for the outer wrapper.
    m = re.search(r"[A-Za-z0-9+/=]{200,}", text)
    if m:
        anomalies.append({
            "id": "possible_missing_extractor",
            "title": "Large base64 blob detected — but no known wrapper",
            "description": (
                "There is a 200+ character base64 block in your payload, "
                "but no built-in extractor recognized its surrounding "
                "syntax. Troubleshoot's fallback plugin will still pull "
                "the largest quoted base64 blob at lower confidence. "
                "For a permanent fix, ask a developer to add an "
                "extractor plugin for this wrapper."
            ),
            "has_fix": False,
        })
    # Presence of hex-encoded XOR key + open() + exec = classic staged loader
    if re.search(r"bytes\.fromhex\s*\(\s*['\"][0-9a-fA-F]{16,}", text) and \
       re.search(r"open\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"]rb['\"]", text):
        anomalies.append({
            "id": "staged_xor_loader",
            "title": "Second-stage XOR file loader detected",
            "description": (
                "This payload reads a companion file and XOR-decrypts it. "
                "To fully decode you need the companion file. Troubleshoot "
                "cannot fetch remote files — but the payload is already "
                "flagged malicious by the rule engine."
            ),
            "has_fix": False,
        })

    return {
        "input_length": len(text),
        "findings": findings,          # things Troubleshoot CAN fix
        "anomalies": anomalies,        # things it CAN'T fix (info only)
        "total_repairs_available": len(findings),
        "would_change": len(findings) > 0,
    }


def refine(text: str) -> RefineResult:
    """Run the deterministic repair pipeline over the given payload text."""
    if not isinstance(text, str):
        text = str(text)
    original = text
    current = text
    fixes: List[Fix] = []
    for step in _PIPELINE:
        new, fix = step(current)
        if fix is not None:
            # Attach a small before/after preview drawn from the first change.
            fix.before_preview = current[:80]
            fix.after_preview = new[:80]
            fixes.append(fix)
            current = new
    return RefineResult(
        refined=current,
        fixes=fixes,
        original_length=len(original),
        refined_length=len(current),
        changed=current != original,
    )


def refine_to_dict(text: str) -> dict:
    """API-friendly serialization."""
    r = refine(text)
    return {
        "refined": r.refined,
        "changed": r.changed,
        "original_length": r.original_length,
        "refined_length": r.refined_length,
        "summary": r.summary(),
        "fixes": [asdict(f) for f in r.fixes],
    }
