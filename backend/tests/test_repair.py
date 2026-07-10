"""Pytest coverage for the deterministic /refine pipeline.

These tests intentionally use ZERO external network calls or LLM APIs —
that's the whole point of `refine`: it must keep working after the app is
moved to any VPS without an Emergent LLM key.
"""
from __future__ import annotations

import pytest

from cyberlab import repair as repair_mod


# ---------------------------------------------------------------------------
# Individual repairs
# ---------------------------------------------------------------------------
def test_no_fixes_needed_returns_clean_result():
    r = repair_mod.refine("powershell.exe -enc SGVsbG8=")
    assert r.changed is False
    assert r.fixes == []
    assert "clean" in r.summary().lower()


def test_folds_all_unicode_dashes():
    src = "powershell.exe \u2013nop \u2014w hidden \u2212enc AAA="
    r = repair_mod.refine(src)
    assert "\u2013" not in r.refined
    assert "-nop" in r.refined and "-w" in r.refined and "-enc" in r.refined
    dash_fix = next(f for f in r.fixes if f.id == "unicode_dash")
    assert dash_fix.count == 3


def test_folds_smart_quotes():
    src = 'echo \u201Chello\u201D and \u2018world\u2019'
    r = repair_mod.refine(src)
    assert '"hello"' in r.refined
    assert "'world'" in r.refined
    quote_fix = next(f for f in r.fixes if f.id == "smart_quote")
    assert quote_fix.count == 4


def test_folds_nbsp_and_narrow_spaces():
    src = "powershell\u00a0-enc\u2009AAA="
    r = repair_mod.refine(src)
    assert "\u00a0" not in r.refined
    assert "\u2009" not in r.refined
    assert next(f for f in r.fixes if f.id == "nbsp").count == 2


def test_strips_zero_width_chars():
    src = "power\u200bshell\u200c.exe\u200d -enc\ufeff AAA="
    r = repair_mod.refine(src)
    assert "\u200b" not in r.refined
    assert "\ufeff" not in r.refined
    assert next(f for f in r.fixes if f.id == "zero_width").count == 4


def test_strips_email_quote_markers():
    src = "> powershell.exe -enc SGVsbG8=\n> next line\nnot quoted"
    r = repair_mod.refine(src)
    assert not r.refined.splitlines()[0].startswith("> ")
    assert next(f for f in r.fixes if f.id == "email_quote").count == 2


def test_strips_ellipsis():
    src = "powershell -enc AAAA\u2026BBBB...CCCC"
    r = repair_mod.refine(src)
    assert "\u2026" not in r.refined
    assert "..." not in r.refined
    ell = next(f for f in r.fixes if f.id == "ellipsis")
    assert ell.count == 2


def test_strips_cmd_carets():
    src = "p^o^w^e^r^shell.exe -e^n^c SGVsbG8="
    r = repair_mod.refine(src)
    assert "powershell.exe" in r.refined
    assert "-enc" in r.refined
    caret = next(f for f in r.fixes if f.id == "cmd_caret")
    assert caret.count >= 4


def test_leaves_isolated_caret_alone():
    """`3 ^ 2` (bit-shift operator) has NO intra-token carets → should be
    left untouched."""
    src = "value = 3 ^ 2"
    r = repair_mod.refine(src)
    assert not any(f.id == "cmd_caret" for f in r.fixes)


def test_unfolds_base64_line_wraps():
    src = "AAAABBBB\nCCCCDDDD\nEEEEFFFF=="
    r = repair_mod.refine(src)
    assert "\n" not in r.refined
    assert r.refined == "AAAABBBBCCCCDDDDEEEEFFFF=="
    assert next(f for f in r.fixes if f.id == "b64_line_wrap").count == 2


def test_adds_missing_base64_padding():
    # 26-char run → needs 2 = padding chars
    src = "SGVsbG8gV29ybGQhIEZvb0Jhcg"  # base64 of "Hello World! FooBar" no padding
    r = repair_mod.refine(src)
    assert r.refined.endswith("==")
    assert next(f for f in r.fixes if f.id == "b64_padding").count == 1


def test_trims_leading_and_trailing_whitespace():
    src = "  \n  powershell -enc SGVsbG8=  \n\t"
    r = repair_mod.refine(src)
    assert not r.refined.startswith(" ")
    assert not r.refined.endswith(" ")


# ---------------------------------------------------------------------------
# End-to-end: user's screenshot payload (en-dashes + NBSP)
# ---------------------------------------------------------------------------
def test_screenshot_payload_end_to_end():
    """The exact failure pattern from the user's Preview screenshot: paste
    from a rich-text source produces en-dashes + NBSPs that break every
    flag-based extractor. Refine must produce a fully-ASCII payload."""
    src = "powershell.exe \u2013nop \u2013w hidden \u2013NonI \u2013enc\u00a0SGVsbG8="
    r = repair_mod.refine(src)
    assert r.changed
    assert r.refined == "powershell.exe -nop -w hidden -NonI -enc SGVsbG8="
    assert {"unicode_dash", "nbsp"} <= {f.id for f in r.fixes}


def test_summary_includes_all_repairs():
    src = "\u2013enc \u201Chello\u201D\u200b..."
    r = repair_mod.refine(src)
    s = r.summary()
    assert "Unicode dash" in s
    assert "Smart quote" in s
    assert "Zero-width" in s


def test_serialization_shape():
    """API returns a JSON-friendly dict with the expected keys."""
    d = repair_mod.refine_to_dict("\u2013enc AAA")
    assert set(d.keys()) == {
        "refined", "changed", "original_length", "refined_length",
        "summary", "fixes",
    }
    assert isinstance(d["fixes"], list)
    if d["fixes"]:
        for k in ("id", "label", "detail", "count",
                  "before_preview", "after_preview"):
            assert k in d["fixes"][0]


def test_pipeline_is_pure_stdlib():
    """Nothing in `repair.py` should depend on network, LLM, or external DB.
    If the app is transferred to another VPS, this endpoint must still work
    with only the Python stdlib available."""
    import inspect
    src = inspect.getsource(repair_mod)
    for forbidden in ("httpx", "requests", "openai", "anthropic",
                      "emergentintegrations", "motor", "aiohttp"):
        assert forbidden not in src, f"repair.py must not import {forbidden}"
