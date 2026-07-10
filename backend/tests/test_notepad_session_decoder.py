"""Regression tests for the Notepad /SESSION: extractor plugin.

Ensures Windows 11 Notepad session-state arguments (which carry a base64-encoded
UTF-16LE file path) are decoded correctly by NivX Forge.
"""
from __future__ import annotations

import cyberlab.plugins  # noqa: F401 — registers plugins
from cyberlab.engine import auto_decode
from cyberlab.plugins import get as get_plugin


# Real-world payload reported by a user (defanged pieces intentionally kept
# as-is; the goal is to prove the decoder yields the persisted path).
REAL_PAYLOAD = (
    "CMDC:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11.2510.14.0"
    "_x64__8wekyb3d8bbwe\\Notepad\\Notepad.exe "
    "/SESSION:mKkWzDoWZ0eSpxweHL9MrwFCQwA6AFwAVQBzAGUAcgBzAFwAbABvAHUAawBpAG8A"
    "cwBrAFwATwBuAGUARAByAGkAdgBlACAALQAgAFAAaQBzAHQAbwBuACAARwByAG8AdQBwAFwA"
    "RABlAHMAawB0AG8AcABcAHMAdABhAHIAdAB1AHAAXwBlAGQAZwBlAC4AYgBhAHQAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECAAEkCAAANwIAAAgD"
    "AAAAAAAA"
)

EXPECTED_PATH = (
    "C:\\Users\\loukiosk\\OneDrive - Piston Group\\Desktop\\startup_edge.bat"
)


def test_plugin_registered():
    plugin = get_plugin("extract-notepad-session")
    assert plugin.category == "Extractors"
    assert plugin.detect is not None


def test_detect_scores_high_on_session_arg():
    plugin = get_plugin("extract-notepad-session")
    score = plugin.detect(REAL_PAYLOAD.encode("utf-8"))
    assert score >= 0.9, f"expected high detect score, got {score}"


def test_detect_returns_zero_on_unrelated_input():
    plugin = get_plugin("extract-notepad-session")
    assert plugin.detect(b"powershell -enc SGVsbG8=") == 0.0
    assert plugin.detect(b"hello world") == 0.0


def test_extract_yields_persisted_path():
    plugin = get_plugin("extract-notepad-session")
    out = plugin.run(REAL_PAYLOAD.encode("utf-8"), {})
    text = out.decode("utf-8", errors="replace")
    assert EXPECTED_PATH in text, (
        f"expected {EXPECTED_PATH!r} in extractor output, got: {text!r}"
    )


def test_auto_decode_recovers_path():
    """The auto-decoder should pick the Notepad /SESSION: extractor and
    surface the persisted path in one pass."""
    final_bytes, trace = auto_decode(REAL_PAYLOAD, max_depth=6)
    text = final_bytes.decode("utf-8", errors="replace")
    assert EXPECTED_PATH in text, (
        f"auto_decode did not surface the persisted path.\n"
        f"trace steps: {[s.id for s in trace]}\n"
        f"final text: {text!r}"
    )
    step_ids = [s.id for s in trace]
    assert "extract-notepad-session" in step_ids, (
        f"extract-notepad-session was not selected by auto_decode; "
        f"trace: {step_ids}"
    )
