"""CyberLab core engine.

Runs recipes (chains of plugin steps) and performs auto-decode using
plugin `detect()` heuristics + confidence scoring on the output text.
"""
from __future__ import annotations
import time
from typing import List, Dict, Any, Tuple

from .plugins import get as get_plugin, auto_candidates
from .plugins.decoders import _to_best_text
from .models import RecipeStep, StepResult


SEVERITY_SCORE = {"info": 5, "low": 10, "medium": 25, "high": 50, "critical": 80}


def run_recipe(input_text: str, recipe: List[RecipeStep]) -> Tuple[bytes, List[StepResult]]:
    """Execute a recipe deterministically. Returns (final_bytes, trace)."""
    current = input_text.encode("utf-8", errors="replace")
    trace: List[StepResult] = []
    for step in recipe:
        if step.disabled:
            continue
        try:
            plugin = get_plugin(step.id)
        except KeyError as e:
            trace.append(StepResult(
                id=step.id, name=step.id, category="Unknown",
                input_preview=_preview(current), output_preview="",
                output_size=0, duration_ms=0.0,
                error=str(e),
            ))
            continue
        t0 = time.perf_counter()
        try:
            out = plugin.run(current, step.params or {})
            if not isinstance(out, (bytes, bytearray)):
                out = str(out).encode("utf-8", errors="replace")
            out = bytes(out)
            dt = (time.perf_counter() - t0) * 1000
            trace.append(StepResult(
                id=plugin.id, name=plugin.name, category=plugin.category,
                input_preview=_preview(current), output_preview=_preview(out),
                output_size=len(out), duration_ms=round(dt, 2),
            ))
            current = out
        except Exception as e:
            dt = (time.perf_counter() - t0) * 1000
            trace.append(StepResult(
                id=plugin.id, name=plugin.name, category=plugin.category,
                input_preview=_preview(current), output_preview="",
                output_size=0, duration_ms=round(dt, 2),
                error=f"{type(e).__name__}: {e}"[:200],
            ))
    return current, trace


def auto_decode(input_text: str, max_depth: int = 8) -> Tuple[bytes, List[StepResult]]:
    """Recursively pick the plugin with the highest detect() score and apply it.
    Stops when no plugin scores above threshold, output stops improving, or
    max_depth is reached."""
    current = input_text.encode("utf-8", errors="replace")
    trace: List[StepResult] = []
    seen_outputs = {_hash_bytes(current)}
    for _ in range(max_depth):
        best_plugin = None
        best_score = 0.0
        for plugin in auto_candidates():
            try:
                score = plugin.detect(current) or 0.0
            except Exception:
                score = 0.0
            if score > best_score:
                best_score = score
                best_plugin = plugin
        if not best_plugin or best_score < 0.7:
            break
        t0 = time.perf_counter()
        try:
            out = best_plugin.run(current, {})
            if not isinstance(out, (bytes, bytearray)):
                out = str(out).encode("utf-8", errors="replace")
            out = bytes(out)
        except Exception as e:
            trace.append(StepResult(
                id=best_plugin.id, name=best_plugin.name, category=best_plugin.category,
                input_preview=_preview(current), output_preview="",
                output_size=0, duration_ms=round((time.perf_counter() - t0) * 1000, 2),
                confidence=round(best_score, 2),
                error=f"{type(e).__name__}: {e}"[:200],
            ))
            break
        dt = (time.perf_counter() - t0) * 1000
        # Guard: skip if identical to a previous output (loop protection)
        h = _hash_bytes(out)
        if h in seen_outputs:
            break
        seen_outputs.add(h)
        # Guard: skip if the output looks obviously worse (mostly non-printable)
        out_text = _to_best_text(out)
        if len(out_text.strip()) == 0 and len(out) > 0:
            # Binary output - allow it but stop chaining text decoders next.
            pass
        trace.append(StepResult(
            id=best_plugin.id, name=best_plugin.name, category=best_plugin.category,
            input_preview=_preview(current), output_preview=_preview(out),
            output_size=len(out), duration_ms=round(dt, 2),
            confidence=round(best_score, 2),
        ))
        current = out
    # Final post-processing: if the decoded output is majority non-printable
    # AND we actually did decode something, surface a helpful diagnostic
    # instead of dumping CJK garbage from UTF-16LE-ing random bytes.
    if trace and _looks_unreadable(current):
        current = _corruption_notice(current)
    return current, trace


def _looks_unreadable(data: bytes) -> bool:
    """True when the output is majority non-printable — no ASCII or UTF-16LE
    strings that a human analyst can actually read."""
    if len(data) < 8:
        return False
    non_printable = sum(1 for b in data if b not in (9, 10, 13) and (b < 32 or b > 126))
    if non_printable / len(data) < 0.6:
        return False
    # Second chance: look for embedded UTF-16LE printable runs.
    import re as _re
    if _re.search(rb"(?:[\x20-\x7e]\x00){6,}", data):
        return False
    if _re.search(rb"[\x20-\x7e]{8,}", data):
        return False
    return True


def _corruption_notice(data: bytes) -> bytes:
    """Prepend a human-readable diagnostic when the payload is unreadable.

    Analysts always prefer a clear 'why did decoding fail?' message over a
    wall of CJK glyphs from UTF-16LE-ing random bytes.
    """
    return (
        b"[NivX Forge notice] Payload decoded successfully but yields no readable "
        b"ASCII or UTF-16LE content. Common causes:\n"
        b"  * The base64 blob has invalid byte alignment (stray char at start)\n"
        b"  * The payload was intentionally malformed to evade sandboxing\n"
        b"  * Custom / proprietary encoding - try manual decoders in the Operations panel\n"
        b"  * Truncated capture - missing bytes from the original payload\n\n"
        b"Raw decoded output (hex, first 128 bytes):\n"
        + data[:128].hex().encode("ascii")
        + (b"\n... (+%d more bytes)" % (len(data) - 128) if len(data) > 128 else b"")
    )


def compute_risk(mitre_count: int, rule_matches: List[Any], ioc_count: int) -> Tuple[int, str, str]:
    """Return (score, verdict, summary)."""
    score = 0
    score += min(mitre_count * 8, 40)
    for rule in rule_matches:
        score += SEVERITY_SCORE.get(getattr(rule, "severity", "medium"), 20)
    score += min(ioc_count, 20)
    score = min(score, 100)

    if score >= 60:
        verdict = "malicious"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "clean"

    parts = []
    if rule_matches:
        parts.append(f"{len(rule_matches)} rule match{'es' if len(rule_matches) != 1 else ''}")
    if mitre_count:
        parts.append(f"{mitre_count} MITRE technique{'s' if mitre_count != 1 else ''}")
    if ioc_count:
        parts.append(f"{ioc_count} IOC{'s' if ioc_count != 1 else ''}")
    summary = f"{verdict.title()} — " + ", ".join(parts) if parts else "No suspicious indicators detected."
    return score, verdict, summary


def _preview(data: bytes, limit: int = 240) -> str:
    text = _to_best_text(data)
    if len(text) > limit:
        return text[:limit] + f"… (+{len(text) - limit} chars)"
    return text


def _hash_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.md5(data).hexdigest()
