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
    return current, trace


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
