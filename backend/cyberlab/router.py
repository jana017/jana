"""FastAPI router for CyberLab endpoints. Mounted at /api/cyberlab/*."""
from __future__ import annotations
import time
import logging
from fastapi import APIRouter, HTTPException

from . import engine
from . import ioc_extract
from . import mitre
from . import rule_scanner
from .plugins import all_plugins
from .plugins.decoders import _to_best_text
from .models import (
    RunRecipeRequest, AutoDecodeRequest, AnalyzeRequest,
    AnalysisReport, PluginInfo,
)

logger = logging.getLogger("cyberlab")
router = APIRouter(prefix="/api/cyberlab", tags=["cyberlab"])


@router.get("/plugins", response_model=list[PluginInfo])
async def list_plugins():
    """List all available plugins (decoders, transformers, analyzers)."""
    return [
        PluginInfo(
            id=p.id, name=p.name, category=p.category,
            description=p.description, params=p.params, tags=p.tags,
        )
        for p in all_plugins()
    ]


@router.get("/rules")
async def list_rules():
    """List all bundled YARA-like rules."""
    return [
        {
            "name": r["name"],
            "tags": r.get("tags", []),
            "severity": r.get("severity", "medium"),
            "description": r.get("description", ""),
            "string_count": len(r.get("strings", [])),
        }
        for r in rule_scanner.BUILTIN_RULES
    ]


@router.post("/run")
async def run_recipe(req: RunRecipeRequest):
    """Execute a manual recipe. Returns final output + step trace."""
    try:
        t0 = time.perf_counter()
        final_bytes, trace = engine.run_recipe(req.input, req.recipe)
        dt = (time.perf_counter() - t0) * 1000
        return {
            "output": _to_best_text(final_bytes),
            "output_size": len(final_bytes),
            "output_hex_preview": final_bytes[:64].hex(),
            "trace": [t.model_dump() for t in trace],
            "duration_ms": round(dt, 2),
        }
    except Exception as e:
        logger.exception("run_recipe failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/auto-decode")
async def auto_decode(req: AutoDecodeRequest):
    """Recursively auto-decode a payload. Returns final output + trace."""
    try:
        t0 = time.perf_counter()
        final_bytes, trace = engine.auto_decode(req.input, max_depth=req.max_depth)
        result = {
            "output": _to_best_text(final_bytes),
            "output_size": len(final_bytes),
            "output_hex_preview": final_bytes[:64].hex(),
            "trace": [t.model_dump() for t in trace],
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
        }
        if req.include_analysis:
            text = _to_best_text(final_bytes)
            refanged = _refang_text(text)
            iocs = ioc_extract.extract(refanged)
            techniques = mitre.map_techniques(text)
            rules = rule_scanner.scan(text, final_bytes)
            score, verdict, summary = engine.compute_risk(
                len(techniques), rules, len(iocs)
            )
            result["analysis"] = {
                "iocs": [i.model_dump() for i in iocs],
                "mitre": [t.model_dump() for t in techniques],
                "rules": [r.model_dump() for r in rules],
                "risk_score": score,
                "verdict": verdict,
                "summary": summary,
            }
        return result
    except Exception as e:
        logger.exception("auto_decode failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze", response_model=AnalysisReport)
async def analyze(req: AnalyzeRequest):
    """Full analysis pipeline: (optional) auto-decode + IOC + MITRE + YARA-lite + risk score."""
    try:
        t0 = time.perf_counter()
        if req.auto_decode:
            final_bytes, trace = engine.auto_decode(req.input, max_depth=10)
        else:
            final_bytes = req.input.encode("utf-8", errors="replace")
            trace = []
        text = _to_best_text(final_bytes)
        # Refang for IOC extraction (doesn't mutate the displayed output)
        refanged = _refang_text(text)
        iocs = ioc_extract.extract(refanged)
        techniques = mitre.map_techniques(text)
        rules = rule_scanner.scan(text, final_bytes)
        score, verdict, summary = engine.compute_risk(
            len(techniques), rules, len(iocs)
        )
        return AnalysisReport(
            input_size=len(req.input.encode("utf-8", errors="replace")),
            final_output=text,
            trace=trace,
            iocs=iocs,
            mitre=techniques,
            rules=rules,
            risk_score=score,
            verdict=verdict,
            summary=summary,
            duration_ms=round((time.perf_counter() - t0) * 1000, 2),
        )
    except Exception as e:
        logger.exception("analyze failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/extract-iocs")
async def extract_iocs(payload: dict):
    """Fast IOC-only extraction endpoint."""
    text = payload.get("input", "")
    text = _refang_text(text)
    iocs = ioc_extract.extract(text)
    return {
        "count": len(iocs),
        "by_type": ioc_extract.summarize(iocs),
        "iocs": [i.model_dump() for i in iocs],
    }


def _refang_text(text: str) -> str:
    """Convert defanged IOCs back to their live form for extraction only."""
    import re as _re
    text = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    text = _re.sub(r"\[?\bhxxp(s?)\b\]?://", r"http\1://", text, flags=_re.IGNORECASE)
    text = _re.sub(r"\[?\bfxp\b\]?://", "ftp://", text, flags=_re.IGNORECASE)
    text = text.replace("[at]", "@").replace("(at)", "@").replace("[@]", "@")
    text = text.replace("[://]", "://")
    return text
