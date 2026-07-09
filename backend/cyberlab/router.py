"""FastAPI router for CyberLab endpoints. Mounted at /api/cyberlab/*.

Endpoints (public):
    GET  /api/cyberlab/plugins
    GET  /api/cyberlab/rules
    POST /api/cyberlab/run
    POST /api/cyberlab/auto-decode
    POST /api/cyberlab/analyze
    POST /api/cyberlab/extract-iocs

Phase 4 additions:
    POST /api/cyberlab/ai-analysis           (Claude Sonnet 4.5 report + rule gen)
    POST /api/cyberlab/share                 (persist analysis, return share_id)
    GET  /api/cyberlab/share/{share_id}      (fetch persisted analysis)
    POST /api/cyberlab/export/pdf            (branded ReportLab PDF)
    POST /api/cyberlab/export/markdown       (Markdown text)

    GET  /api/cyberlab/session-rules         (list rules for a session_id)
    POST /api/cyberlab/session-rules         (add a rule scoped to a session_id)
    DEL  /api/cyberlab/session-rules/{id}    (remove)

    GET  /api/admin/cyberlab/rules           (admin: list all custom rules)
    POST /api/admin/cyberlab/rules           (admin: add rule to global list)
    DEL  /api/admin/cyberlab/rules/{id}      (admin: remove)
"""
from __future__ import annotations
import time
import logging
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from pydantic import BaseModel, Field

from . import engine
from . import ioc_extract
from . import mitre
from . import rule_scanner
from . import persistence
from . import exports
from . import ai_analysis
from . import sysmon
from . import og_image
from .plugins import all_plugins
from .plugins.decoders import _to_best_text
from .models import (
    RunRecipeRequest, AutoDecodeRequest, AnalyzeRequest,
    AnalysisReport, PluginInfo,
)

logger = logging.getLogger("cyberlab")
router = APIRouter(prefix="/api/cyberlab", tags=["cyberlab"])
admin_router = APIRouter(prefix="/api/admin/cyberlab", tags=["cyberlab-admin"])


# ============================================================================
# Public endpoints
# ============================================================================

@router.get("/plugins", response_model=list[PluginInfo])
async def list_plugins():
    return [
        PluginInfo(
            id=p.id, name=p.name, category=p.category,
            description=p.description, params=p.params, tags=p.tags,
        )
        for p in all_plugins()
    ]


@router.get("/rules")
async def list_rules(session_id: Optional[str] = None):
    """Return builtin rules + any session-scoped custom rules if session_id given."""
    builtin = [
        {
            "name": r["name"], "tags": r.get("tags", []),
            "severity": r.get("severity", "medium"),
            "description": r.get("description", ""),
            "string_count": len(r.get("strings", [])),
            "scope": "builtin",
        }
        for r in rule_scanner.BUILTIN_RULES
    ]
    admin_rules = await persistence.list_rules("admin")
    session_rules = await persistence.list_rules("session", session_id) if session_id else []
    return {
        "builtin": builtin,
        "admin": [_rule_summary(r) for r in admin_rules],
        "session": [_rule_summary(r) for r in session_rules],
    }


def _rule_summary(r):
    return {
        "id": r.get("id"), "name": r["name"], "tags": r.get("tags", []),
        "severity": r.get("severity", "medium"),
        "description": r.get("description", ""),
        "string_count": len(r.get("strings", [])),
        "scope": r.get("scope"),
    }


@router.post("/run")
async def run_recipe(req: RunRecipeRequest):
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
async def auto_decode(req: AutoDecodeRequest, session_id: Optional[str] = None):
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
            result["analysis"] = await _analyze(_to_best_text(final_bytes), final_bytes, session_id)
        return result
    except Exception as e:
        logger.exception("auto_decode failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze", response_model=AnalysisReport)
async def analyze(req: AnalyzeRequest, session_id: Optional[str] = None):
    try:
        t0 = time.perf_counter()
        if req.auto_decode:
            final_bytes, trace = engine.auto_decode(req.input, max_depth=10)
        else:
            final_bytes = req.input.encode("utf-8", errors="replace")
            trace = []
        text = _to_best_text(final_bytes)
        analysis_dict = await _analyze(text, final_bytes, session_id)
        return AnalysisReport(
            input_size=len(req.input.encode("utf-8", errors="replace")),
            final_output=text,
            trace=trace,
            iocs=analysis_dict["iocs"],
            mitre=analysis_dict["mitre"],
            rules=analysis_dict["rules"],
            risk_score=analysis_dict["risk_score"],
            verdict=analysis_dict["verdict"],
            summary=analysis_dict["summary"],
            duration_ms=round((time.perf_counter() - t0) * 1000, 2),
        )
    except Exception as e:
        logger.exception("analyze failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/extract-iocs")
async def extract_iocs(payload: dict):
    text = payload.get("input", "")
    text = _refang_text(text)
    iocs = ioc_extract.extract(text)
    return {
        "count": len(iocs),
        "by_type": ioc_extract.summarize(iocs),
        "iocs": [i.model_dump() for i in iocs],
    }


# ============================================================================
# Sysmon / EDR process-tree ingestion (P3)
# ============================================================================

class SysmonRequest(BaseModel):
    input: str
    format: Optional[str] = None  # 'xml' | 'json' | 'csv' | 'zeek' | 'cef' | 'leef' | 'evtx' (base64)


@router.post("/process-tree")
async def process_tree(req: SysmonRequest):
    """Parse Sysmon / EDR / SIEM logs (XML / JSON / CSV / Zeek / CEF / LEEF / EVTX-base64)
    into a parent-child process tree + normalized 34-field forensic records."""
    try:
        if req.format == "evtx":
            import base64
            try:
                data = base64.b64decode(req.input, validate=False)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"EVTX input must be base64-encoded: {e}")
            raw_events = sysmon.parse_evtx(data)
            forensic = [sysmon._normalize_event(e) for e in raw_events if e]
            proc = [e for e in forensic if e["event_id"] == 1]
            tree = sysmon.build_tree(proc) if proc else {"nodes": [], "edges": [], "stats": {"process_count": 0, "edge_count": 0, "risk_counts": {}, "worst_risk": "info"}}
            by_action = {}
            for e in forensic:
                by_action[e["action"]] = by_action.get(e["action"], 0) + 1
            return {
                "format": "evtx",
                "forensic_events": forensic,
                "iocs": sysmon.extract_iocs_from_events(forensic),
                "nodes": tree["nodes"], "edges": tree["edges"],
                "stats": {**tree["stats"], "event_count": len(forensic), "by_action": by_action},
            }
        tree = sysmon.parse(req.input, format_hint=req.format)
        return tree
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("process_tree failed")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Phase 4: AI Analysis (Claude Sonnet 4.5)
# ============================================================================

class AiRequest(BaseModel):
    input: str
    output: str
    analysis: dict


@router.post("/ai-analysis")
async def ai_endpoint(req: AiRequest):
    """Generate an AI triage summary + draft Sigma & YARA rules for the payload."""
    try:
        analysis = req.analysis or {}
        result = await ai_analysis.generate_ai_analysis(
            decoded_output=req.output or req.input,
            mitre=analysis.get("mitre", []),
            rules=analysis.get("rules", []),
            iocs=analysis.get("iocs", []),
            verdict=analysis.get("verdict", "clean"),
            risk=analysis.get("risk_score", 0),
        )
        return result
    except Exception as e:
        logger.exception("ai-analysis failed")
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {e}")


# ============================================================================
# Phase 4: Sharing (30-day TTL) + Exports
# ============================================================================

class ShareRequest(BaseModel):
    input: str
    output: str
    trace: List[dict] = Field(default_factory=list)
    analysis: dict = Field(default_factory=dict)
    ai: Optional[dict] = None


@router.post("/share")
async def create_share(req: ShareRequest):
    payload = req.model_dump()
    result = await persistence.save_share(payload)
    return result


@router.get("/share/{share_id}")
async def get_share(share_id: str):
    doc = await persistence.get_share(share_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Share not found or expired")
    return doc


@router.get("/share/{share_id}/og.png")
async def get_share_og_image(share_id: str):
    """Auto-generated 1200x630 OG image for viral DFIR sharing."""
    doc = await persistence.get_share(share_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Share not found or expired")
    try:
        png = og_image.render(doc["payload"])
    except Exception as e:
        logger.exception("og image render failed")
        raise HTTPException(status_code=500, detail=str(e))
    return Response(
        content=png,
        media_type="image/png",
        headers={
            "Cache-Control": "public, max-age=86400",  # 1 day
            "Content-Disposition": f'inline; filename="cyberlab-share-{share_id}.png"',
        },
    )


@router.post("/export/pdf")
async def export_pdf(req: ShareRequest):
    pdf_bytes = exports.render_pdf(req.model_dump())
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="cyberlab-report-{int(time.time())}.pdf"'},
    )


@router.post("/export/markdown")
async def export_markdown(req: ShareRequest):
    md = exports.render_markdown(req.model_dump())
    return Response(
        content=md,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="cyberlab-report-{int(time.time())}.md"'},
    )


# ============================================================================
# Phase 4: Session-scoped custom rules (anon users)
# ============================================================================

class RulePayload(BaseModel):
    name: str
    severity: str = "medium"
    description: str = ""
    tags: List[str] = Field(default_factory=list)
    strings: List[dict]


@router.get("/session-rules")
async def session_list(session_id: str):
    rules = await persistence.list_rules("session", session_id)
    return {"rules": rules}


@router.post("/session-rules")
async def session_add(rule: RulePayload, session_id: str):
    _validate_rule(rule)
    return await persistence.add_rule(rule.model_dump(), "session", session_id, author="session")


@router.delete("/session-rules/{rule_id}")
async def session_remove(rule_id: str, session_id: str):
    ok = await persistence.delete_rule(rule_id, "session", session_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"deleted": True}


# ============================================================================
# Phase 4: Admin custom rules (global)
# ============================================================================

async def _require_admin(request: Request):
    """Reuse the existing JWT cookie/bearer admin auth from server.py."""
    from server import get_current_user  # deferred to avoid import cycle
    return await get_current_user(request)


@admin_router.get("/rules")
async def admin_list_rules(user=Depends(_require_admin)):
    rules = await persistence.list_rules("admin")
    return {"rules": rules}


@admin_router.post("/rules")
async def admin_add_rule(rule: RulePayload, user=Depends(_require_admin)):
    _validate_rule(rule)
    return await persistence.add_rule(rule.model_dump(), "admin", None, author=user.get("email", "admin"))


@admin_router.delete("/rules/{rule_id}")
async def admin_remove_rule(rule_id: str, user=Depends(_require_admin)):
    ok = await persistence.delete_rule(rule_id, "admin")
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"deleted": True}


# ============================================================================
# Helpers
# ============================================================================

async def _analyze(text: str, raw: bytes, session_id: Optional[str] = None) -> dict:
    """Full non-decoding analysis pipeline. Loads admin + session rules dynamically."""
    refanged = _refang_text(text)
    iocs = ioc_extract.extract(refanged)
    techniques = mitre.map_techniques(text)
    extra_rules = await persistence.list_rules("admin")
    if session_id:
        extra_rules += await persistence.list_rules("session", session_id)
    rules = rule_scanner.scan(text, raw, extra_rules=extra_rules)
    score, verdict, summary = engine.compute_risk(len(techniques), rules, len(iocs))
    return {
        "iocs": [i.model_dump() for i in iocs],
        "mitre": [t.model_dump() for t in techniques],
        "rules": [r.model_dump() for r in rules],
        "risk_score": score,
        "verdict": verdict,
        "summary": summary,
    }


def _refang_text(text: str) -> str:
    import re as _re
    text = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    text = _re.sub(r"\[?\bhxxp(s?)\b\]?://", r"http\1://", text, flags=_re.IGNORECASE)
    text = _re.sub(r"\[?\bfxp\b\]?://", "ftp://", text, flags=_re.IGNORECASE)
    text = text.replace("[at]", "@").replace("(at)", "@").replace("[@]", "@")
    text = text.replace("[://]", "://")
    return text


def _validate_rule(rule: RulePayload) -> None:
    if not rule.name.strip():
        raise HTTPException(status_code=400, detail="Rule name is required")
    if not rule.strings:
        raise HTTPException(status_code=400, detail="At least one string/pattern is required")
    for s in rule.strings:
        if s.get("type") not in ("string", "regex", "hex"):
            raise HTTPException(status_code=400, detail=f"Unknown string type: {s.get('type')}")
        if not s.get("pattern"):
            raise HTTPException(status_code=400, detail="Each string must have a pattern")
    if rule.severity not in ("info", "low", "medium", "high", "critical"):
        raise HTTPException(status_code=400, detail=f"Invalid severity: {rule.severity}")
