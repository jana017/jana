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
from typing import Optional, List, Dict
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


# ============================================================================
# Auto Investigation — end-to-end orchestrator (format detect + decode/parse +
# threat analysis + optional AI). Used by CyberLab UI "Auto Investigate" CTA.
# ============================================================================

# Reasonably strict base64 fragment matcher (UTF-16LE PowerShell payloads,
# nested macros, cert files, etc.). Requires ≥40 chars so we don't
# hallucinate matches for short IDs.
import base64 as _b64
import re as _re
_B64_FRAGMENT = _re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _extract_and_decode_embedded_b64(text: str, limit: int = 5) -> str:
    """Find base64 fragments embedded in a longer text, decode them
    (trying UTF-8 + UTF-16LE), and return a text blob containing the
    decoded strings. Used to surface URLs/IOCs hidden inside VBA macros,
    PowerShell here-strings, certutil-encoded blobs, etc.
    """
    extras: list[str] = []
    matches = list(_B64_FRAGMENT.finditer(text))[:limit]
    for m in matches:
        frag = m.group(0)
        if len(frag) % 4:
            frag = frag + "=" * (-len(frag) % 4)
        try:
            data = _b64.b64decode(frag, validate=False)
        except Exception:
            continue
        # Prefer UTF-16LE first (PowerShell -EncodedCommand + VBA/JS macro
        # style). Fall back to UTF-8. Reject decoded strings with embedded
        # NULs (they slip past IOC regexes).
        candidates: list[str] = []
        # UTF-16LE only if length is even AND the data has plenty of nulls
        if len(data) % 2 == 0 and data.count(b"\x00") >= max(2, len(data) // 4):
            try:
                candidates.append(data.decode("utf-16-le"))
            except Exception:
                pass
        try:
            candidates.append(data.decode("utf-8"))
        except Exception:
            pass
        for cand in candidates:
            cand = cand.strip("\x00").strip()
            if "\x00" in cand:
                continue
            if cand and any(c.isprintable() for c in cand[:80]):
                extras.append(cand)
                break
    return "\n".join(extras)


class DetectFormatRequest(BaseModel):
    input: str


@router.post("/detect-format")
async def detect_format(req: DetectFormatRequest):
    """Classify raw input as a supported log format or a plain payload."""
    text = req.input or ""
    fmt = sysmon.detect_format(text)
    kind = "log" if fmt in {"xml", "json", "csv", "zeek", "cef", "leef"} else "payload"
    # 'json' is ambiguous — could be a small IOC bundle. Only classify as log
    # when it contains recognisable sysmon/EDR fields.
    if fmt == "json":
        low = text.lower()
        markers = ("processguid", "commandline", "event_simpleName".lower(),
                   "event_simplename", "eventid", "winlog", "@timestamp",
                   "process.executable", "device_process_events", "event.code")
        if not any(m in low for m in markers):
            kind = "payload"
    return {
        "format": fmt,
        "kind": kind,
        "size": len(text),
    }


class AutoInvestigateRequest(BaseModel):
    input: str
    max_depth: int = Field(default=10, ge=1, le=20)
    include_ai: bool = True
    format_hint: Optional[str] = None  # 'auto' | 'payload' | 'log' | log-format


@router.post("/auto-investigate")
async def auto_investigate(req: AutoInvestigateRequest, session_id: Optional[str] = None):
    """One-shot orchestrator combining format detection, recursive decoding /
    log parsing, threat analysis, and (optional) AI SIEM-query generation.

    Response shape:
        {
          "kind": "payload" | "log",
          "format": "raw" | "xml" | "json" | "csv" | "cef" | "leef" | "zeek" | "evtx",
          "output": str,                # decoded final payload (payload mode) or ""
          "trace": [StepResult],        # decoder trace (payload mode)
          "forensic_events": [...],     # log mode
          "tree": {nodes, edges, stats},# log mode
          "analysis": {iocs, mitre, rules, risk_score, verdict, summary},
          "ai": {summary, sigma_rule, yara_rule, splunk_spl, sentinel_kql, cisco_xdr} | None,
          "stages": [{name, status, duration_ms, meta}],
          "duration_ms": float,
        }
    """
    t_all = time.perf_counter()
    stages: List[dict] = []

    def _stage(name: str, status: str, dt_ms: float, meta: Optional[dict] = None):
        stages.append({"name": name, "status": status, "duration_ms": round(dt_ms, 2), "meta": meta or {}})

    try:
        # Stage 1 — Detect format
        t0 = time.perf_counter()
        raw = req.input or ""
        if not raw.strip():
            raise HTTPException(status_code=400, detail="Empty input")
        fmt = req.format_hint or sysmon.detect_format(raw)
        log_formats = {"xml", "json", "csv", "zeek", "cef", "leef"}
        kind = "log" if fmt in log_formats else "payload"
        if fmt == "json":
            markers = ("processguid", "commandline", "event_simplename",
                       "eventid", "winlog", "@timestamp", "process.executable")
            if not any(m in raw.lower() for m in markers):
                kind = "payload"
                fmt = "raw"
        if req.format_hint == "payload":
            kind = "payload"
            fmt = "raw"
        _stage("detect", "ok", (time.perf_counter() - t0) * 1000, {"kind": kind, "format": fmt})

        result: dict = {"kind": kind, "format": fmt, "stages": stages}

        if kind == "log":
            # Stage 2a — parse log
            t0 = time.perf_counter()
            tree = sysmon.parse(raw, format_hint=fmt if fmt in log_formats else None)
            _stage("parse-log", "ok", (time.perf_counter() - t0) * 1000,
                   {"event_count": tree["stats"].get("event_count", 0),
                    "process_count": tree["stats"].get("process_count", 0)})
            forensic = tree.get("forensic_events", [])

            # Stage 3a — aggregate MITRE + IOCs across all events
            t0 = time.perf_counter()
            mitre_seen: Dict[str, dict] = {}
            for e in forensic:
                for t in e.get("mitre_techniques", []) or []:
                    mitre_seen.setdefault(t["id"], {
                        "id": t["id"], "name": t["name"], "tactic": t["tactic"],
                        "description": "", "evidence": [],
                    })
                    evd = e.get("command_line") or e.get("registry_key") or e.get("url") or ""
                    if evd and len(mitre_seen[t["id"]]["evidence"]) < 5:
                        mitre_seen[t["id"]]["evidence"].append(evd)
            mitre_list = list(mitre_seen.values())
            iocs = tree.get("iocs", [])
            # Compute risk from aggregated data
            score, verdict, summary = engine.compute_risk(len(mitre_list), [], len(iocs))
            # Boost by worst per-event risk
            worst = tree["stats"].get("worst_risk", "info")
            worst_boost = {"critical": 40, "high": 25, "medium": 10, "low": 5, "info": 0}.get(worst, 0)
            score = min(100, score + worst_boost)
            if score >= 60:
                verdict = "malicious"
            elif score >= 30:
                verdict = "suspicious"
            analysis = {
                "iocs": iocs, "mitre": mitre_list, "rules": [],
                "risk_score": score, "verdict": verdict, "summary": summary,
            }
            _stage("analyze", "ok", (time.perf_counter() - t0) * 1000,
                   {"mitre": len(mitre_list), "iocs": len(iocs), "risk_score": score})
            result.update({
                "output": "",
                "trace": [],
                "forensic_events": forensic,
                "tree": {"nodes": tree.get("nodes", []), "edges": tree.get("edges", []), "stats": tree.get("stats", {})},
                "analysis": analysis,
            })
            # Prepare a text blob for AI: top command lines + IOCs summary
            ai_blob_lines: List[str] = []
            for e in forensic[:40]:
                if e.get("command_line"):
                    ai_blob_lines.append(f"[{e.get('event_type','event')}] {e.get('command_line','')}")
                elif e.get("url"):
                    ai_blob_lines.append(f"[url] {e['url']}")
                elif e.get("registry_key"):
                    ai_blob_lines.append(f"[reg] {e['registry_key']} = {e.get('registry_value','')}")
            ai_blob = "\n".join(ai_blob_lines)[:4000]

        else:
            # Stage 2b — recursive auto-decode
            t0 = time.perf_counter()
            final_bytes, trace = engine.auto_decode(raw, max_depth=req.max_depth)
            text = _to_best_text(final_bytes)
            _stage("auto-decode", "ok", (time.perf_counter() - t0) * 1000,
                   {"steps": len(trace), "output_size": len(final_bytes)})
            # Stage 3b — analyse. Combine ORIGINAL + DECODED + any embedded
            # base64 fragments so MITRE/IOC matches survive when auto-decode
            # only touched the outer wrapper (e.g. `rundll32.exe javascript:...`)
            # or missed nested payloads (e.g. base64 URLs inside VBA macros).
            t0 = time.perf_counter()
            embedded = _extract_and_decode_embedded_b64(raw)
            combined_text = "\n".join(x for x in (raw, text if text != raw else "", embedded) if x)
            combined_bytes = combined_text.encode("utf-8", errors="replace")
            analysis = await _analyze(combined_text, combined_bytes, session_id)
            _stage("analyze", "ok", (time.perf_counter() - t0) * 1000,
                   {"mitre": len(analysis["mitre"]),
                    "rules": len(analysis["rules"]),
                    "iocs": len(analysis["iocs"]),
                    "risk_score": analysis["risk_score"]})
            result.update({
                "output": text,
                "output_size": len(final_bytes),
                "trace": [t.model_dump() for t in trace],
                "forensic_events": [],
                "tree": {"nodes": [], "edges": [], "stats": {}},
                "analysis": analysis,
            })
            ai_blob = text[:4000]

        # Stage 4 — Optional AI analysis (Claude Sonnet 4.5)
        ai_result = None
        if req.include_ai:
            t0 = time.perf_counter()
            try:
                ai_result = await ai_analysis.generate_ai_analysis(
                    decoded_output=ai_blob,
                    mitre=result["analysis"]["mitre"],
                    rules=result["analysis"]["rules"],
                    iocs=result["analysis"]["iocs"],
                    verdict=result["analysis"]["verdict"],
                    risk=result["analysis"]["risk_score"],
                )
                _stage("ai", "ok", (time.perf_counter() - t0) * 1000, {})
            except Exception as e:
                logger.exception("auto-investigate: AI stage failed")
                _stage("ai", "failed", (time.perf_counter() - t0) * 1000, {"error": str(e)[:200]})
        result["ai"] = ai_result
        result["duration_ms"] = round((time.perf_counter() - t_all) * 1000, 2)
        return result
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("auto-investigate failed")
        raise HTTPException(status_code=500, detail=str(e))


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
