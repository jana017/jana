"""UI/UX Scanner — persistence layer only.

The actual scanning runs 100% in the browser (Admin tab), driving hidden
iframes across viewports and running deterministic DOM audits. The backend
only stores reports in Mongo `ui_scans` for history / audit trail.
Zero LLM. Zero external HTTP.
"""
from datetime import datetime, timezone
from typing import Any, List, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class UiFinding(BaseModel):
    route: str
    viewport: str
    viewport_w: int
    viewport_h: int
    severity: str        # CRIT | HIGH | MED | LOW
    type: str
    details: dict = Field(default_factory=dict)


class UiScanReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str
    finished_at: str
    routes_scanned: List[str] = []
    viewports_scanned: List[str] = []
    total_findings: int = 0
    counts_by_severity: dict = Field(default_factory=dict)
    counts_by_type: dict = Field(default_factory=dict)
    findings: List[UiFinding] = []
    triggered_by: Optional[str] = None
    notes: Optional[str] = None


router = APIRouter(prefix="/api/ui-scanner", tags=["ui-scanner"])


def _get_db():
    from server import db as _db  # lazy
    return _db


def attach_routes(app_router: APIRouter, auth_dep):
    """Register routes with the shared JWT auth dependency (admin-only in
    practice — the Admin panel is the only surface that calls these)."""

    @app_router.post("/scan", response_model=UiScanReport)
    async def save_scan(report: UiScanReport, user: dict = Depends(auth_dep)):
        db = _get_db()
        report.id = report.id or str(uuid.uuid4())
        by_sev: dict = {}
        by_type: dict = {}
        for f in report.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_type[f.type] = by_type.get(f.type, 0) + 1
        report.counts_by_severity = by_sev
        report.counts_by_type = by_type
        report.total_findings = len(report.findings)
        report.triggered_by = report.triggered_by or user.get("email")
        try:
            await db.ui_scans.insert_one(report.model_dump())
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"persist failed: {e}") from e
        return report

    @app_router.get("/history")
    async def history(limit: int = 20, user: dict = Depends(auth_dep)):  # noqa: ARG001
        db = _get_db()
        limit = max(1, min(int(limit), 100))
        cursor = db.ui_scans.find({}, {"_id": 0, "findings": 0}).sort("finished_at", -1).limit(limit)
        return {"items": [doc async for doc in cursor]}

    @app_router.get("/latest")
    async def latest(user: dict = Depends(auth_dep)):  # noqa: ARG001
        db = _get_db()
        doc = await db.ui_scans.find_one({}, {"_id": 0}, sort=[("finished_at", -1)])
        return doc or {}

    @app_router.get("/report/{scan_id}", response_model=UiScanReport)
    async def get_report(scan_id: str, user: dict = Depends(auth_dep)):  # noqa: ARG001
        db = _get_db()
        doc = await db.ui_scans.find_one({"id": scan_id}, {"_id": 0})
        if not doc:
            raise HTTPException(status_code=404, detail="scan not found")
        return doc

    @app_router.delete("/report/{scan_id}")
    async def delete_report(scan_id: str, user: dict = Depends(auth_dep)):  # noqa: ARG001
        db = _get_db()
        r = await db.ui_scans.delete_one({"id": scan_id})
        return {"deleted": r.deleted_count}

    @app_router.get("/health")
    async def health():
        try:
            db = _get_db()
            n = await db.ui_scans.count_documents({})
            return {"ok": True, "total_scans": n, "ts": _iso()}
        except Exception as e:
            return {"ok": False, "error": str(e), "ts": _iso()}


async def ensure_indexes() -> None:
    db = _get_db()
    try:
        await db.ui_scans.create_index([("finished_at", -1)])
        await db.ui_scans.create_index("id", unique=True)
    except Exception:
        pass
