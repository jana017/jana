"""HealthBot FastAPI routes — mounted under /api/healthbot.

Endpoints are admin-only (reusing the same JWT auth dep as the rest of the
platform). Every operation is deterministic and works offline.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException

from . import checks as _checks

logger = logging.getLogger("nivx.healthbot")

router = APIRouter(prefix="/api/healthbot", tags=["healthbot"])


def _get_db():
    from server import db as _db  # lazy
    return _db


def _severity_rank(s: str) -> int:
    return {"ok": 0, "info": 1, "warning": 2, "critical": 3}.get(s, 1)


def _overall(results: List[_checks.CheckResult]) -> str:
    return max(results, key=lambda r: _severity_rank(r.severity)).severity if results else "ok"


def _summary(results: List[_checks.CheckResult]) -> Dict[str, int]:
    tally = {"ok": 0, "info": 0, "warning": 0, "critical": 0}
    for r in results:
        tally[r.severity] = tally.get(r.severity, 0) + 1
    return tally


async def _record(scan: Dict[str, Any]) -> None:
    try:
        await _checks.persist_scan(scan)
    except Exception as e:  # noqa: BLE001
        logger.warning("failed to persist healthbot scan: %s", e)


def _serialize_history(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(doc.get("_id")),
        "started_at": doc.get("started_at"),
        "finished_at": doc.get("finished_at"),
        "overall": doc.get("overall"),
        "summary": doc.get("summary"),
        "auto_fixed": doc.get("auto_fixed", 0),
        "results": doc.get("results", []),
        "triggered_by": doc.get("triggered_by"),
    }


# ---------------------------------------------------------------------------
# Public route factory — bound to auth dep by server.py
# ---------------------------------------------------------------------------
def attach_routes(app_router: APIRouter, auth_dep):

    @app_router.post("/scan")
    async def scan_endpoint(user: dict = Depends(auth_dep)):
        started = datetime.now(timezone.utc).isoformat()
        t0 = asyncio.get_event_loop().time()
        results = await _checks.run_all_checks()
        finished = datetime.now(timezone.utc).isoformat()
        scan = {
            "started_at": started,
            "finished_at": finished,
            "duration_ms": round((asyncio.get_event_loop().time() - t0) * 1000, 2),
            "overall": _overall(results),
            "summary": _summary(results),
            "results": [_checks.to_dict(r) for r in results],
            "auto_fixed": 0,
            "triggered_by": user.get("email"),
        }
        await _record(scan)
        return scan

    @app_router.post("/scan-and-fix")
    async def scan_and_fix_endpoint(user: dict = Depends(auth_dep)):
        started = datetime.now(timezone.utc).isoformat()
        t0 = asyncio.get_event_loop().time()
        results = await _checks.run_all_checks()
        results = await _checks.run_all_fixes(results)
        # Re-run checks after fix to reflect the new state.
        post = await _checks.run_all_checks()
        # Merge: preserve fix_message / fixed flags from the fix pass.
        post_by_id = {r.id: r for r in post}
        for r in results:
            if r.id in post_by_id:
                new = post_by_id[r.id]
                # Keep the fix outcome fields on the fresh check.
                new.fixed = r.fixed
                new.fix_message = r.fix_message
        auto_fixed = sum(1 for r in results if r.fixed)
        finished = datetime.now(timezone.utc).isoformat()
        scan = {
            "started_at": started,
            "finished_at": finished,
            "duration_ms": round((asyncio.get_event_loop().time() - t0) * 1000, 2),
            "overall": _overall(list(post_by_id.values())),
            "summary": _summary(list(post_by_id.values())),
            "results": [_checks.to_dict(post_by_id[r.id]) for r in results if r.id in post_by_id],
            "auto_fixed": auto_fixed,
            "triggered_by": user.get("email"),
        }
        await _record(scan)
        return scan

    @app_router.post("/fix/{check_id}")
    async def fix_one_endpoint(check_id: str, user: dict = Depends(auth_dep)):
        result = await _checks.run_one_fix(check_id)
        if result is None:
            raise HTTPException(status_code=404, detail="check_id has no auto-fix")
        return _checks.to_dict(result)

    @app_router.get("/latest")
    async def latest_endpoint(user: dict = Depends(auth_dep)):
        """Most recent scan (from history) — used by the pre-flight banner
        to render an instant status without triggering a fresh scan."""
        db = _get_db()
        doc = await db.healthbot_scans.find_one({}, sort=[("started_at", -1)])
        if not doc:
            # No scan on record yet — banner will just not render.
            return {"overall": "ok", "summary": {}, "results": [],
                    "started_at": None, "finished_at": None,
                    "auto_fixed": 0, "triggered_by": None}
        return _serialize_history(doc)

    @app_router.get("/history")
    async def history_endpoint(limit: int = 50, user: dict = Depends(auth_dep)):
        db = _get_db()
        limit = max(1, min(limit, 100))
        docs = await db.healthbot_scans.find().sort("started_at", -1).limit(limit).to_list(limit)
        return [_serialize_history(d) for d in docs]

    # -----------------------------------------------------------------------
    # Custom regression samples — analysts can pin real-world payloads that
    # HealthBot's decoder_coverage check runs on every scan.
    # -----------------------------------------------------------------------
    def _serialize_sample(doc):
        return {
            "id": doc.get("id"),
            "label": doc.get("label", doc.get("id", "")),
            "input": doc.get("input", ""),
            "must_decode_to_contain": doc.get("must_decode_to_contain", ""),
            "enabled": doc.get("enabled", True),
            "created_at": doc.get("created_at"),
            "created_by": doc.get("created_by"),
        }

    @app_router.get("/regression-samples")
    async def list_samples(user: dict = Depends(auth_dep)):
        db = _get_db()
        docs = await db.healthbot_regression_samples.find().sort("created_at", -1).to_list(200)
        return [_serialize_sample(d) for d in docs]

    @app_router.post("/regression-samples")
    async def create_sample(payload: Dict[str, Any], user: dict = Depends(auth_dep)):
        input_text = (payload.get("input") or "").strip()
        needle = (payload.get("must_decode_to_contain") or "").strip()
        label = (payload.get("label") or "").strip() or f"custom-{int(datetime.now(timezone.utc).timestamp())}"
        if not input_text or not needle:
            raise HTTPException(status_code=400, detail="`input` and `must_decode_to_contain` are required")
        if len(input_text) > 32_000 or len(needle) > 2_000:
            raise HTTPException(status_code=413, detail="payload too large")
        db = _get_db()
        sample_id = payload.get("id") or f"sample_{int(datetime.now(timezone.utc).timestamp() * 1000)}"
        doc = {
            "id": sample_id,
            "label": label,
            "input": input_text,
            "must_decode_to_contain": needle,
            "enabled": bool(payload.get("enabled", True)),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_by": user.get("email"),
        }
        # upsert by id
        await db.healthbot_regression_samples.update_one(
            {"id": sample_id}, {"$set": doc}, upsert=True,
        )
        return _serialize_sample(doc)

    @app_router.delete("/regression-samples/{sample_id}")
    async def delete_sample(sample_id: str, user: dict = Depends(auth_dep)):
        db = _get_db()
        r = await db.healthbot_regression_samples.delete_one({"id": sample_id})
        return {"deleted": r.deleted_count}

    @app_router.post("/regression-samples/{sample_id}/toggle")
    async def toggle_sample(sample_id: str, user: dict = Depends(auth_dep)):
        db = _get_db()
        doc = await db.healthbot_regression_samples.find_one({"id": sample_id})
        if not doc:
            raise HTTPException(status_code=404, detail="sample not found")
        new_state = not doc.get("enabled", True)
        await db.healthbot_regression_samples.update_one(
            {"id": sample_id}, {"$set": {"enabled": new_state}},
        )
        return {"id": sample_id, "enabled": new_state}


async def ensure_indexes():
    db = _get_db()
    await db.healthbot_scans.create_index([("started_at", -1)])
    await db.healthbot_regression_samples.create_index("id", unique=True)
    await db.healthbot_regression_samples.create_index([("created_at", -1)])
