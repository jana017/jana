"""Webhook FastAPI router.

All endpoints require an authenticated admin (same `get_current_user`
dependency the rest of NivX admin uses — admin login is the only
authenticated user in this app).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException

# Reuse the auth dep + db client from server.py without creating a circular
# import — we lazily reach into server module at call time.
from . import delivery as _delivery
from . import presets as _presets
from .models import (
    DeliveryOut,
    PushRequest,
    WebhookCreate,
    WebhookOut,
    WebhookUpdate,
    utcnow_iso,
)

logger = logging.getLogger("nivx.webhooks")

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

_MAX_DELIVERIES = 100
_MASK = "***"


# ---------------------------------------------------------------------------
# Deferred imports to avoid circular deps with server.py
# ---------------------------------------------------------------------------
def _get_db():
    from server import db as _db  # type: ignore
    return _db


# ---------------------------------------------------------------------------
# Serializers
# ---------------------------------------------------------------------------
def _serialize(doc: Dict[str, Any], *, reveal_headers: bool = False) -> WebhookOut:
    headers = doc.get("headers") or {}
    if not reveal_headers:
        # Mask secret values in list/get responses. Header key is preserved so
        # the admin can see WHICH header they configured.
        headers = {k: (_MASK if _is_secret_header(k) else v) for k, v in headers.items()}
    return WebhookOut(
        id=str(doc["_id"]),
        name=doc["name"],
        target_type=doc.get("target_type", "custom"),
        url=doc["url"],
        method=doc.get("method", "POST"),
        headers=headers,
        payload_template=doc["payload_template"],
        content_mode=doc.get("content_mode", "bundle_iocs"),
        enabled=bool(doc.get("enabled", True)),
        created_at=doc.get("created_at") or utcnow_iso(),
        created_by=doc.get("created_by"),
        last_status=doc.get("last_status", "never"),
        last_sent_at=doc.get("last_sent_at"),
    )


def _is_secret_header(name: str) -> bool:
    n = name.lower()
    return any(t in n for t in ("auth", "token", "key", "secret", "cookie"))


def _serialize_delivery(doc: Dict[str, Any]) -> DeliveryOut:
    return DeliveryOut(
        id=str(doc["_id"]),
        webhook_id=str(doc["webhook_id"]),
        webhook_name=doc.get("webhook_name", ""),
        target_type=doc.get("target_type", "custom"),
        status=doc.get("status", "failed"),
        http_status=doc.get("http_status"),
        error=doc.get("error"),
        attempts=int(doc.get("attempts", 1)),
        response_snippet=doc.get("response_snippet"),
        content_summary=doc.get("content_summary", ""),
        sent_at=doc.get("sent_at") or utcnow_iso(),
        triggered_by=doc.get("triggered_by"),
    )


# ---------------------------------------------------------------------------
# Core operations (implementation) — invoked by public route stubs below.
# ---------------------------------------------------------------------------
async def _list_webhooks() -> List[WebhookOut]:
    db = _get_db()
    docs = await db.webhooks.find().sort("created_at", -1).to_list(500)
    return [_serialize(d) for d in docs]


async def _create_webhook(payload: WebhookCreate, user: dict) -> WebhookOut:
    db = _get_db()
    doc = payload.model_dump()
    doc["url"] = str(doc["url"])
    doc["created_at"] = utcnow_iso()
    doc["created_by"] = user.get("email")
    doc["last_status"] = "never"
    res = await db.webhooks.insert_one(doc)
    doc["_id"] = res.inserted_id
    return _serialize(doc, reveal_headers=False)


async def _update_webhook(webhook_id: str, payload: WebhookUpdate) -> WebhookOut:
    db = _get_db()
    try:
        _id = ObjectId(webhook_id)
    except Exception:
        raise HTTPException(status_code=404, detail="webhook not found")
    updates = {k: v for k, v in payload.model_dump(exclude_unset=True).items() if v is not None}
    if "url" in updates:
        updates["url"] = str(updates["url"])
    # Preserve existing headers if user re-submits a partially-masked dict:
    # any header whose value equals `***` is dropped from the update.
    if "headers" in updates and isinstance(updates["headers"], dict):
        existing = await db.webhooks.find_one({"_id": _id}, {"headers": 1})
        existing_headers = (existing or {}).get("headers") or {}
        merged: Dict[str, str] = {}
        for k, v in updates["headers"].items():
            if v == _MASK and k in existing_headers:
                merged[k] = existing_headers[k]
            else:
                merged[k] = v
        updates["headers"] = merged
    if not updates:
        raise HTTPException(status_code=400, detail="no fields to update")
    res = await db.webhooks.find_one_and_update(
        {"_id": _id}, {"$set": updates}, return_document=True,
    )
    if not res:
        raise HTTPException(status_code=404, detail="webhook not found")
    return _serialize(res)


async def _delete_webhook(webhook_id: str) -> Dict[str, str]:
    db = _get_db()
    try:
        _id = ObjectId(webhook_id)
    except Exception:
        raise HTTPException(status_code=404, detail="webhook not found")
    res = await db.webhooks.delete_one({"_id": _id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="webhook not found")
    return {"status": "deleted"}


async def _get_full_webhook(webhook_id: str) -> Dict[str, Any]:
    db = _get_db()
    try:
        _id = ObjectId(webhook_id)
    except Exception:
        raise HTTPException(status_code=404, detail="webhook not found")
    doc = await db.webhooks.find_one({"_id": _id})
    if not doc:
        raise HTTPException(status_code=404, detail="webhook not found")
    return doc


async def _record_delivery(
    *, webhook: Dict[str, Any], summary: str, ok: bool, http_status,
    error, response_snippet, attempts: int, triggered_by: str | None,
) -> DeliveryOut:
    """Insert delivery record + trim to last N + update webhook.last_status."""
    db = _get_db()
    now = utcnow_iso()
    doc = {
        "webhook_id": webhook["_id"],
        "webhook_name": webhook.get("name", ""),
        "target_type": webhook.get("target_type", "custom"),
        "status": "ok" if ok else "failed",
        "http_status": http_status,
        "error": error,
        "attempts": attempts,
        "response_snippet": response_snippet,
        "content_summary": summary,
        "sent_at": now,
        "triggered_by": triggered_by,
    }
    res = await db.webhook_deliveries.insert_one(doc)
    doc["_id"] = res.inserted_id

    # Trim to last _MAX_DELIVERIES.
    total = await db.webhook_deliveries.count_documents({})
    if total > _MAX_DELIVERIES:
        excess = total - _MAX_DELIVERIES
        oldest = await db.webhook_deliveries.find().sort("sent_at", 1).limit(excess).to_list(excess)
        if oldest:
            await db.webhook_deliveries.delete_many({"_id": {"$in": [d["_id"] for d in oldest]}})

    # Bump webhook.last_status + last_sent_at
    await db.webhooks.update_one(
        {"_id": webhook["_id"]},
        {"$set": {"last_status": "ok" if ok else "failed", "last_sent_at": now}},
    )
    return _serialize_delivery(doc)


async def _push(webhook: Dict[str, Any], payload: PushRequest, triggered_by: str | None) -> DeliveryOut:
    content_mode = payload.content_mode or webhook.get("content_mode", "bundle_iocs")
    now = utcnow_iso()
    ctx = _delivery.build_render_context(payload.model_dump(), content_mode, now)
    body = _delivery.render_template(webhook["payload_template"], ctx)
    ok, status, snippet, error, attempts = await _delivery.deliver(
        url=webhook["url"],
        method=webhook.get("method", "POST"),
        headers=webhook.get("headers") or {},
        rendered_body=body,
    )
    summary = _delivery.build_content_summary(payload.model_dump())
    logger.info(
        "webhook push id=%s target=%s ok=%s http=%s attempts=%s",
        webhook["_id"], webhook.get("target_type"), ok, status, attempts,
    )
    return await _record_delivery(
        webhook=webhook, summary=summary, ok=ok, http_status=status,
        error=error, response_snippet=snippet, attempts=attempts,
        triggered_by=triggered_by,
    )


# ---------------------------------------------------------------------------
# Public routes — defined via a factory so we can bind auth Depends at
# app-load time (once server.py has finished importing).
# ---------------------------------------------------------------------------
def attach_routes(app_router: APIRouter, auth_dep):
    """Bind concrete endpoints to `app_router` using the given auth dep.
    Called once from server.py after imports settle.
    """

    @app_router.get("/presets")
    async def presets_ep(user: dict = Depends(auth_dep)):
        return _presets.PRESETS

    @app_router.get("", response_model=List[WebhookOut])
    async def list_ep(user: dict = Depends(auth_dep)):
        return await _list_webhooks()

    @app_router.post("", response_model=WebhookOut, status_code=201)
    async def create_ep(payload: WebhookCreate, user: dict = Depends(auth_dep)):
        return await _create_webhook(payload, user)

    @app_router.patch("/{webhook_id}", response_model=WebhookOut)
    async def update_ep(webhook_id: str, payload: WebhookUpdate, user: dict = Depends(auth_dep)):
        return await _update_webhook(webhook_id, payload)

    @app_router.delete("/{webhook_id}")
    async def delete_ep(webhook_id: str, user: dict = Depends(auth_dep)):
        return await _delete_webhook(webhook_id)

    @app_router.post("/{webhook_id}/test", response_model=DeliveryOut)
    async def test_ep(webhook_id: str, user: dict = Depends(auth_dep)):
        wh = await _get_full_webhook(webhook_id)
        # Synthetic payload — proves connectivity without exposing real data.
        dummy = PushRequest(
            webhook_id=webhook_id,
            summary="NivX Forge test push — connectivity check",
            verdict="clean",
            risk_score=0,
            sigma_rule="title: NivX test\nlogsource: {product: test}\ndetection:\n  condition: false",
            yara_rule='rule NivX_Test { condition: false }',
            iocs=[{"type": "ipv4", "value": "127.0.0.1", "context": "test"}],
            mitre=[{"id": "T1059", "name": "Command Execution", "tactic": "Execution"}],
        )
        return await _push(wh, dummy, triggered_by=user.get("email"))

    @app_router.post("/push", response_model=DeliveryOut)
    async def push_ep(payload: PushRequest, user: dict = Depends(auth_dep)):
        wh = await _get_full_webhook(payload.webhook_id)
        if not wh.get("enabled", True):
            raise HTTPException(status_code=400, detail="webhook is disabled")
        return await _push(wh, payload, triggered_by=user.get("email"))

    @app_router.get("/deliveries", response_model=List[DeliveryOut])
    async def deliveries_ep(limit: int = _MAX_DELIVERIES, user: dict = Depends(auth_dep)):
        db = _get_db()
        limit = max(1, min(limit, _MAX_DELIVERIES))
        docs = await db.webhook_deliveries.find().sort("sent_at", -1).limit(limit).to_list(limit)
        return [_serialize_delivery(d) for d in docs]

    @app_router.post("/deliveries/{delivery_id}/retry", response_model=DeliveryOut)
    async def retry_ep(delivery_id: str, user: dict = Depends(auth_dep)):
        db = _get_db()
        try:
            _id = ObjectId(delivery_id)
        except Exception:
            raise HTTPException(status_code=404, detail="delivery not found")
        original = await db.webhook_deliveries.find_one({"_id": _id})
        if not original:
            raise HTTPException(status_code=404, detail="delivery not found")
        wh = await _get_full_webhook(str(original["webhook_id"]))
        # Retry uses the SAME synthetic push (we don't persist raw payloads —
        # the analyst can trigger a fresh push from NivX Forge if they want).
        dummy = PushRequest(
            webhook_id=str(wh["_id"]),
            summary=f"Retry of delivery {delivery_id} — {original.get('content_summary','')}",
            verdict="unknown", risk_score=0,
        )
        return await _push(wh, dummy, triggered_by=user.get("email"))


async def ensure_indexes():
    db = _get_db()
    await db.webhooks.create_index("created_at")
    await db.webhook_deliveries.create_index([("sent_at", -1)])
    await db.webhook_deliveries.create_index("webhook_id")
