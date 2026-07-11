"""Employee Portal — Phase 2: ServiceNow-style ticketing.

Model:
  service_tickets: {
    _id, ticket_id (human, e.g. NVX-T-000123),
    employee_id (str), employee_email, employee_name,
    category, priority, status, subject, description,
    assigned_to (admin email), assigned_at,
    comments [{id, author_email, author_role, body, created_at}],
    created_at, updated_at, resolved_at, closed_at,
  }

Categories: email, hardware, software, hr, other
Priorities: low, medium, high, urgent
Statuses:   open, in_progress, resolved, closed
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger("nivx.tickets")

router = APIRouter(prefix="/api", tags=["tickets"])

CATEGORIES = {"email", "hardware", "software", "hr", "other"}
PRIORITIES = {"low", "medium", "high", "urgent"}
STATUSES   = {"open", "in_progress", "resolved", "closed"}


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_db():
    from server import db as _db
    return _db


def _require_admin(user: dict) -> None:
    if (user.get("role") or "").lower() != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")


class TicketCreate(BaseModel):
    category: str
    priority: str = "medium"
    subject: str = Field(min_length=3, max_length=200)
    description: str = Field(min_length=5, max_length=5000)


class TicketPatch(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None


class CommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=3000)


async def _next_ticket_number(db) -> str:
    """Deterministic sequential ticket number NVX-T-000001…"""
    counter = await db.counters.find_one_and_update(
        {"_id": "service_tickets"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True,
    )
    seq = counter.get("seq", 1) if counter else 1
    return f"NVX-T-{seq:06d}"


def _serialize(doc: dict) -> dict:
    return {
        "id": str(doc["_id"]),
        "ticket_id": doc["ticket_id"],
        "employee_id": doc["employee_id"],
        "employee_email": doc.get("employee_email"),
        "employee_name": doc.get("employee_name"),
        "category": doc["category"],
        "priority": doc["priority"],
        "status": doc["status"],
        "subject": doc["subject"],
        "description": doc["description"],
        "assigned_to": doc.get("assigned_to"),
        "assigned_at": doc.get("assigned_at"),
        "comments": doc.get("comments", []),
        "created_at": doc["created_at"],
        "updated_at": doc.get("updated_at"),
        "resolved_at": doc.get("resolved_at"),
        "closed_at": doc.get("closed_at"),
    }


def attach_routes(app_router: APIRouter, auth_dep):
    # ========================================================
    # EMPLOYEE — raise + view + comment on own tickets
    # ========================================================
    @app_router.post("/tickets")
    async def create_ticket(payload: TicketCreate, user: dict = Depends(auth_dep)):
        cat = payload.category.lower()
        pri = payload.priority.lower()
        if cat not in CATEGORIES:
            raise HTTPException(status_code=400, detail=f"category must be one of {sorted(CATEGORIES)}")
        if pri not in PRIORITIES:
            raise HTTPException(status_code=400, detail=f"priority must be one of {sorted(PRIORITIES)}")
        db = _get_db()
        ticket_id = await _next_ticket_number(db)
        now = _iso()
        doc = {
            "ticket_id": ticket_id,
            "employee_id": str(user["_id"]),
            "employee_email": user.get("email"),
            "employee_name": user.get("name") or user.get("email"),
            "category": cat,
            "priority": pri,
            "status": "open",
            "subject": payload.subject.strip(),
            "description": payload.description.strip(),
            "assigned_to": None,
            "comments": [],
            "created_at": now,
            "updated_at": now,
        }
        r = await db.service_tickets.insert_one(doc)
        doc["_id"] = r.inserted_id
        return _serialize(doc)

    @app_router.get("/tickets/mine")
    async def my_tickets(user: dict = Depends(auth_dep), status: Optional[str] = None):
        db = _get_db()
        q: dict = {"employee_id": str(user["_id"])}
        if status:
            if status not in STATUSES:
                raise HTTPException(status_code=400, detail="invalid status")
            q["status"] = status
        cursor = db.service_tickets.find(q).sort("created_at", -1).limit(200)
        return {"items": [_serialize(d) async for d in cursor]}

    async def _find_owned(db, ticket_id: str, user: dict, admin_bypass: bool):
        try:
            doc = await db.service_tickets.find_one({"_id": ObjectId(ticket_id)})
        except Exception:
            doc = await db.service_tickets.find_one({"ticket_id": ticket_id})
        if not doc:
            raise HTTPException(status_code=404, detail="Ticket not found")
        if not admin_bypass and doc.get("employee_id") != str(user["_id"]):
            raise HTTPException(status_code=403, detail="Not your ticket")
        return doc

    @app_router.get("/tickets/{ticket_id}")
    async def get_ticket(ticket_id: str, user: dict = Depends(auth_dep)):
        db = _get_db()
        is_admin = (user.get("role") or "").lower() == "admin"
        return _serialize(await _find_owned(db, ticket_id, user, admin_bypass=is_admin))

    @app_router.post("/tickets/{ticket_id}/comment")
    async def comment_on_ticket(ticket_id: str, payload: CommentIn, user: dict = Depends(auth_dep)):
        db = _get_db()
        is_admin = (user.get("role") or "").lower() == "admin"
        doc = await _find_owned(db, ticket_id, user, admin_bypass=is_admin)
        if doc["status"] == "closed":
            raise HTTPException(status_code=400, detail="Cannot comment on closed ticket")
        comment = {
            "id": str(uuid.uuid4()),
            "author_email": user.get("email"),
            "author_role": "admin" if is_admin else "employee",
            "body": payload.body.strip(),
            "created_at": _iso(),
        }
        await db.service_tickets.update_one(
            {"_id": doc["_id"]},
            {"$push": {"comments": comment}, "$set": {"updated_at": _iso()}},
        )
        return comment

    # ========================================================
    # ADMIN — full board + status/assign changes
    # ========================================================
    @app_router.get("/admin/tickets")
    async def admin_list(
        user: dict = Depends(auth_dep),
        status: Optional[str] = None,
        priority: Optional[str] = None,
        category: Optional[str] = None,
        assigned_to: Optional[str] = None,
        q: str = "",
        limit: int = 200,
    ):
        _require_admin(user)
        db = _get_db()
        limit = max(1, min(int(limit), 500))
        query: dict = {}
        if status:   query["status"]   = status
        if priority: query["priority"] = priority
        if category: query["category"] = category
        if assigned_to == "me":
            query["assigned_to"] = user.get("email")
        elif assigned_to == "unassigned":
            query["assigned_to"] = None
        elif assigned_to:
            query["assigned_to"] = assigned_to
        if q:
            query["$or"] = [
                {"ticket_id": {"$regex": q, "$options": "i"}},
                {"subject":   {"$regex": q, "$options": "i"}},
                {"description": {"$regex": q, "$options": "i"}},
                {"employee_email": {"$regex": q, "$options": "i"}},
            ]
        cursor = db.service_tickets.find(query).sort([("priority", 1), ("created_at", -1)]).limit(limit)
        return {"items": [_serialize(d) async for d in cursor]}

    @app_router.get("/admin/tickets/stats")
    async def admin_stats(user: dict = Depends(auth_dep)):
        _require_admin(user)
        db = _get_db()
        pipeline = [{"$group": {"_id": {"status": "$status", "priority": "$priority"},
                                "count": {"$sum": 1}}}]
        by_status: dict = {s: 0 for s in STATUSES}
        by_priority: dict = {p: 0 for p in PRIORITIES}
        total = 0
        async for row in db.service_tickets.aggregate(pipeline):
            s = row["_id"].get("status")
            p = row["_id"].get("priority")
            c = row.get("count", 0)
            total += c
            if s in by_status: by_status[s] += c
            if p in by_priority: by_priority[p] += c
        return {"total": total, "by_status": by_status, "by_priority": by_priority}

    @app_router.patch("/admin/tickets/{ticket_id}")
    async def admin_patch(ticket_id: str, payload: TicketPatch, user: dict = Depends(auth_dep)):
        _require_admin(user)
        db = _get_db()
        doc = await _find_owned(db, ticket_id, user, admin_bypass=True)
        updates: dict = {}
        events: List[dict] = []
        now = _iso()
        if payload.status:
            if payload.status not in STATUSES:
                raise HTTPException(status_code=400, detail="invalid status")
            if payload.status != doc["status"]:
                updates["status"] = payload.status
                events.append({"kind": "status", "from": doc["status"], "to": payload.status})
                if payload.status == "resolved":
                    updates["resolved_at"] = now
                if payload.status == "closed":
                    updates["closed_at"] = now
        if payload.priority:
            if payload.priority not in PRIORITIES:
                raise HTTPException(status_code=400, detail="invalid priority")
            if payload.priority != doc["priority"]:
                updates["priority"] = payload.priority
                events.append({"kind": "priority", "from": doc["priority"], "to": payload.priority})
        if payload.assigned_to is not None:
            new_assign = payload.assigned_to.strip() or None
            if new_assign != doc.get("assigned_to"):
                updates["assigned_to"] = new_assign
                updates["assigned_at"] = now if new_assign else None
                events.append({"kind": "assigned", "from": doc.get("assigned_to"), "to": new_assign})
        if not updates:
            raise HTTPException(status_code=400, detail="No changes")
        updates["updated_at"] = now
        # Log system comments for the audit trail
        audit_comments = [{
            "id": str(uuid.uuid4()),
            "author_email": user.get("email"),
            "author_role": "system",
            "body": f"[{ev['kind']}] {ev['from']} → {ev['to']}",
            "created_at": now,
        } for ev in events]
        push_op = {"$push": {"comments": {"$each": audit_comments}}} if audit_comments else {}
        await db.service_tickets.update_one({"_id": doc["_id"]}, {"$set": updates, **push_op})
        fresh = await db.service_tickets.find_one({"_id": doc["_id"]})
        return _serialize(fresh)


async def ensure_indexes() -> None:
    db = _get_db()
    try:
        await db.service_tickets.create_index([("employee_id", 1), ("created_at", -1)])
        await db.service_tickets.create_index([("status", 1), ("priority", 1)])
        await db.service_tickets.create_index("ticket_id", unique=True)
    except Exception:
        pass
