"""Persistence layer for CyberLab shared analyses & custom rules.

Uses the existing MongoDB connection. Shared analyses expire after 30 days
via a TTL index on `expires_at`.
"""
from __future__ import annotations
import os
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
import uuid

from motor.motor_asyncio import AsyncIOMotorClient

_client: Optional[AsyncIOMotorClient] = None


def _db():
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    return _client[os.environ["DB_NAME"]]


async def ensure_indexes():
    """Create TTL index for auto-expiry of shared analyses (30 days).
    Also indexes for custom rules lookup."""
    db = _db()
    # TTL on expires_at — Mongo deletes documents when their expires_at datetime is reached.
    await db.cyberlab_shares.create_index("expires_at", expireAfterSeconds=0)
    await db.cyberlab_shares.create_index("share_id", unique=True)
    await db.cyberlab_rules.create_index("scope")
    await db.cyberlab_rules.create_index([("session_id", 1), ("scope", 1)])


# --------------------- Shared analyses ---------------------

SHARE_TTL_DAYS = 30


async def save_share(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Persist an analysis. Returns {share_id, expires_at}."""
    share_id = uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=SHARE_TTL_DAYS)
    doc = {
        "share_id": share_id,
        "created_at": now,
        "expires_at": expires_at,
        "payload": payload,
    }
    await _db().cyberlab_shares.insert_one(doc)
    return {
        "share_id": share_id,
        "expires_at": expires_at.isoformat(),
        "expires_in_days": SHARE_TTL_DAYS,
    }


async def get_share(share_id: str) -> Optional[Dict[str, Any]]:
    doc = await _db().cyberlab_shares.find_one({"share_id": share_id})
    if not doc:
        return None
    return {
        "share_id": doc["share_id"],
        "created_at": doc["created_at"].isoformat() if isinstance(doc["created_at"], datetime) else doc["created_at"],
        "expires_at": doc["expires_at"].isoformat() if isinstance(doc["expires_at"], datetime) else doc["expires_at"],
        "payload": doc["payload"],
    }


# --------------------- Custom YARA-lite rules ---------------------

async def list_rules(scope: str, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """List custom rules. scope='admin' returns all admin rules;
    scope='session' returns rules for a specific session_id."""
    if scope == "admin":
        q = {"scope": "admin"}
    else:
        q = {"scope": "session", "session_id": session_id}
    cursor = _db().cyberlab_rules.find(q).sort("created_at", -1)
    out = []
    async for d in cursor:
        d.pop("_id", None)
        out.append(d)
    return out


async def add_rule(rule: Dict[str, Any], scope: str, session_id: Optional[str], author: str) -> Dict[str, Any]:
    doc = {
        "id": uuid.uuid4().hex[:12],
        "scope": scope,
        "session_id": session_id if scope == "session" else None,
        "author": author,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "name": rule.get("name", "Untitled Rule"),
        "severity": rule.get("severity", "medium"),
        "description": rule.get("description", ""),
        "tags": rule.get("tags", []),
        "strings": rule.get("strings", []),
    }
    await _db().cyberlab_rules.insert_one(dict(doc))  # copy to avoid _id mutation
    doc.pop("_id", None)
    return doc


async def delete_rule(rule_id: str, scope: str, session_id: Optional[str] = None) -> bool:
    q = {"id": rule_id, "scope": scope}
    if scope == "session":
        q["session_id"] = session_id
    r = await _db().cyberlab_rules.delete_one(q)
    return r.deleted_count > 0
