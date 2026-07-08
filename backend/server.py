from dotenv import load_dotenv
from pathlib import Path
import os

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI, APIRouter, HTTPException, Request, Depends
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import logging
from pydantic import BaseModel, Field, ConfigDict, BeforeValidator
from typing import List, Optional, Annotated, Any
import uuid
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
# Live external threat feed (CISA Known Exploited Vulnerabilities)
# ---------------------------------------------------------------------------
_feed_cache: dict[str, Any] = {"ts": None, "data": None}


@api_router.get("/live-feed")
async def live_feed():
    """Real-time threat landscape from CISA KEV public feed (cached 30 min)."""
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
            }
            for v in vulns_sorted[:24]
        ]
        result = {
            "source": "CISA Known Exploited Vulnerabilities",
            "catalog_version": raw.get("catalogVersion"),
            "total_count": raw.get("count", len(vulns)),
            "ransomware_linked": sum(1 for v in vulns if v.get("knownRansomwareCampaignUse") == "Known"),
            "updated": now.isoformat(),
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
]


async def seed_threats():
    count = await db.threat_reports.count_documents({})
    if count == 0:
        for t in SAMPLE_THREATS:
            report = ThreatReport(**t)
            await db.threat_reports.insert_one(report.model_dump())
        logger.info("Seeded sample threat reports")


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await seed_admin()
    await seed_threats()


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
