"""Threat Actor Profile module — /api/actors/*.

Deterministic CRUD over a `threat_actors` Mongo collection with a hard-coded
seed of well-known groups (LockBit, APT29, Lazarus, FIN7) so the /actors
index is never empty for a fresh deploy. Analysts (admins) can add / edit /
delete via the admin UI; the public /actors/:slug page reads only.
"""
from __future__ import annotations
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel

_client = AsyncIOMotorClient(os.environ["MONGO_URL"])
_db = _client[os.environ["DB_NAME"]]

router = APIRouter(prefix="/api/actors", tags=["actors"])
admin_router = APIRouter(prefix="/api/admin/actors", tags=["actors-admin"])


async def _require_admin(request: Request):
    from server import get_current_user
    return await get_current_user(request)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ActorIn(BaseModel):
    slug: str
    name: str
    aliases: List[str] = []
    origin_country: Optional[str] = None
    first_seen: Optional[str] = None
    motivation: Optional[str] = None            # e.g. "financial", "espionage", "hacktivism"
    targeted_sectors: List[str] = []
    targeted_regions: List[str] = []
    bio: str = ""
    ttps: List[Dict[str, Any]] = []             # [{id: "T1566.001", name: "Spearphishing"}]
    timeline: List[Dict[str, Any]] = []         # [{date, title, description, source_url}]
    related_iocs: List[Dict[str, Any]] = []     # [{type, value, note}]
    references: List[Dict[str, str]] = []       # [{title, url}]


def _serialize(doc: Dict[str, Any]) -> Dict[str, Any]:
    doc.pop("_id", None)
    return doc


@router.get("")
async def list_actors():
    """Public — list every tracked actor for the /actors index page."""
    cursor = _db.threat_actors.find({}, {
        "slug": 1, "name": 1, "aliases": 1, "origin_country": 1,
        "motivation": 1, "first_seen": 1, "targeted_sectors": 1,
        "ttps": 1,
    }).sort("name", 1)
    out = [_serialize(d) async for d in cursor]
    return {"count": len(out), "actors": out}


@router.get("/{slug}")
async def get_actor(slug: str):
    """Public — full profile for /actors/:slug."""
    doc = await _db.threat_actors.find_one({"slug": slug.lower()})
    if not doc:
        raise HTTPException(404, "Actor not found")
    return _serialize(doc)


@admin_router.post("")
async def create_actor(payload: ActorIn, user=Depends(_require_admin)):
    doc = payload.model_dump()
    doc["slug"] = doc["slug"].lower().strip()
    if not doc["slug"] or not doc["name"]:
        raise HTTPException(400, "slug and name are required")
    doc["updated_at"] = _now()
    doc["updated_by"] = user.get("email")
    existing = await _db.threat_actors.find_one({"slug": doc["slug"]})
    if existing:
        raise HTTPException(409, f"actor '{doc['slug']}' already exists")
    doc["created_at"] = _now()
    await _db.threat_actors.insert_one(doc)
    return _serialize(doc)


@admin_router.put("/{slug}")
async def update_actor(slug: str, payload: ActorIn, user=Depends(_require_admin)):
    slug = slug.lower().strip()
    doc = payload.model_dump()
    doc["slug"] = slug
    doc["updated_at"] = _now()
    doc["updated_by"] = user.get("email")
    r = await _db.threat_actors.update_one({"slug": slug}, {"$set": doc}, upsert=True)
    if r.matched_count == 0 and r.upserted_id is None:
        raise HTTPException(500, "update failed")
    return {"slug": slug, "updated": True}


@admin_router.delete("/{slug}")
async def delete_actor(slug: str, user=Depends(_require_admin)):
    r = await _db.threat_actors.delete_one({"slug": slug.lower()})
    return {"deleted": r.deleted_count}


# ---------------------------------------------------------------------------
# Seed data — well-known groups so /actors is never empty on a fresh deploy.
# Curated from public MITRE ATT&CK Groups, CISA advisories, and Mandiant
# reports as of Feb 2026.  Idempotent: only inserts missing slugs.
# ---------------------------------------------------------------------------
_SEED_ACTORS: List[Dict[str, Any]] = [
    {
        "slug": "lockbit",
        "name": "LockBit",
        "aliases": ["LockBit 3.0", "LockBit Black", "Bitwise Spider"],
        "origin_country": "Russia (attributed)",
        "first_seen": "2019-09",
        "motivation": "Financial (RaaS)",
        "targeted_sectors": ["Financial services", "Healthcare", "Manufacturing", "Government"],
        "targeted_regions": ["North America", "Europe", "Asia"],
        "bio": ("LockBit is one of the most active Ransomware-as-a-Service (RaaS) operations of the "
                "2020s. Their double-extortion model (encrypt + leak) has hit thousands of victims. "
                "Operation Cronos (Feb 2024) disrupted their infrastructure, but affiliates and the "
                "codebase remain active under rebranded variants."),
        "ttps": [
            {"id": "T1566.001", "name": "Spearphishing Attachment"},
            {"id": "T1078",     "name": "Valid Accounts"},
            {"id": "T1486",     "name": "Data Encrypted for Impact"},
            {"id": "T1490",     "name": "Inhibit System Recovery"},
            {"id": "T1567.002", "name": "Exfiltration to Cloud Storage"},
        ],
        "timeline": [
            {"date": "2019-09", "title": "First seen as 'ABCD ransomware'"},
            {"date": "2021-06", "title": "LockBit 2.0 launched with StealBit exfiltration tool"},
            {"date": "2022-06", "title": "LockBit 3.0 (Black) launched — bug bounty program announced"},
            {"date": "2024-02", "title": "Operation Cronos disruption by NCA/FBI/Europol"},
            {"date": "2024-05", "title": "Rebranded infrastructure re-emerged"},
        ],
        "related_iocs": [
            {"type": "hash", "value": "b95a2e...", "note": "LockBit 3.0 loader sample"},
        ],
        "references": [
            {"title": "MITRE ATT&CK — LockBit", "url": "https://attack.mitre.org/software/S1064/"},
            {"title": "CISA #StopRansomware — LockBit", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a"},
        ],
    },
    {
        "slug": "apt29",
        "name": "APT29",
        "aliases": ["Cozy Bear", "Nobelium", "The Dukes", "Midnight Blizzard"],
        "origin_country": "Russia (SVR)",
        "first_seen": "2008",
        "motivation": "Espionage (state-sponsored)",
        "targeted_sectors": ["Government", "Diplomatic missions", "Think tanks", "Healthcare (COVID-19 research)"],
        "targeted_regions": ["NATO countries", "EU", "USA"],
        "bio": ("APT29 is one of Russia's most sophisticated state-sponsored espionage groups, attributed "
                "to the Foreign Intelligence Service (SVR). Known for stealth, custom malware, and "
                "supply-chain attacks (SolarWinds SUNBURST, 2020). Long dwell times and living-off-the-"
                "land techniques make detection difficult."),
        "ttps": [
            {"id": "T1195.002", "name": "Compromise Software Supply Chain"},
            {"id": "T1078.004", "name": "Valid Cloud Accounts"},
            {"id": "T1059.001", "name": "PowerShell"},
            {"id": "T1027",     "name": "Obfuscated Files or Information"},
            {"id": "T1105",     "name": "Ingress Tool Transfer"},
        ],
        "timeline": [
            {"date": "2015-07", "title": "Democratic National Committee breach"},
            {"date": "2020-03", "title": "SolarWinds SUNBURST supply-chain attack begins"},
            {"date": "2020-12", "title": "SolarWinds compromise publicly disclosed"},
            {"date": "2023-11", "title": "Microsoft Midnight Blizzard corporate breach"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — APT29", "url": "https://attack.mitre.org/groups/G0016/"},
            {"title": "CISA SolarWinds advisory", "url": "https://www.cisa.gov/uscert/ncas/alerts/aa20-352a"},
        ],
    },
    {
        "slug": "lazarus",
        "name": "Lazarus Group",
        "aliases": ["Hidden Cobra", "APT38", "Guardians of Peace", "Zinc"],
        "origin_country": "North Korea (Reconnaissance General Bureau)",
        "first_seen": "2009",
        "motivation": "Financial + Espionage (state-sponsored)",
        "targeted_sectors": ["Banking", "Cryptocurrency", "Entertainment", "Defense"],
        "targeted_regions": ["Global"],
        "bio": ("Lazarus Group is a North Korean state-sponsored threat actor infamous for the 2014 Sony "
                "Pictures hack, the 2016 Bangladesh Bank SWIFT heist ($81M stolen), and repeated "
                "cryptocurrency exchange breaches. Sub-groups include APT38 (financial) and BeagleBoyz. "
                "In 2022, they were linked to the $625M Ronin Bridge exploit."),
        "ttps": [
            {"id": "T1566.001", "name": "Spearphishing Attachment"},
            {"id": "T1053.005", "name": "Scheduled Task"},
            {"id": "T1573",     "name": "Encrypted Channel"},
            {"id": "T1055",     "name": "Process Injection"},
        ],
        "timeline": [
            {"date": "2014-11", "title": "Sony Pictures Entertainment attack"},
            {"date": "2016-02", "title": "Bangladesh Bank SWIFT heist"},
            {"date": "2017-05", "title": "WannaCry ransomware (attributed)"},
            {"date": "2022-03", "title": "Ronin Bridge exploit ($625M crypto stolen)"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — Lazarus Group", "url": "https://attack.mitre.org/groups/G0032/"},
        ],
    },
    {
        "slug": "fin7",
        "name": "FIN7",
        "aliases": ["Carbanak", "Carbon Spider", "ITG14"],
        "origin_country": "Ukraine / Russia (mixed attribution)",
        "first_seen": "2013",
        "motivation": "Financial",
        "targeted_sectors": ["Retail", "Hospitality", "Restaurant", "Point-of-Sale systems"],
        "targeted_regions": ["North America", "Europe"],
        "bio": ("FIN7 is a financially motivated cybercrime group primarily targeting the retail and "
                "hospitality industries via point-of-sale malware and spearphishing. They pioneered "
                "the Carbanak banking-trojan platform. Despite arrests of leadership in 2018, the group "
                "has continued operations with new campaigns using Carbanak, GRIFFON, and BADUSB variants."),
        "ttps": [
            {"id": "T1566.002", "name": "Spearphishing Link"},
            {"id": "T1059.003", "name": "Windows Command Shell"},
            {"id": "T1005",     "name": "Data from Local System"},
            {"id": "T1041",     "name": "Exfiltration Over C2 Channel"},
        ],
        "timeline": [
            {"date": "2013-12", "title": "Carbanak trojan first observed"},
            {"date": "2018-08", "title": "3 senior members arrested in Europe"},
            {"date": "2020-07", "title": "BADUSB campaign — mailing malicious USB drives to victims"},
            {"date": "2023-11", "title": "Return with 'AvNeutralizer' EDR-killer tool"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — FIN7", "url": "https://attack.mitre.org/groups/G0046/"},
        ],
    },
]


async def seed_actors() -> None:
    """Idempotent seed — inserts missing slugs only, never overwrites edits."""
    await _db.threat_actors.create_index("slug", unique=True)
    await _db.threat_actors.create_index("name")
    for a in _SEED_ACTORS:
        existing = await _db.threat_actors.find_one({"slug": a["slug"]})
        if existing is None:
            doc = dict(a)
            doc["created_at"] = _now()
            doc["updated_at"] = _now()
            doc["updated_by"] = "seed"
            await _db.threat_actors.insert_one(doc)
