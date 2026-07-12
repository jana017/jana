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
    {
        "slug": "volt-typhoon",
        "name": "Volt Typhoon",
        "aliases": ["Vanguard Panda", "BRONZE SILHOUETTE", "DEV-0391"],
        "origin_country": "China (PRC state-sponsored)",
        "first_seen": "2021",
        "motivation": "Pre-positioning / Espionage",
        "targeted_sectors": ["Critical infrastructure", "Communications", "Energy", "Water", "Transportation"],
        "targeted_regions": ["USA", "Guam", "Indo-Pacific"],
        "bio": ("Volt Typhoon is a China-state-sponsored actor focused on pre-positioning access in US "
                "critical infrastructure. Notorious for living-off-the-land (LOTL) techniques — using "
                "built-in Windows tools (netsh, PowerShell, wmic) and SOHO-router botnets (KV-botnet) as "
                "operational relays to blend into normal traffic. CISA/NSA joint advisory (May 2023, "
                "expanded Feb 2024) warned they are staging for disruptive attacks during a crisis."),
        "ttps": [
            {"id": "T1078",     "name": "Valid Accounts"},
            {"id": "T1059.001", "name": "PowerShell"},
            {"id": "T1546",     "name": "Event Triggered Execution"},
            {"id": "T1090.003", "name": "Multi-hop Proxy (SOHO routers)"},
            {"id": "T1003.001", "name": "LSASS Memory"},
        ],
        "timeline": [
            {"date": "2023-05", "title": "CISA/NSA/Microsoft joint advisory — Guam telecom breach"},
            {"date": "2023-12", "title": "KV-botnet (SOHO router C2 relay) exposed by Black Lotus Labs"},
            {"date": "2024-01", "title": "FBI-court-authorized takedown of KV-botnet"},
            {"date": "2024-02", "title": "CISA #StopRansomware-style advisory: 'urgent' warning to US CI operators"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — Volt Typhoon", "url": "https://attack.mitre.org/groups/G1017/"},
            {"title": "CISA AA24-038A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a"},
        ],
    },
    {
        "slug": "scattered-spider",
        "name": "Scattered Spider",
        "aliases": ["UNC3944", "0ktapus", "Scatter Swine", "Muddled Libra", "Octo Tempest"],
        "origin_country": "USA / UK (English-speaking, mostly teenagers)",
        "first_seen": "2022",
        "motivation": "Financial (Ransomware affiliate + extortion)",
        "targeted_sectors": ["Hospitality", "Gaming (casinos)", "Retail", "Telecom", "BPO"],
        "targeted_regions": ["North America", "UK"],
        "bio": ("Scattered Spider is a native-English-speaking cybercrime group known for aggressive "
                "social-engineering of IT helpdesks. Members are often teenagers/young adults working "
                "with the Com/Comm subculture. They pioneered SIM-swapping + MFA-fatigue + helpdesk "
                "impersonation to reset MFA. High-profile 2023 hits: Caesars ($15M paid), MGM Resorts "
                "($100M+ impact), Clorox, Reddit. Frequently affiliates with ALPHV/BlackCat and "
                "RansomHub for the encryption stage."),
        "ttps": [
            {"id": "T1566.004", "name": "Spearphishing Voice (vishing)"},
            {"id": "T1621",     "name": "Multi-Factor Authentication Request Generation (MFA fatigue)"},
            {"id": "T1098.005", "name": "Device Registration"},
            {"id": "T1078.004", "name": "Valid Cloud Accounts"},
            {"id": "T1486",     "name": "Data Encrypted for Impact"},
        ],
        "timeline": [
            {"date": "2022-08", "title": "0ktapus phishing campaign (Twilio, Cloudflare, DoorDash)"},
            {"date": "2023-09", "title": "MGM Resorts breach — casino floors offline for 10 days"},
            {"date": "2023-09", "title": "Caesars Entertainment $15M ransom paid"},
            {"date": "2024-06", "title": "5 members charged by DOJ; UK arrests follow"},
            {"date": "2025-04", "title": "Marks & Spencer / Co-op UK retail wave"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — Scattered Spider", "url": "https://attack.mitre.org/groups/G1015/"},
            {"title": "CISA AA23-320A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"},
        ],
    },
    {
        "slug": "clop",
        "name": "Clop",
        "aliases": ["CL0P", "TA505 (affiliate)", "FIN11 (related)"],
        "origin_country": "Russia (attributed)",
        "first_seen": "2019-02",
        "motivation": "Financial (Extortion — data theft > encryption)",
        "targeted_sectors": ["Software supply chain victims", "Healthcare", "Financial services", "Higher education"],
        "targeted_regions": ["Global"],
        "bio": ("Clop is a data-extortion group that pivoted from traditional ransomware to mass "
                "zero-day exploitation of managed file-transfer (MFT) products. They pioneered the "
                "'pure extortion' model — steal data, skip encryption, threaten leak. Landmark "
                "campaigns: Accellion FTA (Dec 2020), GoAnywhere MFT (Jan 2023), and the MOVEit "
                "Transfer zero-day (May 2023) that hit 2,700+ organisations including US federal "
                "agencies, Shell, BBC, British Airways, and Zellis payroll customers."),
        "ttps": [
            {"id": "T1190",     "name": "Exploit Public-Facing Application (MOVEit, GoAnywhere)"},
            {"id": "T1567.002", "name": "Exfiltration to Cloud Storage"},
            {"id": "T1657",     "name": "Financial Theft (leak-site extortion)"},
            {"id": "T1486",     "name": "Data Encrypted for Impact"},
        ],
        "timeline": [
            {"date": "2020-12", "title": "Accellion FTA zero-day (CVE-2021-27101)"},
            {"date": "2023-01", "title": "GoAnywhere MFT zero-day (CVE-2023-0669) — 130+ victims"},
            {"date": "2023-05", "title": "MOVEit Transfer zero-day (CVE-2023-34362) — 2,700+ victims"},
            {"date": "2024-11", "title": "Cleo LexiCom / Harmony / VLTrader zero-day (CVE-2024-50623) mass-exploitation"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — Clop", "url": "https://attack.mitre.org/software/S0611/"},
            {"title": "CISA AA23-158A (MOVEit)", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"},
        ],
    },
    {
        "slug": "blackcat",
        "name": "BlackCat / ALPHV",
        "aliases": ["ALPHV", "Noberus", "Sphynx"],
        "origin_country": "Russia (attributed — DarkSide/BlackMatter rebrand)",
        "first_seen": "2021-11",
        "motivation": "Financial (RaaS)",
        "targeted_sectors": ["Healthcare", "Financial services", "Energy", "Retail"],
        "targeted_regions": ["USA", "Europe"],
        "bio": ("BlackCat (ALPHV) was the first ransomware family written in Rust — cross-platform "
                "(Windows/Linux/ESXi) with a highly configurable builder. Widely considered a "
                "DarkSide/BlackMatter rebrand. Ran a triple-extortion program (encrypt + leak + DDoS) "
                "and even filed an SEC complaint against a victim (MeridianLink) for non-disclosure. "
                "Landmark attacks: Change Healthcare (Feb 2024, $22M paid, then affiliate exit-scam), "
                "Reddit, MGM (with Scattered Spider). Infrastructure disrupted Dec 2023 by FBI, "
                "resurfaced briefly, then went dark after the Change Healthcare exit-scam."),
        "ttps": [
            {"id": "T1486",     "name": "Data Encrypted for Impact"},
            {"id": "T1490",     "name": "Inhibit System Recovery"},
            {"id": "T1567.002", "name": "Exfiltration to Cloud Storage"},
            {"id": "T1562.001", "name": "Disable or Modify Tools"},
            {"id": "T1078",     "name": "Valid Accounts"},
        ],
        "timeline": [
            {"date": "2021-11", "title": "BlackCat first observed — Rust-based encryptor"},
            {"date": "2023-09", "title": "MGM Resorts / Caesars (via Scattered Spider affiliate)"},
            {"date": "2023-12", "title": "FBI seizes leak-site & releases decryptor"},
            {"date": "2024-02", "title": "Change Healthcare breach — $22M paid"},
            {"date": "2024-03", "title": "Exit-scam: operators steal affiliate's cut, go dark"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — ALPHV", "url": "https://attack.mitre.org/software/S1068/"},
            {"title": "CISA AA23-353A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a"},
        ],
    },
    {
        "slug": "apt28",
        "name": "APT28",
        "aliases": ["Fancy Bear", "Sofacy", "STRONTIUM", "Forest Blizzard", "Pawn Storm", "GRU Unit 26165"],
        "origin_country": "Russia (GRU Military Intelligence)",
        "first_seen": "2004",
        "motivation": "Espionage (state-sponsored, military intelligence)",
        "targeted_sectors": ["Government", "Military", "Defense contractors", "Media", "Political organisations"],
        "targeted_regions": ["NATO countries", "Ukraine", "Georgia"],
        "bio": ("APT28 is Russia's GRU (military intelligence) cyber unit, tasked with strategic "
                "espionage and information operations. Best known for the 2016 DNC hack and the "
                "TV5Monde attack (2015). Continues to run credential-phishing at scale against "
                "military/government targets, especially in Ukraine post-2022. Uses custom malware "
                "(X-Agent, Zebrocy, HeadLace) and heavy exploitation of Outlook/Roundcube CVEs."),
        "ttps": [
            {"id": "T1566.002", "name": "Spearphishing Link"},
            {"id": "T1190",     "name": "Exploit Public-Facing Application"},
            {"id": "T1550.002", "name": "Pass the Hash"},
            {"id": "T1114.002", "name": "Remote Email Collection"},
        ],
        "timeline": [
            {"date": "2015-04", "title": "TV5Monde broadcast disruption"},
            {"date": "2016-07", "title": "DNC email leak (US election interference)"},
            {"date": "2018-07", "title": "Mueller indictment of 12 GRU officers"},
            {"date": "2023-03", "title": "CVE-2023-23397 Outlook zero-day mass-exploitation (Ukraine targets)"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — APT28", "url": "https://attack.mitre.org/groups/G0007/"},
        ],
    },
    {
        "slug": "apt41",
        "name": "APT41",
        "aliases": ["Winnti", "BARIUM", "BRONZE ATLAS", "Wicked Panda", "Double Dragon"],
        "origin_country": "China (Ministry of State Security contractor)",
        "first_seen": "2012",
        "motivation": "Dual-mission: Espionage + Financial (crypto theft, gaming abuse)",
        "targeted_sectors": ["Video games", "Healthcare", "Telecom", "Government", "Higher education"],
        "targeted_regions": ["Global (US, EU, Asia)"],
        "bio": ("APT41 is unique among Chinese APTs — a state-sponsored group that also moonlights for "
                "personal financial gain (crypto theft, game currency abuse). DOJ indicted 5 members "
                "in 2020. Extremely aggressive supply-chain operators: ShadowPad (NetSarang, CCleaner, "
                "ASUS Live Update). Continues to exploit N-day CVEs at scale — Citrix, Cisco, Zoho "
                "ManageEngine. Sub-clusters include Earth Baku and BRONZE PRESIDENT overlaps."),
        "ttps": [
            {"id": "T1195.002", "name": "Compromise Software Supply Chain"},
            {"id": "T1190",     "name": "Exploit Public-Facing Application"},
            {"id": "T1071.001", "name": "Web Protocols (C2)"},
            {"id": "T1055",     "name": "Process Injection"},
        ],
        "timeline": [
            {"date": "2017-07", "title": "ShadowPad backdoor discovered in NetSarang software"},
            {"date": "2019-03", "title": "ASUS Live Update supply-chain compromise (ShadowHammer)"},
            {"date": "2020-09", "title": "US DOJ indicts 5 APT41 members"},
            {"date": "2022-03", "title": "US state government networks breached via ManageEngine ADSelfService Plus"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — APT41", "url": "https://attack.mitre.org/groups/G0096/"},
        ],
    },
    {
        "slug": "sandworm",
        "name": "Sandworm",
        "aliases": ["Voodoo Bear", "Iron Viking", "TeleBots", "GRU Unit 74455", "Seashell Blizzard"],
        "origin_country": "Russia (GRU Unit 74455)",
        "first_seen": "2009",
        "motivation": "Destructive espionage / Sabotage (state-sponsored)",
        "targeted_sectors": ["Energy grid", "Government", "Media", "Financial", "Ukraine infrastructure"],
        "targeted_regions": ["Ukraine", "NATO countries", "Global (NotPetya spread)"],
        "bio": ("Sandworm is Russia's most destructive GRU cyber unit, responsible for the two Ukraine "
                "power-grid blackouts (2015 BlackEnergy, 2016 Industroyer/CrashOverride) and the 2017 "
                "NotPetya wiper — the most damaging cyberattack in history (~$10B in global damage). "
                "Post-2022 they have run continuous destructive campaigns against Ukrainian civilian "
                "infrastructure (AcidRain wiper on Viasat, WhisperGate, HermeticWiper, CaddyWiper, "
                "Industroyer2). Considered the highest-tier ICS/OT adversary."),
        "ttps": [
            {"id": "T1485",     "name": "Data Destruction (wipers)"},
            {"id": "T1195.002", "name": "Supply Chain Compromise (M.E.Doc)"},
            {"id": "T0800",     "name": "ICS attacks (Industroyer)"},
            {"id": "T1078",     "name": "Valid Accounts"},
        ],
        "timeline": [
            {"date": "2015-12", "title": "Ukraine power grid attack #1 (BlackEnergy)"},
            {"date": "2016-12", "title": "Ukraine power grid attack #2 (Industroyer)"},
            {"date": "2017-06", "title": "NotPetya global outbreak via M.E.Doc supply chain"},
            {"date": "2022-02", "title": "AcidRain wiper on Viasat KA-SAT modems (Ukraine invasion H-hour)"},
            {"date": "2022-04", "title": "Industroyer2 attempt on Ukraine energy provider (thwarted)"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — Sandworm", "url": "https://attack.mitre.org/groups/G0034/"},
            {"title": "CISA AA22-110A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a"},
        ],
    },
    {
        "slug": "kimsuky",
        "name": "Kimsuky",
        "aliases": ["Velvet Chollima", "Thallium", "Black Banshee", "APT43"],
        "origin_country": "North Korea (RGB — Reconnaissance General Bureau)",
        "first_seen": "2012",
        "motivation": "Espionage + Cryptocurrency theft",
        "targeted_sectors": ["Think tanks", "Academia", "Journalists", "NGOs", "Nuclear policy"],
        "targeted_regions": ["South Korea", "USA", "Japan", "Europe"],
        "bio": ("Kimsuky is a North Korean espionage group specialising in credential-phishing and "
                "intelligence gathering on Korean-peninsula policy. They pioneered 'benign' phishing "
                "chains that pretext as journalists, academics or NGO staff requesting interviews. "
                "Sub-cluster APT43 (Mandiant) blends espionage with cryptocurrency laundering to "
                "self-fund operations. Known for lightweight malware: BabyShark, ReconShark, "
                "AppleSeed, and abuse of PowerShell + Blogspot dead-drops."),
        "ttps": [
            {"id": "T1566.001", "name": "Spearphishing Attachment"},
            {"id": "T1566.002", "name": "Spearphishing Link"},
            {"id": "T1102",     "name": "Web Service (blog dead-drops)"},
            {"id": "T1059.001", "name": "PowerShell"},
        ],
        "timeline": [
            {"date": "2014", "title": "Korea Hydro & Nuclear Power (KHNP) leaks attributed"},
            {"date": "2020-10", "title": "CISA advisory AA20-301A on Kimsuky"},
            {"date": "2023-06", "title": "US Treasury sanctions Kimsuky infrastructure"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — Kimsuky", "url": "https://attack.mitre.org/groups/G0094/"},
            {"title": "CISA AA20-301A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-301a"},
        ],
    },
    {
        "slug": "black-basta",
        "name": "Black Basta",
        "aliases": ["UNC4393", "BlackBasta"],
        "origin_country": "Russia (former Conti members attributed)",
        "first_seen": "2022-04",
        "motivation": "Financial (RaaS)",
        "targeted_sectors": ["Healthcare", "Manufacturing", "Construction", "Legal services"],
        "targeted_regions": ["North America", "Europe"],
        "bio": ("Black Basta emerged in April 2022 shortly after Conti's shutdown, and shares "
                "significant TTP, tooling and infrastructure overlap with Conti. Notorious for using "
                "Qakbot → Cobalt Strike → BlackBasta chain and, more recently, Microsoft Teams "
                "impersonation of IT staff. Leaked internal chats (Feb 2025) exposed ~$107M in "
                "ransom revenue and internal disputes."),
        "ttps": [
            {"id": "T1566.001", "name": "Spearphishing Attachment (Qakbot)"},
            {"id": "T1105",     "name": "Ingress Tool Transfer (Cobalt Strike)"},
            {"id": "T1486",     "name": "Data Encrypted for Impact"},
            {"id": "T1567.002", "name": "Exfiltration to Cloud Storage (rclone)"},
        ],
        "timeline": [
            {"date": "2022-04", "title": "First observed on RAMP forum recruiting affiliates"},
            {"date": "2024-05", "title": "CISA/FBI/HHS joint advisory (Ascension Health & Synlab hits)"},
            {"date": "2025-02", "title": "Internal chat logs leaked to Telegram — 'Bloody Wolf' insider dump"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — Black Basta", "url": "https://attack.mitre.org/software/S1070/"},
            {"title": "CISA AA24-131A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a"},
        ],
    },
    {
        "slug": "muddywater",
        "name": "MuddyWater",
        "aliases": ["Static Kitten", "MERCURY", "TEMP.Zagros", "Mango Sandstorm"],
        "origin_country": "Iran (MOIS — Ministry of Intelligence and Security)",
        "first_seen": "2017",
        "motivation": "Espionage (state-sponsored)",
        "targeted_sectors": ["Government", "Telecom", "Oil & gas", "Defense"],
        "targeted_regions": ["Middle East", "Central Asia", "Europe", "North America"],
        "bio": ("MuddyWater is an Iranian MOIS-attributed espionage group operating primarily across "
                "the Middle East and neighbouring regions. Heavy use of PowerShell (POWERSTATS / "
                "POWGOOP) and legitimate remote-monitoring tools (ScreenConnect, Atera, RemoteUtilities) "
                "to blend in. Post-2022 they have partnered with DEV-1084/DarkBit for destructive "
                "operations against Israeli targets."),
        "ttps": [
            {"id": "T1059.001", "name": "PowerShell"},
            {"id": "T1219",     "name": "Remote Access Software (ScreenConnect, Atera)"},
            {"id": "T1566.001", "name": "Spearphishing Attachment"},
        ],
        "timeline": [
            {"date": "2017-11", "title": "First public reporting by Palo Alto Unit 42"},
            {"date": "2022-02", "title": "US CYBERCOM public attribution to Iranian MOIS"},
            {"date": "2023-04", "title": "Joint destructive campaign with DEV-1084 (DarkBit wiper) on Israeli education"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — MuddyWater", "url": "https://attack.mitre.org/groups/G0069/"},
            {"title": "CISA AA22-055A", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a"},
        ],
    },
    {
        "slug": "turla",
        "name": "Turla",
        "aliases": ["Snake", "Venomous Bear", "Waterbug", "Krypton", "Secret Blizzard"],
        "origin_country": "Russia (FSB — Center 16)",
        "first_seen": "1996",
        "motivation": "Espionage (state-sponsored)",
        "targeted_sectors": ["Government", "Diplomatic", "Military", "Research"],
        "targeted_regions": ["Global (100+ countries)"],
        "bio": ("Turla is one of the oldest and most sophisticated Russian state-sponsored groups, "
                "attributed to the FSB. Famous for satellite-link C2 (piggy-backing on unencrypted "
                "downstream satellite IPs), the Snake modular framework (dismantled by FBI Operation "
                "MEDUSA in May 2023), and stealthy Outlook backdoors that use the Exchange webmail "
                "protocol as C2. Ties back to the 2008 Agent.BTZ intrusion of US DOD SIPRNet."),
        "ttps": [
            {"id": "T1071.001", "name": "Application Layer Protocol (HTTP)"},
            {"id": "T1090.003", "name": "Multi-hop Proxy (satellite links)"},
            {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
            {"id": "T1573.002", "name": "Asymmetric Cryptography"},
        ],
        "timeline": [
            {"date": "2008-11", "title": "Agent.BTZ compromise of US DOD SIPRNet"},
            {"date": "2015-09", "title": "Satellite-link C2 technique publicly exposed (Kaspersky)"},
            {"date": "2023-05", "title": "FBI Operation MEDUSA — Snake framework dismantled"},
            {"date": "2023-12", "title": "Kazuar backdoor v2 activity against Ukraine defense targets"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — Turla", "url": "https://attack.mitre.org/groups/G0010/"},
            {"title": "CISA/FBI Operation MEDUSA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a"},
        ],
    },
    {
        "slug": "charming-kitten",
        "name": "Charming Kitten",
        "aliases": ["APT35", "Phosphorus", "Mint Sandstorm", "TA453", "Ballistic Bobcat"],
        "origin_country": "Iran (IRGC — Islamic Revolutionary Guard Corps)",
        "first_seen": "2013",
        "motivation": "Espionage (state-sponsored)",
        "targeted_sectors": ["Journalists", "Human rights activists", "Academia", "Government policy", "Nuclear research"],
        "targeted_regions": ["USA", "UK", "Israel", "Middle East"],
        "bio": ("Charming Kitten is the IRGC's premier cyber-espionage arm, focused on Iran-diaspora "
                "surveillance, journalist targeting, and nuclear-policy intelligence. Known for "
                "long-form, patient social-engineering (fake journalist personas, months-long chat "
                "rapport before payload delivery), MFA-phishing kits, and abuse of legitimate cloud "
                "services (Dropbox, Google Drive) for C2. Sub-cluster HomeLand Justice runs "
                "destructive operations against Albania and Israel."),
        "ttps": [
            {"id": "T1566.003", "name": "Spearphishing via Service (fake journalist personas)"},
            {"id": "T1102",     "name": "Web Service"},
            {"id": "T1621",     "name": "MFA Bypass (Evilginx-style)"},
        ],
        "timeline": [
            {"date": "2019-10", "title": "Attempted breach of a US presidential campaign (Microsoft disclosure)"},
            {"date": "2022-07", "title": "Albania government destructive attack (HomeLand Justice)"},
            {"date": "2023-05", "title": "PowerLess & POWERSTAR backdoor campaigns against Israeli/Western researchers"},
        ],
        "related_iocs": [],
        "references": [
            {"title": "MITRE ATT&CK — APT35", "url": "https://attack.mitre.org/groups/G0059/"},
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
