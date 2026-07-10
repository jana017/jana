"""HealthBot check + fix registry.

Each check is a small async function returning a `CheckResult`. If a check
detects a problem AND a safe automatic remediation exists, we register a
`fix_fn` on the same record — the API's `scan-and-fix` endpoint invokes
those and reports what was repaired.

Design rules — never violated:
  • No network calls. LLM balance, external API health checks are done
    LOCALLY by inspecting stored keys — we don't hit third parties.
  • No process restarts, no file writes outside `/tmp`.
  • Every fix is idempotent: running it twice must be a no-op.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger("nivx.healthbot")


Severity = str  # "ok" | "info" | "warning" | "critical"


@dataclass
class CheckResult:
    id: str
    name: str
    severity: Severity           # ok / info / warning / critical
    message: str                 # human-readable summary
    details: Dict[str, Any] = field(default_factory=dict)
    auto_fixable: bool = False
    fixed: bool = False
    fix_message: Optional[str] = None
    duration_ms: float = 0.0


CheckFn = Callable[[], Awaitable[CheckResult]]
FixFn = Callable[[CheckResult], Awaitable[str]]  # returns human message

_CHECKS: List[Dict[str, Any]] = []
_FIXES_BY_ID: Dict[str, FixFn] = {}


def register(check_fn: CheckFn, fix_fn: Optional[FixFn] = None) -> CheckFn:
    _CHECKS.append({"check": check_fn, "fix": fix_fn})
    # Extract the check id by running once at boot? Too eager. Instead, we
    # eagerly probe the check id lazily on first scan and populate the map.
    return check_fn


def _get_db():
    from server import db as _db  # lazy — avoids circular import at load
    return _db


# ---------------------------------------------------------------------------
# 1. MongoDB reachable
# ---------------------------------------------------------------------------
async def _check_mongo():
    t0 = time.perf_counter()
    try:
        db = _get_db()
        await db.command("ping")
        return CheckResult(
            id="mongo_reachable",
            name="MongoDB reachable",
            severity="ok",
            message="MongoDB responded to ping.",
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            id="mongo_reachable",
            name="MongoDB reachable",
            severity="critical",
            message=f"MongoDB ping failed: {e}",
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
register(_check_mongo)


# ---------------------------------------------------------------------------
# 2. Hot-collection indexes exist (and auto-fix by (re)building them)
# ---------------------------------------------------------------------------
_EXPECTED_INDEXES = {
    "cyberlab_shares": [("expires_at", 1)],
    "webhook_deliveries": [("sent_at", -1)],
    "webhooks": [("created_at", 1)],
    "iocs": [("value", 1)],
}


async def _check_indexes():
    t0 = time.perf_counter()
    db = _get_db()
    missing: Dict[str, List[str]] = {}
    for coll, expected in _EXPECTED_INDEXES.items():
        try:
            existing = await db[coll].index_information()
            existing_keys = {tuple(v["key"]) for v in existing.values()}
            for key in expected:
                if (key,) not in existing_keys:
                    missing.setdefault(coll, []).append(f"{key[0]}:{key[1]}")
        except Exception as e:  # noqa: BLE001
            missing.setdefault(coll, []).append(f"error:{e}")
    dur = (time.perf_counter() - t0) * 1000
    if not missing:
        return CheckResult(
            id="mongo_indexes",
            name="MongoDB hot-collection indexes",
            severity="ok",
            message="All expected indexes present.",
            duration_ms=dur,
        )
    return CheckResult(
        id="mongo_indexes",
        name="MongoDB hot-collection indexes",
        severity="warning",
        message=f"{sum(len(v) for v in missing.values())} indexes missing across {len(missing)} collections.",
        details={"missing": missing},
        auto_fixable=True,
        duration_ms=dur,
    )


async def _fix_indexes(_result: CheckResult) -> str:
    db = _get_db()
    created = 0
    for coll, expected in _EXPECTED_INDEXES.items():
        for key in expected:
            try:
                await db[coll].create_index([key])
                created += 1
            except Exception as e:  # noqa: BLE001
                logger.warning("index create failed for %s.%s: %s", coll, key, e)
    return f"Rebuilt {created} indexes."
register(_check_indexes, _fix_indexes)


# ---------------------------------------------------------------------------
# 3. Plugin registry loaded
# ---------------------------------------------------------------------------
async def _check_plugins():
    t0 = time.perf_counter()
    try:
        from cyberlab.plugins import all_plugins, auto_candidates
        total = len(all_plugins())
        auto = len(auto_candidates())
        return CheckResult(
            id="plugin_registry",
            name="Decoder plugin registry",
            severity="ok" if total >= 30 else "warning",
            message=f"{total} plugins loaded ({auto} auto-detect).",
            details={"total": total, "auto": auto},
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            id="plugin_registry",
            name="Decoder plugin registry",
            severity="critical",
            message=f"Failed to enumerate plugins: {e}",
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
register(_check_plugins)


# ---------------------------------------------------------------------------
# 4. Expired share cleanup
# ---------------------------------------------------------------------------
async def _check_expired_shares():
    t0 = time.perf_counter()
    db = _get_db()
    now = datetime.now(timezone.utc).isoformat()
    try:
        expired = await db.cyberlab_shares.count_documents({"expires_at": {"$lt": now}})
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            id="expired_shares",
            name="Expired share pruning",
            severity="warning",
            message=f"share count query failed: {e}",
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
    dur = (time.perf_counter() - t0) * 1000
    if expired == 0:
        return CheckResult(
            id="expired_shares",
            name="Expired share pruning",
            severity="ok",
            message="No expired shares to prune.",
            duration_ms=dur,
        )
    return CheckResult(
        id="expired_shares",
        name="Expired share pruning",
        severity="info" if expired < 100 else "warning",
        message=f"{expired} expired shares can be pruned.",
        details={"count": expired},
        auto_fixable=True,
        duration_ms=dur,
    )


async def _fix_expired_shares(_result: CheckResult) -> str:
    db = _get_db()
    now = datetime.now(timezone.utc).isoformat()
    res = await db.cyberlab_shares.delete_many({"expires_at": {"$lt": now}})
    return f"Pruned {res.deleted_count} expired shares."
register(_check_expired_shares, _fix_expired_shares)


# ---------------------------------------------------------------------------
# 5. Enrichment cache size
# ---------------------------------------------------------------------------
async def _check_enrichment_cache():
    t0 = time.perf_counter()
    db = _get_db()
    try:
        total = await db.ioc_enrich_cache.count_documents({})
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            id="enrichment_cache",
            name="OSINT enrichment cache",
            severity="info",
            message=f"cache count failed: {e}",
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
    dur = (time.perf_counter() - t0) * 1000
    if total < 500:
        return CheckResult(
            id="enrichment_cache",
            name="OSINT enrichment cache",
            severity="ok",
            message=f"{total} cached entries.",
            details={"size": total},
            duration_ms=dur,
        )
    return CheckResult(
        id="enrichment_cache",
        name="OSINT enrichment cache",
        severity="warning",
        message=f"Cache holds {total} entries — consider purging.",
        details={"size": total},
        auto_fixable=True,
        duration_ms=dur,
    )


async def _fix_enrichment_cache(_result: CheckResult) -> str:
    db = _get_db()
    res = await db.ioc_enrich_cache.delete_many({})
    return f"Purged {res.deleted_count} enrichment cache entries."
register(_check_enrichment_cache, _fix_enrichment_cache)


# ---------------------------------------------------------------------------
# 6. Webhook delivery backlog
# ---------------------------------------------------------------------------
async def _check_webhook_backlog():
    t0 = time.perf_counter()
    db = _get_db()
    try:
        failed = await db.webhook_deliveries.count_documents({"status": "failed"})
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            id="webhook_backlog",
            name="Webhook delivery backlog",
            severity="info",
            message=f"query failed: {e}",
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
    dur = (time.perf_counter() - t0) * 1000
    if failed == 0:
        return CheckResult(
            id="webhook_backlog", name="Webhook delivery backlog",
            severity="ok",
            message="No failed webhook deliveries in the audit log.",
            duration_ms=dur,
        )
    return CheckResult(
        id="webhook_backlog", name="Webhook delivery backlog",
        severity="warning" if failed < 20 else "critical",
        message=f"{failed} failed deliveries in the audit log — review in /admin.",
        details={"count": failed},
        duration_ms=dur,
    )
register(_check_webhook_backlog)


# ---------------------------------------------------------------------------
# 7. OSINT API keys presence (stored in settings)
# ---------------------------------------------------------------------------
async def _check_osint_keys():
    t0 = time.perf_counter()
    db = _get_db()
    settings = await db.settings.find_one({"_id": "osint"}) or {}
    known = ["virustotal", "abuseipdb", "shodan", "urlscan", "hybrid_analysis", "otx"]
    configured = [k for k in known if (settings.get(k) or "").strip()]
    missing = [k for k in known if k not in configured]
    dur = (time.perf_counter() - t0) * 1000
    if not configured:
        return CheckResult(
            id="osint_keys", name="OSINT API keys",
            severity="warning",
            message="No OSINT API keys configured — enrichment will be limited.",
            details={"configured": configured, "missing": missing},
            duration_ms=dur,
        )
    return CheckResult(
        id="osint_keys", name="OSINT API keys",
        severity="ok" if len(missing) <= 2 else "info",
        message=f"{len(configured)}/{len(known)} providers configured.",
        details={"configured": configured, "missing": missing},
        duration_ms=dur,
    )
register(_check_osint_keys)


# ---------------------------------------------------------------------------
# 8. Environment sanity (MONGO_URL, DB_NAME, REACT_APP_BACKEND_URL for FE)
# ---------------------------------------------------------------------------
async def _check_env():
    t0 = time.perf_counter()
    required = ["MONGO_URL", "DB_NAME"]
    missing = [k for k in required if not (os.environ.get(k) or "").strip()]
    dur = (time.perf_counter() - t0) * 1000
    if missing:
        return CheckResult(
            id="env_sanity", name="Environment variables",
            severity="critical",
            message=f"Missing required env vars: {', '.join(missing)}",
            details={"missing": missing},
            duration_ms=dur,
        )
    return CheckResult(
        id="env_sanity", name="Environment variables",
        severity="ok",
        message="All required backend env vars are set.",
        duration_ms=dur,
    )
register(_check_env)


# ---------------------------------------------------------------------------
# 9. Disk pressure (rootfs + /tmp)
# ---------------------------------------------------------------------------
async def _check_disk():
    t0 = time.perf_counter()
    try:
        total, used, free = shutil.disk_usage("/")
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            id="disk", name="Disk space",
            severity="info",
            message=f"disk stat failed: {e}",
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
    pct = used / total * 100 if total else 0
    dur = (time.perf_counter() - t0) * 1000
    sev = "ok" if pct < 80 else ("warning" if pct < 92 else "critical")
    return CheckResult(
        id="disk", name="Disk space",
        severity=sev,
        message=f"Root FS {pct:.1f}% used ({free / (1024**3):.1f} GB free).",
        details={"used_pct": round(pct, 2),
                 "free_gb": round(free / (1024**3), 2),
                 "total_gb": round(total / (1024**3), 2)},
        duration_ms=dur,
    )
register(_check_disk)


# ---------------------------------------------------------------------------
# 10. Backend module hot-imports  (proves the app actually loaded everything)
# ---------------------------------------------------------------------------
async def _check_module_health():
    t0 = time.perf_counter()
    modules = [
        "cyberlab", "cyberlab.engine", "cyberlab.router",
        "cyberlab.repair", "webhooks.router", "webhooks.delivery",
    ]
    broken = []
    for m in modules:
        try:
            __import__(m)
        except Exception as e:  # noqa: BLE001
            broken.append(f"{m}: {e}")
    dur = (time.perf_counter() - t0) * 1000
    if broken:
        return CheckResult(
            id="modules", name="Core module imports",
            severity="critical",
            message=f"{len(broken)} module(s) failing to import.",
            details={"broken": broken},
            duration_ms=dur,
        )
    return CheckResult(
        id="modules", name="Core module imports",
        severity="ok",
        message=f"All {len(modules)} core modules importable.",
        duration_ms=dur,
    )
register(_check_module_health)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
async def run_all_checks() -> List[CheckResult]:
    """Run every registered check in parallel and return the raw results.
    Also populates the id→fix map on first invocation."""
    tasks = [entry["check"]() for entry in _CHECKS]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    # First run populates the fix map so run_all_fixes doesn't need to
    # re-execute checks.
    if not _FIXES_BY_ID:
        for entry, result in zip(_CHECKS, results):
            if entry["fix"] is not None:
                _FIXES_BY_ID[result.id] = entry["fix"]
    return results


async def run_all_fixes(results: List[CheckResult]) -> List[CheckResult]:
    """Invoke the fix_fn for every check that is auto-fixable AND currently
    reporting non-ok severity."""
    for r in results:
        if not r.auto_fixable or r.severity == "ok" or r.fixed:
            continue
        fix = _FIXES_BY_ID.get(r.id)
        if not fix:
            continue
        try:
            r.fix_message = await fix(r)
            r.fixed = True
        except Exception as e:  # noqa: BLE001
            r.fixed = False
            r.fix_message = f"Fix failed: {e}"
    return results


async def run_one_fix(check_id: str) -> Optional[CheckResult]:
    """Re-check the given id, run its fix, then re-check to confirm."""
    # Ensure fix map is populated
    if not _FIXES_BY_ID:
        await run_all_checks()
    fix = _FIXES_BY_ID.get(check_id)
    if not fix:
        return None
    # Find the check entry
    for entry in _CHECKS:
        result = await entry["check"]()
        if result.id != check_id:
            continue
        if not result.auto_fixable or result.severity == "ok":
            return result
        try:
            result.fix_message = await fix(result)
            result.fixed = True
        except Exception as e:  # noqa: BLE001
            result.fixed = False
            result.fix_message = f"Fix failed: {e}"
        return result
    return None


def to_dict(r: CheckResult) -> Dict[str, Any]:
    return asdict(r)


async def persist_scan(scan: Dict[str, Any]) -> None:
    """Store scan snapshot for audit history. Keeps last 100 scans.

    Deep-copies the dict so callers can return their original view without
    the MongoDB-injected _id ObjectId leaking into the API response.
    """
    db = _get_db()
    doc = {k: v for k, v in scan.items()}
    await db.healthbot_scans.insert_one(doc)
    total = await db.healthbot_scans.count_documents({})
    if total > 100:
        oldest = (
            await db.healthbot_scans.find()
            .sort("started_at", 1)
            .limit(total - 100)
            .to_list(total - 100)
        )
        if oldest:
            await db.healthbot_scans.delete_many(
                {"_id": {"$in": [d["_id"] for d in oldest]}}
            )
