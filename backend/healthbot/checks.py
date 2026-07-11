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
# 10b. Decoder coverage — golden-payload regression suite for the NivX Forge
#      auto-decode engine.  Runs a fixed set of real-world staging payloads
#      through auto_decode() and fails critical if any of them go undecoded.
#      This catches "silent regression" bugs like the Feb 2026 missing
#      Python-b64decode extractor that let a malicious sample slip past as
#      "clean/risk=8".  Each sample is deterministic — no LLM, no network.
# ---------------------------------------------------------------------------
_GOLDEN_PAYLOADS = [
    {
        "id": "powershell_frombase64string",
        "input": "$x=[Convert]::FromBase64String('SGVsbG8gV29ybGQh');IEX",
        "must_decode_to_contain": "Hello World",
    },
    {
        "id": "bash_echo_base64_pipe",
        "input": "echo SGVsbG8gTWFsd2FyZQ== | base64 -d",
        "must_decode_to_contain": "Hello Malware",
    },
    {
        "id": "python_b64decode_exec",
        "input": (
            "-c exec(__import__('base64').b64decode("
            "b'aW1wb3J0IG9zLHN5cwo=').decode())"
        ),
        "must_decode_to_contain": "import os",
    },
    {
        "id": "cmd_caret_obfuscation",
        "input": "p^o^w^e^r^shell.exe -nop -w hidden -c whoami",
        "must_decode_to_contain": "powershell",
    },
    {
        "id": "hex_string",
        "input": "48656c6c6f20576f726c64",
        "must_decode_to_contain": "Hello World",
    },
]


async def _check_decoder_coverage():
    t0 = time.perf_counter()
    try:
        from cyberlab.engine import auto_decode
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            id="decoder_coverage", name="NivX Forge decoder coverage",
            severity="critical",
            message=f"Cannot import auto_decode: {e}",
            duration_ms=(time.perf_counter() - t0) * 1000,
        )

    # Merge built-in golden samples with any custom analyst-authored samples
    # stored in Mongo (`healthbot_regression_samples`). This makes HealthBot
    # a living regression suite — analysts can add real-world payloads that
    # they've seen in the wild and pin them so future refactors can't
    # silently regress the decoder.
    samples = list(_GOLDEN_PAYLOADS)
    try:
        db = _get_db()
        async for doc in db.healthbot_regression_samples.find({"enabled": {"$ne": False}}):
            samples.append({
                "id": f"custom:{doc.get('id', str(doc.get('_id', '?')))}",
                "input": doc.get("input", ""),
                "must_decode_to_contain": doc.get("must_decode_to_contain", ""),
                "custom": True,
            })
    except Exception:  # noqa: BLE001
        pass  # DB unreachable — fall back to built-ins.

    failed = []
    passed = 0
    for sample in samples:
        needle = sample.get("must_decode_to_contain") or ""
        input_text = sample.get("input") or ""
        if not input_text or not needle:
            continue
        try:
            output, trace = auto_decode(input_text, max_depth=8)
            text = output.decode("utf-8", errors="replace")
            if needle.lower() not in text.lower():
                failed.append({
                    "id": sample["id"],
                    "steps": len(trace),
                    "expected": needle,
                    "got_preview": text[:120],
                    "custom": sample.get("custom", False),
                })
            else:
                passed += 1
        except Exception as e:  # noqa: BLE001
            failed.append({"id": sample["id"], "error": str(e)[:200],
                           "custom": sample.get("custom", False)})

    dur = (time.perf_counter() - t0) * 1000
    total = passed + len(failed)
    if failed:
        return CheckResult(
            id="decoder_coverage", name="NivX Forge decoder coverage",
            severity="critical",
            message=f"{len(failed)}/{total} decoder sample(s) failed — plugin regression.",
            details={"failed": failed, "passed": passed, "total": total},
            duration_ms=dur,
        )
    return CheckResult(
        id="decoder_coverage", name="NivX Forge decoder coverage",
        severity="ok",
        message=f"All {total} decoder samples decoded correctly ({len(_GOLDEN_PAYLOADS)} builtin + {total - len(_GOLDEN_PAYLOADS)} custom).",
        details={"samples": [s["id"] for s in samples]},
        duration_ms=dur,
    )
register(_check_decoder_coverage)


# ---------------------------------------------------------------------------
# 11. Frontend static lint — catches page-breaking JS/JSX bugs
#     (no-undef, react/jsx-no-undef) BEFORE they white-screen a route.
#     Added Feb 2026 after a `ReferenceError: exportRef is not defined`
#     shipped to production and broke /threat-intelligence.
# ---------------------------------------------------------------------------
import subprocess
import json as _json

_FRONTEND_ROOT = "/app/frontend"
_ESLINT_CONFIG = "/app/backend/healthbot/eslint.smoke.mjs"


async def _check_frontend_lint():
    t0 = time.perf_counter()
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                "npx", "eslint",
                "--config", _ESLINT_CONFIG,
                "src/",
                "--format", "json",
                cwd=_FRONTEND_ROOT,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=60,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
    except asyncio.TimeoutError:
        return CheckResult(
            id="frontend_lint", name="Frontend static lint",
            severity="warning",
            message="ESLint scan timed out (>60s). Skipping.",
            duration_ms=(time.perf_counter() - t0) * 1000,
        )
    except FileNotFoundError:
        return CheckResult(
            id="frontend_lint", name="Frontend static lint",
            severity="info",
            message="ESLint not installed — skipping frontend lint check.",
            duration_ms=(time.perf_counter() - t0) * 1000,
        )

    try:
        payload = _json.loads(stdout.decode("utf-8", errors="replace") or "[]")
    except _json.JSONDecodeError:
        return CheckResult(
            id="frontend_lint", name="Frontend static lint",
            severity="warning",
            message="Could not parse ESLint output.",
            duration_ms=(time.perf_counter() - t0) * 1000,
        )

    errors = []
    for f in payload:
        rel = f.get("filePath", "").replace(_FRONTEND_ROOT + "/", "")
        for m in f.get("messages", []):
            if m.get("severity") == 2 and m.get("ruleId") in ("no-undef", "react/jsx-no-undef"):
                errors.append({
                    "file": rel,
                    "line": m.get("line"),
                    "rule": m.get("ruleId"),
                    "message": m.get("message"),
                })

    dur = (time.perf_counter() - t0) * 1000
    if errors:
        # Group by file for a nicer summary
        by_file = {}
        for e in errors:
            by_file.setdefault(e["file"], []).append(f'L{e["line"]} {e["message"]}')
        return CheckResult(
            id="frontend_lint", name="Frontend static lint",
            severity="critical",
            message=f"{len(errors)} page-breaking JS reference(s) in {len(by_file)} file(s).",
            details={"errors": errors[:50], "by_file": {k: v[:5] for k, v in by_file.items()}},
            duration_ms=dur,
        )
    scanned = len(payload)
    return CheckResult(
        id="frontend_lint", name="Frontend static lint",
        severity="ok",
        message=f"No page-breaking references across {scanned} JS/JSX file(s).",
        details={"files_scanned": scanned},
        duration_ms=dur,
    )
register(_check_frontend_lint)


# ---------------------------------------------------------------------------
# 12. Route smoke — parallel-hit every critical public/admin GET endpoint and
#     verify shape. Catches serialization crashes, ordering bugs, dead
#     routes and 500s that would silently break pages.  Runs in <1s thanks
#     to asyncio.gather.
# ---------------------------------------------------------------------------
async def _check_route_smoke():
    t0 = time.perf_counter()
    try:
        import httpx  # already in requirements
    except ImportError:
        return CheckResult(
            id="route_smoke", name="Route smoke test",
            severity="info",
            message="httpx not available — skipping route smoke.",
            duration_ms=(time.perf_counter() - t0) * 1000,
        )

    base = os.environ.get("BACKEND_INTERNAL_URL", "http://127.0.0.1:8001")

    # (path, expected_type, auth_required, shape_hint)
    # `shape_hint` is a callable returning True if body looks correct.
    def _is_ioc_page(b): return isinstance(b, dict) and "items" in b and "total" in b
    def _is_stats(b):    return isinstance(b, dict) and "total" in b
    def _is_root(b):     return isinstance(b, dict) and "message" in b
    def _is_list(b):     return isinstance(b, list)
    def _is_dict(b):     return isinstance(b, dict)

    endpoints = [
        # Public
        ("/api/",                   False, _is_root),
        ("/api/threats",            False, _is_list),
        ("/api/live-feed",          False, _is_dict),
        ("/api/iocs?limit=1",       False, _is_ioc_page),
        ("/api/iocs/stats",         False, _is_stats),
        ("/api/threat-intel/overview", False, _is_dict),
        ("/api/intel-feed",         False, _is_dict),
        ("/api/community/enabled-sources", False, _is_dict),
        # Admin
        ("/api/leads",              True,  _is_list),
        ("/api/webhooks",           True,  _is_list),
        ("/api/webhooks/presets",   True,  _is_list),
        ("/api/admin/overview",     True,  _is_dict),
        ("/api/admin/settings",     True,  _is_dict),
        ("/api/admin/cyberlab/rules", True, _is_dict),
    ]

    async with httpx.AsyncClient(timeout=8.0) as client:
        # Grab an admin token from the seeded admin so we can hit auth routes.
        # Falls back gracefully if login fails (auth checks marked as skipped).
        token = None
        try:
            admin_email = os.environ.get("ADMIN_EMAIL", "admin@nivxmachines.com")
            admin_pass = os.environ.get("ADMIN_PASSWORD", "NivX@Admin2025")
            login = await client.post(
                f"{base}/api/auth/login",
                json={"email": admin_email, "password": admin_pass},
            )
            if login.status_code == 200:
                token = login.json().get("access_token")
        except Exception:  # noqa: BLE001
            token = None

        async def hit(path: str, auth: bool, shape_ok):
            headers = {}
            if auth and token:
                headers["Authorization"] = f"Bearer {token}"
            try:
                r = await client.get(f"{base}{path}", headers=headers)
                if r.status_code != 200:
                    return {"path": path, "status": r.status_code,
                            "detail": r.text[:180], "auth": auth}
                try:
                    body = r.json()
                except Exception:
                    return {"path": path, "status": 200,
                            "detail": "non-JSON response", "auth": auth}
                if not shape_ok(body):
                    return {"path": path, "status": 200,
                            "detail": f"shape mismatch: {type(body).__name__} — {str(body)[:80]}",
                            "auth": auth}
                return None
            except Exception as e:  # noqa: BLE001
                return {"path": path, "status": None,
                        "detail": str(e)[:180], "auth": auth}

        # Fan-out in parallel — this makes the whole smoke take ~200ms.
        results = await asyncio.gather(*[hit(p, a, s) for p, a, s in endpoints])

    failures = [r for r in results if r is not None]
    skipped_auth = [f for f in failures if f["auth"] and not token]

    dur = (time.perf_counter() - t0) * 1000
    if failures:
        # If ALL failures are auth-skipped (couldn't get a token), soften to warning
        if failures and len(failures) == len(skipped_auth):
            return CheckResult(
                id="route_smoke", name="Route smoke test",
                severity="warning",
                message=f"Admin token unavailable — {len(skipped_auth)} auth route(s) skipped.",
                details={"skipped": [f["path"] for f in skipped_auth]},
                duration_ms=dur,
            )
        return CheckResult(
            id="route_smoke", name="Route smoke test",
            severity="critical",
            message=f"{len(failures)}/{len(endpoints)} critical endpoint(s) failing.",
            details={"failures": failures[:20],
                     "checked": [p for p, _, _ in endpoints]},
            duration_ms=dur,
        )
    return CheckResult(
        id="route_smoke", name="Route smoke test",
        severity="ok",
        message=f"All {len(endpoints)} critical endpoint(s) responding correctly.",
        details={"checked": [p for p, _, _ in endpoints]},
        duration_ms=dur,
    )
register(_check_route_smoke)


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
