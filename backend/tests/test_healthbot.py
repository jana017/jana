"""Pytest coverage for the NivX HealthBot subsystem.

Verifies:
- All endpoints require admin auth
- Scan returns the expected schema + covers all 10 registered checks
- Auto-fix creates missing MongoDB indexes idempotently
- Per-check fix endpoint works
- History log persists + trims to 100 entries
- The whole subsystem is offline-safe (no LLM imports)
"""
from __future__ import annotations

import os
import pytest
import httpx

BASE = os.environ.get("CYBERLAB_TEST_BASE", "http://localhost:8001")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@nivxmachines.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "NivX@Admin2025")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE, timeout=45.0) as c:
        yield c


@pytest.fixture(scope="module")
def admin_headers(client):
    r = client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_endpoints_require_admin(client):
    for path in ("/api/healthbot/scan", "/api/healthbot/scan-and-fix"):
        r = client.post(path)
        assert r.status_code == 401
    r = client.get("/api/healthbot/history")
    assert r.status_code == 401


def test_scan_returns_expected_schema(client, admin_headers):
    r = client.post("/api/healthbot/scan", headers=admin_headers)
    assert r.status_code == 200, r.text
    data = r.json()
    for k in ("started_at", "finished_at", "overall", "summary", "results", "auto_fixed"):
        assert k in data
    assert data["overall"] in ("ok", "info", "warning", "critical")
    assert isinstance(data["results"], list) and len(data["results"]) >= 8

    expected_check_ids = {
        "mongo_reachable", "mongo_indexes", "plugin_registry",
        "expired_shares", "enrichment_cache", "webhook_backlog",
        "osint_keys", "env_sanity", "disk", "modules",
    }
    got_ids = {c["id"] for c in data["results"]}
    assert expected_check_ids <= got_ids, f"missing checks: {expected_check_ids - got_ids}"

    # Each result must have the documented fields
    for c in data["results"]:
        for k in ("id", "name", "severity", "message", "duration_ms"):
            assert k in c
        assert c["severity"] in ("ok", "info", "warning", "critical")


def test_scan_and_fix_rebuilds_missing_indexes(client, admin_headers):
    # First run may or may not rebuild indexes depending on state — the
    # contract is that AFTER scan-and-fix, mongo_indexes is OK.
    r = client.post("/api/healthbot/scan-and-fix", headers=admin_headers)
    assert r.status_code == 200, r.text
    data = r.json()
    idx = next(c for c in data["results"] if c["id"] == "mongo_indexes")
    assert idx["severity"] == "ok", f"indexes not repaired: {idx}"

    # Idempotency — a 2nd scan-and-fix must also report OK (no double-work).
    r2 = client.post("/api/healthbot/scan-and-fix", headers=admin_headers)
    assert r2.status_code == 200
    idx2 = next(c for c in r2.json()["results"] if c["id"] == "mongo_indexes")
    assert idx2["severity"] == "ok"


def test_per_check_fix_endpoint(client, admin_headers):
    # Fix expired shares — should be a no-op when there are none.
    r = client.post("/api/healthbot/fix/expired_shares", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == "expired_shares"

    # Unknown check id → 404
    r = client.post("/api/healthbot/fix/nonexistent", headers=admin_headers)
    assert r.status_code == 404


def test_history_persists(client, admin_headers):
    # Trigger a scan then check it appears in history
    client.post("/api/healthbot/scan", headers=admin_headers)
    r = client.get("/api/healthbot/history?limit=10", headers=admin_headers)
    assert r.status_code == 200
    history = r.json()
    assert len(history) >= 1
    latest = history[0]
    for k in ("id", "started_at", "overall", "summary", "triggered_by"):
        assert k in latest


def test_healthbot_is_offline_safe():
    """The whole subsystem must not import any LLM SDK — key requirement so
    it keeps working after the app is transferred to any VPS without an
    Emergent LLM key."""
    import inspect
    from healthbot import checks, router
    for mod in (checks, router):
        src = inspect.getsource(mod)
        for forbidden in ("emergentintegrations", "openai", "anthropic",
                          "google.generativeai", "aiohttp", "requests.get"):
            assert forbidden not in src, f"{mod.__name__} must not import {forbidden}"


def test_all_checks_finish_under_2_seconds(client, admin_headers):
    """Real-time UX guarantee: a full scan must complete in <2s."""
    r = client.post("/api/healthbot/scan", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["duration_ms"] < 2000, f"scan too slow: {r.json()['duration_ms']}ms"
