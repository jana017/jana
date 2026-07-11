"""Tests for the UI/UX Scanner backend module.

Exercises persistence + querying end-to-end through the actual running
FastAPI backend (matches the pattern used by test_webhooks.py so no
event-loop juggling is needed).
"""
import os
import uuid

import httpx
import pytest


BASE = os.environ.get("CYBERLAB_TEST_BASE", "http://localhost:8001")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@nivxmachines.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "NivX@Admin2025")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE, timeout=30.0) as c:
        yield c


@pytest.fixture(scope="module")
def admin_headers(client):
    r = client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _sample_payload():
    return {
        "started_at": "2026-07-11T05:00:00Z",
        "finished_at": "2026-07-11T05:00:12Z",
        "routes_scanned": ["/", "/nivx-forge"],
        "viewports_scanned": ["iPhone-14(390x844)", "Desktop(1920x1080)"],
        "findings": [
            {
                "route": "/nivx-forge", "viewport": "iPhone-14(390x844)",
                "viewport_w": 390, "viewport_h": 844,
                "severity": "CRIT", "type": "h-overflow",
                "details": {"doc_w": 500, "viewport_w": 390},
            },
            {
                "route": "/", "viewport": "iPhone-14(390x844)",
                "viewport_w": 390, "viewport_h": 844,
                "severity": "HIGH", "type": "small-tap-target",
                "details": {"count": 3},
            },
            {
                "route": "/", "viewport": "Desktop(1920x1080)",
                "viewport_w": 1920, "viewport_h": 1080,
                "severity": "MED", "type": "img-no-alt",
                "details": {"count": 1},
            },
        ],
    }


def test_health_endpoint_is_public(client):
    r = client.get("/api/ui-scanner/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert "total_scans" in body


def test_history_requires_auth(client):
    r = client.get("/api/ui-scanner/history")
    assert r.status_code == 401


def test_save_and_retrieve_report(client, admin_headers):
    r = client.post("/api/ui-scanner/scan", json=_sample_payload(), headers=admin_headers)
    assert r.status_code == 200, r.text
    saved = r.json()
    scan_id = saved["id"]
    try:
        # Aggregate counts must be computed server-side
        assert saved["total_findings"] == 3
        assert saved["counts_by_severity"]["CRIT"] == 1
        assert saved["counts_by_severity"]["HIGH"] == 1
        assert saved["counts_by_severity"]["MED"] == 1
        assert saved["counts_by_type"]["h-overflow"] == 1
        assert saved["counts_by_type"]["small-tap-target"] == 1
        # triggered_by is auto-set from the JWT user when omitted from payload
        assert saved["triggered_by"] == ADMIN_EMAIL
        # Fetch specific report
        r2 = client.get(f"/api/ui-scanner/report/{scan_id}", headers=admin_headers)
        assert r2.status_code == 200
        got = r2.json()
        assert got["id"] == scan_id
        assert len(got["findings"]) == 3
    finally:
        client.delete(f"/api/ui-scanner/report/{scan_id}", headers=admin_headers)


def test_history_returns_recent_scans(client, admin_headers):
    # Create two scans
    ids = []
    for _ in range(2):
        r = client.post("/api/ui-scanner/scan", json=_sample_payload(), headers=admin_headers)
        assert r.status_code == 200
        ids.append(r.json()["id"])
    try:
        r = client.get("/api/ui-scanner/history?limit=5", headers=admin_headers)
        assert r.status_code == 200
        items = r.json().get("items", [])
        # Findings must be stripped from history list (perf)
        for it in items:
            assert "findings" not in it
            assert "counts_by_severity" in it
        # Both of our scans should be present
        found = {it["id"] for it in items}
        assert set(ids).issubset(found)
    finally:
        for sid in ids:
            client.delete(f"/api/ui-scanner/report/{sid}", headers=admin_headers)


def test_latest_returns_most_recent(client, admin_headers):
    r = client.post("/api/ui-scanner/scan", json=_sample_payload(), headers=admin_headers)
    assert r.status_code == 200
    scan_id = r.json()["id"]
    try:
        r2 = client.get("/api/ui-scanner/latest", headers=admin_headers)
        assert r2.status_code == 200
        got = r2.json()
        assert got["id"] == scan_id
    finally:
        client.delete(f"/api/ui-scanner/report/{scan_id}", headers=admin_headers)


def test_delete_report(client, admin_headers):
    r = client.post("/api/ui-scanner/scan", json=_sample_payload(), headers=admin_headers)
    scan_id = r.json()["id"]
    r2 = client.delete(f"/api/ui-scanner/report/{scan_id}", headers=admin_headers)
    assert r2.status_code == 200
    assert r2.json()["deleted"] == 1
    r3 = client.get(f"/api/ui-scanner/report/{scan_id}", headers=admin_headers)
    assert r3.status_code == 404


def test_get_missing_report_returns_404(client, admin_headers):
    r = client.get(f"/api/ui-scanner/report/{uuid.uuid4()}", headers=admin_headers)
    assert r.status_code == 404


def test_empty_findings_payload_ok(client, admin_headers):
    payload = _sample_payload()
    payload["findings"] = []
    r = client.post("/api/ui-scanner/scan", json=payload, headers=admin_headers)
    assert r.status_code == 200
    saved = r.json()
    try:
        assert saved["total_findings"] == 0
        assert saved["counts_by_severity"] == {}
    finally:
        client.delete(f"/api/ui-scanner/report/{saved['id']}", headers=admin_headers)
