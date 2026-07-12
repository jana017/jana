"""Tests for AlienVault OTX sync + IOC bulk-save-flagged features (iteration 17)."""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://threat-intel-hub-85.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "admin@nivxmachines.com"
ADMIN_PASSWORD = "NivX@Admin2025"


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=15)
    assert r.status_code == 200, f"Login failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def auth_headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ---- OTX ----

class TestOTX:
    def test_otx_status_public(self):
        r = requests.get(f"{BASE_URL}/api/otx/status", timeout=15)
        assert r.status_code == 200
        data = r.json()
        assert data.get("configured") is True
        # last_sync may or may not be present yet; if present, check shape
        if data.get("last_sync"):
            ls = data["last_sync"]
            for k in ["pulses", "indicators", "added", "updated", "skipped", "synced_at"]:
                assert k in ls, f"Missing key {k} in last_sync"

    def test_otx_sync_requires_auth(self):
        r = requests.post(f"{BASE_URL}/api/otx/sync", timeout=15)
        assert r.status_code in (401, 403), f"Expected 401/403 without token, got {r.status_code}"

    def test_otx_sync_manual_run(self, auth_headers):
        t0 = time.time()
        r = requests.post(f"{BASE_URL}/api/otx/sync", headers=auth_headers, timeout=120)
        elapsed = time.time() - t0
        assert r.status_code == 200, f"OTX sync failed: {r.status_code} {r.text}"
        summary = r.json()
        for k in ["pulses", "indicators", "added", "updated", "skipped", "synced_at"]:
            assert k in summary, f"Missing key {k}"
        assert summary["pulses"] > 0, "Expected >0 pulses"
        assert summary["indicators"] > 0, "Expected >0 indicators"
        assert elapsed < 90, f"Sync too slow: {elapsed:.1f}s"
        # store for next test
        pytest.otx_first = summary

    def test_otx_iocs_persisted(self, auth_headers):
        # Feb 2026: with URLhaus/CINS Army/ThreatFox syncs in place, OTX no
        # longer appears in the first 50 by created_at.  Explicitly query for
        # OTX-sourced docs via the built-in search parameter.
        r = requests.get(f"{BASE_URL}/api/iocs", params={"limit": 50, "q": "AlienVault OTX"}, headers=auth_headers, timeout=15)
        assert r.status_code == 200
        body = r.json()
        items = body.get("items") if isinstance(body, dict) else body
        assert isinstance(items, list) and len(items) > 0
        otx_items = [i for i in items if "AlienVault OTX" in (i.get("source") or "")]
        assert len(otx_items) > 0, "No IOCs with source starting 'AlienVault OTX'"
        sevs = {i.get("severity") for i in otx_items}
        assert sevs - {"low"}, f"Severity distribution all 'low': {sevs}"

    def test_otx_sync_idempotent(self, auth_headers):
        # Second run
        r = requests.post(f"{BASE_URL}/api/otx/sync", headers=auth_headers, timeout=120)
        assert r.status_code == 200
        second = r.json()
        first = getattr(pytest, "otx_first", None)
        assert first is not None
        # updated should be > added on second run (data already there)
        assert second["updated"] >= second["added"], f"Expected updated>=added on second run: {second}"
        assert second["indicators"] > 0


# ---- IOC bulk (new frontend payload shape) ----

class TestIocBulk:
    def test_bulk_insert_flagged(self, auth_headers):
        payload = {
            "values": ["44d88612fea8a8f36de82e1278abb02f", "1.1.1.1"],
            "severity": "high",
            "source": "TEST_bulk_save_flagged",
            "tags": ["test", "iteration17"],
        }
        r = requests.post(f"{BASE_URL}/api/iocs/bulk", headers=auth_headers, json=payload, timeout=30)
        assert r.status_code in (200, 201), f"Bulk insert failed: {r.status_code} {r.text}"
        # Verify persistence via GET
        r2 = requests.get(f"{BASE_URL}/api/iocs", params={"q": "44d88612fea8a8f36de82e1278abb02f", "limit": 5}, headers=auth_headers, timeout=15)
        assert r2.status_code == 200
        body2 = r2.json()
        items2 = body2.get("items") if isinstance(body2, dict) else body2
        found = [i for i in items2 if i.get("value") == "44d88612fea8a8f36de82e1278abb02f"]
        assert len(found) > 0, "Bulk-saved IOC not found"
        assert found[0].get("source") == "TEST_bulk_save_flagged"
