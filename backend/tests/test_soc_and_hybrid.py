"""Tests for Admin SOC Overview + Hybrid Analysis integration (iteration 18)."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or \
    open("/app/frontend/.env").read().split("REACT_APP_BACKEND_URL=")[1].split("\n")[0].strip()
ADMIN_EMAIL = "admin@nivxmachines.com"
ADMIN_PASS = "NivX@Admin2025"

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


@pytest.fixture(scope="module")
def admin_token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASS}, timeout=15)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


# ---------- Admin SOC Overview ----------
class TestAdminOverview:
    def test_requires_auth(self):
        r = requests.get(f"{BASE_URL}/api/admin/overview", timeout=15)
        assert r.status_code in (401, 403), r.status_code

    def test_admin_overview_shape(self, auth_headers):
        r = requests.get(f"{BASE_URL}/api/admin/overview", headers=auth_headers, timeout=20)
        assert r.status_code == 200, r.text
        d = r.json()
        for k in ("iocs", "leads", "reports", "otx", "recent", "top_families", "providers", "generated_at"):
            assert k in d, f"missing key {k}"
        assert isinstance(d["iocs"]["by_severity"], dict) and len(d["iocs"]["by_severity"]) > 0
        assert isinstance(d["iocs"]["by_type"], dict) and len(d["iocs"]["by_type"]) > 0
        # numbers populated
        assert all(isinstance(v, int) for v in d["iocs"]["by_severity"].values())
        assert all(isinstance(v, int) for v in d["iocs"]["by_type"].values())
        assert d["providers"]["hybrid_analysis"] is True


# ---------- Threat Intel Overview (public) ----------
class TestThreatIntelOverview:
    def test_public_shape(self):
        r = requests.get(f"{BASE_URL}/api/threat-intel/overview", timeout=15)
        assert r.status_code == 200, r.text
        d = r.json()
        for k in ("total_iocs", "by_type", "by_severity", "adversaries", "malware_families",
                  "top_campaigns", "top_sources", "recent", "last_otx_sync", "providers"):
            assert k in d, f"missing key {k}"
        assert d["providers"].get("hybrid_analysis") is True


# ---------- IOC Lookup + Hybrid Analysis ----------
class TestIocLookupHybrid:
    def test_sha256_has_hybrid(self):
        r = requests.get(f"{BASE_URL}/api/ioc-lookup",
                         params={"value": EICAR_SHA256}, timeout=45)
        assert r.status_code == 200, r.text
        rep = r.json().get("reputation", {})
        ha = rep.get("hybrid_analysis")
        assert ha is not None, f"hybrid_analysis missing; rep keys={list(rep.keys())}"
        # HA may find or not — but should not be a skipped stub
        if ha.get("skipped"):
            pytest.fail(f"expected HA lookup for sha256, got skipped: {ha}")
        assert "found" in ha
        if ha.get("found"):
            assert "verdict" in ha
            assert "threat_score" in ha
            assert ha.get("url", "").startswith("https://www.hybrid-analysis.com/sample/")

    def test_md5_skipped(self):
        r = requests.get(f"{BASE_URL}/api/ioc-lookup",
                         params={"value": EICAR_MD5}, timeout=30)
        assert r.status_code == 200, r.text
        rep = r.json().get("reputation", {})
        ha = rep.get("hybrid_analysis")
        assert ha == {"skipped": True, "reason": "sha256_required"}, ha


# ---------- Hybrid Quick Scan URL ----------
class TestHybridQuickScanUrl:
    def test_invalid_url_422(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/hybrid/quick-scan-url",
                          json={"url": "malware.wicar.org", "scan_type": "all"},
                          headers=auth_headers, timeout=15)
        assert r.status_code == 422, r.status_code

    def test_valid_url_scan(self, auth_headers):
        r = requests.post(f"{BASE_URL}/api/hybrid/quick-scan-url",
                          json={"url": "http://malware.wicar.org/data/eicar.com",
                                "scan_type": "all"},
                          headers=auth_headers, timeout=60)
        # 503 acceptable if HA not configured — but key IS set per env
        if r.status_code == 503:
            pytest.skip("Hybrid Analysis not configured (503)")
        assert r.status_code == 200, r.text
        d = r.json()
        for k in ("id", "verdict", "malicious_scanners", "total_scanners", "scanners", "report_url"):
            assert k in d, f"missing {k}"
        assert isinstance(d["scanners"], list)
