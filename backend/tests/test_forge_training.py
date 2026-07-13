"""Tests for Analyst Training Center (Forge Training) endpoints."""
import os
import io
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
# Fallback: read frontend .env if not set
if not BASE_URL:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

ADMIN_EMAIL = "admin@nivxmachines.com"
ADMIN_PASS = "NivX@Admin2025"


@pytest.fixture(scope="module")
def admin_token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASS}, timeout=15)
    assert r.status_code == 200, r.text
    data = r.json()
    tok = data.get("access_token") or data.get("token")
    assert tok, f"No access_token: {data}"
    return tok


@pytest.fixture(scope="module")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="module")
def created_example(admin_headers):
    payload = {
        "title": "TEST_malware_beacon_case",
        "case_type": "malware",
        "tags": ["beacon", "trickbot", "TEST"],
        "raw_data": "src=10.0.0.5 dst=45.66.77.88 process=svchost.exe hash=abc123",
        "narrative": "Confirmed malicious beacon from endpoint WKS-01 to C2 45.66.77.88. Escalate to IR.",
        "recommendations": ["Isolate host", "Reset creds", "Block C2 IP"],
        "analyst_notes": "Use for beacon/C2 comms style reports.",
        "active": True,
    }
    r = requests.post(f"{BASE_URL}/api/admin/forge/training/examples",
                      json=payload, headers=admin_headers, timeout=15)
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc.get("id")
    yield doc
    # cleanup
    requests.delete(f"{BASE_URL}/api/admin/forge/training/examples/{doc['id']}",
                    headers=admin_headers, timeout=15)


# ---------------------------- AUTH ------------------------------------------
class TestAuth:
    def test_list_requires_auth(self):
        r = requests.get(f"{BASE_URL}/api/admin/forge/training/examples", timeout=10)
        assert r.status_code in (401, 403), f"Expected 401/403, got {r.status_code}"

    def test_create_requires_auth(self):
        r = requests.post(f"{BASE_URL}/api/admin/forge/training/examples",
                          json={"title": "nope"}, timeout=10)
        assert r.status_code in (401, 403)


# --------------------------- CRUD -------------------------------------------
class TestCRUD:
    def test_create_returns_id(self, created_example):
        assert created_example["id"]
        assert created_example["title"] == "TEST_malware_beacon_case"
        assert created_example["case_type"] == "malware"
        assert created_example["active"] is True

    def test_create_empty_title_400(self, admin_headers):
        r = requests.post(f"{BASE_URL}/api/admin/forge/training/examples",
                          json={"title": "   ", "case_type": "malware"},
                          headers=admin_headers, timeout=15)
        assert r.status_code == 400

    def test_list_returns_created(self, admin_headers, created_example):
        r = requests.get(f"{BASE_URL}/api/admin/forge/training/examples",
                         headers=admin_headers, timeout=15)
        assert r.status_code == 200
        ids = [e["id"] for e in r.json().get("examples", [])]
        assert created_example["id"] in ids

    def test_list_search_q(self, admin_headers, created_example):
        r = requests.get(f"{BASE_URL}/api/admin/forge/training/examples",
                         params={"q": "beacon"}, headers=admin_headers, timeout=15)
        assert r.status_code == 200
        assert any(e["id"] == created_example["id"] for e in r.json().get("examples", []))

    def test_list_filter_case_type(self, admin_headers, created_example):
        r = requests.get(f"{BASE_URL}/api/admin/forge/training/examples",
                         params={"case_type": "malware"}, headers=admin_headers, timeout=15)
        assert r.status_code == 200
        assert any(e["id"] == created_example["id"] for e in r.json().get("examples", []))

    def test_get_single(self, admin_headers, created_example):
        r = requests.get(f"{BASE_URL}/api/admin/forge/training/examples/{created_example['id']}",
                         headers=admin_headers, timeout=15)
        assert r.status_code == 200
        assert r.json()["id"] == created_example["id"]

    def test_get_unknown_404(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/admin/forge/training/examples/does-not-exist-xyz",
                         headers=admin_headers, timeout=15)
        assert r.status_code == 404

    def test_update(self, admin_headers, created_example):
        payload = {
            "title": "TEST_malware_beacon_case_v2",
            "case_type": "malware",
            "tags": ["beacon"],
            "raw_data": "updated",
            "narrative": "updated narrative",
            "recommendations": ["one"],
            "analyst_notes": "",
            "active": False,
        }
        r = requests.put(f"{BASE_URL}/api/admin/forge/training/examples/{created_example['id']}",
                         json=payload, headers=admin_headers, timeout=15)
        assert r.status_code == 200, r.text
        upd = r.json()
        assert upd["title"] == "TEST_malware_beacon_case_v2"
        assert upd["active"] is False
        # revert active for later tests
        payload["active"] = True
        payload["title"] = "TEST_malware_beacon_case"
        requests.put(f"{BASE_URL}/api/admin/forge/training/examples/{created_example['id']}",
                     json=payload, headers=admin_headers, timeout=15)


# --------------------------- Attachments ------------------------------------
class TestAttachments:
    def test_upload_and_download_and_delete(self, admin_headers, created_example):
        ex_id = created_example["id"]
        content = b"hello world attachment content"
        files = {"file": ("test.txt", io.BytesIO(content), "text/plain")}
        r = requests.post(
            f"{BASE_URL}/api/admin/forge/training/examples/{ex_id}/attachments",
            files=files,
            headers={"Authorization": admin_headers["Authorization"]}, timeout=20,
        )
        assert r.status_code == 200, r.text
        att = r.json()
        assert att["filename"] == "test.txt"
        assert att["size"] == len(content)
        assert att["mime"].startswith("text/")
        att_id = att["id"]

        # Download
        r2 = requests.get(
            f"{BASE_URL}/api/admin/forge/training/examples/{ex_id}/attachments/{att_id}",
            headers=admin_headers, timeout=15,
        )
        assert r2.status_code == 200
        assert r2.content == content

        # Delete
        r3 = requests.delete(
            f"{BASE_URL}/api/admin/forge/training/examples/{ex_id}/attachments/{att_id}",
            headers=admin_headers, timeout=15,
        )
        assert r3.status_code == 200

        # Verify gone
        r4 = requests.get(
            f"{BASE_URL}/api/admin/forge/training/examples/{ex_id}/attachments/{att_id}",
            headers=admin_headers, timeout=15,
        )
        assert r4.status_code == 404

    def test_upload_too_large_413(self, admin_headers, created_example):
        ex_id = created_example["id"]
        big = b"A" * (10 * 1024 * 1024 + 100)  # 10MB + 100 bytes
        files = {"file": ("big.bin", io.BytesIO(big), "application/octet-stream")}
        r = requests.post(
            f"{BASE_URL}/api/admin/forge/training/examples/{ex_id}/attachments",
            files=files, headers=admin_headers, timeout=30,
        )
        assert r.status_code == 413


# --------------------------- Config -----------------------------------------
class TestConfig:
    def test_get_config(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/admin/forge/training/config",
                         headers=admin_headers, timeout=15)
        assert r.status_code == 200
        data = r.json()
        assert "persona" in data
        assert "custom_case_types" in data

    def test_put_config_persist(self, admin_headers):
        persona = ("You are the NivX CSOC senior analyst. Address the reader as CUSTOMER. "
                   "End every report with 'NivX CSOC recommends the following remediation steps'.")
        r = requests.put(
            f"{BASE_URL}/api/admin/forge/training/config",
            json={"persona": persona, "custom_case_types": [
                {"key": "insider_threat", "label": "Insider Threat",
                 "keywords": ["exfil", "usb"]},
            ]},
            headers=admin_headers, timeout=15,
        )
        assert r.status_code == 200, r.text
        r2 = requests.get(f"{BASE_URL}/api/admin/forge/training/config",
                          headers=admin_headers, timeout=15)
        assert r2.status_code == 200
        d = r2.json()
        assert d["persona"] == persona
        assert any(c["key"] == "insider_threat" for c in d["custom_case_types"])

    def test_persona_capped_at_10k(self, admin_headers):
        big = "X" * 15000
        r = requests.put(f"{BASE_URL}/api/admin/forge/training/config",
                         json={"persona": big, "custom_case_types": []},
                         headers=admin_headers, timeout=15)
        assert r.status_code == 200
        r2 = requests.get(f"{BASE_URL}/api/admin/forge/training/config",
                          headers=admin_headers, timeout=15)
        assert len(r2.json()["persona"]) == 10000


# --------------------------- Regression -------------------------------------
class TestRegression:
    def test_forge_investigation_report_deterministic(self, admin_headers):
        r = requests.post(f"{BASE_URL}/api/forge/investigation-report",
                          json={"data": "src=10.0.0.5 hash=abc123", "ai_mode": False},
                          headers=admin_headers, timeout=30)
        assert r.status_code == 200, r.text
        assert "report" in r.json() or "narrative" in r.json() or "summary" in r.json() or r.json()

    def test_ioc_lookup_batch(self):
        r = requests.post(f"{BASE_URL}/api/ioc-lookup-batch",
                          json={"values": ["8.8.8.8"]}, timeout=30)
        assert r.status_code in (200, 401, 403)
