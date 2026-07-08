"""NivX Machines backend API tests."""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    # fallback: read from frontend .env
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
                break

API = f"{BASE_URL}/api"
ADMIN_EMAIL = "admin@nivxmachines.com"
ADMIN_PASSWORD = "NivX@Admin2025"


@pytest.fixture(scope="session")
def s():
    return requests.Session()


@pytest.fixture(scope="session")
def token(s):
    r = s.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=15)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "access_token" in data and "user" in data
    return data["access_token"]


@pytest.fixture
def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ------- root -------
def test_root(s):
    r = s.get(f"{API}/", timeout=10)
    assert r.status_code == 200
    assert "online" in r.json().get("message", "").lower()


# ------- auth -------
def test_login_wrong_password(s):
    r = s.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong"}, timeout=10)
    assert r.status_code == 401


def test_me_without_token(s):
    r = s.get(f"{API}/auth/me", timeout=10)
    assert r.status_code == 401


def test_me_with_token(s, auth_headers):
    r = s.get(f"{API}/auth/me", headers=auth_headers, timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert data["email"] == ADMIN_EMAIL
    assert data.get("role") == "admin"


# ------- threats -------
def test_list_threats(s):
    r = s.get(f"{API}/threats", timeout=10)
    assert r.status_code == 200
    items = r.json()
    assert isinstance(items, list) and len(items) >= 3
    first = items[0]
    for key in ["id", "title", "summary", "attack_chain", "iocs", "process_tree"]:
        assert key in first


def test_get_threat_by_id_and_404(s):
    items = s.get(f"{API}/threats", timeout=10).json()
    tid = items[0]["id"]
    r = s.get(f"{API}/threats/{tid}", timeout=10)
    assert r.status_code == 200
    assert r.json()["id"] == tid
    r2 = s.get(f"{API}/threats/does-not-exist-xyz", timeout=10)
    assert r2.status_code == 404


def test_threat_crud_requires_auth(s):
    r = s.post(f"{API}/threats", json={"title": "x", "summary": "y"}, timeout=10)
    assert r.status_code == 401


def test_threat_full_crud(s, auth_headers):
    payload = {
        "title": "TEST_Threat Sample",
        "summary": "TEST summary",
        "severity": "high",
        "category": "Malware",
        "attack_chain": ["Initial Access", "Execution"],
        "iocs": ["sha256:test"],
        "process_tree": {"name": "test.exe", "malicious": False, "children": []},
    }
    r = s.post(f"{API}/threats", json=payload, headers=auth_headers, timeout=10)
    assert r.status_code == 200, r.text
    created = r.json()
    tid = created["id"]
    assert created["title"] == payload["title"]

    # verify GET
    r2 = s.get(f"{API}/threats/{tid}", timeout=10)
    assert r2.status_code == 200
    assert r2.json()["title"] == payload["title"]

    # update
    upd = {**payload, "title": "TEST_Threat Updated"}
    r3 = s.put(f"{API}/threats/{tid}", json=upd, headers=auth_headers, timeout=10)
    assert r3.status_code == 200
    assert r3.json()["title"] == "TEST_Threat Updated"

    # verify persisted
    r4 = s.get(f"{API}/threats/{tid}", timeout=10)
    assert r4.json()["title"] == "TEST_Threat Updated"

    # delete
    r5 = s.delete(f"{API}/threats/{tid}", headers=auth_headers, timeout=10)
    assert r5.status_code == 200
    assert r5.json().get("deleted") is True

    # verify gone
    r6 = s.get(f"{API}/threats/{tid}", timeout=10)
    assert r6.status_code == 404


# ------- live feed -------
def test_live_feed(s):
    r = s.get(f"{API}/live-feed", timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    for k in ["total_count", "ransomware_linked", "items"]:
        assert k in d
    assert isinstance(d["items"], list) and len(d["items"]) > 0
    item = d["items"][0]
    for k in ["cve", "vendor", "product", "name"]:
        assert k in item
