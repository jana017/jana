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
    # up to 50 items
    assert len(d["items"]) <= 50
    item = d["items"][0]
    for k in ["cve", "vendor", "product", "name", "nvd_url"]:
        assert k in item
    assert item["nvd_url"].startswith("https://nvd.nist.gov/vuln/detail/CVE-")


# ------- attack feed (ransomware.live) -------
def test_attack_feed(s):
    r = s.get(f"{API}/attack-feed", timeout=30)
    # ransomware.live may occasionally 502; treat as non-blocking
    if r.status_code == 502:
        pytest.skip("attack-feed upstream unavailable (502)")
    assert r.status_code == 200, r.text
    d = r.json()
    for k in ["source", "count", "items"]:
        assert k in d
    assert isinstance(d["items"], list)
    if d["items"]:
        it = d["items"][0]
        for k in ["victim", "group", "country", "sector", "screenshot", "url"]:
            assert k in it


# ------- threats now returns >= 7 with new fields -------
def test_threats_has_seven_with_image(s):
    r = s.get(f"{API}/threats", timeout=10)
    assert r.status_code == 200
    items = r.json()
    assert len(items) >= 7, f"expected >=7 seeded threats, got {len(items)}"
    # every item has attack_chain, process_tree; image_url should be present on seeded
    seeded = [i for i in items if i.get("source") == "NivX Threat Intel"]
    assert len(seeded) >= 7
    for i in seeded[:7]:
        assert i.get("attack_chain")
        assert i.get("process_tree")
        assert i.get("image_url", "").startswith("http")


# ------- intel-feed (Unit42) -------
def test_intel_feed(s):
    r = s.get(f"{API}/intel-feed", timeout=45)
    if r.status_code == 502:
        pytest.skip("Unit42 upstream unavailable (502)")
    assert r.status_code == 200, r.text
    d = r.json()
    for k in ["source", "repo_url", "count", "items"]:
        assert k in d
    assert "Unit42" in d["source"]
    assert isinstance(d["items"], list)
    assert d["count"] == len(d["items"])
    assert len(d["items"]) >= 1
    it = d["items"][0]
    for k in ["title", "date", "summary", "url", "ioc_count", "image", "source", "name"]:
        assert k in it
    assert it["name"].endswith(".txt")
    assert it["source"] == "Palo Alto Unit42"
    assert it["url"].startswith("https://github.com/")
    assert isinstance(it["ioc_count"], int)
    # date YYYY-MM-DD
    import re
    assert re.match(r"^\d{4}-\d{2}-\d{2}$", it["date"]) or it["date"] == ""


# ------- leads -------
def test_leads_get_requires_auth(s):
    r = s.get(f"{API}/leads", timeout=10)
    assert r.status_code == 401


def test_lead_create_public_and_list(s, auth_headers):
    payload = {
        "name": "TEST_Lead User",
        "email": "TEST_lead@example.com",
        "company": "TEST Co",
        "interest": "MDR",
    }
    r = s.post(f"{API}/leads", json=payload, timeout=10)
    assert r.status_code == 200, r.text
    lead = r.json()
    assert lead.get("id")
    assert lead["status"] == "new"
    assert lead["email"] == payload["email"]

    # list via admin token includes it
    r2 = s.get(f"{API}/leads", headers=auth_headers, timeout=10)
    assert r2.status_code == 200
    leads = r2.json()
    assert any(l["id"] == lead["id"] for l in leads)


# ------- intel-report (Unit42 full reader) -------
def test_intel_report_invalid_name(s):
    r = s.get(f"{API}/intel-report/../etc", timeout=15)
    assert r.status_code in (400, 404)

def test_intel_report_valid(s):
    feed = s.get(f"{API}/intel-feed", timeout=45)
    if feed.status_code == 502:
        pytest.skip("Unit42 upstream unavailable")
    items = feed.json().get("items", [])
    assert items, "no intel items"
    name = items[0]["name"]
    r = s.get(f"{API}/intel-report/{name}", timeout=30)
    if r.status_code == 502:
        pytest.skip("intel-report upstream unavailable")
    assert r.status_code == 200, r.text
    d = r.json()
    for k in ["title", "date", "authors", "notes", "references", "indicators", "ioc_count", "url"]:
        assert k in d
    assert isinstance(d["notes"], list)
    assert isinstance(d["references"], list)
    assert isinstance(d["indicators"], list)


# ---------- P2 Round: new features ----------

# intel-feed pagination + filters
def test_intel_feed_pagination(s):
    r = s.get(f"{API}/intel-feed?page=1&page_size=9", timeout=60)
    if r.status_code == 502:
        pytest.skip("Unit42 upstream unavailable")
    assert r.status_code == 200
    d = r.json()
    for k in ["total", "page", "page_size", "has_more", "types", "items"]:
        assert k in d
    assert d["page"] == 1
    assert d["page_size"] == 9
    assert d["total"] >= 100  # ~395
    assert isinstance(d["types"], list) and len(d["types"]) >= 8
    assert len(d["items"]) <= 9
    for it in d["items"]:
        assert "type" in it
    # page 2 differs
    r2 = s.get(f"{API}/intel-feed?page=2&page_size=9", timeout=60)
    assert r2.status_code == 200
    items2 = r2.json()["items"]
    names1 = {i["name"] for i in d["items"]}
    names2 = {i["name"] for i in items2}
    assert names1 != names2


def test_intel_feed_type_filter(s):
    r = s.get(f"{API}/intel-feed?page=1&page_size=9&type=Ransomware", timeout=60)
    if r.status_code == 502:
        pytest.skip("Unit42 upstream unavailable")
    assert r.status_code == 200
    d = r.json()
    for it in d["items"]:
        assert it["type"] == "Ransomware"


def test_intel_feed_since_and_q(s):
    r = s.get(f"{API}/intel-feed?page=1&page_size=9&since=2024-01-01", timeout=60)
    if r.status_code == 502:
        pytest.skip("Unit42 upstream unavailable")
    assert r.status_code == 200
    for it in r.json()["items"]:
        assert it["date"] >= "2024-01-01"
    r2 = s.get(f"{API}/intel-feed?page=1&page_size=9&q=ransom", timeout=60)
    assert r2.status_code == 200
    for it in r2.json()["items"]:
        assert "ransom" in it["title"].lower()


# threats all have process_tree
def test_all_threats_have_process_tree(s):
    r = s.get(f"{API}/threats", timeout=10)
    assert r.status_code == 200
    items = r.json()
    seeded = [i for i in items if i.get("source") == "NivX Threat Intel"]
    assert len(seeded) >= 7
    for i in seeded:
        pt = i.get("process_tree")
        assert pt is not None and isinstance(pt, dict) and pt.get("name")


# leads PATCH auth + validation
def test_leads_patch_requires_auth(s):
    r = s.patch(f"{API}/leads/does-not-matter", json={"status": "qualified"}, timeout=10)
    assert r.status_code == 401


def test_leads_patch_invalid_status(s, auth_headers):
    # need a real lead first
    payload = {"name": "TEST_Patch", "email": "TEST_patch@example.com", "company": "TEST", "interest": "MDR"}
    cr = s.post(f"{API}/leads", json=payload, timeout=10)
    if cr.status_code == 429:
        pytest.skip("rate-limited")
    assert cr.status_code == 200
    lid = cr.json()["id"]
    r = s.patch(f"{API}/leads/{lid}", json={"status": "bogus"}, headers=auth_headers, timeout=10)
    assert r.status_code == 400


def test_leads_patch_valid_status(s, auth_headers):
    payload = {"name": "TEST_PatchOk", "email": "TEST_patchok@example.com", "company": "TEST", "interest": "MDR"}
    cr = s.post(f"{API}/leads", json=payload, timeout=10)
    if cr.status_code == 429:
        pytest.skip("rate-limited")
    lid = cr.json()["id"]
    r = s.patch(f"{API}/leads/{lid}", json={"status": "qualified"}, headers=auth_headers, timeout=10)
    assert r.status_code == 200
    assert r.json()["status"] == "qualified"
    # verify persisted
    r2 = s.get(f"{API}/leads", headers=auth_headers, timeout=10)
    match = [l for l in r2.json() if l["id"] == lid]
    assert match and match[0]["status"] == "qualified"


# honeypot: submitting with 'website' should not persist
def test_lead_honeypot(s, auth_headers):
    payload = {
        "name": "TEST_Bot", "email": "TEST_bot@spam.example.com", "company": "SpamCo",
        "interest": "n/a", "website": "http://spam.example.com"
    }
    r = s.post(f"{API}/leads", json=payload, timeout=10)
    if r.status_code == 429:
        pytest.skip("rate-limited")
    assert r.status_code == 200
    # response is dummy honeypot@blocked.local; verify no real lead created
    all_leads = s.get(f"{API}/leads", headers=auth_headers, timeout=10).json()
    assert not any(l["email"] == payload["email"] for l in all_leads)
