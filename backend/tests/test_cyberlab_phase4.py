"""Integration tests for CyberLab Phase 4 endpoints.

Covers:
    * AI analysis (Claude Sonnet 4.5)
    * Share create / fetch / TTL
    * PDF & Markdown exports
    * Session-scoped custom rules
    * Admin custom rules (JWT-protected)
    * Custom rules firing during analysis

Run with:  pytest -xvs /app/backend/tests/test_cyberlab_phase4.py
"""
import io
import os
import uuid
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
def admin_token(client):
    r = client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, f"login failed: {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="function")
def session_id():
    return uuid.uuid4().hex[:12]


# ============================================================================
# Share endpoints
# ============================================================================

def test_share_create_and_fetch(client):
    payload = {
        "input": "powershell.exe -e xxx",
        "output": "Invoke-Expression",
        "trace": [{"id": "base64-decode", "name": "Base64 Decode", "category": "Encoding",
                   "output_size": 20, "duration_ms": 1.2, "input_preview": "", "output_preview": "",
                   "confidence": 0.95}],
        "analysis": {"verdict": "suspicious", "risk_score": 45, "mitre": [], "rules": [],
                     "iocs": [], "summary": "test"},
    }
    r = client.post("/api/cyberlab/share", json=payload)
    assert r.status_code == 200
    d = r.json()
    assert "share_id" in d
    assert d["expires_in_days"] == 30
    share_id = d["share_id"]

    r2 = client.get(f"/api/cyberlab/share/{share_id}")
    assert r2.status_code == 200
    got = r2.json()
    assert got["share_id"] == share_id
    assert got["payload"]["output"] == "Invoke-Expression"
    assert got["payload"]["analysis"]["verdict"] == "suspicious"


def test_share_not_found_returns_404(client):
    r = client.get("/api/cyberlab/share/nonexistent12")
    assert r.status_code == 404


# ============================================================================
# Export endpoints
# ============================================================================

def test_export_pdf_returns_pdf_bytes(client):
    payload = {
        "input": "test", "output": "decoded",
        "trace": [], "analysis": {"verdict": "clean", "risk_score": 10, "mitre": [], "rules": [], "iocs": [], "summary": "s"},
    }
    r = client.post("/api/cyberlab/export/pdf", json=payload)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
    assert len(r.content) > 1000


def test_export_markdown(client):
    payload = {
        "input": "test", "output": "decoded",
        "trace": [], "analysis": {"verdict": "malicious", "risk_score": 90,
                                   "mitre": [{"id": "T1059", "name": "Command Execution", "tactic": "Execution", "evidence": []}],
                                   "rules": [{"rule": "TestRule", "severity": "high", "description": "d", "tags": [], "matched": []}],
                                   "iocs": [{"type": "ipv4", "value": "1.2.3.4", "context": ""}],
                                   "summary": "test summary"},
    }
    r = client.post("/api/cyberlab/export/markdown", json=payload)
    assert r.status_code == 200
    md = r.text
    assert "# NivX CyberLab Analysis Report" in md
    assert "**MALICIOUS**" in md
    assert "T1059" in md
    assert "TestRule" in md
    assert "1.2.3.4" in md


# ============================================================================
# Session-scoped custom rules
# ============================================================================

def test_session_rule_add_and_fire(client, session_id):
    rule = {
        "name": "TestSessionRule",
        "severity": "high",
        "description": "test",
        "tags": ["test"],
        "strings": [{"type": "string", "pattern": "SUPER_SECRET_TOKEN"}],
    }
    r = client.post(f"/api/cyberlab/session-rules?session_id={session_id}", json=rule)
    assert r.status_code == 200
    rule_id = r.json()["id"]

    # Should fire when session_id is passed
    r2 = client.post(f"/api/cyberlab/analyze?session_id={session_id}",
                     json={"input": "log contains SUPER_SECRET_TOKEN in the payload",
                           "auto_decode": False})
    assert r2.status_code == 200
    rule_names = {rr["rule"] for rr in r2.json()["rules"]}
    assert "TestSessionRule" in rule_names

    # Should NOT fire without session_id (or with a different one)
    other_sid = uuid.uuid4().hex[:12]
    r3 = client.post(f"/api/cyberlab/analyze?session_id={other_sid}",
                     json={"input": "log contains SUPER_SECRET_TOKEN in the payload",
                           "auto_decode": False})
    assert r3.status_code == 200
    rule_names_other = {rr["rule"] for rr in r3.json()["rules"]}
    assert "TestSessionRule" not in rule_names_other

    # Delete
    r4 = client.delete(f"/api/cyberlab/session-rules/{rule_id}?session_id={session_id}")
    assert r4.status_code == 200
    assert r4.json()["deleted"] is True


def test_session_rule_bad_payload_rejected(client, session_id):
    r = client.post(f"/api/cyberlab/session-rules?session_id={session_id}",
                    json={"name": "", "strings": []})
    assert r.status_code == 400


# ============================================================================
# Admin custom rules (JWT-protected)
# ============================================================================

def test_admin_rules_require_auth(client):
    r = client.get("/api/admin/cyberlab/rules")
    assert r.status_code == 401


def test_admin_rule_lifecycle_and_fire(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}

    # List (may already contain some)
    r0 = client.get("/api/admin/cyberlab/rules", headers=headers)
    assert r0.status_code == 200
    baseline = len(r0.json()["rules"])

    # Add
    rule = {
        "name": "AdminTestRule",
        "severity": "critical",
        "description": "admin lifecycle test",
        "tags": ["ci"],
        "strings": [{"type": "regex", "pattern": "ADMIN_TEST_PATTERN_[0-9]+"}],
    }
    r1 = client.post("/api/admin/cyberlab/rules", headers=headers, json=rule)
    assert r1.status_code == 200
    rule_id = r1.json()["id"]

    # Now list contains it
    r2 = client.get("/api/admin/cyberlab/rules", headers=headers)
    assert len(r2.json()["rules"]) == baseline + 1

    # It should fire on ANY analysis (no session_id needed) because admin scope
    # is global.
    r3 = client.post("/api/cyberlab/analyze",
                     json={"input": "found ADMIN_TEST_PATTERN_42 in the log",
                           "auto_decode": False})
    assert r3.status_code == 200
    names = {rr["rule"] for rr in r3.json()["rules"]}
    assert "AdminTestRule" in names

    # Delete
    r4 = client.delete(f"/api/admin/cyberlab/rules/{rule_id}", headers=headers)
    assert r4.status_code == 200


def test_rules_endpoint_returns_all_scopes(client, session_id):
    r = client.get(f"/api/cyberlab/rules?session_id={session_id}")
    assert r.status_code == 200
    d = r.json()
    assert "builtin" in d
    assert "admin" in d
    assert "session" in d
    assert len(d["builtin"]) >= 10


# ============================================================================
# AI Analysis (Claude Sonnet 4.5) — smoke test (real LLM call)
# ============================================================================

@pytest.mark.slow
def test_ai_analysis_returns_summary_sigma_yara(client):
    r = client.post("/api/cyberlab/ai-analysis", json={
        "input": "powershell -e xxx",
        "output": "$os = Get-CimInstance Win32_OperatingSystem\nInvoke-WebRequest https://1.2.3.4/x",
        "analysis": {
            "verdict": "suspicious",
            "risk_score": 45,
            "mitre": [{"id": "T1082", "name": "System Info Discovery", "tactic": "Discovery", "evidence": []}],
            "rules": [{"rule": "PowerShell_Downloader", "severity": "high", "tags": []}],
            "iocs": [{"type": "url", "value": "https://1.2.3.4/x"}],
        },
    })
    assert r.status_code == 200
    d = r.json()
    assert len(d["summary"]) > 50, "summary too short"
    # sigma_rule / yara_rule may be empty if the model returned free-form,
    # but for our prompt they should always be populated.
    assert "title:" in d["sigma_rule"] or "logsource" in d["sigma_rule"]
    assert "rule " in d["yara_rule"].lower()
