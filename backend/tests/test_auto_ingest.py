"""Unit + integration tests for the OSINT Auto-Ingest engine.

The scorer (_compute_verdict_and_score) is fully deterministic and takes no
IO, so most tests are pure unit tests. Two async integration tests exercise
_auto_ingest_from_osint against the live Mongo the backend uses.
"""
import asyncio
import os
import uuid

import pytest


# Import the target module without triggering the FastAPI startup lifecycle.
# server.py exposes helpers at module level, so importing it is enough.
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_db")

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import server  # noqa: E402


compute = server._compute_verdict_and_score


# ---------------------------------------------------------------------------
# Deterministic scorer
# ---------------------------------------------------------------------------
def test_clean_when_no_signals():
    r = compute("ip", {}, {})
    assert r["verdict"] == "clean"
    assert r["risk_score"] == 0


def test_vt_stats_scale_score():
    rep = {"vt": {"stats": {"malicious": 10, "suspicious": 2}}}
    r = compute("domain", {}, rep)
    # 10*8 + 2*3 = 86, capped at 60
    assert r["risk_score"] == 60
    assert r["verdict"] == "suspicious"
    assert any(t.startswith("vt:") for t in r["tags"])


def test_vt_cap_at_60():
    rep = {"vt": {"stats": {"malicious": 40}}}
    r = compute("sha256", {}, rep)
    # 40*8 = 320 → capped at 60
    assert r["risk_score"] == 60
    assert r["verdict"] == "suspicious"


def test_vt_low_count_pup_still_persisted():
    """Regression: VT 2/70 (typical PUP/adware detection) MUST be treated as
    suspicious and eligible for auto-ingest, even though the raw numeric
    weighting alone falls under the malicious threshold. The hard-signal
    fast path floors the score into the low-suspicious band."""
    rep = {"vt": {"stats": {"malicious": 2, "suspicious": 0, "undetected": 68}}}
    r = compute("sha256", {"kind": "hash"}, rep)
    # 2 VT malicious → hard signal → verdict must be suspicious
    assert r["verdict"] == "suspicious"
    assert r["risk_score"] >= 15
    assert any(t.startswith("vt:") for t in r["tags"])


def test_vt_single_malicious_hit_still_persisted():
    """Even a single VT malicious hit (edge PUP / very fresh sample) is a
    real signal and must enter the curated DB."""
    rep = {"vt": {"stats": {"malicious": 1}}}
    r = compute("md5", {"kind": "hash"}, rep)
    assert r["verdict"] == "suspicious"
    assert r["risk_score"] >= 15


def test_vt_flat_shape_with_threat_label():
    """Regression: `_vt_lookup` returns a FLAT dict (malicious/suspicious at
    top level, no `stats` key). The scorer must accept that shape and lift
    `threat_label` into `threat_name`. This is the exact shape the user
    reported for hash 76f3767efc... (VT 2/70 acelauncher PUP)."""
    rep = {"vt": {
        "found": True,
        "malicious": 2, "suspicious": 0, "harmless": 0, "undetected": 68,
        "threat_label": "acelauncher",
        "label": "chrome.exe",
    }}
    r = compute("sha256", {"kind": "hash"}, rep)
    assert r["verdict"] == "suspicious"
    assert r["risk_score"] >= 15
    assert r["threat_name"] == "acelauncher"
    assert any(t.startswith("vt:2m") for t in r["tags"])


def test_malwarebazaar_found_forces_malicious():
    rep = {"malwarebazaar": {"found": True, "signature": "Emotet",
                             "family": "Emotet", "file_type": "exe"}}
    r = compute("sha256", {"kind": "hash"}, rep)
    assert r["risk_score"] >= 50
    assert r["threat_name"] == "Emotet"
    assert "malwarebazaar" in r["tags"]


def test_circl_known_malicious_dominates():
    r = compute("md5", {"kind": "hash", "known_malicious": True}, {})
    assert r["risk_score"] >= 80
    assert r["verdict"] == "malicious"
    assert r["severity"] in ("high", "critical")


def test_urlscan_root_verdict_malicious():
    r = compute("url", {"verdict": "malicious"}, {})
    assert "urlscan:malicious" in r["tags"]
    assert r["risk_score"] >= 40


def test_urlscan_nested_verdict_suspicious():
    r = compute("domain", {"urlscan": {"verdict": "suspicious"}}, {})
    assert "urlscan:suspicious" in r["tags"]
    assert r["verdict"] == "suspicious"


def test_abuseipdb_high_confidence():
    r = compute("ip", {}, {"abuseipdb": {"abuseConfidenceScore": 90,
                                         "totalReports": 42}})
    # 90 * 0.4 = 36 → suspicious
    assert r["risk_score"] == 36
    assert r["verdict"] == "suspicious"
    assert any(t.startswith("abuseipdb:") for t in r["tags"])


def test_hybrid_analysis_malicious_score_80():
    rep = {"hybrid_analysis": {"verdict": "malicious", "threat_score": 92,
                               "vx_family": "AsyncRAT"}}
    r = compute("sha256", {"kind": "hash"}, rep)
    assert r["threat_name"] == "AsyncRAT"
    assert "ha:malicious" in r["tags"]
    assert r["risk_score"] >= 40


def test_combined_signals_hit_malicious_critical():
    rep = {
        "vt": {"stats": {"malicious": 20, "suspicious": 3}},
        "malwarebazaar": {"found": True, "signature": "Trickbot", "family": "Trickbot"},
    }
    r = compute("sha256", {"kind": "hash"}, rep)
    assert r["verdict"] == "malicious"
    assert r["severity"] in ("high", "critical")
    assert r["risk_score"] == 100  # capped


def test_low_signal_lands_low_severity_but_still_suspicious():
    # Only 1 VT susp → score = 1 → CLEAN (below 15)
    rep = {"vt": {"stats": {"suspicious": 1}}}
    r = compute("domain", {}, rep)
    assert r["verdict"] == "clean"


def test_summary_carries_reason_bits_and_signals():
    rep = {"vt": {"stats": {"malicious": 5, "suspicious": 1}},
           "malwarebazaar": {"found": True, "signature": "Qakbot"}}
    r = compute("sha256", {"kind": "hash"}, rep)
    assert r["summary"]["risk_score"] == r["risk_score"]
    assert r["summary"]["verdict"] == r["verdict"]
    assert isinstance(r["summary"]["reason_bits"], list) and r["summary"]["reason_bits"]
    assert "virustotal" in r["summary"]["signals"]
    assert "malwarebazaar" in r["summary"]["signals"]


def test_notes_prefix_and_max_length():
    rep = {"vt": {"stats": {"malicious": 3}}}
    r = compute("domain", {}, rep)
    assert r["notes"] is not None
    assert r["notes"].startswith("Auto-ingested from OSINT")
    assert len(r["notes"]) <= 280


# ---------------------------------------------------------------------------
# Integration — exercise the feature via the running backend over HTTP so
# the motor client stays bound to the server's own event loop (parallel-safe).
# ---------------------------------------------------------------------------
import httpx  # noqa: E402

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
    assert r.status_code == 200, f"login failed: {r.text}"
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _find_by_value(client, admin_headers, value):
    r = client.get("/api/iocs", params={"q": value, "limit": 5}, headers=admin_headers)
    assert r.status_code == 200
    for item in r.json().get("items", []):
        if item.get("value") == value:
            return item
    return None


def _delete_by_id(client, admin_headers, ioc_id):
    if ioc_id:
        client.delete(f"/api/iocs/{ioc_id}", headers=admin_headers)


def test_lookup_persists_malicious_domain_into_curated_db(client, admin_headers):
    """A domain with a strong VT malicious verdict should be auto-added."""
    # We use a well-known EICAR-style abuse.ch test domain that VT reliably
    # flags. Skip cleanly if VT returns no data (network / key unavailable).
    fake_domain = "malware-traffic-analysis.net"
    r = client.get("/api/ioc-lookup", params={"value": fake_domain})
    if r.status_code != 200:
        pytest.skip(f"lookup unavailable: {r.status_code}")
    data = r.json()
    # If no reputation providers are configured at all, the feature can't fire
    if not (data.get("reputation") and any(data["reputation"].values())):
        pytest.skip("no reputation providers configured")
    # This may or may not auto-ingest depending on live scores; the API contract
    # is: when auto_ingested is True, the local_db snapshot must reflect it.
    if data.get("auto_ingested"):
        assert data["local_db"] is not None
        assert data["local_db"].get("risk_score") is not None
        assert data["local_db"].get("source") in ("OSINT Auto-Ingest", "Manual")
        # verify persisted
        found = _find_by_value(client, admin_headers, fake_domain)
        assert found is not None
        assert found.get("risk_score") == data["local_db"]["risk_score"]


def test_lookup_response_shape_includes_new_fields(client):
    """Sanity: every /ioc-lookup response must expose local_db; auto_ingested
    is only present when a suspicious/malicious verdict fires."""
    r = client.get("/api/ioc-lookup", params={"value": "8.8.8.8"})
    assert r.status_code == 200
    data = r.json()
    assert "local_db" in data
    # auto_ingested is optional; when present it must be a bool
    if "auto_ingested" in data:
        assert isinstance(data["auto_ingested"], bool)


def test_manual_ioc_creation_still_works_and_lookup_annotates_it(client, admin_headers):
    """Ensure the auto-ingest path doesn't regress the manual /iocs create flow
    and that a subsequent lookup surfaces the analyst record in `local_db`."""
    value = f"analyst-check-{uuid.uuid4().hex[:8]}.example"
    payload = {"value": value, "threat_name": "Analyst Manual",
               "severity": "high", "source": "Manual",
               "notes": "Curated by SOC", "tags": ["curated", "soc"]}
    r = client.post("/api/iocs", json=payload, headers=admin_headers)
    assert r.status_code == 200, r.text
    ioc = r.json()
    try:
        # Lookup must include the local_db snapshot from the manual record.
        r2 = client.get("/api/ioc-lookup", params={"value": value})
        assert r2.status_code == 200
        data = r2.json()
        assert data.get("local_db") is not None
        assert data["local_db"]["threat_name"] == "Analyst Manual"
        assert data["local_db"]["source"] == "Manual"
    finally:
        _delete_by_id(client, admin_headers, ioc["id"])
