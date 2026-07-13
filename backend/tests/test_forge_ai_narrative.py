"""Tests for the new AI-narrative mode on /api/forge/investigation-report.

Covers:
 - ai_mode=true + gemini-3-flash-preview → engine=ai, ai_model set, Recommendations block present
 - ai_mode=true + gemini-3.5-flash → engine=ai, ai_model set correctly
 - ai_mode=false / unset → engine=deterministic, ai_model=null (regression)
 - ai_mode=true + unknown model_id → falls back to gemini-3-flash-preview, no 400
 - AI narrative honors evidence-only rule (contains real facts, must not include invented family names)
 - Regression on sibling endpoints
"""
import os
import time
import requests
import pytest

def _load_backend_url():
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if not v:
        try:
            with open("/app/frontend/.env") as f:
                for line in f:
                    if line.startswith("REACT_APP_BACKEND_URL="):
                        v = line.split("=", 1)[1].strip()
                        break
        except Exception:
            pass
    if not v:
        raise RuntimeError("REACT_APP_BACKEND_URL not configured")
    return v.rstrip("/")

BASE_URL = _load_backend_url()
API = f"{BASE_URL}/api"

# A short log that has real, extractable facts to compare against the AI output.
SHORT_LOG = (
    "2025-01-15T10:22:11Z host=srv-fin-07 user=jdoe action=BLOCKED "
    "src=10.0.4.11 dst_domain=malicious-example.com file=invoice.exe "
    "sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
    "engine=Umbrella verdict=malware\n"
)

TIMEOUT_AI = 90  # AI can take 5-10s but be generous


@pytest.fixture(scope="module")
def s():
    return requests.Session()


# ---------- AI mode tests ----------

def _post_forge(sess, **kwargs):
    body = {
        "instructions": kwargs.pop("instructions", "Write in 2 short paragraphs."),
        "data": kwargs.pop("data", SHORT_LOG),
        "enrich": kwargs.pop("enrich", False),
        "max_iocs": kwargs.pop("max_iocs", 5),
    }
    body.update(kwargs)
    return sess.post(f"{API}/forge/investigation-report", json=body, timeout=TIMEOUT_AI)


def test_ai_mode_gemini3_flash(s):
    r = _post_forge(s, ai_mode=True, ai_model="gemini-3-flash-preview")
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["engine"] == "ai"
    assert j["ai_model"] == "gemini-3-flash-preview"
    assert "Recommendations:" in j["report"]
    # narrative should come BEFORE the Recommendations block
    body, _, recs = j["report"].partition("Recommendations:")
    assert len(body.strip()) > 40, "Narrative body too short"
    assert recs.strip().startswith("-"), "Recommendations must be a bullet list"


def test_ai_mode_gemini35_flash(s):
    r = _post_forge(s, ai_mode=True, ai_model="gemini-3.5-flash")
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["engine"] == "ai"
    assert j["ai_model"] == "gemini-3.5-flash"
    assert "Recommendations:" in j["report"]


def test_ai_mode_unknown_model_falls_back(s):
    r = _post_forge(s, ai_mode=True, ai_model="totally-fake-model-xyz")
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["engine"] == "ai"
    # ai_model on response echoes what user asked for (server used fallback internally)
    # Either way the request must not 400.
    assert j["ai_model"] in ("totally-fake-model-xyz", "gemini-3-flash-preview")
    assert "Recommendations:" in j["report"]


def test_ai_narrative_contains_real_facts_no_fabrication(s):
    r = _post_forge(s, ai_mode=True, ai_model="gemini-3-flash-preview",
                    instructions="Write with all details.")
    assert r.status_code == 200
    body = r.json()["report"].split("Recommendations:")[0].lower()
    # Must reference at least one real fact from the log
    has_fact = any(f in body for f in ["jdoe", "srv-fin-07", "malicious-example.com",
                                        "invoice.exe", "umbrella"])
    assert has_fact, f"AI narrative missing all real facts. Body: {body[:400]}"
    # Guard against fabrication of common malware family names not present in log
    for invented in ["emotet", "trickbot", "qakbot", "lockbit", "conti", "revil"]:
        assert invented not in body, f"AI narrative fabricated family name: {invented}"


# ---------- Deterministic regression ----------

def test_deterministic_default_no_ai_field(s):
    r = _post_forge(s, ai_mode=False)
    assert r.status_code == 200
    j = r.json()
    assert j["engine"] == "deterministic"
    assert j["ai_model"] is None
    assert "Recommendations:" in j["report"]


def test_deterministic_when_ai_mode_omitted(s):
    # No ai_mode key at all
    r = s.post(f"{API}/forge/investigation-report",
               json={"instructions": "", "data": SHORT_LOG, "enrich": False, "max_iocs": 5},
               timeout=30)
    assert r.status_code == 200
    j = r.json()
    assert j["engine"] == "deterministic"
    assert j["ai_model"] is None


# ---------- Sibling endpoint regression ----------

def test_iocs_batch_summary(s):
    r = s.post(f"{API}/iocs/batch-summary",
               json={"values": ["8.8.8.8", "malicious-example.com"]}, timeout=30)
    assert r.status_code == 200


def test_ioc_lookup_batch(s):
    r = s.post(f"{API}/ioc-lookup-batch",
               json={"values": ["1.1.1.1"]}, timeout=30)
    assert r.status_code == 200


def test_cyberlab_enrich_iocs(s):
    r = s.post(f"{API}/cyberlab/enrich-iocs",
               json={"values": ["8.8.8.8"]}, timeout=30)
    assert r.status_code == 200


def test_ioc_ai_summary(s):
    r = s.post(f"{API}/ioc-ai-summary",
               json={"value": "8.8.8.8"}, timeout=45)
    # 200 when key configured, 503 when not — both acceptable
    assert r.status_code in (200, 503)
