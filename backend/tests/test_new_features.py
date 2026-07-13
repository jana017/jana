"""Tests for new features: batch-summary + forge investigation-report."""
import os
import requests
import pytest

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://threat-intel-hub-85.preview.emergentagent.com").rstrip("/")


def test_iocs_batch_summary_values():
    r = requests.post(f"{BASE_URL}/api/iocs/batch-summary",
                      json={"values": ["1.1.1.1", "example.com", "44d88612fea8a8f36de82e1278abb02f"]},
                      timeout=60)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "summary" in data and isinstance(data["summary"], str) and len(data["summary"]) > 20
    assert "stats" in data
    stats = data["stats"]
    for k in ["total", "malicious", "suspicious", "clean", "kinds"]:
        assert k in stats


def test_iocs_batch_summary_precomputed_results():
    r = requests.post(f"{BASE_URL}/api/iocs/batch-summary",
                      json={"results": [
                          {"value": "1.1.1.1", "kind": "ip", "verdict": "clean"},
                          {"value": "bad.com", "kind": "domain", "verdict": "malicious"},
                      ]},
                      timeout=30)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["stats"]["total"] == 2


def test_forge_investigation_report_no_enrich():
    payload = {
        "instructions": "Write MDR investigation report in 2 paras",
        "data": "2026-06-28 05:45:34 UTC blocked device MDT-DT-DELLAB1 queried 1.1.1.1 and hxxps://malware-domain[.]com hash 44d88612fea8a8f36de82e1278abb02f detected",
        "enrich": False,
    }
    r = requests.post(f"{BASE_URL}/api/forge/investigation-report", json=payload, timeout=60)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "report" in data
    assert data.get("paragraph_count") == 2, f"expected 2, got {data.get('paragraph_count')}"
    assert isinstance(data.get("iocs_extracted"), list) and len(data["iocs_extracted"]) >= 2


def test_forge_investigation_report_three_paragraphs():
    payload = {
        "instructions": "Draft report in three paragraphs.",
        "data": "device X queried 8.8.8.8 and evil.com hash 44d88612fea8a8f36de82e1278abb02f",
        "enrich": False,
    }
    r = requests.post(f"{BASE_URL}/api/forge/investigation-report", json=payload, timeout=60)
    assert r.status_code == 200
    assert r.json().get("paragraph_count") == 3


def test_forge_investigation_report_sentences_hint():
    payload = {
        "instructions": "give it in 5 sentences",
        "data": "attacker 9.9.9.9 attempted access to badsite.com",
        "enrich": False,
    }
    r = requests.post(f"{BASE_URL}/api/forge/investigation-report", json=payload, timeout=60)
    assert r.status_code == 200
    # Just ensure endpoint returns valid report
    assert len(r.json().get("report", "")) > 0


def test_regression_ioc_lookup_batch():
    r = requests.post(f"{BASE_URL}/api/ioc-lookup-batch",
                      json={"values": ["1.1.1.1", "example.com"]}, timeout=60)
    assert r.status_code == 200
    assert isinstance(r.json(), (list, dict))


def test_regression_cyberlab_enrich_iocs():
    r = requests.post(f"{BASE_URL}/api/cyberlab/enrich-iocs",
                      json={"values": ["1.1.1.1"], "depth": "free"}, timeout=60)
    assert r.status_code == 200


def test_regression_ioc_ai_summary():
    r = requests.post(f"{BASE_URL}/api/ioc-ai-summary",
                      json={"value": "1.1.1.1"}, timeout=60)
    # 503 acceptable if AI not configured
    assert r.status_code in (200, 201, 503)
