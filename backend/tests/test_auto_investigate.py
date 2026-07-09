"""Regression tests for the CyberLab Auto Investigate pipeline.

Runs a curated set of real-world malware payloads through
`POST /api/cyberlab/auto-investigate` and asserts the pipeline
delivers verdict, MITRE, and IOC extraction as expected.

AI is disabled (`include_ai=False`) to keep tests hermetic + fast.

Run with:  pytest -xvs /app/backend/tests/test_auto_investigate.py
"""
from __future__ import annotations
import os
import pytest
import httpx

from tests.samples.malware_samples import SAMPLES

BASE = os.environ.get("CYBERLAB_TEST_BASE", "http://localhost:8001")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE, timeout=30.0) as c:
        yield c


def test_detect_format_payload(client):
    r = client.post("/api/cyberlab/detect-format", json={"input": "powershell.exe -e AAAA"})
    assert r.status_code == 200
    assert r.json()["kind"] == "payload"


def test_detect_format_xml_log(client):
    r = client.post("/api/cyberlab/detect-format", json={"input": "<Events><Event/></Events>"})
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "log"
    assert body["format"] == "xml"


def test_detect_format_json_payload_not_log(client):
    # Plain JSON without sysmon markers must NOT be classified as a log.
    r = client.post("/api/cyberlab/detect-format", json={"input": '{"foo": "bar"}'})
    assert r.status_code == 200
    assert r.json()["kind"] == "payload"


@pytest.mark.parametrize("sample", SAMPLES, ids=[s["name"] for s in SAMPLES])
def test_auto_investigate_sample(client, sample):
    r = client.post(
        "/api/cyberlab/auto-investigate",
        json={"input": sample["input"], "include_ai": False},
    )
    assert r.status_code == 200, r.text
    data = r.json()

    # Structural assertions
    assert data["kind"] == sample["expected_kind"], f"kind mismatch: {data['kind']}"
    assert "stages" in data and len(data["stages"]) >= 2
    stage_names = [s["name"] for s in data["stages"]]
    assert stage_names[0] == "detect"
    if sample["expected_kind"] == "payload":
        assert "auto-decode" in stage_names
    else:
        assert "parse-log" in stage_names
    assert "analyze" in stage_names
    # AI stage MUST be absent when include_ai=False
    assert "ai" not in stage_names

    analysis = data["analysis"]
    ioc_types = {i["type"] for i in analysis["iocs"]}
    mitre_ids = {m["id"] for m in analysis["mitre"]}

    # Behavioural assertions
    for tid in sample["expected_mitre"]:
        assert tid in mitre_ids, f"{sample['name']}: missing MITRE {tid} (got {sorted(mitre_ids)})"
    for kind in sample["expected_iocs"]:
        assert kind in ioc_types, f"{sample['name']}: missing IOC type {kind} (got {sorted(ioc_types)})"
    assert analysis["risk_score"] >= sample["min_risk"], (
        f"{sample['name']}: risk {analysis['risk_score']} below floor {sample['min_risk']}"
    )
    if sample["expected_verdict"] == "not_clean":
        assert analysis["verdict"] in ("suspicious", "malicious"), (
            f"{sample['name']}: verdict={analysis['verdict']}"
        )


def test_auto_investigate_rejects_empty(client):
    r = client.post("/api/cyberlab/auto-investigate", json={"input": "   "})
    assert r.status_code == 400
