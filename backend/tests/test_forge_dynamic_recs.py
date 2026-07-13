"""Tests for the dynamic (finding-driven) recommendation engine in
/api/forge/investigation-report — rule triggers A-E plus regressions.
"""
import os
import pytest
import requests

def _load_base():
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
    assert v, "REACT_APP_BACKEND_URL not set"
    return v.rstrip("/")

BASE = _load_base()
URL = f"{BASE}/api/forge/investigation-report"


def _post(instructions: str, data: str, enrich: bool = False):
    r = requests.post(URL, json={"instructions": instructions, "data": data, "enrich": enrich}, timeout=60)
    assert r.status_code == 200, r.text
    return r.json()


def _recs(js):
    return js.get("recommendations") or []


def _has(recs, needle: str) -> bool:
    n = needle.lower()
    return any(n in r.lower() for r in recs)


# --------------------------------------------------------------------------
# Rule 1 — Detection A: Umbrella BLOCKED, no OSINT enrichment.
# Must NOT contain URGENT ALLOWED, MUST contain the "No OSINT source flagged" closer.
# --------------------------------------------------------------------------
def test_detection_A_blocked_no_osint():
    txt = (
        "2026-01-14 09:00:00 UTC Cisco Umbrella BLOCKED 8 requests to "
        "adexchangerapid.com and evil-c2.example.com from user alice on LAPTOP-01."
    )
    js = _post("Summarise the incident in 3 sentences.", txt, enrich=False)
    recs = _recs(js)
    assert recs, "recommendations list is empty"
    assert not _has(recs, "urgent"), f"URGENT should not fire when nothing allowed: {recs}"
    assert not _has(recs, "allowed"), f"ALLOWED rule should not fire: {recs}"
    assert _has(recs, "no osint source flagged"), f"Expected no-OSINT closer, got: {recs}"


# --------------------------------------------------------------------------
# Rule 2 — Detection B: Umbrella ALLOWED cryptomining domain (no OSINT).
# Must contain the "Remove any unauthorized browser extensions/plugins" rule.
# --------------------------------------------------------------------------
def test_detection_B_allowed_triggers_browser_ext_rule():
    txt = (
        "Cisco Umbrella ALLOWED 5 requests to cryptomining-pool.example.net "
        "from user bob on WKS-42."
    )
    js = _post("Give me the report in 4 lines.", txt, enrich=False)
    recs = _recs(js)
    assert _has(recs, "unauthorized browser extensions"), f"Expected browser-ext rule: {recs}"


# --------------------------------------------------------------------------
# Rule 3 — Detection C: EDR quarantined hash.  Must fire the confirm-quarantine rule.
# --------------------------------------------------------------------------
def test_detection_C_quarantined_hash():
    txt = ("EDR quarantined hash 44d88612fea8a8f36de82e1278abb02f on SERVER-DB "
           "at 2026-01-14 10:15:00 UTC.")
    js = _post("Report in 2 sentences.", txt, enrich=False)
    recs = _recs(js)
    assert _has(recs, "confirm the quarantine"), f"Expected quarantine confirmation rule: {recs}"
    assert _has(recs, "sweep the wider fleet"), f"Expected fleet-sweep phrasing: {recs}"


# --------------------------------------------------------------------------
# Rule 4 — Detection D: EDR DETECTED hash, no quarantine/block.
# Must include the "DETECTED N event(s) but no automated enforcement" rule
# AND the malware-case hygiene "Run a full antivirus/EDR scan" line.
# --------------------------------------------------------------------------
def test_detection_D_detected_but_not_enforced():
    txt = ("EDR DETECTED hash abc123def4567890abc123def4567890 on LAPTOP-99 "
           "but no quarantine or block occurred.")
    js = _post("3 lines please.", txt, enrich=False)
    recs = _recs(js)
    assert _has(recs, "no automated enforcement"), f"Expected DETECTED-no-enforcement rule: {recs}"
    assert _has(recs, "run a full antivirus"), f"Expected AV/EDR-scan hygiene rule: {recs}"
    assert _has(recs, "autoruns"), f"Expected persistence-artefacts sweep: {recs}"


# --------------------------------------------------------------------------
# Rule 5 — Detection E (real OSINT): known-malicious IP + hash + ALLOWED + malware kwds.
# --------------------------------------------------------------------------
def test_detection_E_real_osint_urgent():
    txt = ("2026-01-14 11:00 UTC Umbrella ALLOWED 3 requests to 185.220.101.42 "
           "from user carol on LAPTOP-77 while EDR flagged malware trojan hash "
           "44d88612fea8a8f36de82e1278abb02f.")
    js = _post("Full report, 1 paragraph, all details.", txt, enrich=True)
    recs = _recs(js)
    assert recs, "recommendations empty"
    # Softer asserts because live OSINT can be flaky; at least ONE evidence-cited
    # rule should fire and reference the specific IOCs.
    urgent_ok = _has(recs, "urgent") and _has(recs, "185.220.101.42")
    remove_hash_ok = _has(recs, "44d88612fea8a8f36de82e1278abb02f") and _has(recs, "remove the malicious")
    abuse_ok = _has(recs, "abuseipdb reports") and _has(recs, "185.220.101.42")
    assert urgent_ok or remove_hash_ok or abuse_ok, (
        f"Expected at least one OSINT-driven evidence-cited rec citing "
        f"185.220.101.42 or hash. Got: {recs}"
    )


# --------------------------------------------------------------------------
# Cross-detection contrast: SAME case_type must produce DIFFERENT rec lists.
# --------------------------------------------------------------------------
def test_two_dns_proxy_detections_produce_different_lists():
    a = _post("2 lines.", "Umbrella BLOCKED 8 requests to adexchangerapid.com from alice.", enrich=False)
    b = _post("2 lines.", "Umbrella ALLOWED 5 requests to cryptomining-pool.example.net from bob.", enrich=False)
    assert a["case_type"] == b["case_type"] == "dns_proxy"
    assert _recs(a) != _recs(b), "Same case_type produced identical rec lists"


def test_two_malware_detections_produce_different_lists():
    c = _post("2 lines.", "EDR quarantined malware hash 44d88612fea8a8f36de82e1278abb02f on SERVER-DB.", enrich=False)
    d = _post("2 lines.", "EDR DETECTED malware hash abc123def4567890abc123def4567890 on LAPTOP-99 but no quarantine or block.", enrich=False)
    assert c["case_type"] == d["case_type"]  # both malware
    assert _recs(c) != _recs(d), "Two different malware detections produced identical rec lists"


# --------------------------------------------------------------------------
# Regression — case_type classifier still works.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("txt,expected", [
    ("EDR quarantined hash 44d88612fea8a8f36de82e1278abb02f on host X.", "malware"),
    ("Umbrella BLOCKED requests to example.com", "dns_proxy"),
    ("Umbrella ALLOWED to evil.com AND EDR flagged hash 44d88612fea8a8f36de82e1278abb02f", "mixed"),
    ("Nothing much to see here today.", "generic"),
])
def test_case_type_regression(txt, expected):
    js = _post("1 line.", txt, enrich=False)
    assert js["case_type"] == expected, f"Expected {expected}, got {js['case_type']} for: {txt}"


# --------------------------------------------------------------------------
# Regression — format engine still shapes output.
# --------------------------------------------------------------------------
def test_format_lines():
    js = _post("Give me the report in 5 lines.", "Umbrella BLOCKED requests to a.com from user u.", enrich=False)
    assert js["format"]["mode"] == "lines"
    assert js["format"]["count"] == 5


def test_format_sentences():
    js = _post("Report in 3 sentences.", "Umbrella BLOCKED requests to a.com from user u.", enrich=False)
    assert js["format"]["mode"] == "sentences"
    assert js["format"]["count"] == 3


def test_format_bullets():
    js = _post("bullet points please", "Umbrella BLOCKED requests to a.com from user u.", enrich=False)
    assert js["format"]["mode"] == "bullets"


def test_format_paragraph_verbose():
    js = _post("1 para with all details without missing anything.",
              "Umbrella BLOCKED requests to a.com from user u.", enrich=False)
    assert js["format"]["mode"] == "paragraphs"
    assert js["format"]["verbose"] is True


# --------------------------------------------------------------------------
# Regression — sibling batch endpoints still 200.
# --------------------------------------------------------------------------
def test_regression_batch_summary():
    r = requests.post(f"{BASE}/api/iocs/batch-summary",
                      json={"values": ["8.8.8.8", "example.com"]}, timeout=45)
    assert r.status_code == 200, r.text


def test_regression_ioc_lookup_batch():
    r = requests.post(f"{BASE}/api/ioc-lookup-batch",
                      json={"values": ["8.8.8.8"]}, timeout=45)
    assert r.status_code == 200, r.text


def test_regression_cyberlab_enrich_iocs():
    r = requests.post(f"{BASE}/api/cyberlab/enrich-iocs",
                      json={"values": ["8.8.8.8"]}, timeout=45)
    assert r.status_code == 200, r.text


def test_regression_ioc_ai_summary():
    r = requests.post(f"{BASE}/api/ioc-ai-summary",
                      json={"value": "8.8.8.8"}, timeout=45)
    # 200 when AI key configured, 503 when not — both valid regressions
    assert r.status_code in (200, 503), r.text
