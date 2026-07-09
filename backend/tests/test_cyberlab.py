"""Integration tests for the CyberLab modular backend.

Run with:  pytest -xvs /app/backend/tests/test_cyberlab.py
"""
import os
import pytest
import httpx


BASE = os.environ.get("CYBERLAB_TEST_BASE", "http://localhost:8001")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE, timeout=15.0) as c:
        yield c


def test_list_plugins(client):
    r = client.get("/api/cyberlab/plugins")
    assert r.status_code == 200
    plugins = r.json()
    assert len(plugins) >= 20
    ids = {p["id"] for p in plugins}
    for essential in ("base64-decode", "hex-decode", "url-decode", "gzip-decompress",
                      "xor", "utf16le-decode", "extract-powershell-encoded", "refang"):
        assert essential in ids, f"missing plugin: {essential}"


def test_list_rules(client):
    r = client.get("/api/cyberlab/rules")
    assert r.status_code == 200
    data = r.json()
    # Phase 4: response is {builtin, admin, session}; earlier was a flat list.
    rules = data["builtin"] if isinstance(data, dict) else data
    assert len(rules) >= 10
    names = {rule["name"] for rule in rules}
    assert "Ransomware_Note_Keywords" in names
    assert "Mimikatz_Command" in names


def test_auto_decode_powershell_encoded(client):
    payload = ("powershell.exe -e JABvAHMAIAA9ACAARwBlAHQALQBDAGkAbQBJAG4AcwB0AGE"
               "AbgBjAGUAIABXAGkAbgAzADIAXwBPAHAAZQByAGEAdABpAG4AZwBTAHkAcwB0AGU"
               "AbQA=")
    r = client.post("/api/cyberlab/auto-decode", json={
        "input": payload, "max_depth": 8, "include_analysis": True,
    })
    assert r.status_code == 200
    data = r.json()
    assert "Get-CimInstance" in data["output"]
    assert "Win32_OperatingSystem" in data["output"]
    trace_ids = [t["id"] for t in data["trace"]]
    assert "extract-powershell-encoded" in trace_ids
    assert "base64-decode" in trace_ids
    assert "utf16le-decode" in trace_ids
    assert "analysis" in data
    mitre_ids = [t["id"] for t in data["analysis"]["mitre"]]
    assert "T1082" in mitre_ids  # System Info Discovery


def test_analyze_ransomware(client):
    text = ("All your files have been encrypted with AES-256!\n"
            "Contact us at hxxps://attacker[.]xyz/pay Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
            "vssadmin.exe delete shadows /all /quiet")
    r = client.post("/api/cyberlab/analyze", json={"input": text, "auto_decode": False})
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] == "malicious"
    assert data["risk_score"] >= 60
    rule_names = {rr["rule"] for rr in data["rules"]}
    assert "Ransomware_Note_Keywords" in rule_names
    assert "Shadow_Copy_Deletion" in rule_names
    # Refanged URL / BTC should surface as IOCs
    ioc_values = {i["value"] for i in data["iocs"]}
    assert any("attacker.xyz" in v for v in ioc_values)
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in ioc_values


def test_run_recipe_manual(client):
    # Simple: hex -> base64 encode chain
    r = client.post("/api/cyberlab/run", json={
        "input": "48656c6c6f",
        "recipe": [
            {"id": "hex-decode", "params": {}},
        ],
    })
    assert r.status_code == 200
    data = r.json()
    assert data["output"] == "Hello"
    assert len(data["trace"]) == 1
    assert data["trace"][0]["name"] == "Hex Decode"


def test_run_recipe_xor(client):
    # XOR "Hello" with key "K" == 0x03 0x2E 0x27 0x27 0x24
    # Actually XOR "Hello" with "K": H^K = 0x48^0x4B = 0x03
    r = client.post("/api/cyberlab/run", json={
        "input": "Hello",
        "recipe": [{"id": "xor", "params": {"key": "K"}}, {"id": "hex-encode", "params": {}}],
    })
    assert r.status_code == 200
    data = r.json()
    assert data["output"] == "032e2727 24".replace(" ", "") or data["output"].startswith("032e2727")


def test_extract_iocs_endpoint(client):
    text = ("Callback: hxxps://malicious[.]site/beacon "
            "C2 = 185[.]220[.]101[.]42 "
            "Hash: 44d88612fea8a8f36de82e1278abb02f "
            "Contact: bad@attacker.xyz "
            "CVE-2024-3400")
    r = client.post("/api/cyberlab/extract-iocs", json={"input": text})
    assert r.status_code == 200
    data = r.json()
    assert data["count"] >= 5
    types = data["by_type"]
    assert "url" in types
    assert "ipv4" in types
    assert "md5" in types
    assert "email" in types
    assert "cve" in types


def test_auto_decode_nested_base64(client):
    # "cmd.exe /c whoami" -> b64 -> b64
    import base64 as _b64
    inner = _b64.b64encode(b"cmd.exe /c whoami").decode()
    outer = _b64.b64encode(inner.encode()).decode()
    r = client.post("/api/cyberlab/auto-decode", json={
        "input": outer, "max_depth": 6, "include_analysis": False,
    })
    assert r.status_code == 200
    data = r.json()
    assert "cmd.exe" in data["output"]
    assert "whoami" in data["output"]
    assert len(data["trace"]) == 2


def test_yara_lite_mimikatz(client):
    r = client.post("/api/cyberlab/analyze", json={
        "input": "sekurlsa::logonpasswords privilege::debug",
        "auto_decode": False,
    })
    assert r.status_code == 200
    data = r.json()
    rule_names = {rr["rule"] for rr in data["rules"]}
    assert "Mimikatz_Command" in rule_names
    assert data["verdict"] == "malicious"
