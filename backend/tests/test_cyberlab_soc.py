"""Tests for enterprise SOC additions: new decoder plugins, CEF/LEEF parsers,
extended AI query generation (Splunk SPL, Sentinel KQL, Cisco XDR)."""
import os
import pytest
import httpx


BASE = os.environ.get("CYBERLAB_TEST_BASE", "http://localhost:8001")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE, timeout=45.0) as c:
        yield c


def test_new_decoder_plugins_registered(client):
    plugins = client.get("/api/cyberlab/plugins").json()
    ids = {p["id"] for p in plugins}
    for pid in ("json-pretty", "json-minify", "xml-pretty", "cmd-deobfuscate", "js-deobfuscate"):
        assert pid in ids, f"missing plugin: {pid}"


def test_json_pretty(client):
    r = client.post("/api/cyberlab/run", json={
        "input": '{"a":1,"b":[1,2,3]}',
        "recipe": [{"id": "json-pretty", "params": {"indent": 2}}],
    })
    assert r.status_code == 200
    out = r.json()["output"]
    assert '"a": 1' in out
    assert "\n" in out


def test_cmd_deobfuscate(client):
    r = client.post("/api/cyberlab/run", json={
        "input": 'c^md.exe /c "^w^h^oami"',
        "recipe": [{"id": "cmd-deobfuscate", "params": {}}],
    })
    assert r.json()["output"] == "cmd.exe /c whoami"


def test_js_deobfuscate_fromcharcode(client):
    r = client.post("/api/cyberlab/run", json={
        "input": "var x = 'ab' + 'cd' + String.fromCharCode(65,66,67);",
        "recipe": [{"id": "js-deobfuscate", "params": {}}],
    })
    out = r.json()["output"]
    assert "abcd" in out
    assert "ABC" in out


def test_cef_parser(client):
    cef = ("<134>Aug 15 10:00:00 host01 CEF:0|Microsoft|Windows|10|4688|"
           "A new process|8|src=10.0.5.20 dst=185.220.101.42 spt=54321 dpt=443 "
           "proto=tcp suser=bob fname=C:\\Windows\\powershell.exe "
           "requestUrl=https://evil.tld/beacon "
           "fileHash=deadbeef11223344556677889900112233445566778899aabbccddeeff00112233")
    r = client.post("/api/cyberlab/process-tree", json={"input": cef, "format": "cef"})
    assert r.status_code == 200
    d = r.json()
    assert d["format"] == "cef"
    ev = d["forensic_events"][0]
    assert ev["src_ip"] == "10.0.5.20"
    assert ev["dst_ip"] == "185.220.101.42"
    assert ev["dst_port"] == "443"
    assert ev["protocol"] == "tcp"
    assert ev["url"].startswith("https://evil.tld")


def test_leef_parser(client):
    leef = ("<134>Aug 15 10:00:00 host01 LEEF:2.0|IBM|QRadar|1.0|20050|^|"
            "src=10.0.5.20^dst=185.220.101.42^srcPort=54321^dstPort=443^proto=tcp^usrName=bob")
    r = client.post("/api/cyberlab/process-tree", json={"input": leef, "format": "leef"})
    assert r.status_code == 200
    d = r.json()
    assert d["format"] == "leef"
    ev = d["forensic_events"][0]
    assert ev["src_ip"] == "10.0.5.20"
    assert ev["dst_ip"] == "185.220.101.42"
    assert ev["user"] == "bob"


@pytest.mark.slow
def test_ai_generates_all_hunt_queries(client):
    r = client.post("/api/cyberlab/ai-analysis", json={
        "input": "powershell -e xxx",
        "output": "$os = Get-CimInstance Win32_OperatingSystem",
        "analysis": {
            "verdict": "suspicious", "risk_score": 45,
            "mitre": [{"id": "T1082", "name": "System Info Discovery", "tactic": "Discovery", "evidence": []}],
            "rules": [],
            "iocs": [],
        },
    })
    assert r.status_code == 200
    d = r.json()
    # All 6 outputs must be non-empty
    assert len(d["summary"]) > 30
    assert d["sigma_rule"], "sigma_rule empty"
    assert d["yara_rule"], "yara_rule empty"
    assert d["splunk_spl"], "splunk_spl empty"
    assert d["sentinel_kql"], "sentinel_kql empty"
    assert d["cisco_xdr"], "cisco_xdr empty"
