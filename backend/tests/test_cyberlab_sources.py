"""Tests for P2/P3 additions: CrowdStrike Falcon + Zeek + tshark ingestion, and OG image endpoint."""
import os
import json
import pytest
import httpx


BASE = os.environ.get("CYBERLAB_TEST_BASE", "http://localhost:8001")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE, timeout=15.0) as c:
        yield c


def test_crowdstrike_falcon_json(client):
    falcon = [
        {"event_simpleName": "ProcessRollup2", "@timestamp": "2024-08-15T10:00:00Z",
         "aid": "abc", "ImageFileName": "\\Device\\HarddiskVolume4\\Windows\\System32\\powershell.exe",
         "CommandLine": "powershell -EncodedCommand JABv",
         "TargetProcessId_decimal": "2001", "ParentProcessId_decimal": "100",
         "ParentImageFileName": "explorer.exe",
         "SHA256HashData": "deadbeef11223344556677889900112233445566778899aabbccddeeff00112233"},
        {"event_simpleName": "NetworkConnectIP4", "@timestamp": "2024-08-15T10:00:03Z",
         "aid": "abc", "ContextProcessId_decimal": "2001",
         "LocalAddressIP4": "10.0.5.20", "LocalPort": "54321",
         "RemoteAddressIP4": "185.220.101.42", "RemotePort": "443",
         "ConnectionProtocol": "TCP"},
        {"event_simpleName": "DnsRequest", "@timestamp": "2024-08-15T10:00:02Z",
         "aid": "abc", "ContextProcessId_decimal": "2001",
         "DomainName": "evil-c2.attacker.xyz"},
    ]
    r = client.post("/api/cyberlab/process-tree", json={"input": json.dumps(falcon)})
    assert r.status_code == 200
    d = r.json()
    actions = d["stats"]["by_action"]
    assert actions.get("process_create", 0) == 1
    assert actions.get("network_connect", 0) == 1
    assert actions.get("dns_query", 0) == 1
    net = next(e for e in d["forensic_events"] if e["action"] == "network_connect")
    assert net["dst_ip"] == "185.220.101.42"
    assert net["dst_port"] == "443"
    assert net["src_ip"] == "10.0.5.20"
    dns = next(e for e in d["forensic_events"] if e["action"] == "dns_query")
    assert dns["domain"] == "evil-c2.attacker.xyz"


def test_zeek_conn_log(client):
    zeek = ("#separator \\x09\n"
            "#set_separator\t,\n"
            "#path\tconn\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\n"
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\n"
            "1723716000.123\tCabc\t10.0.5.20\t54321\t185.220.101.42\t443\ttcp\tssl\n"
            "1723716001.456\tCdef\t10.0.5.20\t60111\t1.2.3.4\t80\ttcp\thttp\n")
    r = client.post("/api/cyberlab/process-tree", json={"input": zeek})
    assert r.status_code == 200
    d = r.json()
    assert d["format"] == "zeek"
    assert d["stats"]["event_count"] == 2
    events = d["forensic_events"]
    assert all(e["action"] == "network_connect" for e in events)
    ips = {e["dst_ip"] for e in events}
    assert "185.220.101.42" in ips
    assert "1.2.3.4" in ips


def test_og_image_endpoint(client):
    payload = {
        "input": "test", "output": "decoded",
        "trace": [],
        "analysis": {
            "verdict": "malicious", "risk_score": 85,
            "mitre": [{"id": "T1486", "name": "Data Encrypted", "tactic": "Impact", "evidence": []},
                      {"id": "T1490", "name": "Inhibit Recovery", "tactic": "Impact", "evidence": []}],
            "rules": [{"rule": "Ransomware_Note_Keywords", "severity": "critical", "tags": [], "description": ""}],
            "iocs": [{"type": "ipv4", "value": "1.2.3.4", "context": ""}],
            "summary": "Ransomware family observed — vssadmin delete shadows detected.",
        },
    }
    r = client.post("/api/cyberlab/share", json=payload)
    assert r.status_code == 200
    share_id = r.json()["share_id"]

    r2 = client.get(f"/api/cyberlab/share/{share_id}/og.png")
    assert r2.status_code == 200
    assert r2.headers["content-type"] == "image/png"
    # PNG magic bytes
    assert r2.content.startswith(b"\x89PNG\r\n\x1a\n")
    # Reasonable size: >2KB, <200KB
    assert 2000 < len(r2.content) < 200000


def test_og_image_not_found(client):
    r = client.get("/api/cyberlab/share/nonexistent12/og.png")
    assert r.status_code == 404
