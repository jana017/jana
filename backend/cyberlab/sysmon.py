"""Sysmon / EDR / Firewall telemetry ingestion for CyberLab.

Parses raw log dumps in three flavors:
    * XML (native Windows EventLog wevtutil export)
    * JSON (Winlogbeat / Elastic ECS, EDR alerts, or single-event dumps)
    * CSV / TSV (with header row)

Supports the following Sysmon event types (auto-tagged into `action` / `category`):

    ID  1  Process Create         → action=process_create,  category=process
    ID  3  Network Connection     → action=network_connect, category=network
    ID  5  Process Terminated     → action=process_terminate, category=process
    ID  7  Image / DLL Loaded     → action=image_load,      category=process
    ID 11  File Created           → action=file_create,     category=filesystem
    ID 12  Registry Object Created→ action=registry_create, category=registry
    ID 13  Registry Value Set     → action=registry_set,    category=registry
    ID 22  DNS Query              → action=dns_query,       category=network

Normalized forensic record schema:

    timestamp, event_id, event_type, action, category, host, user, integrity_level,
    process_guid, process_id, process_name, process_image, command_line,
    parent_process_guid, parent_process_id, parent_process_name, parent_image, parent_command_line,
    file_path, file_hash_md5, file_hash_sha1, file_hash_sha256, parent_file_hash,
    src_ip, src_port, dst_ip, dst_port, protocol,
    domain, url, dns_query, dns_answer,
    registry_key, registry_value,
    mitre_techniques, risk
"""
from __future__ import annotations
import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import mitre


# ---------------------------------------------------------------------------
# Field aliases — map source-log keys (Sysmon, ECS, custom) to canonical names
# ---------------------------------------------------------------------------
FIELD_ALIASES = {
    "processguid":       ["processguid", "process.entity_id", "process_guid", "guid"],
    "parentprocessguid": ["parentprocessguid", "process.parent.entity_id", "parent_process_guid", "parentguid"],
    "processid":         ["processid", "process.pid", "pid"],
    "parentprocessid":   ["parentprocessid", "process.parent.pid", "parent_pid", "ppid"],
    "image":             ["image", "process.executable", "process_image", "executable"],
    "parentimage":       ["parentimage", "process.parent.executable", "parent_image", "parent_executable"],
    "commandline":       ["commandline", "process.command_line", "process_command_line", "cmd", "cmdline"],
    "parentcommandline": ["parentcommandline", "process.parent.command_line", "parent_command_line"],
    "user":              ["user", "user.name", "process.user.name", "username"],
    "utctime":           ["utctime", "@timestamp", "timestamp", "eventtime", "creationutctime"],
    "hashes":            ["hashes", "hash"],
    "hashmd5":           ["md5", "process.hash.md5", "file.hash.md5"],
    "hashsha1":          ["sha1", "process.hash.sha1", "file.hash.sha1"],
    "hashsha256":        ["sha256", "process.hash.sha256", "file.hash.sha256"],
    "parenthash":        ["parenthashes", "parenthash", "parent.hash.sha256"],
    "integritylevel":    ["integritylevel", "process.integrity_level"],
    "originalfilename":  ["originalfilename", "process.pe.original_file_name"],
    "hostname":          ["computer", "hostname", "host.name", "host.hostname"],
    # Network
    "srcip":             ["sourceip", "src_ip", "source.ip", "source.address"],
    "dstip":             ["destinationip", "dest_ip", "dst_ip", "destination.ip", "destination.address"],
    "srcport":           ["sourceport", "src_port", "source.port"],
    "dstport":           ["destinationport", "dest_port", "dst_port", "destination.port"],
    "protocol":          ["protocol", "network.protocol", "network.transport"],
    # DNS
    "queryname":         ["queryname", "dns.question.name", "dns_query"],
    "queryresults":      ["queryresults", "dns.answers.data", "dns_answer"],
    # File / URL / Registry
    "targetfilename":    ["targetfilename", "file.path", "file_path", "filename"],
    "targetobject":      ["targetobject", "registry.path", "registry_key"],
    "details":           ["details", "registry.data.strings", "registry_value"],
    "url":               ["url", "url.full", "url.original"],
    "domain":            ["domain", "url.domain", "dns.question.registered_domain"],
    # Event-type indicators
    "eventid":           ["eventid", "winlog.event_id", "event.code", "event.id"],
    "eventaction":       ["eventaction", "event.action", "action"],
    "eventcategory":     ["eventcategory", "event.category"],
}


# Event ID → (action, category)
EVENT_TYPES = {
    1:  ("process_create",    "process"),
    3:  ("network_connect",   "network"),
    5:  ("process_terminate", "process"),
    7:  ("image_load",        "process"),
    11: ("file_create",       "filesystem"),
    12: ("registry_create",   "registry"),
    13: ("registry_set",      "registry"),
    14: ("registry_rename",   "registry"),
    22: ("dns_query",         "network"),
    23: ("file_delete",       "filesystem"),
}


def _norm(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


ALIAS_MAP: Dict[str, str] = {}
for canonical, aliases in FIELD_ALIASES.items():
    ALIAS_MAP[canonical] = canonical
    for a in aliases:
        ALIAS_MAP[_norm(a)] = canonical


def _map_fields(raw: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in raw.items():
        canon = ALIAS_MAP.get(_norm(k))
        if canon and v not in (None, "", []):
            out[canon] = v if isinstance(v, str) else (",".join(str(x) for x in v) if isinstance(v, list) else str(v))
    return out


# ---------------------------------------------------------------------------
# Format detection + parsers (unchanged from earlier module — extended by more events)
# ---------------------------------------------------------------------------

def detect_format(text: str) -> str:
    stripped = text.lstrip()
    if not stripped:
        return "unknown"
    if stripped.startswith("<"):
        return "xml"
    if stripped.startswith(("{", "[")):
        return "json"
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) >= 2:
        header = lines[0].lower()
        if ("," in header or "\t" in header) and any(
            f in header.replace(" ", "") for f in ("image", "processid", "commandline", "processguid", "src", "dest")
        ):
            return "csv"
    if lines and lines[0].startswith("{"):
        try:
            json.loads(lines[0])
            return "json"
        except Exception:
            pass
    return "unknown"


def _flatten_json(obj: Any, prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                out.update(_flatten_json(v, key))
            else:
                out[key] = v
    elif isinstance(obj, list) and prefix:
        out[prefix] = ",".join(str(x) for x in obj)
    return out


def parse_xml(text: str) -> List[Dict[str, Any]]:
    cleaned = re.sub(r'\sxmlns="[^"]+"', "", text)
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        try:
            root = ET.fromstring(f"<Root>{cleaned}</Root>")
        except ET.ParseError:
            return []
    events = []
    for ev in root.iter("Event"):
        eid_el = ev.find("./System/EventID")
        eid = int(eid_el.text) if eid_el is not None and eid_el.text and eid_el.text.strip().isdigit() else 1
        raw: Dict[str, Any] = {"eventid": eid}
        for d in ev.iter("Data"):
            name = d.attrib.get("Name")
            if name:
                raw[name] = (d.text or "").strip()
        tc = ev.find("./System/TimeCreated")
        if tc is not None and "SystemTime" in tc.attrib:
            raw["UtcTime"] = tc.attrib["SystemTime"]
        comp = ev.find("./System/Computer")
        if comp is not None and comp.text:
            raw["Computer"] = comp.text
        mapped = _map_fields(raw)
        mapped["eventid"] = str(eid)
        events.append(mapped)
    return events


def parse_json(text: str) -> List[Dict[str, Any]]:
    stripped = text.strip()
    docs: List[Any] = []
    try:
        parsed = json.loads(stripped)
        docs = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                docs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    events = []
    for d in docs:
        if not isinstance(d, dict):
            continue
        flat = _flatten_json(d)
        mapped = _map_fields(flat)
        # Best-effort EventID extraction
        if "eventid" not in mapped:
            for k in ("winlog.event_id", "event.code", "event.id", "EventID"):
                if k in flat:
                    mapped["eventid"] = str(flat[k])
                    break
        events.append(mapped)
    return events


def parse_csv(text: str) -> List[Dict[str, Any]]:
    sample = text[:2048]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    events = []
    for row in reader:
        if not row:
            continue
        mapped = _map_fields({k: (v or "") for k, v in row.items() if k})
        events.append(mapped)
    return events


# ---------------------------------------------------------------------------
# Rich forensic normalization
# ---------------------------------------------------------------------------

def _parse_hashes_blob(blob: str) -> Dict[str, str]:
    """Sysmon's `Hashes` field is `MD5=xxx,SHA256=yyy,IMPHASH=zzz`."""
    out: Dict[str, str] = {}
    for part in re.split(r"[,;\s]+", blob or ""):
        m = re.match(r"(md5|sha1|sha256|sha512|imphash)\s*=\s*([0-9a-fA-F]+)", part, re.IGNORECASE)
        if m:
            out[m.group(1).lower()] = m.group(2).lower()
    return out


def _short(path: str) -> str:
    if not path:
        return ""
    return path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]


def _split_hostuser(user: str) -> str:
    return user or ""


def _risk_from_techniques(techs: List[Any]) -> str:
    n = len(techs)
    if n >= 3:
        return "critical"
    if n == 2:
        return "high"
    if n == 1:
        return "medium"
    return "info"


def _normalize_event(raw: Dict[str, str]) -> Dict[str, Any]:
    """Convert an alias-mapped raw dict into a fully-normalized forensic record."""
    eid_raw = raw.get("eventid", "").strip()
    try:
        eid = int(eid_raw)
    except (ValueError, TypeError):
        eid = 1 if (raw.get("commandline") or raw.get("image")) else 0
    action, category = EVENT_TYPES.get(eid, ("event", "other"))

    hashes: Dict[str, str] = {}
    if raw.get("hashes"):
        hashes.update(_parse_hashes_blob(raw["hashes"]))
    for canonical, algo in (("hashmd5", "md5"), ("hashsha1", "sha1"), ("hashsha256", "sha256")):
        if raw.get(canonical):
            hashes[algo] = raw[canonical].lower()

    cmd = raw.get("commandline", "")
    techniques = [
        {"id": t.id, "name": t.name, "tactic": t.tactic}
        for t in mitre.map_techniques(cmd or raw.get("targetobject", ""))
    ]

    # Extract url/domain from command_line if not already present
    url = raw.get("url", "")
    if not url and cmd:
        m = re.search(r"https?://[^\s\"'<>`|\\]{4,}", cmd, re.IGNORECASE)
        if m:
            url = m.group(0)
    domain = raw.get("domain", "") or raw.get("queryname", "")

    record = {
        "timestamp":            raw.get("utctime", ""),
        "event_id":             eid,
        "event_type":           _event_type_label(eid),
        "action":               action,
        "category":             category,
        "host":                 raw.get("hostname", ""),
        "user":                 _split_hostuser(raw.get("user", "")),
        "integrity_level":      raw.get("integritylevel", ""),
        # Process
        "process_guid":         raw.get("processguid", ""),
        "process_id":           raw.get("processid", ""),
        "process_image":        raw.get("image", ""),
        "process_name":         _short(raw.get("image", "")) or raw.get("originalfilename", ""),
        "command_line":         cmd,
        # Parent process
        "parent_process_guid":  raw.get("parentprocessguid", ""),
        "parent_process_id":    raw.get("parentprocessid", ""),
        "parent_image":         raw.get("parentimage", ""),
        "parent_process_name":  _short(raw.get("parentimage", "")),
        "parent_command_line":  raw.get("parentcommandline", ""),
        # Files & hashes
        "file_path":            raw.get("targetfilename", "") or raw.get("image", ""),
        "file_hash_md5":        hashes.get("md5", ""),
        "file_hash_sha1":       hashes.get("sha1", ""),
        "file_hash_sha256":     hashes.get("sha256", ""),
        "parent_file_hash":     (raw.get("parenthash", "") or "").lower(),
        # Network
        "src_ip":               raw.get("srcip", ""),
        "src_port":             raw.get("srcport", ""),
        "dst_ip":               raw.get("dstip", ""),
        "dst_port":             raw.get("dstport", ""),
        "protocol":             raw.get("protocol", ""),
        # URL / DNS
        "url":                  url,
        "domain":               domain,
        "dns_query":            raw.get("queryname", ""),
        "dns_answer":           raw.get("queryresults", ""),
        # Registry
        "registry_key":         raw.get("targetobject", ""),
        "registry_value":       raw.get("details", ""),
        # Analysis
        "mitre_techniques":     techniques,
        "risk":                 _risk_from_techniques(techniques),
    }
    return record


def _event_type_label(eid: int) -> str:
    labels = {
        1: "Process Create", 3: "Network Connection", 5: "Process Terminated",
        7: "Image Loaded", 11: "File Created", 12: "Registry Object Created",
        13: "Registry Value Set", 14: "Registry Rename", 22: "DNS Query",
        23: "File Deleted",
    }
    return labels.get(eid, f"Event {eid}" if eid else "Event")


def extract_iocs_from_events(events: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Pull unique IOCs from the events. Used for the 'Send to Analyzer' handoff."""
    seen = set()
    iocs: List[Dict[str, str]] = []

    def add(t: str, v: str):
        if not v:
            return
        key = f"{t}:{v.lower()}"
        if key in seen:
            return
        seen.add(key)
        iocs.append({"type": t, "value": v})

    for e in events:
        for h_kind, key in (("md5", "file_hash_md5"), ("sha1", "file_hash_sha1"), ("sha256", "file_hash_sha256")):
            add(h_kind, e.get(key, ""))
        add("ipv4", e.get("dst_ip", ""))
        add("ipv4", e.get("src_ip", ""))
        add("url", e.get("url", ""))
        add("domain", e.get("domain", ""))
        add("filepath", e.get("file_path", ""))
    return iocs


# ---------------------------------------------------------------------------
# Process tree (Event ID 1 only — same as before, kept for /process-tree)
# ---------------------------------------------------------------------------

def build_tree(process_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    for i, e in enumerate(process_events):
        gid = e.get("process_guid") or f"pid-{e.get('process_id', 'x')}-{i}"
        e["_id"] = gid
        e["_parent"] = e.get("parent_process_guid") or None

    def _ts(e):
        v = e.get("timestamp", "")
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)
    process_events.sort(key=_ts)

    known_ids = {e["_id"] for e in process_events}
    for e in process_events:
        if e["_parent"] and e["_parent"] in known_ids:
            continue
        ppid = e.get("parent_process_id")
        pimg = (e.get("parent_image", "") or "").lower()
        if ppid or pimg:
            for cand in process_events:
                if cand is e:
                    continue
                if cand.get("process_id") == ppid or cand.get("process_image", "").lower() == pimg:
                    e["_parent"] = cand["_id"]
                    break

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    risk_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for e in process_events:
        risk_counts[e["risk"]] = risk_counts.get(e["risk"], 0) + 1
        nodes.append({
            "id": e["_id"],
            "parent_id": e["_parent"],
            "image": e.get("process_image", ""),
            "image_short": e.get("process_name", ""),
            "command_line": e.get("command_line", ""),
            "pid": e.get("process_id", ""),
            "ppid": e.get("parent_process_id", ""),
            "user": e.get("user", ""),
            "utc_time": e.get("timestamp", ""),
            "integrity_level": e.get("integrity_level", ""),
            "hashes": (
                (f"MD5={e['file_hash_md5']} " if e.get("file_hash_md5") else "")
                + (f"SHA256={e['file_hash_sha256']}" if e.get("file_hash_sha256") else "")
            ).strip(),
            "risk": e["risk"],
            "techniques": e.get("mitre_techniques", []),
        })
        if e["_parent"] and e["_parent"] in known_ids:
            edges.append({"source": e["_parent"], "target": e["_id"]})

    id_to_node = {n["id"]: n for n in nodes}
    depth: Dict[str, int] = {}
    for n in nodes:
        if not n["parent_id"] or n["parent_id"] not in id_to_node:
            depth[n["id"]] = 0
    changed = True
    while changed:
        changed = False
        for n in nodes:
            if n["id"] in depth:
                continue
            pd = depth.get(n["parent_id"])
            if pd is not None:
                depth[n["id"]] = pd + 1
                changed = True
    for n in nodes:
        n["depth"] = depth.get(n["id"], 0)

    SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    worst = "info"
    for r, c in risk_counts.items():
        if c > 0 and SEV_ORDER[r] > SEV_ORDER[worst]:
            worst = r

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "process_count": len(nodes),
            "edge_count": len(edges),
            "risk_counts": risk_counts,
            "worst_risk": worst,
        },
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse(text: str, format_hint: Optional[str] = None) -> Dict[str, Any]:
    """Parse arbitrary log dump text.

    Returns:
        {
          "format": "xml" | "json" | "csv",
          "forensic_events": [ ...normalized records with all fields... ],
          "iocs": [ ...extracted IOC dicts... ],
          "nodes": [...],  # process tree nodes (Event ID 1 only)
          "edges": [...],
          "stats": {process_count, edge_count, risk_counts, worst_risk, event_count, by_action},
        }
    """
    fmt = format_hint or detect_format(text)
    if fmt == "xml":
        raw_events = parse_xml(text)
    elif fmt == "json":
        raw_events = parse_json(text)
    elif fmt == "csv":
        raw_events = parse_csv(text)
    else:
        raise ValueError(
            "Unrecognized format. Provide Sysmon XML, JSON (Winlogbeat/ECS/EDR), "
            "or CSV/TSV with a header row containing standard fields "
            "(Image, CommandLine, ProcessGuid, ParentProcessGuid, SourceIp, DestinationIp, ...)."
        )
    forensic = [_normalize_event(e) for e in raw_events if e.get("image") or e.get("commandline") or e.get("targetfilename") or e.get("targetobject") or e.get("dstip") or e.get("queryname")]
    if not forensic:
        raise ValueError(
            f"Detected format '{fmt}' but no recognizable Sysmon/EDR events were found. "
            "Ensure your export contains at least one of: Image, CommandLine, TargetFilename, "
            "DestinationIp, or QueryName."
        )

    # Process tree from Event ID 1 events only
    proc_events = [e for e in forensic if e["event_id"] == 1]
    tree = build_tree(proc_events) if proc_events else {"nodes": [], "edges": [], "stats": {"process_count": 0, "edge_count": 0, "risk_counts": {}, "worst_risk": "info"}}

    # by-action histogram for the events table
    by_action: Dict[str, int] = {}
    for e in forensic:
        by_action[e["action"]] = by_action.get(e["action"], 0) + 1

    iocs = extract_iocs_from_events(forensic)

    return {
        "format": fmt,
        "forensic_events": forensic,
        "iocs": iocs,
        "nodes": tree["nodes"],
        "edges": tree["edges"],
        "stats": {
            **tree["stats"],
            "event_count": len(forensic),
            "by_action": by_action,
        },
    }
