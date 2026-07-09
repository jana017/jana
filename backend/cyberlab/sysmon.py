"""Sysmon / EDR telemetry ingestion for CyberLab.

Parses raw Windows Sysmon Event ID 1 dumps in three flavors:
    * XML (native Windows EventLog wevtutil export)
    * JSON (Winlogbeat / Elastic ECS or single-event JSON dumps)
    * CSV / TSV (with header row containing Sysmon field names)

Then reconstructs a parent-child process tree using ProcessGuid /
ParentProcessGuid when available, falling back to (PID, ParentPID) with
timestamp ordering when it isn't.

Every node's `command_line` is scanned against the existing MITRE mapper
so the frontend can color-code by risk level.
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


# Sysmon field aliases we accept (case-insensitive)
FIELD_ALIASES = {
    "processguid":       ["processguid", "process.entity_id", "process_guid", "guid"],
    "parentprocessguid": ["parentprocessguid", "process.parent.entity_id", "parent_process_guid", "parentguid"],
    "processid":         ["processid", "process.pid", "pid"],
    "parentprocessid":   ["parentprocessid", "process.parent.pid", "parent_pid", "ppid"],
    "image":             ["image", "process.executable", "process_image", "executable", "path"],
    "parentimage":       ["parentimage", "process.parent.executable", "parent_image", "parent_executable"],
    "commandline":       ["commandline", "process.command_line", "process_command_line", "cmd", "cmdline"],
    "parentcommandline": ["parentcommandline", "process.parent.command_line", "parent_command_line", "parent_cmdline"],
    "user":              ["user", "user.name", "process.user.name", "username"],
    "utctime":           ["utctime", "@timestamp", "timestamp", "eventtime"],
    "hashes":            ["hashes", "process.hash.md5", "process.hash.sha256", "hash"],
    "integritylevel":    ["integritylevel", "process.integrity_level", "integrity_level"],
    "originalfilename":  ["originalfilename", "process.pe.original_file_name", "original_file_name"],
}


def _norm(key: str) -> str:
    """Lowercase and strip separators for alias matching."""
    return re.sub(r"[^a-z0-9]", "", key.lower())


ALIAS_MAP = {}
for canonical, aliases in FIELD_ALIASES.items():
    for a in aliases:
        ALIAS_MAP[_norm(a)] = canonical


def _map_fields(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten arbitrary keys onto canonical Sysmon field names."""
    out: Dict[str, Any] = {}
    for k, v in raw.items():
        canon = ALIAS_MAP.get(_norm(k))
        if canon and v not in (None, "", []):
            out[canon] = v if isinstance(v, str) else str(v)
    return out


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_format(text: str) -> str:
    """Returns one of: 'xml', 'json', 'csv', 'unknown'."""
    stripped = text.lstrip()
    if not stripped:
        return "unknown"
    if stripped.startswith("<"):
        return "xml"
    if stripped.startswith(("{", "[")):
        return "json"
    # Try CSV: needs multiple lines, comma or tab separated header + at least one data row
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) >= 2:
        header = lines[0].lower()
        if ("," in header or "\t" in header) and any(
            f in header.replace(" ", "") for f in ("image", "processid", "commandline", "processguid")
        ):
            return "csv"
    # NDJSON (one JSON object per line)
    if len(lines) >= 1 and lines[0].startswith("{"):
        try:
            json.loads(lines[0])
            return "json"
        except Exception:
            pass
    return "unknown"


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_xml(text: str) -> List[Dict[str, Any]]:
    """Parse Windows Event XML (single event or wrapping <Events> element).
    Accepts both the Sysmon namespaced form and stripped variants."""
    # Strip xmlns to make ET parsing easier
    cleaned = re.sub(r'\sxmlns="[^"]+"', "", text)
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        # Might be multiple concatenated events without a root — wrap them
        try:
            root = ET.fromstring(f"<Root>{cleaned}</Root>")
        except ET.ParseError:
            return []

    events = []
    for ev in root.iter("Event"):
        # Only care about Sysmon EventID 1 (Process Create). Accept missing EventID too.
        eid_el = ev.find("./System/EventID")
        eid = int(eid_el.text) if eid_el is not None and eid_el.text and eid_el.text.strip().isdigit() else 1
        if eid != 1:
            continue
        raw: Dict[str, Any] = {}
        for d in ev.iter("Data"):
            name = d.attrib.get("Name")
            if name:
                raw[name] = (d.text or "").strip()
        # Include timestamp
        tc = ev.find("./System/TimeCreated")
        if tc is not None and "SystemTime" in tc.attrib:
            raw["UtcTime"] = tc.attrib["SystemTime"]
        mapped = _map_fields(raw)
        if mapped.get("image") or mapped.get("commandline"):
            events.append(mapped)
    return events


def parse_json(text: str) -> List[Dict[str, Any]]:
    """Parse a single JSON object, JSON array, or NDJSON (line-oriented)."""
    stripped = text.strip()
    docs: List[Any] = []
    try:
        parsed = json.loads(stripped)
        docs = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        # NDJSON fallback
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
        # Only capture process-create-ish events (Sysmon EventID 1 or ECS "process")
        eid = flat.get("winlog.event_id") or flat.get("EventID") or flat.get("event.code") or flat.get("event.id")
        if eid and str(eid) != "1":
            continue
        mapped = _map_fields(flat)
        if mapped.get("image") or mapped.get("commandline"):
            events.append(mapped)
    return events


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
        # For hash arrays like ["MD5=...", "SHA256=..."], keep as delimited string
        out[prefix] = ",".join(str(x) for x in obj)
    return out


def parse_csv(text: str) -> List[Dict[str, Any]]:
    """Parse CSV or TSV. Sniffs delimiter automatically."""
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
        if mapped.get("image") or mapped.get("commandline"):
            events.append(mapped)
    return events


# ---------------------------------------------------------------------------
# Tree builder + MITRE tagging
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _risk_for_commandline(cmd: str) -> Tuple[str, List[Dict[str, str]]]:
    """Return (risk_level, [technique_summaries])."""
    if not cmd:
        return "info", []
    techniques = mitre.map_techniques(cmd)
    if not techniques:
        return "info", []
    # Basic heuristic: N techniques → risk level
    n = len(techniques)
    if n >= 3:
        risk = "critical"
    elif n == 2:
        risk = "high"
    else:
        risk = "medium"
    return risk, [
        {"id": t.id, "name": t.name, "tactic": t.tactic}
        for t in techniques[:5]
    ]


def build_tree(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a parent-child process tree. Returns {nodes: [...], edges: [...], stats: {...}}."""
    # Assign IDs — prefer ProcessGuid, else pid+image
    for i, e in enumerate(events):
        gid = e.get("processguid") or f"pid-{e.get('processid', 'x')}-{i}"
        e["_id"] = gid
        pgid = e.get("parentprocessguid") or ""
        e["_parent"] = pgid or None

    # Sort by timestamp when available
    def _ts(e):
        v = e.get("utctime", "")
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)
    events.sort(key=_ts)

    known_ids = {e["_id"] for e in events}

    # Fallback: if parent guid isn't known and we have parentimage/parentpid, try to
    # find matching event by (image==parentimage & pid==parentpid).
    for e in events:
        if e["_parent"] and e["_parent"] in known_ids:
            continue
        ppid = e.get("parentprocessid")
        pimg = e.get("parentimage", "").lower()
        if ppid or pimg:
            for candidate in events:
                if candidate is e:
                    continue
                if candidate.get("processid") == ppid or candidate.get("image", "").lower() == pimg:
                    e["_parent"] = candidate["_id"]
                    break

    # Build nodes
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    risk_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for e in events:
        risk, techs = _risk_for_commandline(e.get("commandline", ""))
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        nodes.append({
            "id": e["_id"],
            "parent_id": e["_parent"],
            "image": e.get("image", ""),
            "image_short": (e.get("image", "") or "").rsplit("\\", 1)[-1].rsplit("/", 1)[-1],
            "command_line": e.get("commandline", ""),
            "pid": e.get("processid", ""),
            "ppid": e.get("parentprocessid", ""),
            "user": e.get("user", ""),
            "utc_time": e.get("utctime", ""),
            "integrity_level": e.get("integritylevel", ""),
            "hashes": e.get("hashes", ""),
            "risk": risk,
            "techniques": techs,
        })
        if e["_parent"] and e["_parent"] in known_ids:
            edges.append({"source": e["_parent"], "target": e["_id"]})

    # Determine layout depth for each node (BFS from roots)
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
            parent_depth = depth.get(n["parent_id"])
            if parent_depth is not None:
                depth[n["id"]] = parent_depth + 1
                changed = True
    for n in nodes:
        n["depth"] = depth.get(n["id"], 0)

    # Overall worst risk
    worst = "info"
    for r, count in risk_counts.items():
        if count > 0 and SEVERITY_ORDER[r] > SEVERITY_ORDER[worst]:
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
# Public entrypoint
# ---------------------------------------------------------------------------

def parse(text: str, format_hint: Optional[str] = None) -> Dict[str, Any]:
    """Parse arbitrary Sysmon dump text into a process tree."""
    fmt = format_hint or detect_format(text)
    if fmt == "xml":
        events = parse_xml(text)
    elif fmt == "json":
        events = parse_json(text)
    elif fmt == "csv":
        events = parse_csv(text)
    else:
        raise ValueError(
            "Unrecognized format. Provide Sysmon XML, JSON (Winlogbeat/Elastic), "
            "or CSV/TSV with a header row containing standard Sysmon field names "
            "(Image, CommandLine, ProcessGuid, ParentProcessGuid, ...)."
        )
    if not events:
        raise ValueError(
            f"Detected format '{fmt}' but no process-create events (Sysmon EventID 1) were found."
        )
    tree = build_tree(events)
    tree["format"] = fmt
    return tree
