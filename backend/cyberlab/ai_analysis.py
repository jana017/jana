"""AI-powered analysis using Claude Sonnet 4.5 via the Emergent LLM key.

Given a decoded payload + threat findings (MITRE / rules / IOCs), Claude
generates:
  1. A DFIR triage summary — what the payload does, what an analyst should do.
  2. Draft Sigma rule (YAML) detecting this behavior.
  3. Draft YARA rule detecting the payload strings.

These are DRAFTS — always human-reviewed before production deployment.
"""
from __future__ import annotations
import os
import json
import logging
import re
import uuid
from typing import Dict, Any, List

from emergentintegrations.llm.chat import LlmChat, UserMessage

logger = logging.getLogger("cyberlab.ai")


SYSTEM_PROMPT = """You are a senior DFIR (Digital Forensics & Incident Response) analyst.
You receive a decoded malware payload plus enumerated MITRE ATT&CK techniques,
YARA-lite rule hits and extracted IOCs. Your job is to produce SIX outputs
in strict JSON format:

1. `summary` — 3–5 crisp sentences explaining what the payload does, its likely
   attribution / family (if evident), and the top 3 remediation steps an
   analyst should take now. Plain English, no markdown, no bullet points.

2. `sigma_rule` — a complete Sigma rule (YAML string) detecting this behavior.
   Use `logsource` appropriate for the platform observed (Windows PowerShell,
   Windows Sysmon EventID 1, etc.) and correct Sigma modifiers. Include
   `title`, `id` (a UUID), `status`, `description`, `author`, `date`, `tags`
   (with the MITRE technique IDs), `logsource`, `detection`, `condition`,
   `falsepositives`, `level`.

3. `yara_rule` — a complete YARA rule (plain text) detecting the payload
   strings. Include a `meta:` block with `author`, `description`, `date`,
   `hash`, and MITRE `technique_id`. Provide 3–6 `strings:` and an
   appropriate `condition`. Do NOT use anything that requires the yara PE
   or math modules — keep it portable.

4. `splunk_spl` — a Splunk SPL hunt query. Target `index=wineventlog`
   `sourcetype=XmlWinEventLog` or generic firewall / EDR indices. Use
   Sysmon fields (`EventCode`, `Image`, `CommandLine`, `ParentImage`,
   `DestinationIp`, `QueryName`). Include one `| stats` clause and one
   `| where` filter reducing false positives.

5. `sentinel_kql` — a Microsoft Sentinel KQL query using standard tables
   (`DeviceProcessEvents`, `DeviceNetworkEvents`, `DnsEvents`,
   `SecurityEvent`). Reference columns `ProcessCommandLine`,
   `InitiatingProcessFileName`, `RemoteIP`, `RemoteUrl`, `Query`.
   End with a `project` or `summarize`.

6. `cisco_xdr` — a Cisco XDR CQL / Investigation Query. Reference
   `observable_type`, `observable_value`, `process_command_line`,
   `network_connection.destination_ip`, `dns_lookup.hostname`.

Return ONLY valid JSON matching:
{"summary": "...", "sigma_rule": "...", "yara_rule": "...",
 "splunk_spl": "...", "sentinel_kql": "...", "cisco_xdr": "..."}

No prose before/after the JSON. No markdown code fences."""


def _key() -> str:
    return os.environ["EMERGENT_LLM_KEY"]


def _build_user_prompt(decoded_output: str, mitre: List[Dict], rules: List[Dict],
                       iocs: List[Dict], verdict: str, risk: int) -> str:
    lines = [
        f"VERDICT: {verdict.upper()} (risk score {risk}/100)",
        "",
        "DECODED PAYLOAD:",
        "```",
        decoded_output[:4000],  # cap to keep tokens bounded
        "```",
        "",
        f"MITRE TECHNIQUES ({len(mitre)}):",
    ]
    for m in mitre[:20]:
        lines.append(f"  - {m['id']} · {m['name']} · {m['tactic']}")
        for ev in (m.get("evidence") or [])[:2]:
            lines.append(f"      evidence: {ev}")

    lines += ["", f"YARA-LITE RULE HITS ({len(rules)}):"]
    for r in rules[:20]:
        lines.append(f"  - {r['rule']} · severity={r['severity']} · tags={r.get('tags', [])}")

    lines += ["", f"EXTRACTED IOCS ({len(iocs)}):"]
    ioc_by_type: Dict[str, List[str]] = {}
    for i in iocs[:40]:
        ioc_by_type.setdefault(i["type"], []).append(i["value"])
    for t, values in ioc_by_type.items():
        lines.append(f"  - {t}: {', '.join(values[:5])}" + (f" (+{len(values) - 5} more)" if len(values) > 5 else ""))

    return "\n".join(lines)


async def generate_ai_analysis(
    decoded_output: str,
    mitre: List[Dict[str, Any]],
    rules: List[Dict[str, Any]],
    iocs: List[Dict[str, Any]],
    verdict: str,
    risk: int,
) -> Dict[str, Any]:
    """Call Claude Sonnet 4.5 and parse its JSON response."""
    chat = LlmChat(
        api_key=_key(),
        session_id=f"cyberlab-{uuid.uuid4().hex[:12]}",
        system_message=SYSTEM_PROMPT,
    ).with_model("anthropic", "claude-sonnet-4-5-20250929")

    prompt = _build_user_prompt(decoded_output, mitre, rules, iocs, verdict, risk)
    logger.info("cyberlab.ai request: verdict=%s risk=%s mitre=%d rules=%d iocs=%d",
                verdict, risk, len(mitre), len(rules), len(iocs))
    response_text = await chat.send_message(UserMessage(text=prompt))
    return _parse_response(response_text)


def _parse_response(text: str) -> Dict[str, Any]:
    """Extract the JSON payload from the LLM response, tolerant to markdown fences."""
    stripped = text.strip()
    # Strip markdown code fences if the model added them despite instructions.
    fence_match = re.match(r"^```(?:json)?\s*(.*?)\s*```$", stripped, re.DOTALL)
    if fence_match:
        stripped = fence_match.group(1).strip()
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        # Fallback: find the first { … } block
        m = re.search(r"\{.*\}", stripped, re.DOTALL)
        if not m:
            raise
        data = json.loads(m.group(0))
    return {
        "summary": data.get("summary", "").strip(),
        "sigma_rule": data.get("sigma_rule", "").strip(),
        "yara_rule": data.get("yara_rule", "").strip(),
        "splunk_spl": data.get("splunk_spl", "").strip(),
        "sentinel_kql": data.get("sentinel_kql", "").strip(),
        "cisco_xdr": data.get("cisco_xdr", "").strip(),
    }
