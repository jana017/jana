"""Curated webhook presets — payload templates and setup docs for popular
EDR/SIEM/collaboration targets. The analyst still supplies the target URL
and any secret headers (bearer tokens, API keys) — we just pre-fill the
schema so the push works on the first try.

Every template is rendered with the vars documented in `delivery.render_payload`.
"""
from __future__ import annotations

from typing import Dict, List, TypedDict


class Preset(TypedDict):
    id: str
    name: str
    docs_url: str
    method: str
    headers_template: Dict[str, str]  # {} means user must add auth manually
    payload_template: str
    notes: str


# Sigma-block-first template used by SIEM ingestion endpoints (schemaless).
_SIEM_BUNDLE_TMPL = """{
  "source": "NivX Forge",
  "generated_at": "{{ sent_at }}",
  "verdict": "{{ verdict }}",
  "risk_score": {{ risk_score }},
  "summary": {{ summary_json }},
  "input_preview": {{ input_preview_json }},
  "sigma": {{ sigma_rule_json }},
  "yara": {{ yara_rule_json }},
  "splunk_spl": {{ splunk_spl_json }},
  "sentinel_kql": {{ sentinel_kql_json }},
  "mitre": {{ mitre_json }},
  "iocs": {{ iocs_json }}
}"""


_SPLUNK_HEC_TMPL = """{
  "event": {
    "source": "nivx_forge",
    "verdict": "{{ verdict }}",
    "risk_score": {{ risk_score }},
    "summary": {{ summary_json }},
    "sigma_rule": {{ sigma_rule_json }},
    "yara_rule": {{ yara_rule_json }},
    "spl": {{ splunk_spl_json }},
    "mitre": {{ mitre_json }},
    "iocs": {{ iocs_json }}
  },
  "sourcetype": "nivx:forge:analysis",
  "index": "main"
}"""


_ELASTIC_RULE_TMPL = """{
  "name": "NivX Forge — {{ verdict|title }} ({{ risk_score }}/100)",
  "description": {{ summary_json }},
  "risk_score": {{ risk_score }},
  "severity": "{{ severity_word }}",
  "type": "query",
  "language": "kuery",
  "query": "*",
  "index": ["logs-*"],
  "tags": ["nivx-forge", "auto-generated"],
  "note": {{ sigma_rule_json }}
}"""


_CROWDSTRIKE_CUSTOM_IOA_TMPL = """{
  "comment": "Auto-imported from NivX Forge",
  "description": {{ summary_json }},
  "name": "NivX Forge {{ verdict }} #{{ risk_score }}",
  "pattern_severity": "{{ severity_word }}",
  "rulegroup_id": "REPLACE_WITH_RULEGROUP_ID",
  "ruletype_id": "1",
  "field_values": [
    {"name": "CommandLine", "type": "excludes", "value": ".*", "values": []}
  ]
}"""


_SLACK_TMPL = """{
  "text": ":rotating_light: *NivX Forge — {{ verdict|title }}* (risk {{ risk_score }}/100)",
  "blocks": [
    {"type": "header", "text": {"type": "plain_text", "text": "NivX Forge triage · {{ verdict|title }}"}},
    {"type": "section", "text": {"type": "mrkdwn", "text": {{ summary_json }} }},
    {"type": "section", "text": {"type": "mrkdwn", "text": "*IOCs:* {{ ioc_count }} · *MITRE:* {{ mitre_count }} · *Sigma:* {{ has_sigma }}"}},
    {"type": "context", "elements": [{"type": "mrkdwn", "text": "generated {{ sent_at }} by nivxmachines.com"}]}
  ]
}"""


_DISCORD_TMPL = """{
  "username": "NivX Forge",
  "embeds": [{
    "title": "{{ verdict|title }} — risk {{ risk_score }}/100",
    "description": {{ summary_json }},
    "color": {{ discord_color }},
    "fields": [
      {"name": "IOCs", "value": "{{ ioc_count }}", "inline": true},
      {"name": "MITRE", "value": "{{ mitre_count }}", "inline": true},
      {"name": "Sigma", "value": "{{ has_sigma }}", "inline": true}
    ],
    "footer": {"text": "nivxmachines.com · {{ sent_at }}"}
  }]
}"""


_TEAMS_TMPL = """{
  "type": "message",
  "attachments": [{
    "contentType": "application/vnd.microsoft.card.adaptive",
    "content": {
      "type": "AdaptiveCard",
      "version": "1.4",
      "body": [
        {"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": "NivX Forge — {{ verdict|title }} ({{ risk_score }}/100)"},
        {"type": "TextBlock", "wrap": true, "text": {{ summary_json }} },
        {"type": "FactSet", "facts": [
          {"title": "IOCs", "value": "{{ ioc_count }}"},
          {"title": "MITRE", "value": "{{ mitre_count }}"},
          {"title": "Sigma", "value": "{{ has_sigma }}"}
        ]}
      ]
    }
  }]
}"""


PRESETS: List[Preset] = [
    {
        "id": "custom",
        "name": "Custom / Generic Webhook",
        "docs_url": "https://nivxmachines.com/support",
        "method": "POST",
        "headers_template": {"Content-Type": "application/json"},
        "payload_template": _SIEM_BUNDLE_TMPL,
        "notes": "Any HTTPS endpoint. Bring your own auth header if needed.",
    },
    {
        "id": "splunk_hec",
        "name": "Splunk HTTP Event Collector (HEC)",
        "docs_url": "https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector",
        "method": "POST",
        "headers_template": {
            "Authorization": "Splunk YOUR_HEC_TOKEN_HERE",
            "Content-Type": "application/json",
        },
        "payload_template": _SPLUNK_HEC_TMPL,
        "notes": "URL format: https://<splunk-host>:8088/services/collector/event. Replace HEC token in Authorization header.",
    },
    {
        "id": "sentinel_logic_app",
        "name": "Microsoft Sentinel (Logic App HTTP trigger)",
        "docs_url": "https://learn.microsoft.com/en-us/azure/sentinel/playbook-triggers-actions",
        "method": "POST",
        "headers_template": {"Content-Type": "application/json"},
        "payload_template": _SIEM_BUNDLE_TMPL,
        "notes": "Create a Logic App with 'When an HTTP request is received' trigger, then paste its callback URL here. Signature-in-URL — no auth header needed.",
    },
    {
        "id": "elastic_security",
        "name": "Elastic Security — Detection Rule",
        "docs_url": "https://www.elastic.co/guide/en/security/current/rules-api-create.html",
        "method": "POST",
        "headers_template": {
            "Authorization": "ApiKey YOUR_BASE64_API_KEY_HERE",
            "kbn-xsrf": "nivx-forge",
            "Content-Type": "application/json",
        },
        "payload_template": _ELASTIC_RULE_TMPL,
        "notes": "URL format: https://<kibana-host>/api/detection_engine/rules. Create API key with Kibana>Stack Management>API Keys.",
    },
    {
        "id": "crowdstrike_falcon",
        "name": "CrowdStrike Falcon — Custom IOA Rule",
        "docs_url": "https://falconpy.io/Service-Collections/Custom-IOA.html",
        "method": "POST",
        "headers_template": {
            "Authorization": "Bearer YOUR_OAUTH2_TOKEN_HERE",
            "Content-Type": "application/json",
        },
        "payload_template": _CROWDSTRIKE_CUSTOM_IOA_TMPL,
        "notes": "URL format: https://api.crowdstrike.com/ioarules/entities/rules/v1. Requires OAuth2 token — get one from POST /oauth2/token then paste. Also update rulegroup_id in the template.",
    },
    {
        "id": "slack",
        "name": "Slack Incoming Webhook",
        "docs_url": "https://api.slack.com/messaging/webhooks",
        "method": "POST",
        "headers_template": {"Content-Type": "application/json"},
        "payload_template": _SLACK_TMPL,
        "notes": "URL format: https://hooks.slack.com/services/T00/B00/xxx. No auth header — the URL itself is the secret.",
    },
    {
        "id": "discord",
        "name": "Discord Webhook",
        "docs_url": "https://support.discord.com/hc/en-us/articles/228383668",
        "method": "POST",
        "headers_template": {"Content-Type": "application/json"},
        "payload_template": _DISCORD_TMPL,
        "notes": "URL format: https://discord.com/api/webhooks/<id>/<token>. Channel Settings → Integrations → Webhooks → New.",
    },
    {
        "id": "teams",
        "name": "Microsoft Teams (Workflow webhook)",
        "docs_url": "https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook",
        "method": "POST",
        "headers_template": {"Content-Type": "application/json"},
        "payload_template": _TEAMS_TMPL,
        "notes": "Use the Workflows app in Teams → 'Post to a channel when a webhook request is received'. Copy the workflow URL.",
    },
]


def get_preset(preset_id: str) -> Preset | None:
    for p in PRESETS:
        if p["id"] == preset_id:
            return p
    return None
