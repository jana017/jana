"""Pydantic models for the webhook subsystem.

Kept in a dedicated module so tests and router can share the same schema.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, HttpUrl


# ---------------------------------------------------------------------------
# Preset target types
# ---------------------------------------------------------------------------
# `custom` = user brings their own URL/headers/template.
# All others come with a curated default template and docs URL.
TargetType = Literal[
    "custom",
    "splunk_hec",
    "sentinel_logic_app",
    "elastic_security",
    "crowdstrike_falcon",
    "slack",
    "discord",
    "teams",
]

ContentMode = Literal["bundle_iocs", "bundle_full"]


# ---------------------------------------------------------------------------
# Webhook config
# ---------------------------------------------------------------------------
class WebhookCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    target_type: TargetType = "custom"
    url: HttpUrl
    method: Literal["POST", "PUT"] = "POST"
    # Free-form dict — user supplies whatever auth header the target requires.
    # We never log or return the raw value in list endpoints (masked).
    headers: Dict[str, str] = Field(default_factory=dict)
    # Jinja-style `{{ var }}` template. See render_payload() for available vars.
    payload_template: str = Field(..., min_length=1)
    content_mode: ContentMode = "bundle_iocs"
    enabled: bool = True


class WebhookUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=80)
    url: Optional[HttpUrl] = None
    method: Optional[Literal["POST", "PUT"]] = None
    headers: Optional[Dict[str, str]] = None
    payload_template: Optional[str] = None
    content_mode: Optional[ContentMode] = None
    enabled: Optional[bool] = None


class WebhookOut(BaseModel):
    id: str
    name: str
    target_type: TargetType
    url: str
    method: str
    # Values masked (`***`) — only header keys are surfaced in the list view.
    headers: Dict[str, str]
    payload_template: str
    content_mode: ContentMode
    enabled: bool
    created_at: str
    created_by: Optional[str] = None
    last_status: Optional[str] = None  # ok | failed | never
    last_sent_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------
class PushRequest(BaseModel):
    """Payload sent by the analyst when clicking `Push to SIEM`."""
    webhook_id: str
    # Optional overrides if analyst wants to send a different content_mode
    # than the webhook default (e.g. "everything for this one incident").
    content_mode: Optional[ContentMode] = None
    # Analysis context — everything the AI panel already computed. All fields
    # optional; whatever the analyst has is what gets pushed.
    input: Optional[str] = ""
    output: Optional[str] = ""
    summary: Optional[str] = ""
    verdict: Optional[str] = ""
    risk_score: Optional[int] = 0
    sigma_rule: Optional[str] = ""
    yara_rule: Optional[str] = ""
    splunk_spl: Optional[str] = ""
    sentinel_kql: Optional[str] = ""
    cisco_xdr: Optional[str] = ""
    iocs: List[Dict[str, Any]] = Field(default_factory=list)
    mitre: List[Dict[str, Any]] = Field(default_factory=list)
    rules: List[Dict[str, Any]] = Field(default_factory=list)


class DeliveryOut(BaseModel):
    id: str
    webhook_id: str
    webhook_name: str
    target_type: TargetType
    status: Literal["ok", "failed"]
    http_status: Optional[int] = None
    error: Optional[str] = None
    attempts: int = 1
    response_snippet: Optional[str] = None
    content_summary: str  # e.g. "Sigma+YARA+7 IOCs · verdict=malicious"
    sent_at: str
    triggered_by: Optional[str] = None


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
