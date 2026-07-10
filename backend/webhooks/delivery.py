"""Webhook delivery: template rendering, HTTP push with retry.

Templates use a **minimal, safe** subset of Jinja-style substitution
(`{{ var }}` / `{{ var|title }}`) — we do NOT use real Jinja to avoid the
sandbox escape surface. Everything is pre-computed and JSON-encoded.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any, Dict, Tuple

import httpx

MAX_RESPONSE_SNIPPET = 500
DEFAULT_TIMEOUT_S = 15
MAX_ATTEMPTS = 3
BACKOFF_SEC = (1, 3)  # attempt 2 waits 1s, attempt 3 waits 3s


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------
_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)(?:\s*\|\s*(title|upper|lower))?\s*\}\}")


def _severity_word(risk_score: int) -> str:
    if risk_score >= 80:
        return "critical"
    if risk_score >= 60:
        return "high"
    if risk_score >= 30:
        return "medium"
    return "low"


def _discord_color(verdict: str) -> int:
    # Discord embed colors — integer RGB.
    return {
        "malicious": 0xE11D48,   # red
        "suspicious": 0xF59E0B,  # amber
        "clean": 0x10B981,       # green
    }.get(verdict, 0x64748B)     # slate default


def build_render_context(payload: Dict[str, Any], content_mode: str, sent_at: str) -> Dict[str, str]:
    """Precompute every variable the template can reference.

    Every value is a pre-formatted STRING so template substitution is a
    single string-replace pass and cannot produce invalid JSON.

    Variables:
      Scalars: verdict, risk_score, severity_word, ioc_count, mitre_count,
               has_sigma, has_yara, sent_at, input_preview, discord_color
      JSON-encoded (safe to embed inside `{{ }}` in a JSON template):
               summary_json, sigma_rule_json, yara_rule_json,
               splunk_spl_json, sentinel_kql_json, cisco_xdr_json,
               iocs_json, mitre_json, rules_json, input_preview_json
    """
    verdict = (payload.get("verdict") or "unknown").lower()
    risk_score = int(payload.get("risk_score") or 0)
    iocs = payload.get("iocs") or []
    mitre = payload.get("mitre") or []
    rules = payload.get("rules") or []
    sigma = payload.get("sigma_rule") or ""
    yara = payload.get("yara_rule") or ""
    summary = payload.get("summary") or ""
    input_preview = (payload.get("input") or "")[:200]

    # In `bundle_iocs` mode we strip queries + full input to slim the payload.
    if content_mode == "bundle_iocs":
        splunk = kql = xdr = ""
    else:  # bundle_full
        splunk = payload.get("splunk_spl") or ""
        kql = payload.get("sentinel_kql") or ""
        xdr = payload.get("cisco_xdr") or ""

    def j(x: Any) -> str:
        return json.dumps(x, ensure_ascii=False)

    return {
        "verdict": verdict,
        "risk_score": str(risk_score),
        "severity_word": _severity_word(risk_score),
        "ioc_count": str(len(iocs)),
        "mitre_count": str(len(mitre)),
        "has_sigma": "yes" if sigma.strip() else "no",
        "has_yara": "yes" if yara.strip() else "no",
        "sent_at": sent_at,
        "input_preview": input_preview,
        "discord_color": str(_discord_color(verdict)),
        # JSON-encoded strings (embed inside JSON templates without quotes).
        "summary_json": j(summary),
        "sigma_rule_json": j(sigma),
        "yara_rule_json": j(yara),
        "splunk_spl_json": j(splunk),
        "sentinel_kql_json": j(kql),
        "cisco_xdr_json": j(xdr),
        "iocs_json": j(iocs),
        "mitre_json": j(mitre),
        "rules_json": j(rules),
        "input_preview_json": j(input_preview),
    }


def render_template(template: str, ctx: Dict[str, str]) -> str:
    """Replace `{{ var }}` and `{{ var|title }}` occurrences.

    Missing vars render as an empty string so the caller never sees the
    literal `{{ }}` markers in production output.
    """
    def _sub(m: re.Match) -> str:
        name = m.group(1)
        filt = m.group(2)
        val = ctx.get(name, "")
        if filt == "title":
            return val.title()
        if filt == "upper":
            return val.upper()
        if filt == "lower":
            return val.lower()
        return val
    return _VAR_RE.sub(_sub, template)


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------
async def deliver(
    *,
    url: str,
    method: str,
    headers: Dict[str, str],
    rendered_body: str,
    timeout_s: int = DEFAULT_TIMEOUT_S,
) -> Tuple[bool, int | None, str | None, str | None, int]:
    """Send with retry. Returns (ok, http_status, response_snippet, error, attempts)."""
    last_status: int | None = None
    last_snippet: str | None = None
    last_error: str | None = None

    async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True) as c:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                resp = await c.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    content=rendered_body.encode("utf-8"),
                )
                last_status = resp.status_code
                last_snippet = resp.text[:MAX_RESPONSE_SNIPPET] if resp.text else None
                if 200 <= resp.status_code < 300:
                    return True, resp.status_code, last_snippet, None, attempt
                # Non-2xx — only retry on 5xx / 429; 4xx is a client error.
                last_error = f"HTTP {resp.status_code}"
                if resp.status_code < 500 and resp.status_code != 429:
                    return False, resp.status_code, last_snippet, last_error, attempt
            except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError) as e:
                last_error = f"{type(e).__name__}: {str(e)[:200]}"
                last_status = None
                last_snippet = None
            except Exception as e:  # noqa: BLE001 — worker must never crash
                last_error = f"{type(e).__name__}: {str(e)[:200]}"
                last_status = None
                last_snippet = None
            # backoff before next attempt
            if attempt < MAX_ATTEMPTS:
                await asyncio.sleep(BACKOFF_SEC[attempt - 1])
    return False, last_status, last_snippet, last_error, MAX_ATTEMPTS


def build_content_summary(payload: Dict[str, Any]) -> str:
    parts = []
    if (payload.get("sigma_rule") or "").strip():
        parts.append("Sigma")
    if (payload.get("yara_rule") or "").strip():
        parts.append("YARA")
    ioc_n = len(payload.get("iocs") or [])
    if ioc_n:
        parts.append(f"{ioc_n} IOC{'s' if ioc_n != 1 else ''}")
    head = "+".join(parts) if parts else "no-rules"
    verdict = (payload.get("verdict") or "unknown").lower()
    return f"{head} · verdict={verdict} · risk={payload.get('risk_score') or 0}"
