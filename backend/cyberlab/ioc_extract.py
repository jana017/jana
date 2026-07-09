"""IOC (indicator of compromise) extraction from decoded payloads."""
from __future__ import annotations
import re
from typing import List, Dict, Set

from .models import Ioc


# Regex patterns
IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
IPV6 = re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.IGNORECASE)
URL = re.compile(
    r"\bhttps?://[^\s\"'<>`|\\]{4,}", re.IGNORECASE
)
DOMAIN = re.compile(
    r"\b(?=[a-z0-9-]{1,63}\.)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,}"
    r"(?:xn--[a-z0-9]{2,63}|"
    r"com|net|org|io|co|dev|app|xyz|info|biz|us|uk|de|fr|ru|cn|jp|in|br|au|ca|it|nl|pl|se|no|fi|tv|me|top|club|online|site|shop|store|tech|ai|gg|to|ws|cc|pw|link|space|live|world|solutions|systems|security|cloud)\b",
    re.IGNORECASE,
)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
SHA512 = re.compile(r"\b[a-fA-F0-9]{128}\b")
BTC = re.compile(r"\b(?:bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,62}\b")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
WIN_PATH = re.compile(r"[A-Za-z]:\\(?:[^\s\"'<>|:*?\\\r\n]+\\)*[^\s\"'<>|:*?\\\r\n]+")
UNC_PATH = re.compile(r"\\\\[A-Za-z0-9._-]+\\[^\s\"'<>|:*?\\\r\n]+")
REG_KEY = re.compile(r"HK(?:LM|CU|CR|U|CC)\\[^\s\"'<>|*?\r\n]+", re.IGNORECASE)


# Private/reserved IPs to filter out
_PRIVATE_IP_PREFIXES = ("0.", "10.", "127.", "169.254.", "192.168.", "255.")


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(_PRIVATE_IP_PREFIXES):
        return True
    parts = ip.split(".")
    if len(parts) == 4 and parts[0] == "172":
        try:
            if 16 <= int(parts[1]) <= 31:
                return True
        except ValueError:
            pass
    return False


# Common noise domains to skip
_NOISE_DOMAINS = {
    "example.com", "example.org", "example.net", "localhost.com",
    "schema.org", "w3.org", "w3.com", "microsoft.com", "windows.com",
}


def extract(text: str) -> List[Ioc]:
    """Extract IOCs from text. Deduplicates by (type, value)."""
    seen: Set[str] = set()
    iocs: List[Ioc] = []

    def add(t: str, v: str, ctx: str = ""):
        v = v.strip().rstrip(".,;:)]}\"'")
        key = f"{t}:{v.lower()}"
        if key in seen:
            return
        seen.add(key)
        iocs.append(Ioc(type=t, value=v, context=ctx[:80]))

    for m in URL.finditer(text):
        add("url", m.group(0), _ctx(text, m))

    for m in IPV4.finditer(text):
        ip = m.group(0)
        if not _is_private_ip(ip):
            add("ipv4", ip, _ctx(text, m))

    for m in IPV6.finditer(text):
        if ":" in m.group(0) and m.group(0).count(":") >= 2:
            add("ipv6", m.group(0), _ctx(text, m))

    for m in DOMAIN.finditer(text):
        d = m.group(0).lower()
        if d in _NOISE_DOMAINS:
            continue
        # Skip if this domain is inside a URL we already captured
        add("domain", d, _ctx(text, m))

    for m in EMAIL.finditer(text):
        add("email", m.group(0), _ctx(text, m))

    for m in SHA512.finditer(text):
        add("sha512", m.group(0).lower(), _ctx(text, m))
    # Order matters: SHA256 -> SHA1 -> MD5 to avoid overlaps
    consumed: Set[tuple] = set()
    for m in SHA256.finditer(text):
        consumed.add(m.span())
        add("sha256", m.group(0).lower(), _ctx(text, m))
    for m in SHA1.finditer(text):
        if not any(s <= m.start() < e for (s, e) in consumed):
            consumed.add(m.span())
            add("sha1", m.group(0).lower(), _ctx(text, m))
    for m in MD5.finditer(text):
        if not any(s <= m.start() < e for (s, e) in consumed):
            add("md5", m.group(0).lower(), _ctx(text, m))

    for m in BTC.finditer(text):
        add("btc", m.group(0), _ctx(text, m))

    for m in MAC.finditer(text):
        add("mac", m.group(0), _ctx(text, m))

    for m in CVE.finditer(text):
        add("cve", m.group(0).upper(), _ctx(text, m))

    for m in WIN_PATH.finditer(text):
        add("filepath", m.group(0), _ctx(text, m))

    for m in UNC_PATH.finditer(text):
        add("filepath", m.group(0), _ctx(text, m))

    for m in REG_KEY.finditer(text):
        add("registry", m.group(0), _ctx(text, m))

    return iocs


def _ctx(text: str, match: re.Match) -> str:
    start = max(0, match.start() - 25)
    end = min(len(text), match.end() + 25)
    return text[start:end].replace("\n", " ")


def summarize(iocs: List[Ioc]) -> Dict[str, int]:
    """Return {type: count} summary."""
    result: Dict[str, int] = {}
    for i in iocs:
        result[i.type] = result.get(i.type, 0) + 1
    return result
