"""Risk-reason detector for CyberLab.

Produces a human-readable, structured list of *why* a payload / log scored
what it scored. Each reason has:

    { "label":    "EncodedCommand detected",   # short chip label
      "severity": "high" | "medium" | "low",   # visual tone
      "category": "encoding" | "execution" | "lolbin" |
                  "network"  | "persistence" | "impact"  |
                  "credential" | "recon" | "forensic",
      "evidence": "…snippet…"                  # optional 60-char evidence
    }

Indicators are additive and multi-source — the same payload may produce
5–15 reasons which the UI renders as a bulleted list under the risk score.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List


# Ordered rules: (regex, severity, category, label). First match wins per rule.
_RULES: List[tuple] = [
    # -- Encoding / obfuscation ------------------------------------------------
    (r"-e(?:ncodedcommand|nc|c)?\s+[A-Za-z0-9+/=]{20,}", "high",   "encoding",  "PowerShell -EncodedCommand detected"),
    (r"powershell(?:\.exe)?\s+.*-nop", "medium", "encoding", "PowerShell no-profile flag (-nop)"),
    (r"-w(?:indowstyle)?\s+hidden",   "high",   "encoding",  "Hidden window flag"),
    (r"FromBase64String",             "high",   "encoding",  "Runtime Base64 decode call"),
    (r"[A-Za-z0-9+/]{80,}={0,2}",     "medium", "encoding",  "Long Base64 blob embedded"),
    (r"\bH4sI",                       "medium", "encoding",  "Gzip-compressed Base64 (magic H4sI)"),

    # -- Execution / scripting -------------------------------------------------
    (r"\b(?:Invoke-Expression|IEX)\b", "high",   "execution", "Invoke-Expression (IEX) call"),
    (r"\bStart-Process\b",             "medium", "execution", "Start-Process invocation"),
    (r"\bWScript\.Shell\b",            "high",   "execution", "WScript.Shell scripting"),
    (r"\bShellExecute\b",              "medium", "execution", "ShellExecute Win32 call"),
    (r"\bAuto_Open\b",                 "high",   "execution", "Office VBA Auto_Open macro"),
    (r"\bDocument_Open\b",             "high",   "execution", "Office VBA Document_Open macro"),
    (r"\bCreateObject\b",              "medium", "execution", "VBA CreateObject invocation"),
    (r"\bAdd-MpPreference\b",          "high",   "execution", "Windows Defender preference tampering"),

    # -- LOLBins ---------------------------------------------------------------
    (r"\bmshta(?:\.exe)?\b",                     "high",   "lolbin", "mshta.exe LOLBin"),
    (r"\brundll32(?:\.exe)?\b",                  "high",   "lolbin", "rundll32.exe LOLBin"),
    (r"\bregsvr32(?:\.exe)?\b",                  "high",   "lolbin", "regsvr32.exe LOLBin"),
    (r"\bcertutil(?:\.exe)?\b.*(?:-urlcache|-decode)", "high", "lolbin", "certutil download/decode"),
    (r"\bbitsadmin(?:\.exe)?\b",                 "high",   "lolbin", "bitsadmin transfer LOLBin"),
    (r"\bwmic(?:\.exe)?\b\s+process\s+call\s+create", "high", "lolbin", "WMIC process-create"),

    # -- Network / delivery ---------------------------------------------------
    (r"\bDownloadString\b",            "high",   "network",   "DownloadString network call"),
    (r"\bDownloadFile\b",              "high",   "network",   "DownloadFile network call"),
    (r"\bNet\.WebClient\b",            "medium", "network",   "Net.WebClient instantiated"),
    (r"\b(?:iwr|Invoke-WebRequest)\b", "high",   "network",   "Invoke-WebRequest call"),
    (r"https?://[^\s\"'>)]+",          "medium", "network",   "HTTP(S) URL present"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b",   "low",    "network",   "IPv4 address present"),

    # -- Persistence -----------------------------------------------------------
    (r"\\CurrentVersion\\Run\\", "high", "persistence", "HKCU/HKLM Run key persistence"),
    (r"\bschtasks(?:\.exe)?\s+/create\b", "high", "persistence", "Scheduled task creation"),
    (r"\bNew-Service\b|\bsc\.exe\s+create\b", "high", "persistence", "New service persistence"),
    (r"\bWmiEventSubscription\b|\bRegister-WmiEvent\b", "high", "persistence", "WMI event subscription"),

    # -- Impact / anti-recovery ------------------------------------------------
    (r"\bvssadmin(?:\.exe)?\s+delete\s+shadows", "high", "impact", "Shadow-copy deletion (vssadmin)"),
    (r"\bwbadmin(?:\.exe)?\s+delete", "high", "impact",  "Backup deletion (wbadmin)"),
    (r"\bbcdedit(?:\.exe)?\b.*recoveryenabled\s+No", "high", "impact", "Recovery disabled (bcdedit)"),
    (r"\bcipher(?:\.exe)?\s+/w:", "medium", "impact", "cipher.exe secure-wipe"),

    # -- Credential access / recon --------------------------------------------
    (r"\bmimikatz\b",                              "high",   "credential", "Mimikatz string"),
    (r"\bsekurlsa::",                              "high",   "credential", "Mimikatz sekurlsa module"),
    (r"\blsass(?:\.exe)?\b",                       "medium", "credential", "LSASS reference"),
    (r"\bGet-CimInstance\s+Win32_OperatingSystem", "low",    "recon",      "OS recon (Win32_OperatingSystem)"),
    (r"\bwhoami\b",                                "low",    "recon",      "whoami reconnaissance"),
    (r"\bnet\s+(?:user|group|localgroup|view)\b",  "medium", "recon",      "net.exe enumeration"),
    (r"\bnltest(?:\.exe)?\s+/dclist",              "medium", "recon",      "nltest domain-controller listing"),
]


_COMPILED = [(re.compile(pat, re.IGNORECASE | re.MULTILINE), sev, cat, label)
             for pat, sev, cat, label in _RULES]


_SEVERITY_WEIGHT = {"high": 3, "medium": 2, "low": 1}


def detect_risk_reasons(text: str, iocs: List[Dict[str, Any]] | None = None,
                        max_reasons: int = 20) -> List[Dict[str, Any]]:
    """Return an ordered, deduplicated list of risk indicators.

    * `text`  — combined ORIGINAL + DECODED payload text (already produced
                by the auto-investigate orchestrator).
    * `iocs`  — the analysis IOC list; used to add IOC-count reasons.
    """
    reasons: List[Dict[str, Any]] = []
    seen: set[str] = set()
    if not text:
        return reasons

    # Rule-driven detection — first match wins per rule (grab evidence too).
    for pattern, severity, category, label in _COMPILED:
        m = pattern.search(text)
        if not m:
            continue
        if label in seen:
            continue
        seen.add(label)
        evidence = _short_evidence(text, m)
        reasons.append({
            "label": label,
            "severity": severity,
            "category": category,
            "evidence": evidence,
        })

    # UTF-16LE marker: many consecutive `\x00` bytes in decoded text imply
    # a PowerShell -EncodedCommand payload (already reported above); we add
    # an additional low-severity confirmation for the reason-list clarity.
    if "\x00" in text and text.count("\x00") >= 4 and "UTF-16LE payload" not in seen:
        reasons.append({
            "label": "UTF-16LE payload",
            "severity": "low",
            "category": "encoding",
            "evidence": "",
        })

    # IOC-driven reasons — one aggregate reason per meaningful IOC type.
    counts: Dict[str, int] = {}
    for i in iocs or []:
        counts[i.get("type", "unknown")] = counts.get(i.get("type", "unknown"), 0) + 1
    ioc_reasons = [
        ("url",         "medium", "network",    "Malicious URL indicator"),
        ("ipv4",        "medium", "network",    "IPv4 indicator"),
        ("ipv6",        "medium", "network",    "IPv6 indicator"),
        ("domain",      "low",    "network",    "Suspicious domain"),
        ("md5",         "medium", "forensic",   "MD5 hash indicator"),
        ("sha1",        "medium", "forensic",   "SHA-1 hash indicator"),
        ("sha256",      "high",   "forensic",   "SHA-256 hash indicator"),
        ("email",       "low",    "network",    "Email address indicator"),
        ("btc",         "high",   "impact",     "Bitcoin wallet (ransom indicator)"),
        ("cve",         "medium", "forensic",   "CVE reference"),
        ("registry",    "medium", "persistence","Registry key indicator"),
        ("filepath",    "low",    "forensic",   "Suspicious file path"),
    ]
    for kind, severity, category, base_label in ioc_reasons:
        n = counts.get(kind, 0)
        if not n:
            continue
        label = f"{base_label}" + (f" (×{n})" if n > 1 else "")
        if label in seen:
            continue
        seen.add(label)
        reasons.append({
            "label": label,
            "severity": severity,
            "category": category,
            "evidence": "",
        })

    # Order: high → medium → low, preserving detection order within tier.
    tier = {"high": 0, "medium": 1, "low": 2}
    reasons.sort(key=lambda r: tier.get(r["severity"], 3))
    return reasons[:max_reasons]


def _short_evidence(text: str, m: re.Match, span: int = 50) -> str:
    start = max(0, m.start() - 10)
    end = min(len(text), m.end() + span)
    frag = text[start:end].replace("\n", " ").replace("\r", " ").strip()
    frag = re.sub(r"\s+", " ", frag)
    if len(frag) > 80:
        frag = frag[:80] + "…"
    return frag
