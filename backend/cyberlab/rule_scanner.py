"""Lightweight YARA-alike rule engine.

Since we don't ship the yara-python native binding, this engine implements a
subset of YARA's most useful behaviors:

* String rules (`$s1 = "malicious"`)
* Hex rules (`$h1 = { 4D 5A ?? ?? }` - hex bytes with wildcards)
* Regex rules (`$r1 = /Invoke-\\w+/i`)
* Condition: implicit "any of them" (any string hit = rule match)
* Tags & severity metadata

Rules are Python dicts to keep it dependency-free. Users can add custom rules
via the admin API. Bundled rules cover common malware families & TTPs.
"""
from __future__ import annotations
import re
from typing import List, Dict, Any
from .models import YaraLikeMatch


# --- Built-in ruleset ------------------------------------------------------
BUILTIN_RULES: List[Dict[str, Any]] = [
    {
        "name": "PowerShell_Downloader",
        "tags": ["powershell", "downloader"],
        "severity": "high",
        "description": "PowerShell one-liner used to download and execute a remote payload.",
        "strings": [
            {"type": "regex", "pattern": r"(?:iex|Invoke-Expression)\s*\(\s*(?:new-object\s+)?(?:System\.)?Net\.WebClient", "flags": "i"},
            {"type": "regex", "pattern": r"DownloadString\s*\(\s*['\"]https?://", "flags": "i"},
            {"type": "regex", "pattern": r"Invoke-WebRequest\s+[^|]{0,40}\|\s*iex", "flags": "i"},
        ],
    },
    {
        "name": "PowerShell_EncodedCommand",
        "tags": ["powershell", "obfuscation", "T1027"],
        "severity": "high",
        "description": "PowerShell -EncodedCommand / -enc invocation.",
        "strings": [
            {"type": "regex", "pattern": r"powershell(?:\.exe)?\s+.*-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}", "flags": "i"},
        ],
    },
    {
        "name": "Mimikatz_Command",
        "tags": ["credential-dumping", "mimikatz", "T1003"],
        "severity": "critical",
        "description": "Mimikatz command line or module reference.",
        "strings": [
            {"type": "string", "pattern": "sekurlsa::logonpasswords", "flags": "i"},
            {"type": "string", "pattern": "sekurlsa::wdigest", "flags": "i"},
            {"type": "string", "pattern": "lsadump::sam", "flags": "i"},
            {"type": "string", "pattern": "kerberos::golden", "flags": "i"},
            {"type": "string", "pattern": "privilege::debug", "flags": "i"},
        ],
    },
    {
        "name": "Cobalt_Strike_Beacon",
        "tags": ["c2", "cobaltstrike"],
        "severity": "critical",
        "description": "Indicators consistent with Cobalt Strike beacon config.",
        "strings": [
            {"type": "regex", "pattern": r"beacon_?config", "flags": "i"},
            {"type": "string", "pattern": "%s.4%08x.%s"},
            {"type": "string", "pattern": "spawnto_x86"},
            {"type": "string", "pattern": "spawnto_x64"},
            {"type": "regex", "pattern": r"/(?:ptj|dot|submit\.php|updates\.rss)\b"},
        ],
    },
    {
        "name": "Ransomware_Note_Keywords",
        "tags": ["ransomware", "impact", "T1486"],
        "severity": "critical",
        "description": "Text patterns typical of ransomware ransom notes.",
        "strings": [
            {"type": "regex", "pattern": r"all\s+your\s+(?:files|data|documents)\s+(?:are|have\s+been)\s+encrypted", "flags": "i"},
            {"type": "regex", "pattern": r"how[_\s-]?to[_\s-]?decrypt", "flags": "i"},
            {"type": "regex", "pattern": r"pay\s+the\s+ransom", "flags": "i"},
            {"type": "regex", "pattern": r"contact\s+us.*(?:bitcoin|monero|xmr|tox)", "flags": "i"},
        ],
    },
    {
        "name": "Shadow_Copy_Deletion",
        "tags": ["anti-recovery", "T1490"],
        "severity": "high",
        "description": "Volume Shadow Copy deletion — classic ransomware anti-recovery step.",
        "strings": [
            {"type": "regex", "pattern": r"vssadmin(?:\.exe)?\s+delete\s+shadows", "flags": "i"},
            {"type": "regex", "pattern": r"wmic\s+shadowcopy\s+delete", "flags": "i"},
            {"type": "regex", "pattern": r"bcdedit(?:\.exe)?\s+/set\s+.*recoveryenabled\s+(?:no|off)", "flags": "i"},
        ],
    },
    {
        "name": "AMSI_Bypass",
        "tags": ["defense-evasion", "amsi"],
        "severity": "high",
        "description": "Known AMSI (Antimalware Scan Interface) bypass pattern.",
        "strings": [
            {"type": "string", "pattern": "amsiInitFailed", "flags": "i"},
            {"type": "regex", "pattern": r"\[Ref\]\.Assembly\.GetType\('System\.Management\.Automation\.AmsiUtils'\)", "flags": "i"},
            {"type": "regex", "pattern": r"amsi\.dll.*(?:AmsiScanBuffer|AmsiScanString)", "flags": "i"},
        ],
    },
    {
        "name": "SSH_Reverse_Shell",
        "tags": ["reverse-shell", "T1059"],
        "severity": "critical",
        "description": "Common reverse-shell payload signatures.",
        "strings": [
            {"type": "regex", "pattern": r"/dev/tcp/[^/]+/\d+", "flags": "i"},
            {"type": "regex", "pattern": r"bash\s+-i\s+>&\s*/dev/tcp/", "flags": "i"},
            {"type": "regex", "pattern": r"python.*socket\.socket.*connect", "flags": "i"},
            {"type": "regex", "pattern": r"nc(?:\.exe)?\s+-e\s+", "flags": "i"},
        ],
    },
    {
        "name": "Suspicious_LOLBins",
        "tags": ["lolbas", "living-off-the-land"],
        "severity": "medium",
        "description": "Living-off-the-land binaries invoked in suspicious ways.",
        "strings": [
            {"type": "regex", "pattern": r"certutil(?:\.exe)?\s+-urlcache\s+-split\s+-f\s+https?://", "flags": "i"},
            {"type": "regex", "pattern": r"bitsadmin(?:\.exe)?\s+/transfer", "flags": "i"},
            {"type": "regex", "pattern": r"mshta(?:\.exe)?\s+(?:https?|javascript|vbscript):", "flags": "i"},
            {"type": "regex", "pattern": r"rundll32(?:\.exe)?\s+.*\.dll,[A-Za-z_]", "flags": "i"},
            {"type": "regex", "pattern": r"regsvr32(?:\.exe)?\s+/s\s+/n\s+/u\s+/i:", "flags": "i"},
        ],
    },
    {
        "name": "Crypto_Wallet_Addresses",
        "tags": ["crypto", "impact"],
        "severity": "medium",
        "description": "Cryptocurrency wallet addresses (BTC/ETH) — possible ransom target.",
        "strings": [
            {"type": "regex", "pattern": r"\b(?:bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,62}\b"},
            {"type": "regex", "pattern": r"\b0x[a-fA-F0-9]{40}\b"},
        ],
    },
    {
        "name": "MZ_PE_Header",
        "tags": ["binary", "executable"],
        "severity": "info",
        "description": "PE executable header (MZ magic) present in payload.",
        "strings": [
            {"type": "hex", "pattern": "4D 5A"},
        ],
    },
    {
        "name": "Base64_ShellCode",
        "tags": ["shellcode", "obfuscation"],
        "severity": "high",
        "description": "Base64-encoded shellcode / PE header signatures.",
        "strings": [
            {"type": "string", "pattern": "TVqQAAMAAAAEAAAA"},  # b64("MZ\x90\x00\x03..." PE header start
            {"type": "string", "pattern": "TVpBAAA"},
        ],
    },
    {
        "name": "Python_Fileless_B64_Loader",
        "tags": ["python", "fileless", "execution", "T1059.006", "T1027"],
        "severity": "critical",
        "description": (
            "Python `-c exec(base64.b64decode(...).decode())` fileless loader. "
            "Frequently used as a stage-1 dropper — the decoded stage often reads "
            "a companion file from disk, XOR-decrypts it and exec()s the result. "
            "See Feb 2026 sample: base64 payload → XOR key `4fab0f4d5f6d...` → "
            "reads `instructions.docx` → exec()."
        ),
        "strings": [
            # -c "exec(...)"  or  -c exec(...)  followed by b64decode
            {"type": "regex",
             "pattern": r"""-c\s*(?:['"])?exec\s*\(\s*(?:__import__\s*\(\s*['"]base64['"]\s*\)|base64)\s*\.\s*b64decode\s*\(""",
             "flags": "i"},
            # Bare form: exec(__import__('base64').b64decode(b'...').decode())
            {"type": "regex",
             "pattern": r"""exec\s*\(\s*__import__\s*\(\s*['"]base64['"]\s*\)\s*\.\s*b64decode\s*\(""",
             "flags": "i"},
        ],
    },
    {
        "name": "Python_XOR_File_Loader",
        "tags": ["python", "xor", "fileless", "defense-evasion", "T1027"],
        "severity": "critical",
        "description": (
            "Python fileless-XOR staged loader — reads a companion file (docx, "
            "txt, dat), XOR-decrypts it with a hex-encoded key and exec()s the "
            "result. Classic 2nd-stage of the `python -c exec(b64decode(...))` "
            "dropper chain."
        ),
        "strings": [
            {"type": "regex",
             "pattern": r"""bytes\.fromhex\s*\(\s*['"][0-9a-fA-F]{16,}['"]\s*\)""",
             "flags": "i"},
            {"type": "regex",
             "pattern": r"""open\s*\(\s*['"][^'"]+\.(?:docx?|txt|dat|bin|log|tmp)['"]\s*,\s*['"]rb['"]""",
             "flags": "i"},
            {"type": "regex",
             "pattern": r"""for\s+\w+\s*,\s*\w+\s+in\s+enumerate\s*\([^\)]+\)\s*\)\s*""",
             "flags": "s"},
            {"type": "regex",
             "pattern": r"""exec\s*\([^\)]{0,60}\.decode\s*\(\s*['"]utf-?8['"]""",
             "flags": "i"},
        ],
    },
    {
        "name": "Amateur_XOR_Crypter_Signature",
        "tags": ["xor", "crypter", "obfuscation", "T1027"],
        "severity": "high",
        "description": (
            "Amateur / commodity XOR crypter signature — short (17–32 byte) "
            "hex XOR key combined with a modular index (`key[i % len(key)]`). "
            "Common in Python, Go and .NET stagers for hobbyist RATs and "
            "off-the-shelf crypters. Not itself proof of malware, but a strong "
            "signal in combination with any file-read + exec pattern."
        ),
        "strings": [
            # 17–32-byte hex XOR key (34–64 hex chars) — the amateur-crypter sweet spot.
            {"type": "regex",
             "pattern": r"""bytes\.fromhex\s*\(\s*['"][0-9a-fA-F]{34,64}['"]\s*\)""",
             "flags": "i"},
            # Modular indexing `key[i % len(key)]` is the give-away for repeating-XOR.
            {"type": "regex",
             "pattern": r"""\[\s*\w+\s*%\s*len\s*\(\s*\w+\s*\)\s*\]""",
             "flags": ""},
        ],
    },
    {
        "name": "Suspicious_Registry_Persistence",
        "tags": ["persistence", "T1547"],
        "severity": "high",
        "description": "Registry Run key persistence.",
        "strings": [
            {"type": "regex", "pattern": r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?\b", "flags": "i"},
            {"type": "regex", "pattern": r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "flags": "i"},
        ],
    },
]


def _hex_pattern_to_regex(pattern: str) -> bytes:
    """Convert YARA-style hex pattern (with ?? wildcards) to a regex bytes pattern."""
    tokens = pattern.strip().split()
    out = b""
    for tok in tokens:
        if tok == "??":
            out += b"."
        elif len(tok) == 2:
            try:
                out += re.escape(bytes([int(tok, 16)]))
            except ValueError:
                out += b"."
        else:
            # Nibble-level wildcards like "4?"
            hi, lo = tok[0], tok[1]
            if hi == "?" and lo == "?":
                out += b"."
            else:
                # Enumerate matches (16 possibilities max) — simpler: use hex charclass
                out += b"."
    return out


def _make_matcher(spec: Dict[str, Any]):
    stype = spec.get("type", "string")
    pattern = spec["pattern"]
    flags_str = spec.get("flags", "")
    if stype == "string":
        flags = re.IGNORECASE if "i" in flags_str.lower() else 0
        return re.compile(re.escape(pattern), flags)
    if stype == "regex":
        flags = 0
        if "i" in flags_str.lower():
            flags |= re.IGNORECASE
        if "s" in flags_str.lower():
            flags |= re.DOTALL
        return re.compile(pattern, flags)
    if stype == "hex":
        return re.compile(_hex_pattern_to_regex(pattern), re.DOTALL)
    raise ValueError(f"Unknown rule string type: {stype}")


def _scan_one(text: str, raw: bytes, rule: Dict[str, Any]) -> YaraLikeMatch | None:
    matched: List[str] = []
    for spec in rule["strings"]:
        matcher = _make_matcher(spec)
        if spec.get("type") == "hex":
            m = matcher.search(raw)
            if m:
                matched.append(m.group(0).hex()[:40])
        else:
            m = matcher.search(text)
            if m:
                snippet = m.group(0)
                if len(snippet) > 80:
                    snippet = snippet[:80] + "..."
                matched.append(snippet)
        if matched:
            break  # implicit "any of them"
    if not matched:
        return None
    return YaraLikeMatch(
        rule=rule["name"],
        tags=list(rule.get("tags", [])),
        severity=rule.get("severity", "medium"),
        description=rule.get("description", ""),
        matched=matched,
    )


def scan(text: str, raw: bytes, extra_rules: List[Dict[str, Any]] | None = None) -> List[YaraLikeMatch]:
    """Scan text + raw bytes against builtin + optional custom rules."""
    results: List[YaraLikeMatch] = []
    all_rules = BUILTIN_RULES + (extra_rules or [])
    for rule in all_rules:
        try:
            match = _scan_one(text, raw, rule)
            if match:
                results.append(match)
        except re.error:
            continue
    return results
