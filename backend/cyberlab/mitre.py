"""MITRE ATT&CK pattern mapper.

Maps decoded payload artifacts to MITRE techniques using signature-based
pattern matching. This is intentionally conservative — false positives are
worse than misses for a DFIR analyst's initial triage.

Reference: https://attack.mitre.org/
"""
from __future__ import annotations
import re
from typing import List, Dict
from .models import MitreTechnique


# Each rule is (technique_id, name, tactic, description, [regex, ...])
# Regexes are compiled with IGNORECASE.
_RULES = [
    # ------ Execution ------
    ("T1059.001", "PowerShell", "Execution",
     "PowerShell used for execution.",
     [r"\bpowershell(?:\.exe)?\b", r"-EncodedCommand\b", r"-nop\b", r"-ExecutionPolicy\s+Bypass",
      r"IEX\s*\(", r"Invoke-Expression"]),

    ("T1059.003", "Windows Command Shell", "Execution",
     "cmd.exe / batch execution.",
     [r"\bcmd\.exe\b", r"\bcmd\s+/c\b", r"\bcmd\s+/k\b"]),

    ("T1059.005", "Visual Basic", "Execution",
     "VBScript/VBA execution.",
     [r"\bwscript\.shell\b", r"\bcreateobject\s*\(", r"\bshell\.application\b",
      r"\.vbs\b", r"\bexecute\s+\("]),

    ("T1059.006", "Python", "Execution",
     "Python interpreter execution.",
     [r"\bpython(?:\.exe|3)?\b", r"\bexec\s*\(", r"\b__import__\s*\("]),

    ("T1059.007", "JavaScript", "Execution",
     "JavaScript/JScript execution.",
     [r"\beval\s*\(", r"\bnew\s+ActiveXObject\b", r"\bwscript\.exe\b",
      r"\bcscript\.exe\b", r"\bFunction\s*\(\s*[\"']"]),

    ("T1053.005", "Scheduled Task/Job", "Persistence",
     "Scheduled task creation.",
     [r"\bschtasks(?:\.exe)?\b", r"\bat\.exe\b", r"\bTaskScheduler\b",
      r"\bRegister-ScheduledTask\b"]),

    ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence",
     "Persistence via Run/RunOnce registry keys.",
     [r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\b",
      r"\\CurrentVersion\\RunOnce\b",
      r"\\Startup\b"]),

    ("T1218.011", "Rundll32", "Defense Evasion",
     "Rundll32 abuse for defense evasion.",
     [r"\brundll32(?:\.exe)?\b"]),

    ("T1218.010", "Regsvr32", "Defense Evasion",
     "Regsvr32 abuse (Squiblydoo).",
     [r"\bregsvr32(?:\.exe)?\b", r"/s\s+/n\s+/u\s+/i:"]),

    ("T1218.005", "Mshta", "Defense Evasion",
     "MSHTA execution of HTA content.",
     [r"\bmshta(?:\.exe)?\b", r"\bmshta:\b"]),

    ("T1027", "Obfuscated Files or Information", "Defense Evasion",
     "Encoded / obfuscated payload observed.",
     [r"-EncodedCommand\b", r"\bFromBase64String\b", r"\bConvert\.FromBase64String\b",
      r"\[Convert\]::FromBase64String", r"\bchar\[\]\s*::"]),

    ("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion",
     "Runtime deobfuscation routine detected.",
     [r"\bDecodeBase64\b", r"\bXor\b.*\bkey\b", r"\bbxor\b", r"-bxor\b"]),

    ("T1105", "Ingress Tool Transfer", "Command and Control",
     "Payload / tool download from remote host.",
     [r"\b(?:Invoke-WebRequest|iwr)\b", r"\bDownloadString\b", r"\bDownloadFile\b",
      r"\bStart-BitsTransfer\b", r"\bcertutil(?:\.exe)?\b.*-urlcache",
      r"\bbitsadmin(?:\.exe)?\b.*/transfer", r"\bcurl\.exe\b", r"\bwget\.exe\b",
      r"\.WebClient\b"]),

    ("T1071.001", "Application Layer Protocol: Web", "Command and Control",
     "HTTP/HTTPS C2 communication.",
     [r"https?://[^\s'\"<>]{6,}\.(?:xyz|top|club|space|shop|link|world|tk|ml|ga|cf|gq)\b",
      r"\bUser-Agent:\s*Mozilla"]),

    ("T1090", "Proxy", "Command and Control",
     "Tor / proxy relay usage.",
     [r"\.onion\b", r"\bsocks5://", r"\btor2web\b"]),

    ("T1055", "Process Injection", "Defense Evasion",
     "Process injection primitives.",
     [r"\bVirtualAlloc(?:Ex)?\b", r"\bWriteProcessMemory\b",
      r"\bCreateRemoteThread\b", r"\bNtCreateThreadEx\b",
      r"\bRtlCreateUserThread\b", r"\bQueueUserAPC\b"]),

    ("T1112", "Modify Registry", "Defense Evasion",
     "Registry modification.",
     [r"\breg\.exe\b.*\s+add\b", r"\bSet-ItemProperty\b.*HKLM",
      r"\bNew-ItemProperty\b.*HKCU"]),

    ("T1548.002", "Bypass User Account Control", "Privilege Escalation",
     "UAC bypass techniques.",
     [r"\bfodhelper(?:\.exe)?\b", r"\bcomputerdefaults(?:\.exe)?\b",
      r"\bslui(?:\.exe)?\b\s+3", r"\beventvwr(?:\.exe)?\b"]),

    ("T1562.001", "Disable or Modify Tools", "Defense Evasion",
     "Disabling AV / Defender / logging.",
     [r"\bSet-MpPreference\b", r"\bDisableRealtimeMonitoring\b",
      r"\bAdd-MpPreference\b.*ExclusionPath",
      r"\bwevtutil\b\s+cl\b", r"\bStop-Service\b.*Defender"]),

    ("T1486", "Data Encrypted for Impact", "Impact",
     "Ransomware-style encryption behavior.",
     [r"\bAes(?:Managed|CryptoServiceProvider)\b", r"\.locked\b", r"\.encrypted\b",
      r"README_?FOR_?DECRYPT", r"HOW_TO_DECRYPT", r"ransom(?:ware|note)?"]),

    ("T1490", "Inhibit System Recovery", "Impact",
     "Shadow copy / backup deletion.",
     [r"\bvssadmin(?:\.exe)?\b.*delete\s+shadows", r"\bwmic\b.*shadowcopy\s+delete",
      r"\bbcdedit(?:\.exe)?\b.*recoveryenabled\s+No",
      r"\bwbadmin(?:\.exe)?\b.*delete\s+catalog"]),

    ("T1082", "System Information Discovery", "Discovery",
     "OS/host recon.",
     [r"\bsysteminfo\b", r"\bGet-ComputerInfo\b", r"\bWin32_OperatingSystem\b",
      r"\bhostname\.exe\b"]),

    ("T1016", "System Network Configuration Discovery", "Discovery",
     "Network config recon.",
     [r"\bipconfig(?:\.exe)?\b", r"\bnetstat\b", r"\bGet-NetIPConfiguration\b",
      r"\bGet-NetTCPConnection\b", r"\bnet\s+config\b"]),

    ("T1087", "Account Discovery", "Discovery",
     "Enumerating accounts.",
     [r"\bnet\s+user\b", r"\bnet\s+localgroup\b", r"\bGet-LocalUser\b",
      r"\bwhoami\b", r"\bquser\b"]),

    ("T1057", "Process Discovery", "Discovery",
     "Enumerating processes.",
     [r"\btasklist(?:\.exe)?\b", r"\bGet-Process\b", r"\bps\s+-ef\b"]),

    ("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access",
     "LSASS memory access.",
     [r"\blsass(?:\.exe)?\b", r"\bmimikatz\b", r"\bcomsvcs\.dll\b.*MiniDump",
      r"\bprocdump(?:\.exe)?\b.*lsass"]),

    ("T1552.001", "Credentials In Files", "Credential Access",
     "Searching files for credentials.",
     [r"\bfindstr\b.*password", r"\bSelect-String\b.*password",
      r"unattend\.xml\b", r"\bcpassword\b"]),
]

# Compile regexes upfront
_COMPILED = [
    (tid, name, tactic, desc, [re.compile(r, re.IGNORECASE) for r in patterns])
    for (tid, name, tactic, desc, patterns) in _RULES
]


def map_techniques(text: str) -> List[MitreTechnique]:
    """Return list of MITRE techniques matched in `text`."""
    results: List[MitreTechnique] = []
    for tid, name, tactic, desc, patterns in _COMPILED:
        evidence: List[str] = []
        for p in patterns:
            for m in p.finditer(text):
                snippet = _snippet(text, m.start(), m.end())
                if snippet not in evidence:
                    evidence.append(snippet)
                if len(evidence) >= 3:
                    break
            if len(evidence) >= 3:
                break
        if evidence:
            results.append(MitreTechnique(
                id=tid, name=name, tactic=tactic,
                description=desc, evidence=evidence,
            ))
    return results


def _snippet(text: str, start: int, end: int) -> str:
    s = max(0, start - 20)
    e = min(len(text), end + 20)
    return text[s:e].replace("\n", " ").strip()
