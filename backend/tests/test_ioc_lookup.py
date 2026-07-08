"""Tests for /api/ioc-lookup endpoint - Smart IOC Analyzer"""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL") or open("/app/frontend/.env").read().split("REACT_APP_BACKEND_URL=")[1].split("\n")[0].strip()
BASE_URL = BASE_URL.rstrip("/")
IOC = f"{BASE_URL}/api/ioc-lookup"


def test_ip_lookup():
    r = requests.get(IOC, params={"value": "1.1.1.1"}, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["type"] == "ip"
    assert d["value"] == "1.1.1.1"
    links = d["links"]
    for name in ["VirusTotal", "AbuseIPDB", "Cisco Talos", "IBM X-Force"]:
        assert name in links
        assert "1.1.1.1" in links[name]
    en = d["enrichment"]
    assert en is not None
    assert en["kind"] == "ip"
    assert isinstance(en["open_ports"], list)
    assert "Shodan InternetDB" in en["sources"] and "ip-api.com" in en["sources"]
    if en.get("geo"):
        # optional but usually populated for 1.1.1.1 (Cloudflare)
        assert "isp" in en["geo"] and "country" in en["geo"]


def test_md5_hash_lookup():
    h = "44d88612fea8a8f36de82e1278abb02f"
    r = requests.get(IOC, params={"value": h}, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["type"] == "md5"
    assert d["links"]["VirusTotal"] == f"https://www.virustotal.com/gui/file/{h}"
    assert d["links"]["IBM X-Force"] == f"https://exchange.xforce.ibmcloud.com/malware/{h}"
    assert d["enrichment"]["kind"] == "hash"
    assert "note" in d["enrichment"]


def test_domain_lookup():
    r = requests.get(IOC, params={"value": "example.com"}, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["type"] == "domain"
    for name in ["VirusTotal", "urlscan.io", "Cisco Talos", "IBM X-Force"]:
        assert name in d["links"]
    en = d["enrichment"]
    assert en["kind"] == "web"
    assert "scan_count" in en
    assert isinstance(en["scan_count"], int)


def test_url_lookup():
    r = requests.get(IOC, params={"value": "https://example.com/x"}, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["type"] == "url"
    for name in ["VirusTotal", "urlscan.io", "IBM X-Force"]:
        assert name in d["links"]


def test_unrecognizable_returns_422():
    r = requests.get(IOC, params={"value": "hello world"}, timeout=15)
    assert r.status_code == 422


def test_empty_returns_400():
    r = requests.get(IOC, params={"value": ""}, timeout=15)
    assert r.status_code == 400


def test_too_long_returns_400():
    r = requests.get(IOC, params={"value": "a" * 3000}, timeout=15)
    assert r.status_code == 400
