"""Backend tests for extended NivX Forge Offline Investigation Report.
Covers: case detection, dynamic format parsing, 5W1H hits, recommendations,
and regression on prior endpoints.
"""
import os
import re
import pytest
import requests

def _load_url():
    v = os.environ.get("REACT_APP_BACKEND_URL")
    if not v:
        try:
            with open("/app/frontend/.env") as f:
                for ln in f:
                    if ln.startswith("REACT_APP_BACKEND_URL="):
                        v = ln.split("=", 1)[1].strip()
                        break
        except Exception:
            pass
    return (v or "").rstrip("/")


BASE_URL = _load_url()
FORGE = f"{BASE_URL}/api/forge/investigation-report"


def _post(payload):
    return requests.post(FORGE, json=payload, timeout=60)


# --- Case classification --------------------------------------------------

class TestCaseType:
    def test_malware_case_hash(self):
        r = _post({
            "instructions": "write in 2 paras",
            "data": "EDR alert: trojan hash 44d88612fea8a8f36de82e1278abb02f detected on host WKS-01",
            "enrich": False,
        })
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["case_type"] == "malware"
        assert any("Remove the piece of malware" in x for x in j["recommendations"])

    def test_dns_proxy_case(self):
        r = _post({
            "instructions": "write in 3 lines",
            "data": "Umbrella DNS query blocked user alice to badsite.example.com and evil-c2.test proxy log",
            "enrich": False,
        })
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["case_type"] == "dns_proxy"
        assert any("Secure Access/Umbrella" in x for x in j["recommendations"])
        # No malware-only line in DNS/proxy template
        assert not any("Remove the piece of malware" in x for x in j["recommendations"])

    def test_mixed_case(self):
        r = _post({
            "instructions": "in 4 paragraphs",
            "data": "EDR flagged sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 and Umbrella blocked http://bad.example.com/malicious",
            "enrich": False,
        })
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["case_type"] == "mixed"
        recs = j["recommendations"]
        assert any("Remove the piece of malware" in x for x in recs)
        assert any("Secure Access/Umbrella" in x for x in recs)
        # Dedup: lead-in "Determine if the detected activity was authorized or expected." appears once
        assert sum(1 for x in recs if x.startswith("Determine if the detected activity")) == 1


# --- Format parser --------------------------------------------------------

class TestFormatParsing:
    def _body_of(self, report: str) -> str:
        return report.split("\n\nRecommendations")[0]

    def test_lines_5(self):
        r = _post({"instructions": "write in 5 lines", "data": "Umbrella blocked evil.example.com from user bob at 2025-01-01T10:00:00Z", "enrich": False})
        j = r.json()
        assert j["format"] == {"mode": "lines", "count": 5, "verbose": False}
        body = self._body_of(j["report"])
        assert len(body.split("\n")) == 5

    def test_sentences_3(self):
        r = _post({"instructions": "summarize in 3 sentences", "data": "Umbrella dns query for evil.test blocked user alice device WKS", "enrich": False})
        j = r.json()
        assert j["format"]["mode"] == "sentences"
        assert j["format"]["count"] == 3

    def test_bullets(self):
        r = _post({"instructions": "output as bullet points", "data": "Umbrella blocked evil.test", "enrich": False})
        j = r.json()
        assert j["format"]["mode"] == "bullets"
        assert j["report"].lstrip().startswith("-")
        assert "Recommendations:" in j["report"]

    def test_paragraphs_1_verbose(self):
        r = _post({"instructions": "1 para with all details without missing anything", "data": "Umbrella DNS blocked user alice to evil.test at 2025-01-01T10:00:00Z", "enrich": False})
        j = r.json()
        assert j["format"] == {"mode": "paragraphs", "count": 1, "verbose": True}
        body = j["report"].split("\n\nRecommendations")[0]
        # single paragraph → no double newlines in body
        assert "\n\n" not in body


# --- 5W1H extraction ------------------------------------------------------

class TestWWWWWH:
    def test_target_hit_multiplicity(self):
        # evil-c2.test appears 3 times in the corpus
        data = ("Umbrella dns_query evil-c2.test blocked\n"
                "Umbrella dns_query evil-c2.test blocked\n"
                "Umbrella dns_query evil-c2.test blocked\n")
        r = _post({"instructions": "write in 2 paras", "data": data, "enrich": False})
        j = r.json()
        assert j["case_type"] == "dns_proxy"
        assert re.search(r"evil-c2\.test\s*\(×\s*3\)", j["report"]), j["report"]

    def test_action_counts_surface(self):
        data = ("Umbrella blocked user alice evil.test\n" * 4 +
                "Umbrella allowed user alice ok.test\n" * 2 +
                "Umbrella quarantined evil.test\n")
        r = _post({"instructions": "in 3 paras", "data": data, "enrich": False})
        j = r.json()
        rep = j["report"]
        assert "Volume of activity:" in rep
        assert "blocked" in rep and "allowed" in rep and "quarantined" in rep


# --- Regression ----------------------------------------------------------

class TestRegression:
    def test_batch_summary(self):
        r = requests.post(f"{BASE_URL}/api/iocs/batch-summary",
                          json={"values": ["8.8.8.8", "1.1.1.1"]}, timeout=60)
        assert r.status_code == 200, r.text
        j = r.json()
        assert "summary" in j and "stats" in j

    def test_lookup_batch(self):
        r = requests.post(f"{BASE_URL}/api/ioc-lookup-batch",
                          json={"values": ["8.8.8.8"]}, timeout=60)
        assert r.status_code == 200, r.text

    def test_cyberlab_enrich(self):
        r = requests.post(f"{BASE_URL}/api/cyberlab/enrich-iocs",
                          json={"values": ["8.8.8.8"]}, timeout=60)
        assert r.status_code == 200, r.text

    def test_ioc_ai_summary(self):
        r = requests.post(f"{BASE_URL}/api/ioc-ai-summary",
                          json={"value": "8.8.8.8"}, timeout=60)
        assert r.status_code == 200, r.text
