"""Iteration 30 backend tests — OCR endpoint, attachment OCR, AI investigation report, and regression endpoints."""
import io
import os
import pytest
import requests
from PIL import Image, ImageDraw, ImageFont

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
ADMIN_EMAIL = "admin@nivxmachines.com"
ADMIN_PW = "NivX@Admin2025"


def _png_bytes(text="ALERT hostname host-99 ip 8.8.8.8", size=(600, 200)):
    img = Image.new("RGB", size, "white")
    d = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 28)
    except Exception:
        font = ImageFont.load_default()
    d.text((10, 60), text, fill="black", font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@pytest.fixture(scope="module")
def s():
    return requests.Session()


@pytest.fixture(scope="module")
def admin_token(s):
    r = s.post(f"{BASE_URL}/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PW})
    assert r.status_code == 200, r.text
    tok = r.json().get("access_token")
    assert tok
    return tok


# --- OCR endpoint ---
class TestOCRImage:
    def test_ocr_success_png(self, s):
        png = _png_bytes()
        r = s.post(f"{BASE_URL}/api/forge/ocr-image",
                   files={"file": ("alert.png", png, "image/png")})
        assert r.status_code == 200, r.text
        data = r.json()
        assert set(["filename", "mime", "bytes", "text", "char_count", "line_count"]).issubset(data.keys())
        assert data["bytes"] == len(png)
        assert data["char_count"] == len(data["text"])
        # text should contain some recognisable substring
        assert data["char_count"] > 0

    def test_ocr_rejects_non_image_415(self, s):
        r = s.post(f"{BASE_URL}/api/forge/ocr-image",
                   files={"file": ("note.txt", b"hello world", "text/plain")})
        assert r.status_code == 415

    def test_ocr_rejects_oversize_413(self, s):
        # Create ~11MB junk with image mimetype (server checks size before decoding).
        big = b"\x89PNG\r\n\x1a\n" + b"0" * (11 * 1024 * 1024)
        r = s.post(f"{BASE_URL}/api/forge/ocr-image",
                   files={"file": ("big.png", big, "image/png")})
        assert r.status_code == 413

    def test_ocr_empty_400(self, s):
        r = s.post(f"{BASE_URL}/api/forge/ocr-image",
                   files={"file": ("x.png", b"", "image/png")})
        assert r.status_code == 400


# --- Attachment upload w/ OCR ---
class TestAttachmentOCR:
    def test_image_attachment_gets_ocr_text(self, s, admin_token):
        headers = {"Authorization": f"Bearer {admin_token}"}
        # create example
        r = s.post(f"{BASE_URL}/api/admin/forge/training/examples",
                   json={"title": "TEST_iter30_ocr", "case_type": "phishing",
                         "raw_input": "TEST raw", "expected_output": "TEST expected"},
                   headers=headers)
        assert r.status_code in (200, 201), r.text
        ex_id = r.json()["id"]
        try:
            png = _png_bytes("PHISHING attachment sample")
            r2 = s.post(f"{BASE_URL}/api/admin/forge/training/examples/{ex_id}/attachments",
                        files={"file": ("shot.png", png, "image/png")},
                        headers=headers)
            assert r2.status_code == 200, r2.text
            att = r2.json()
            assert att["kind"] == "image"
            assert "ocr_text" in att
            assert isinstance(att["ocr_text"], str)
            assert len(att["ocr_text"]) > 0

            # non-image: ocr_text should be ""
            r3 = s.post(f"{BASE_URL}/api/admin/forge/training/examples/{ex_id}/attachments",
                        files={"file": ("note.txt", b"plain text file", "text/plain")},
                        headers=headers)
            assert r3.status_code == 200, r3.text
            att2 = r3.json()
            assert att2["kind"] == "file"
            assert att2.get("ocr_text", "") == ""
        finally:
            s.delete(f"{BASE_URL}/api/admin/forge/training/examples/{ex_id}", headers=headers)


# --- Investigation report AI mode ---
class TestInvestigationReport:
    RAW = "2026-01-05 12:03 SRC=host-42 USER=jsmith DST=8.8.8.8 EVENT=suspicious_download file=payload.exe"

    def test_offline_mode(self, s):
        r = s.post(f"{BASE_URL}/api/forge/investigation-report",
                   json={"data": self.RAW, "ai_mode": False, "instructions": "2 paragraphs"})
        assert r.status_code == 200, r.text
        j = r.json()
        assert j.get("engine") in ("deterministic", "offline")

    def test_ai_mode(self, s):
        r = s.post(f"{BASE_URL}/api/forge/investigation-report",
                   json={"data": self.RAW, "ai_mode": True, "instructions": "2 paragraphs",
                         "ai_model": "gemini-3-flash-preview"})
        assert r.status_code == 200, r.text
        j = r.json()
        assert j.get("engine") == "ai", j
        assert j.get("ai_model"), "ai_model missing in AI response"
        assert "gemini" in str(j.get("ai_model")).lower()


# --- Regression: previously-working endpoints still 200 ---
class TestRegression:
    IOCS = ["8.8.8.8", "example.com"]

    def test_ioc_lookup_batch(self, s):
        r = s.post(f"{BASE_URL}/api/ioc-lookup-batch", json={"values": self.IOCS})
        assert r.status_code == 200, r.text

    def test_iocs_batch_summary(self, s):
        r = s.post(f"{BASE_URL}/api/iocs/batch-summary", json={"values": self.IOCS})
        assert r.status_code == 200, r.text

    def test_cyberlab_enrich(self, s):
        r = s.post(f"{BASE_URL}/api/cyberlab/enrich-iocs", json={"values": self.IOCS})
        assert r.status_code == 200, r.text

    def test_admin_training_requires_auth(self, s):
        r = s.get(f"{BASE_URL}/api/admin/forge/training/examples")
        assert r.status_code in (401, 403)

    def test_admin_training_with_auth(self, s, admin_token):
        r = s.get(f"{BASE_URL}/api/admin/forge/training/examples",
                  headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
