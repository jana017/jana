"""Pytest coverage for the Site CMS + file uploads + branding endpoints.

Verifies:
- Admin-only endpoints enforce auth
- Public endpoints (admin-tabs, landing-sections, announcement, pages, branding) are readable without a token
- File upload + serve + delete works for common formats
- Custom pages CRUD works
- Markdown → HTML rendering escapes user input safely
- Everything is offline-safe (no LLM imports in cms/)
"""
from __future__ import annotations

import io
import os
import time

import httpx
import pytest

BASE = os.environ.get("CYBERLAB_TEST_BASE", "http://localhost:8001")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@nivxmachines.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "NivX@Admin2025")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE, timeout=45.0) as c:
        yield c


@pytest.fixture(scope="module")
def admin_headers(client):
    r = client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ---------------------------------------------------------------------------
# Public reads
# ---------------------------------------------------------------------------
def test_admin_tabs_public_read(client):
    r = client.get("/api/cms/admin-tabs")
    assert r.status_code == 200
    tabs = r.json()
    ids = {t["id"] for t in tabs}
    assert {"overview", "settings", "webhooks", "healthbot", "cms"} <= ids


def test_landing_sections_public_read(client):
    r = client.get("/api/cms/landing-sections")
    assert r.status_code == 200
    secs = r.json()
    assert isinstance(secs, list) and len(secs) >= 5
    # ordered ascending
    orders = [s["order"] for s in secs]
    assert orders == sorted(orders)


def test_announcement_public_read(client):
    r = client.get("/api/cms/announcement")
    assert r.status_code == 200
    assert "active" in r.json()


def test_branding_public_read(client):
    r = client.get("/api/cms/branding")
    assert r.status_code == 200
    b = r.json()
    for k in ("logo_url", "favicon_url", "site_title", "custom_css", "custom_js"):
        assert k in b


# ---------------------------------------------------------------------------
# Admin-only enforcement
# ---------------------------------------------------------------------------
def test_admin_endpoints_require_auth(client):
    for method, path in [
        ("PUT", "/api/cms/admin-tabs"),
        ("PUT", "/api/cms/landing-sections"),
        ("PUT", "/api/cms/announcement"),
        ("PUT", "/api/cms/branding"),
        ("POST", "/api/cms/pages"),
        ("GET", "/api/cms/files"),
        ("POST", "/api/cms/files"),
    ]:
        r = client.request(method, path, json={} if method != "GET" else None)
        assert r.status_code in (401, 422), f"{method} {path} → {r.status_code}"


# ---------------------------------------------------------------------------
# Pages CRUD
# ---------------------------------------------------------------------------
def test_pages_crud(client, admin_headers):
    slug = f"pytest-{int(time.time())}"
    # Create
    r = client.post("/api/cms/pages", headers=admin_headers, json={
        "slug": slug, "title": "Pytest page",
        "markdown_body": "# Hello\n\nThis is **bold** and `code`.",
        "published": True,
    })
    assert r.status_code == 201, r.text
    page = r.json()
    assert page["slug"] == slug
    assert "<h1>Hello</h1>" in page["html_body"]
    assert "<strong>bold</strong>" in page["html_body"]
    assert "<code>code</code>" in page["html_body"]

    # Public fetch
    r = client.get(f"/api/cms/pages/{slug}")
    assert r.status_code == 200

    # Update
    r = client.patch(f"/api/cms/pages/{slug}", headers=admin_headers, json={"title": "Renamed"})
    assert r.status_code == 200
    assert r.json()["title"] == "Renamed"

    # Draft → 404 for public
    r = client.patch(f"/api/cms/pages/{slug}", headers=admin_headers, json={"published": False})
    assert r.status_code == 200
    assert client.get(f"/api/cms/pages/{slug}").status_code == 404

    # Delete
    r = client.delete(f"/api/cms/pages/{slug}", headers=admin_headers)
    assert r.status_code == 200


def test_markdown_escapes_html_injection(client, admin_headers):
    slug = f"esc-{int(time.time())}"
    payload = {
        "slug": slug, "title": "esc",
        "markdown_body": '<script>alert(1)</script> hello',
        "published": True,
    }
    r = client.post("/api/cms/pages", headers=admin_headers, json=payload)
    assert r.status_code == 201
    html = r.json()["html_body"]
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    client.delete(f"/api/cms/pages/{slug}", headers=admin_headers)


# ---------------------------------------------------------------------------
# File uploads
# ---------------------------------------------------------------------------
def test_file_upload_and_serve(client, admin_headers):
    # 1x1 transparent PNG
    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
        "0000000d49444154789c626001000000ffff03000006000557bfabd400000000"
        "49454e44ae426082"
    )
    r = client.post(
        "/api/cms/files", headers=admin_headers,
        files={"file": ("tiny.png", png, "image/png")},
    )
    assert r.status_code == 201, r.text
    meta = r.json()
    assert meta["content_type"] == "image/png"
    assert meta["size"] > 0
    assert meta["url"].startswith("/api/cms/files/") and meta["url"].endswith("/raw")

    # Public serve
    r = client.get(meta["url"])
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/png")
    assert len(r.content) == meta["size"]

    # Listing
    r = client.get("/api/cms/files", headers=admin_headers)
    assert r.status_code == 200
    assert any(f["id"] == meta["id"] for f in r.json())

    # Delete
    r = client.delete(f"/api/cms/files/{meta['id']}", headers=admin_headers)
    assert r.status_code == 200


def test_file_upload_accepts_any_format(client, admin_headers):
    """Every content type — PDFs, text, arbitrary binary — must be accepted."""
    cases = [
        ("hello.txt", b"just some text", "text/plain"),
        ("data.json", b'{"ok":true}', "application/json"),
        ("blob.bin", bytes(range(256)), "application/octet-stream"),
    ]
    for name, blob, ct in cases:
        r = client.post(
            "/api/cms/files", headers=admin_headers,
            files={"file": (name, blob, ct)},
        )
        assert r.status_code == 201, f"{name} → {r.text}"
        client.delete(f"/api/cms/files/{r.json()['id']}", headers=admin_headers)


# ---------------------------------------------------------------------------
# Offline safety
# ---------------------------------------------------------------------------
def test_cms_is_offline_safe():
    """CMS module must not import LLM or external-network libraries."""
    import importlib
    router_mod = importlib.import_module("cms.router")
    files_mod = importlib.import_module("cms.files")
    for mod in (router_mod, files_mod):
        with open(mod.__file__, "r", encoding="utf-8") as fh:
            src = fh.read()
        for forbidden in ("emergentintegrations", "openai", "anthropic",
                          "google.generativeai", "aiohttp", "requests.get"):
            assert forbidden not in src, f"{mod.__name__} must not import {forbidden}"
