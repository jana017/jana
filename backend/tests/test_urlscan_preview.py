"""Regression tests for the urlscan preview + subdomain-fallback logic
and the "never cache empty results" contract for free-enrichment providers.

Runs against the live localhost:8001 backend (same pattern as the other tests).
"""
from __future__ import annotations
import os
import pytest
import httpx


BASE = os.environ.get("CYBERLAB_TEST_BASE", "http://localhost:8001")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE, timeout=45.0) as c:
        yield c


def _clear_urlscan_cache(host: str):
    """Delete any existing cache entry for a host so the test hits urlscan."""
    from dotenv import load_dotenv
    load_dotenv("/app/backend/.env")
    from pymongo import MongoClient
    c = MongoClient(os.environ["MONGO_URL"])
    db = c[os.environ["DB_NAME"]]
    db.ioc_enrich_cache.delete_many({"provider": "urlscan", "key": host})
    c.close()


def test_urlscan_preview_exact_host(client):
    """A well-known domain with plenty of exact-host urlscan scans returns
    a preview screenshot + at least 1 recent scan."""
    _clear_urlscan_cache("google.com")
    r = client.get("/api/ioc-lookup", params={"value": "google.com"})
    assert r.status_code == 200
    en = (r.json().get("enrichment") or {})
    assert en.get("kind") == "web"
    assert en.get("scan_count", 0) > 100, f"expected many scans, got {en.get('scan_count')}"
    assert en.get("preview"), "urlscan preview must be present for popular domains"
    assert en["preview"]["screenshot"].startswith("https://urlscan.io/screenshots/")


def test_urlscan_subdomain_fallback(client):
    """cloudflare.com root is rarely scanned, but many subdomains are.
    Subdomain fallback must surface a preview screenshot rather than empty."""
    _clear_urlscan_cache("cloudflare.com")
    r = client.get("/api/ioc-lookup", params={"value": "cloudflare.com"})
    assert r.status_code == 200
    en = (r.json().get("enrichment") or {})
    assert en.get("preview"), "subdomain fallback must produce a preview"
    preview_host = en["preview"]["url"].split("/")[2].split(":")[0]
    # Preview URL must be cloudflare.com root OR one of its subdomains
    assert preview_host == "cloudflare.com" or preview_host.endswith(".cloudflare.com"), (
        f"preview URL {en['preview']['url']} is not a cloudflare.com subdomain"
    )


def test_urlscan_negative_results_are_not_cached(client):
    """A host that yields no urlscan matches must NOT be poisoned into cache,
    so subsequent lookups keep re-trying and can recover."""
    from dotenv import load_dotenv
    load_dotenv("/app/backend/.env")
    from pymongo import MongoClient
    c = MongoClient(os.environ["MONGO_URL"])
    db = c[os.environ["DB_NAME"]]
    # Pick a host that almost certainly has zero urlscan entries.
    junk = "totally-nonexistent-host-abc12345.invalid"
    db.ioc_enrich_cache.delete_many({"provider": "urlscan", "key": junk})
    r = client.get("/api/ioc-lookup", params={"value": junk})
    assert r.status_code == 200
    # No cache entry should have been written for the empty result.
    doc = db.ioc_enrich_cache.find_one({"provider": "urlscan", "key": junk})
    assert doc is None, "empty urlscan result was cached — will poison future lookups"
    c.close()
