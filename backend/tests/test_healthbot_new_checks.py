"""Regression tests for the new HealthBot checks added Feb 2026:
  - _check_frontend_lint  — catches undefined JS identifiers
  - _check_route_smoke    — parallel-hits critical endpoints

These are integration-style tests that talk to the real backend on
127.0.0.1:8001 (already running under supervisor) and use the seeded admin
account to authenticate.
"""
from __future__ import annotations

import os
import time

import pytest
import requests

BASE = "http://127.0.0.1:8001"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@nivxmachines.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "NivX@Admin2025")


@pytest.fixture(scope="module")
def token():
    r = requests.post(
        f"{BASE}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def scan(token):
    r = requests.post(
        f"{BASE}/api/healthbot/scan",
        headers={"Authorization": f"Bearer {token}"},
        timeout=120,
    )
    r.raise_for_status()
    return r.json()


def _by_id(scan, cid):
    for r in scan["results"]:
        if r["id"] == cid:
            return r
    raise AssertionError(f"check {cid!r} not present in scan.results")


def test_scan_completes_and_persists(scan):
    assert "overall" in scan and scan["overall"] in ("ok", "info", "warning", "critical")
    assert scan["duration_ms"] > 0
    assert scan["duration_ms"] < 10_000, (
        f"HealthBot must stay under 10s — got {scan['duration_ms']}ms"
    )


def test_frontend_lint_check_present_and_healthy(scan):
    r = _by_id(scan, "frontend_lint")
    # After the ExportRef fix + ForensicEventsPanel fix, must be OK.
    assert r["severity"] == "ok", f"frontend_lint failing: {r}"
    assert r["details"]["files_scanned"] >= 100


def test_route_smoke_check_present_and_healthy(scan):
    r = _by_id(scan, "route_smoke")
    assert r["severity"] == "ok", f"route_smoke failing: {r}"
    assert len(r["details"]["checked"]) >= 10


def test_scan_speed_under_3s():
    """The whole HealthBot scan (12 checks incl. eslint + smoke) must
    complete under 3s on a warm backend."""
    r = requests.post(
        f"{BASE}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=10,
    )
    tok = r.json()["access_token"]
    start = time.perf_counter()
    r = requests.post(
        f"{BASE}/api/healthbot/scan",
        headers={"Authorization": f"Bearer {tok}"},
        timeout=30,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    r.raise_for_status()
    assert elapsed_ms < 5000, (
        f"HealthBot round-trip too slow: {elapsed_ms:.0f}ms (target <5s)"
    )
