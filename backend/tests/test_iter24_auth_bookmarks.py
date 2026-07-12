"""Iteration 24: E2E tests for user signup/login, bookmarks, watchlist, RBAC, feeds."""
import os
import time
import uuid
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://threat-intel-hub-85.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"

ADMIN_EMAIL = "admin@nivxmachines.com"
ADMIN_PASS = "NivX@Admin2025"


@pytest.fixture(scope="module")
def user_creds():
    return {
        "email": f"test_iter24_{uuid.uuid4().hex[:8]}@example.com",
        "password": "TestPass1234",
        "name": "Iter24 Test User",
    }


@pytest.fixture(scope="module")
def user_token(user_creds):
    r = requests.post(f"{API}/auth/signup", json=user_creds, timeout=15)
    if r.status_code == 429:
        pytest.skip("Signup rate limited")
    assert r.status_code == 200, f"signup failed: {r.status_code} {r.text}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def admin_token():
    r = requests.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASS}, timeout=15)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


# ---------- Auth ----------

def test_signup_and_role(user_token, user_creds):
    r = requests.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {user_token}"}, timeout=15)
    assert r.status_code == 200
    data = r.json()
    assert data["email"] == user_creds["email"]
    assert data["role"] == "user"


def test_weak_password_rejected():
    email = f"test_weak_{uuid.uuid4().hex[:8]}@example.com"
    r = requests.post(f"{API}/auth/signup", json={"email": email, "password": "passwordonly", "name": "x"}, timeout=15)
    if r.status_code == 429:
        pytest.skip("rate limited")
    assert r.status_code in (400, 422), f"expected reject, got {r.status_code}: {r.text}"


def test_duplicate_email_rejected(user_creds):
    r = requests.post(f"{API}/auth/signup", json=user_creds, timeout=15)
    if r.status_code == 429:
        pytest.skip("rate limited")
    assert r.status_code in (400, 409), f"expected dup reject, got {r.status_code}: {r.text}"


# ---------- RBAC ----------

def test_user_blocked_from_threats_post(user_token):
    r = requests.post(
        f"{API}/threats",
        headers={"Authorization": f"Bearer {user_token}"},
        json={"title": "hack", "description": "x", "severity": "low", "category": "test"},
        timeout=15,
    )
    assert r.status_code == 403, f"expected 403 for user creating threat, got {r.status_code}"


def test_admin_can_get_me(admin_token):
    r = requests.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {admin_token}"}, timeout=15)
    assert r.status_code == 200
    assert r.json()["role"] == "admin"


# ---------- Bookmarks ----------

def test_bookmark_add_and_list(user_token):
    h = {"Authorization": f"Bearer {user_token}"}
    r = requests.post(f"{API}/me/bookmarks/threatbox/lockbit", headers=h, timeout=15)
    assert r.status_code in (200, 201), f"bookmark add: {r.status_code} {r.text}"

    r2 = requests.get(f"{API}/me/bookmarks", headers=h, timeout=15)
    assert r2.status_code == 200
    data = r2.json()
    bms = data.get("bookmarks", [])
    slugs = [b.get("slug") if isinstance(b, dict) else b for b in bms]
    assert "lockbit" in slugs, f"lockbit not in bookmarks: {slugs}"


def test_bookmark_remove(user_token):
    h = {"Authorization": f"Bearer {user_token}"}
    r = requests.delete(f"{API}/me/bookmarks/threatbox/lockbit", headers=h, timeout=15)
    assert r.status_code in (200, 204)


# ---------- Watchlist ----------

def test_watchlist_add_valid_ip(user_token):
    h = {"Authorization": f"Bearer {user_token}"}
    r = requests.post(f"{API}/me/watchlist", json={"value": "1.1.1.1", "note": "Cloudflare DNS"}, headers=h, timeout=15)
    assert r.status_code in (200, 201), f"watchlist add: {r.status_code} {r.text}"
    body = r.json()
    # verify persistence
    r2 = requests.get(f"{API}/me/watchlist", headers=h, timeout=15)
    assert r2.status_code == 200
    items = r2.json() if isinstance(r2.json(), list) else r2.json().get("watchlist", [])
    vals = [i.get("value") for i in items]
    assert "1.1.1.1" in vals


def test_watchlist_duplicate_rejected(user_token):
    h = {"Authorization": f"Bearer {user_token}"}
    r = requests.post(f"{API}/me/watchlist", json={"value": "1.1.1.1", "note": "dup"}, headers=h, timeout=15)
    assert r.status_code in (400, 409), f"expected duplicate reject, got {r.status_code}: {r.text}"


def test_watchlist_invalid_rejected(user_token):
    h = {"Authorization": f"Bearer {user_token}"}
    r = requests.post(f"{API}/me/watchlist", json={"value": "not an ioc", "note": "bad"}, headers=h, timeout=15)
    assert r.status_code in (400, 422), f"expected invalid reject, got {r.status_code}: {r.text}"


# ---------- Threat Intelligence / ThreatBox ----------

def test_threat_actors_index():
    r = requests.get(f"{API}/actors", timeout=15)
    assert r.status_code == 200, f"actors list: {r.status_code}"
    data = r.json()
    items = data if isinstance(data, list) else data.get("actors", []) or data.get("items", [])
    assert len(items) >= 16, f"expected >=16 actors, got {len(items)}"


def test_apt41_related_incidents():
    # actor_slug FK cross-linking
    r = requests.get(f"{API}/actors/apt41", timeout=15)
    assert r.status_code == 200


# ---------- Live Feed pagination ----------

def test_live_feed_limit_50():
    r = requests.get(f"{API}/live-feed?limit=50", timeout=20)
    assert r.status_code == 200
    items = r.json().get("items", [])
    assert len(items) <= 50


def test_live_feed_limit_200():
    r = requests.get(f"{API}/live-feed?limit=200", timeout=20)
    assert r.status_code == 200
    items = r.json().get("items", [])
    assert len(items) <= 200
    assert len(items) > 50  # should return more than 50


def test_live_feed_limit_cap_500():
    r = requests.get(f"{API}/live-feed?limit=99999", timeout=20)
    assert r.status_code == 200
    items = r.json().get("items", [])
    assert len(items) <= 500


# ---------- Feed Collectors ----------

def test_ioc_sync_status_has_new_feeds():
    r = requests.get(f"{API}/iocs/sync-status", timeout=15)
    assert r.status_code == 200
    data = r.json()
    # data could be dict with entries or list
    if isinstance(data, dict):
        keys = list(data.keys())
        # possibly nested
        text = str(data).lower()
    else:
        text = str(data).lower()
    for feed in ["urlhaus", "threatfox", "cins"]:
        assert feed in text, f"missing feed {feed} in sync-status"


# ---------- Backward compat ----------

def test_actors_backward_compat():
    r = requests.get(f"{API}/actors/lockbit", timeout=15, allow_redirects=True)
    assert r.status_code == 200, f"actors/lockbit: {r.status_code}"
