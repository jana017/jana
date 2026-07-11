"""End-to-end tests for the Employee Portal (Phase 1)."""
import io
import os
import uuid

import httpx
import pytest


BASE = os.environ.get("CYBERLAB_TEST_BASE", "http://localhost:8001")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@nivxmachines.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "NivX@Admin2025")


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE, timeout=30.0) as c:
        yield c


@pytest.fixture(scope="module")
def admin_headers(client):
    r = client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _new_employee_payload():
    unique = uuid.uuid4().hex[:6]
    return {
        "name": f"Test Emp {unique}",
        "email": f"test-{unique}@nivxtest.com",
        "employee_id": f"NVX-{unique}",
        "department": "QA",
        "designation": "Tester",
        "joining_date": "2025-01-15",
    }


def _cleanup(client, admin_headers, emp_id):
    if emp_id:
        client.delete(f"/api/admin/employees/{emp_id}", headers=admin_headers)


# ---------- CRUD ----------------------------------------------------------
def test_create_employee_returns_temp_password(client, admin_headers):
    payload = _new_employee_payload()
    r = client.post("/api/admin/employees", json=payload, headers=admin_headers)
    assert r.status_code == 200, r.text
    data = r.json()
    try:
        assert data["email"] == payload["email"]
        assert "id" in data
        assert len(data["temp_password"]) >= 10
    finally:
        _cleanup(client, admin_headers, data.get("id"))


def test_duplicate_email_is_rejected(client, admin_headers):
    p = _new_employee_payload()
    r1 = client.post("/api/admin/employees", json=p, headers=admin_headers)
    eid = r1.json()["id"]
    try:
        # Same email → 409
        r2 = client.post("/api/admin/employees", json=p, headers=admin_headers)
        assert r2.status_code == 409
    finally:
        _cleanup(client, admin_headers, eid)


def test_non_admin_cannot_create_employees(client, admin_headers):
    p = _new_employee_payload()
    r = client.post("/api/admin/employees", json=p, headers=admin_headers)
    temp_pw = r.json()["temp_password"]
    eid = r.json()["id"]
    try:
        emp_login = client.post("/api/auth/login", json={"email": p["email"], "password": temp_pw})
        emp_headers = {"Authorization": f"Bearer {emp_login.json()['access_token']}"}
        r2 = client.post("/api/admin/employees", json=_new_employee_payload(), headers=emp_headers)
        assert r2.status_code == 403
    finally:
        _cleanup(client, admin_headers, eid)


def test_list_search_and_update(client, admin_headers):
    p = _new_employee_payload()
    r = client.post("/api/admin/employees", json=p, headers=admin_headers)
    eid = r.json()["id"]
    try:
        # Search by employee_id
        r2 = client.get(f"/api/admin/employees?q={p['employee_id']}", headers=admin_headers)
        assert r2.status_code == 200
        items = r2.json()["items"]
        assert any(it["employee_id"] == p["employee_id"] for it in items)
        # Patch
        r3 = client.patch(f"/api/admin/employees/{eid}", json={"designation": "Senior QA"}, headers=admin_headers)
        assert r3.status_code == 200
        # Verify
        r4 = client.get(f"/api/admin/employees?q={p['employee_id']}", headers=admin_headers)
        assert next(it for it in r4.json()["items"] if it["id"] == eid)["designation"] == "Senior QA"
    finally:
        _cleanup(client, admin_headers, eid)


def test_reset_password(client, admin_headers):
    p = _new_employee_payload()
    r = client.post("/api/admin/employees", json=p, headers=admin_headers)
    eid = r.json()["id"]
    try:
        r2 = client.post(f"/api/admin/employees/{eid}/reset-password", headers=admin_headers)
        assert r2.status_code == 200
        new_pw = r2.json()["temp_password"]
        assert len(new_pw) >= 10
        # New password works for login
        login = client.post("/api/auth/login", json={"email": p["email"], "password": new_pw})
        assert login.status_code == 200
    finally:
        _cleanup(client, admin_headers, eid)


# ---------- Employee self-service --------------------------------------
def test_employee_login_and_profile(client, admin_headers):
    p = _new_employee_payload()
    r = client.post("/api/admin/employees", json=p, headers=admin_headers)
    eid, temp = r.json()["id"], r.json()["temp_password"]
    try:
        login = client.post("/api/auth/login", json={"email": p["email"], "password": temp})
        assert login.status_code == 200
        assert login.json()["user"]["role"] == "employee"
        hdr = {"Authorization": f"Bearer {login.json()['access_token']}"}
        prof = client.get("/api/me/profile", headers=hdr)
        assert prof.status_code == 200
        j = prof.json()
        assert j["email"] == p["email"]
        assert j["must_change_password"] is True
        assert j["storage_limit_bytes"] > 0
    finally:
        _cleanup(client, admin_headers, eid)


def test_change_password_flow(client, admin_headers):
    p = _new_employee_payload()
    r = client.post("/api/admin/employees", json=p, headers=admin_headers)
    eid, temp = r.json()["id"], r.json()["temp_password"]
    try:
        login = client.post("/api/auth/login", json={"email": p["email"], "password": temp})
        hdr = {"Authorization": f"Bearer {login.json()['access_token']}"}
        # Wrong current password → 401
        bad = client.post("/api/me/change-password", json={"current_password": "wrong", "new_password": "NewSecurePw2026!"}, headers=hdr)
        assert bad.status_code == 401
        # Too-short new password → 400
        short = client.post("/api/me/change-password", json={"current_password": temp, "new_password": "short"}, headers=hdr)
        assert short.status_code == 400
        # Success
        ok = client.post("/api/me/change-password", json={"current_password": temp, "new_password": "NewSecurePw2026!"}, headers=hdr)
        assert ok.status_code == 200
        # Old password no longer works
        old = client.post("/api/auth/login", json={"email": p["email"], "password": temp})
        assert old.status_code == 401
        # must_change_password flag cleared
        prof = client.get("/api/me/profile", headers={"Authorization": f"Bearer {client.post('/api/auth/login', json={'email': p['email'], 'password': 'NewSecurePw2026!'}).json()['access_token']}"})
        assert prof.json()["must_change_password"] is False
    finally:
        _cleanup(client, admin_headers, eid)


def test_upload_list_download_delete_document(client, admin_headers):
    p = _new_employee_payload()
    r = client.post("/api/admin/employees", json=p, headers=admin_headers)
    eid, temp = r.json()["id"], r.json()["temp_password"]
    try:
        login = client.post("/api/auth/login", json={"email": p["email"], "password": temp})
        hdr = {"Authorization": f"Bearer {login.json()['access_token']}"}
        # Upload
        files = {"file": ("payslip.txt", io.BytesIO(b"Fake payslip content"), "text/plain")}
        up = client.post("/api/me/documents", data={"doc_type": "payslip", "notes": "Sept"}, files=files, headers=hdr)
        assert up.status_code == 200
        doc_id = up.json()["id"]
        # Invalid doc_type → 400
        bad = client.post("/api/me/documents", data={"doc_type": "notreal"}, files={"file": ("a.txt", io.BytesIO(b"x"), "text/plain")}, headers=hdr)
        assert bad.status_code == 400
        # List
        lst = client.get("/api/me/documents", headers=hdr)
        assert lst.status_code == 200
        assert any(d["id"] == doc_id for d in lst.json())
        # Download
        dl = client.get(f"/api/me/documents/{doc_id}/download", headers=hdr)
        assert dl.status_code == 200
        assert dl.content == b"Fake payslip content"
        # Cannot download other employee's doc — 404 (never see it)
        another = _new_employee_payload()
        r2 = client.post("/api/admin/employees", json=another, headers=admin_headers)
        eid2 = r2.json()["id"]
        try:
            other_login = client.post("/api/auth/login", json={"email": another["email"], "password": r2.json()["temp_password"]})
            other_hdr = {"Authorization": f"Bearer {other_login.json()['access_token']}"}
            bad_dl = client.get(f"/api/me/documents/{doc_id}/download", headers=other_hdr)
            assert bad_dl.status_code in (403, 404)
        finally:
            _cleanup(client, admin_headers, eid2)
        # Delete
        rm = client.delete(f"/api/me/documents/{doc_id}", headers=hdr)
        assert rm.status_code == 200
        # Gone
        gone = client.get(f"/api/me/documents/{doc_id}/download", headers=hdr)
        assert gone.status_code == 404
    finally:
        _cleanup(client, admin_headers, eid)


def test_delete_employee_cascades_documents(client, admin_headers):
    p = _new_employee_payload()
    r = client.post("/api/admin/employees", json=p, headers=admin_headers)
    eid, temp = r.json()["id"], r.json()["temp_password"]
    login = client.post("/api/auth/login", json={"email": p["email"], "password": temp})
    hdr = {"Authorization": f"Bearer {login.json()['access_token']}"}
    up = client.post("/api/me/documents",
                     data={"doc_type": "id_card"},
                     files={"file": ("id.txt", io.BytesIO(b"badge"), "text/plain")},
                     headers=hdr)
    assert up.status_code == 200
    # Delete employee → docs should be gone
    r2 = client.delete(f"/api/admin/employees/{eid}", headers=admin_headers)
    assert r2.status_code == 200
    # Employee can no longer login
    l2 = client.post("/api/auth/login", json={"email": p["email"], "password": temp})
    assert l2.status_code == 401


def test_admin_can_upload_and_list_for_employee(client, admin_headers):
    p = _new_employee_payload()
    r = client.post("/api/admin/employees", json=p, headers=admin_headers)
    eid = r.json()["id"]
    try:
        up = client.post(
            f"/api/admin/employees/{eid}/documents",
            data={"doc_type": "offer_letter"},
            files={"file": ("offer.txt", io.BytesIO(b"You are hired"), "text/plain")},
            headers=admin_headers,
        )
        assert up.status_code == 200
        lst = client.get(f"/api/admin/employees/{eid}/documents", headers=admin_headers)
        assert lst.status_code == 200
        docs = lst.json()
        assert len(docs) == 1 and docs[0]["doc_type"] == "offer_letter"
    finally:
        _cleanup(client, admin_headers, eid)
