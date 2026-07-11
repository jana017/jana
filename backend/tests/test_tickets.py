"""End-to-end tests for the Phase 2 ticketing system."""
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
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="module")
def emp_context(client, admin_headers):
    """Create a throwaway employee + their auth header. Torn down at end."""
    unique = uuid.uuid4().hex[:6]
    payload = {
        "name": f"TicketEmp {unique}",
        "email": f"ticket-{unique}@nivxtest.com",
        "employee_id": f"NVX-TT-{unique}",
    }
    r = client.post("/api/admin/employees", json=payload, headers=admin_headers)
    assert r.status_code == 200, r.text
    eid = r.json()["id"]
    temp = r.json()["temp_password"]
    login = client.post("/api/auth/login", json={"email": payload["email"], "password": temp})
    assert login.status_code == 200
    hdr = {"Authorization": f"Bearer {login.json()['access_token']}"}
    yield {"id": eid, "email": payload["email"], "headers": hdr}
    client.delete(f"/api/admin/employees/{eid}", headers=admin_headers)


def _make_ticket(client, hdr, **overrides):
    payload = {
        "category": "hardware",
        "priority": "high",
        "subject": f"Test ticket {uuid.uuid4().hex[:6]}",
        "description": "Repro steps: try to turn on laptop. Nothing happens.",
    }
    payload.update(overrides)
    return client.post("/api/tickets", json=payload, headers=hdr)


# ---------- Creation & validation -----------------------------------------
def test_employee_can_create_ticket(client, emp_context):
    r = _make_ticket(client, emp_context["headers"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ticket_id"].startswith("NVX-T-")
    assert body["status"] == "open"
    assert body["employee_email"] == emp_context["email"]
    assert body["comments"] == []


def test_invalid_category_rejected(client, emp_context):
    r = _make_ticket(client, emp_context["headers"], category="notacat")
    assert r.status_code == 400
    assert "category" in r.json()["detail"]


def test_invalid_priority_rejected(client, emp_context):
    r = _make_ticket(client, emp_context["headers"], priority="critical")
    assert r.status_code == 400


def test_short_subject_rejected(client, emp_context):
    r = _make_ticket(client, emp_context["headers"], subject="hi")
    assert r.status_code == 422  # Pydantic min_length


# ---------- Listing & isolation -------------------------------------------
def test_employee_only_sees_own_tickets(client, admin_headers, emp_context):
    # Create ticket as our employee
    r1 = _make_ticket(client, emp_context["headers"])
    my_tid = r1.json()["ticket_id"]
    # Second isolated employee
    unique = uuid.uuid4().hex[:6]
    other = client.post("/api/admin/employees", json={
        "name": "Other", "email": f"other-{unique}@nivxtest.com", "employee_id": f"NVX-O-{unique}"
    }, headers=admin_headers).json()
    other_login = client.post("/api/auth/login", json={"email": f"other-{unique}@nivxtest.com", "password": other["temp_password"]})
    other_hdr = {"Authorization": f"Bearer {other_login.json()['access_token']}"}
    try:
        # Other user's tickets list must NOT contain my ticket
        lst = client.get("/api/tickets/mine", headers=other_hdr).json()["items"]
        assert not any(t["ticket_id"] == my_tid for t in lst)
        # Nor can they fetch it by id
        r = client.get(f"/api/tickets/{my_tid}", headers=other_hdr)
        assert r.status_code == 403
    finally:
        client.delete(f"/api/admin/employees/{other['id']}", headers=admin_headers)


def test_admin_can_view_any_ticket(client, admin_headers, emp_context):
    r1 = _make_ticket(client, emp_context["headers"])
    tid = r1.json()["ticket_id"]
    r = client.get(f"/api/tickets/{tid}", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["ticket_id"] == tid


# ---------- Admin actions -------------------------------------------------
def test_admin_can_change_status_and_priority(client, admin_headers, emp_context):
    r1 = _make_ticket(client, emp_context["headers"])
    tid = r1.json()["ticket_id"]
    r = client.patch(f"/api/admin/tickets/{tid}", json={"status": "in_progress", "priority": "urgent"}, headers=admin_headers)
    assert r.status_code == 200
    updated = r.json()
    assert updated["status"] == "in_progress"
    assert updated["priority"] == "urgent"
    # Audit trail: system comments appended
    system_comments = [c for c in updated["comments"] if c["author_role"] == "system"]
    assert len(system_comments) >= 2


def test_admin_can_assign_and_resolve(client, admin_headers, emp_context):
    tid = _make_ticket(client, emp_context["headers"]).json()["ticket_id"]
    client.patch(f"/api/admin/tickets/{tid}", json={"assigned_to": "admin@nivxmachines.com"}, headers=admin_headers)
    resolved = client.patch(f"/api/admin/tickets/{tid}", json={"status": "resolved"}, headers=admin_headers).json()
    assert resolved["status"] == "resolved"
    assert resolved["resolved_at"] is not None


def test_employee_cannot_change_status(client, admin_headers, emp_context):
    tid = _make_ticket(client, emp_context["headers"]).json()["ticket_id"]
    r = client.patch(f"/api/admin/tickets/{tid}", json={"status": "closed"}, headers=emp_context["headers"])
    assert r.status_code == 403


# ---------- Comments ------------------------------------------------------
def test_employee_and_admin_can_comment(client, admin_headers, emp_context):
    tid = _make_ticket(client, emp_context["headers"]).json()["ticket_id"]
    e_reply = client.post(f"/api/tickets/{tid}/comment", json={"body": "Update from employee"}, headers=emp_context["headers"])
    assert e_reply.status_code == 200
    assert e_reply.json()["author_role"] == "employee"
    a_reply = client.post(f"/api/tickets/{tid}/comment", json={"body": "Working on it"}, headers=admin_headers)
    assert a_reply.status_code == 200
    assert a_reply.json()["author_role"] == "admin"
    detail = client.get(f"/api/tickets/{tid}", headers=emp_context["headers"]).json()
    bodies = [c["body"] for c in detail["comments"]]
    assert "Update from employee" in bodies
    assert "Working on it" in bodies


def test_cannot_comment_on_closed_ticket(client, admin_headers, emp_context):
    tid = _make_ticket(client, emp_context["headers"]).json()["ticket_id"]
    client.patch(f"/api/admin/tickets/{tid}", json={"status": "closed"}, headers=admin_headers)
    r = client.post(f"/api/tickets/{tid}/comment", json={"body": "Post-close"}, headers=emp_context["headers"])
    assert r.status_code == 400


# ---------- Stats + filters ----------------------------------------------
def test_admin_stats_and_filters(client, admin_headers, emp_context):
    _make_ticket(client, emp_context["headers"], priority="urgent", category="email")
    _make_ticket(client, emp_context["headers"], priority="low", category="software")
    stats = client.get("/api/admin/tickets/stats", headers=admin_headers).json()
    assert stats["total"] >= 2
    assert "open" in stats["by_status"]
    # Filter by priority
    lst = client.get("/api/admin/tickets?priority=urgent", headers=admin_headers).json()["items"]
    assert all(t["priority"] == "urgent" for t in lst)
    # Filter by category
    lst = client.get("/api/admin/tickets?category=email", headers=admin_headers).json()["items"]
    assert all(t["category"] == "email" for t in lst)
