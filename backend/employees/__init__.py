"""Employee Portal — Phase 1 (Employees CRUD + Document Management).

Design notes
------------
* Employees are stored in the SAME `users` collection with `role: "employee"`.
* Login uses the existing `/api/auth/login` flow. After login, the frontend
  reads `role` from the JWT payload / /auth/me response and redirects
  admins → /admin, employees → /employee.
* Documents are stored via MongoDB GridFS (already used by the CMS module).
  Metadata (owner_employee_id, doc_type, filename, size, notes) lives in a
  dedicated `employee_documents` collection so listing / filtering is fast.
* Storage limit: 50 MB total per employee (configurable via `EMPLOYEE_MAX_MB`).
* Doc types are validated against a whitelist. Free-form "other" bucket
  captures anything not in the standard set.
* Email delivery is intentionally NOT wired in v1 — admin sees the temp
  password on-screen right after creation with a copy button. This ships
  fastest and doesn't need an external key.

No LLM. No external HTTP.
"""
from __future__ import annotations

import io
import logging
import os
import secrets
import string
from datetime import datetime, timezone
from typing import Any, List, Optional

import bcrypt
from bson import ObjectId
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pydantic import BaseModel, EmailStr, Field

logger = logging.getLogger("nivx.employees")

router = APIRouter(prefix="/api", tags=["employees"])

# ---------------------------------------------------------------------------
# Config + constants
# ---------------------------------------------------------------------------
DOC_TYPES = {
    "payslip", "pf_details", "ff_settlement", "id_card",
    "offer_letter", "hike_letter", "experience_letter", "relieving_letter",
    "appraisal_letter", "tax_form", "other",
}
MAX_TOTAL_BYTES = int(os.environ.get("EMPLOYEE_MAX_MB", "50")) * 1024 * 1024
MAX_FILE_BYTES  = 25 * 1024 * 1024                            # per-file
ALLOWED_MIMES = {
    "application/pdf",
    "image/png", "image/jpeg", "image/webp",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain", "text/csv",
    "application/zip",
}


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _gen_temp_password(length: int = 14) -> str:
    """URL-safe, mixed-case, digit + symbol, unambiguous chars only."""
    alphabet = string.ascii_letters + string.digits + "!@#$%&*"
    # Guarantee at least one of each class
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%&*"),
    ]
    pwd += [secrets.choice(alphabet) for _ in range(length - len(pwd))]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class EmployeeCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    employee_id: str = Field(min_length=1, max_length=40)
    department: Optional[str] = None
    designation: Optional[str] = None
    joining_date: Optional[str] = None       # ISO YYYY-MM-DD
    phone: Optional[str] = None
    manager_email: Optional[EmailStr] = None
    notes: Optional[str] = None


class EmployeeUpdate(BaseModel):
    name: Optional[str] = None
    department: Optional[str] = None
    designation: Optional[str] = None
    joining_date: Optional[str] = None
    phone: Optional[str] = None
    manager_email: Optional[EmailStr] = None
    notes: Optional[str] = None
    is_active: Optional[bool] = None


class EmployeeOut(BaseModel):
    id: str
    email: str
    name: str
    employee_id: str
    department: Optional[str] = None
    designation: Optional[str] = None
    joining_date: Optional[str] = None
    phone: Optional[str] = None
    manager_email: Optional[str] = None
    notes: Optional[str] = None
    is_active: bool = True
    role: str = "employee"
    created_at: Optional[str] = None
    documents_count: int = 0
    documents_bytes: int = 0


class DocumentOut(BaseModel):
    id: str
    doc_type: str
    filename: str
    size: int
    content_type: Optional[str] = None
    notes: Optional[str] = None
    uploaded_by: str
    uploaded_at: str


# ---------------------------------------------------------------------------
# Router factory (follows healthbot/ui_scanner pattern)
# ---------------------------------------------------------------------------
def _get_db():
    from server import db as _db  # lazy
    return _db


def _require_admin(user: dict) -> None:
    if (user.get("role") or "").lower() != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")


def _serialize_employee(doc: dict, docs_agg: dict) -> EmployeeOut:
    return EmployeeOut(
        id=str(doc["_id"]),
        email=doc["email"],
        name=doc.get("name", ""),
        employee_id=doc.get("employee_id", ""),
        department=doc.get("department"),
        designation=doc.get("designation"),
        joining_date=doc.get("joining_date"),
        phone=doc.get("phone"),
        manager_email=doc.get("manager_email"),
        notes=doc.get("notes"),
        is_active=doc.get("is_active", True),
        role=doc.get("role", "employee"),
        created_at=doc.get("created_at"),
        documents_count=docs_agg.get("count", 0),
        documents_bytes=docs_agg.get("bytes", 0),
    )


async def _aggregate_docs(db, employee_ids: List[str]) -> dict:
    """Return {employee_id: {count, bytes}} in one round-trip."""
    if not employee_ids:
        return {}
    pipeline = [
        {"$match": {"employee_id": {"$in": employee_ids}}},
        {"$group": {"_id": "$employee_id", "count": {"$sum": 1}, "bytes": {"$sum": "$size"}}},
    ]
    out = {}
    async for row in db.employee_documents.aggregate(pipeline):
        out[row["_id"]] = {"count": row["count"], "bytes": row.get("bytes", 0)}
    return out


def attach_routes(app_router: APIRouter, auth_dep):
    # ============================================================
    # ADMIN — Employees CRUD
    # ============================================================
    @app_router.post("/admin/employees")
    async def create_employee(payload: EmployeeCreate, user: dict = Depends(auth_dep)):
        _require_admin(user)
        db = _get_db()
        email = payload.email.lower().strip()
        existing = await db.users.find_one({"email": email})
        if existing:
            raise HTTPException(status_code=409, detail="An account with this email already exists")
        eid_dup = await db.users.find_one({"employee_id": payload.employee_id})
        if eid_dup:
            raise HTTPException(status_code=409, detail="Employee ID already in use")

        temp_password = _gen_temp_password()
        doc = {
            "email": email,
            "name": payload.name.strip(),
            "employee_id": payload.employee_id.strip(),
            "department": (payload.department or "").strip() or None,
            "designation": (payload.designation or "").strip() or None,
            "joining_date": payload.joining_date,
            "phone": (payload.phone or "").strip() or None,
            "manager_email": payload.manager_email,
            "notes": payload.notes,
            "role": "employee",
            "is_active": True,
            "must_change_password": True,
            "password_hash": _hash(temp_password),
            "created_at": _iso(),
            "created_by": user.get("email"),
        }
        result = await db.users.insert_one(doc)
        return {
            "id": str(result.inserted_id),
            "email": email,
            "temp_password": temp_password,   # ⚠️ returned ONCE, admin must copy
            "instructions": "Share these credentials with the employee via a secure channel (encrypted chat, in-person, HR tool). The employee will be prompted to change their password on first login.",
        }

    @app_router.get("/admin/employees")
    async def list_employees(user: dict = Depends(auth_dep), q: str = "", limit: int = 100):
        _require_admin(user)
        db = _get_db()
        limit = max(1, min(int(limit), 500))
        query: dict = {"role": "employee"}
        if q:
            q = q.strip()
            query["$or"] = [
                {"email": {"$regex": q, "$options": "i"}},
                {"name": {"$regex": q, "$options": "i"}},
                {"employee_id": {"$regex": q, "$options": "i"}},
                {"department": {"$regex": q, "$options": "i"}},
            ]
        cursor = db.users.find(query, {"password_hash": 0}).sort("created_at", -1).limit(limit)
        docs = [d async for d in cursor]
        agg = await _aggregate_docs(db, [str(d["_id"]) for d in docs])
        items = [_serialize_employee(d, agg.get(str(d["_id"]), {})).model_dump() for d in docs]
        return {"items": items, "total": len(items)}

    @app_router.patch("/admin/employees/{employee_id}")
    async def update_employee(employee_id: str, payload: EmployeeUpdate, user: dict = Depends(auth_dep)):
        _require_admin(user)
        db = _get_db()
        try:
            oid = ObjectId(employee_id)
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid employee id") from e
        updates = {k: v for k, v in payload.model_dump().items() if v is not None}
        if not updates:
            raise HTTPException(status_code=400, detail="No fields to update")
        updates["updated_at"] = _iso()
        r = await db.users.update_one({"_id": oid, "role": "employee"}, {"$set": updates})
        if r.matched_count == 0:
            raise HTTPException(status_code=404, detail="Employee not found")
        return {"updated": True}

    @app_router.delete("/admin/employees/{employee_id}")
    async def delete_employee(employee_id: str, user: dict = Depends(auth_dep)):
        _require_admin(user)
        db = _get_db()
        try:
            oid = ObjectId(employee_id)
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid employee id") from e
        emp = await db.users.find_one({"_id": oid, "role": "employee"})
        if not emp:
            raise HTTPException(status_code=404, detail="Employee not found")
        # Delete their documents from GridFS + metadata
        bucket = AsyncIOMotorGridFSBucket(db, bucket_name="employee_docs")
        async for meta in db.employee_documents.find({"employee_id": str(oid)}):
            try:
                await bucket.delete(ObjectId(meta["gridfs_id"]))
            except Exception:
                pass
        await db.employee_documents.delete_many({"employee_id": str(oid)})
        await db.users.delete_one({"_id": oid})
        return {"deleted": True}

    @app_router.post("/admin/employees/{employee_id}/reset-password")
    async def reset_password(employee_id: str, user: dict = Depends(auth_dep)):
        _require_admin(user)
        db = _get_db()
        try:
            oid = ObjectId(employee_id)
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid employee id") from e
        temp_password = _gen_temp_password()
        r = await db.users.update_one(
            {"_id": oid, "role": "employee"},
            {"$set": {"password_hash": _hash(temp_password), "must_change_password": True, "password_reset_at": _iso()}},
        )
        if r.matched_count == 0:
            raise HTTPException(status_code=404, detail="Employee not found")
        return {"temp_password": temp_password}

    @app_router.get("/admin/employees/{employee_id}/documents", response_model=List[DocumentOut])
    async def admin_list_documents(employee_id: str, user: dict = Depends(auth_dep)):
        _require_admin(user)
        db = _get_db()
        cursor = db.employee_documents.find({"employee_id": employee_id}).sort("uploaded_at", -1)
        return [
            DocumentOut(
                id=str(d["_id"]),
                doc_type=d["doc_type"],
                filename=d["filename"],
                size=d["size"],
                content_type=d.get("content_type"),
                notes=d.get("notes"),
                uploaded_by=d.get("uploaded_by", ""),
                uploaded_at=d["uploaded_at"],
            ) async for d in cursor
        ]

    # ============================================================
    # EMPLOYEE — Self-service
    # ============================================================
    @app_router.get("/me/profile")
    async def my_profile(user: dict = Depends(auth_dep)):
        if (user.get("role") or "").lower() not in ("employee", "admin"):
            raise HTTPException(status_code=403, detail="Not an employee account")
        db = _get_db()
        emp = await db.users.find_one({"_id": ObjectId(user["_id"])}, {"password_hash": 0})
        if not emp:
            raise HTTPException(status_code=404, detail="User not found")
        agg = await _aggregate_docs(db, [str(emp["_id"])])
        out = _serialize_employee(emp, agg.get(str(emp["_id"]), {}))
        # Extra: expose must_change_password + storage cap
        return {**out.model_dump(), "must_change_password": bool(emp.get("must_change_password")),
                "storage_limit_bytes": MAX_TOTAL_BYTES, "storage_limit_mb": MAX_TOTAL_BYTES // (1024*1024)}

    @app_router.post("/me/change-password")
    async def change_password(payload: dict, user: dict = Depends(auth_dep)):
        db = _get_db()
        current = str(payload.get("current_password") or "")
        new = str(payload.get("new_password") or "")
        if len(new) < 10:
            raise HTTPException(status_code=400, detail="Password must be at least 10 characters")
        u = await db.users.find_one({"_id": ObjectId(user["_id"])})
        if not u or not bcrypt.checkpw(current.encode("utf-8"), u["password_hash"].encode("utf-8")):
            raise HTTPException(status_code=401, detail="Current password is incorrect")
        await db.users.update_one(
            {"_id": u["_id"]},
            {"$set": {"password_hash": _hash(new), "must_change_password": False, "password_changed_at": _iso()}},
        )
        return {"changed": True}

    @app_router.get("/me/documents", response_model=List[DocumentOut])
    async def my_documents(user: dict = Depends(auth_dep)):
        db = _get_db()
        cursor = db.employee_documents.find({"employee_id": user["_id"]}).sort("uploaded_at", -1)
        return [
            DocumentOut(
                id=str(d["_id"]),
                doc_type=d["doc_type"],
                filename=d["filename"],
                size=d["size"],
                content_type=d.get("content_type"),
                notes=d.get("notes"),
                uploaded_by=d.get("uploaded_by", ""),
                uploaded_at=d["uploaded_at"],
            ) async for d in cursor
        ]

    async def _upload_impl(db, owner_id: str, uploaded_by: str, doc_type: str,
                          notes: Optional[str], file: UploadFile) -> DocumentOut:
        doc_type = (doc_type or "").strip().lower()
        if doc_type not in DOC_TYPES:
            raise HTTPException(status_code=400, detail=f"Invalid doc_type. Must be one of: {sorted(DOC_TYPES)}")
        ct = (file.content_type or "").lower()
        if ct and ct not in ALLOWED_MIMES:
            raise HTTPException(status_code=415, detail=f"Unsupported file type: {ct}")
        # Read + size check
        data = await file.read()
        if not data:
            raise HTTPException(status_code=400, detail="Empty file")
        if len(data) > MAX_FILE_BYTES:
            raise HTTPException(status_code=413, detail=f"File exceeds per-file limit ({MAX_FILE_BYTES//(1024*1024)}MB)")
        # Per-employee storage cap
        agg = await _aggregate_docs(db, [owner_id])
        used = agg.get(owner_id, {}).get("bytes", 0)
        if used + len(data) > MAX_TOTAL_BYTES:
            raise HTTPException(status_code=413,
                detail=f"Storage limit reached ({MAX_TOTAL_BYTES//(1024*1024)}MB total). Delete older docs first.")
        # Sanitize filename
        raw_name = os.path.basename(file.filename or "document")
        safe_name = "".join(c for c in raw_name if c.isalnum() or c in "._- ()")[:200] or "document"
        # Persist to GridFS
        bucket = AsyncIOMotorGridFSBucket(db, bucket_name="employee_docs")
        gridfs_id = await bucket.upload_from_stream(safe_name, io.BytesIO(data),
                                                    metadata={"content_type": ct, "employee_id": owner_id})
        meta = {
            "employee_id": owner_id,
            "doc_type": doc_type,
            "filename": safe_name,
            "size": len(data),
            "content_type": ct or None,
            "notes": (notes or "").strip() or None,
            "gridfs_id": str(gridfs_id),
            "uploaded_by": uploaded_by,
            "uploaded_at": _iso(),
        }
        r = await db.employee_documents.insert_one(meta)
        return DocumentOut(id=str(r.inserted_id), **{k: meta[k] for k in
            ("doc_type", "filename", "size", "content_type", "notes", "uploaded_by", "uploaded_at")})

    @app_router.post("/me/documents", response_model=DocumentOut)
    async def upload_my_document(
        doc_type: str = Form(...),
        notes: Optional[str] = Form(None),
        file: UploadFile = File(...),
        user: dict = Depends(auth_dep),
    ):
        db = _get_db()
        return await _upload_impl(db, user["_id"], user.get("email", ""), doc_type, notes, file)

    @app_router.post("/admin/employees/{employee_id}/documents", response_model=DocumentOut)
    async def admin_upload_document(
        employee_id: str,
        doc_type: str = Form(...),
        notes: Optional[str] = Form(None),
        file: UploadFile = File(...),
        user: dict = Depends(auth_dep),
    ):
        _require_admin(user)
        db = _get_db()
        # Verify the employee exists
        try:
            emp = await db.users.find_one({"_id": ObjectId(employee_id), "role": "employee"})
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid employee id") from e
        if not emp:
            raise HTTPException(status_code=404, detail="Employee not found")
        return await _upload_impl(db, employee_id, user.get("email", ""), doc_type, notes, file)

    @app_router.get("/me/documents/{doc_id}/download")
    async def download_my_document(doc_id: str, user: dict = Depends(auth_dep)):
        db = _get_db()
        return await _stream_document(db, doc_id, owner_id=user["_id"], is_admin=False)

    @app_router.get("/admin/employees/{employee_id}/documents/{doc_id}/download")
    async def admin_download_document(employee_id: str, doc_id: str, user: dict = Depends(auth_dep)):
        _require_admin(user)
        db = _get_db()
        return await _stream_document(db, doc_id, owner_id=employee_id, is_admin=True)

    @app_router.delete("/me/documents/{doc_id}")
    async def delete_my_document(doc_id: str, user: dict = Depends(auth_dep)):
        db = _get_db()
        return await _delete_document(db, doc_id, owner_id=user["_id"], is_admin=False)

    @app_router.delete("/admin/employees/{employee_id}/documents/{doc_id}")
    async def admin_delete_document(employee_id: str, doc_id: str, user: dict = Depends(auth_dep)):
        _require_admin(user)
        db = _get_db()
        return await _delete_document(db, doc_id, owner_id=employee_id, is_admin=True)


async def _stream_document(db, doc_id: str, owner_id: str, is_admin: bool):
    try:
        meta = await db.employee_documents.find_one({"_id": ObjectId(doc_id)})
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid doc id") from e
    if not meta:
        raise HTTPException(status_code=404, detail="Document not found")
    if not is_admin and meta["employee_id"] != owner_id:
        raise HTTPException(status_code=403, detail="Not your document")
    if is_admin and meta["employee_id"] != owner_id:
        # Admin's path also passes owner_id from the URL — must match
        raise HTTPException(status_code=404, detail="Document does not belong to this employee")
    bucket = AsyncIOMotorGridFSBucket(db, bucket_name="employee_docs")
    try:
        stream = await bucket.open_download_stream(ObjectId(meta["gridfs_id"]))
    except Exception as e:
        raise HTTPException(status_code=404, detail="File data missing") from e

    async def _iter():
        while True:
            chunk = await stream.readchunk()
            if not chunk:
                break
            yield chunk

    return StreamingResponse(
        _iter(),
        media_type=meta.get("content_type") or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{meta["filename"]}"'},
    )


async def _delete_document(db, doc_id: str, owner_id: str, is_admin: bool):
    try:
        meta = await db.employee_documents.find_one({"_id": ObjectId(doc_id)})
    except Exception as e:
        raise HTTPException(status_code=400, detail="Invalid doc id") from e
    if not meta:
        raise HTTPException(status_code=404, detail="Document not found")
    if not is_admin and meta["employee_id"] != owner_id:
        raise HTTPException(status_code=403, detail="Not your document")
    if is_admin and meta["employee_id"] != owner_id:
        raise HTTPException(status_code=404, detail="Document does not belong to this employee")
    bucket = AsyncIOMotorGridFSBucket(db, bucket_name="employee_docs")
    try:
        await bucket.delete(ObjectId(meta["gridfs_id"]))
    except Exception:
        pass
    await db.employee_documents.delete_one({"_id": meta["_id"]})
    return {"deleted": True}


async def ensure_indexes() -> None:
    db = _get_db()
    try:
        await db.employee_documents.create_index([("employee_id", 1), ("uploaded_at", -1)])
        await db.employee_documents.create_index("gridfs_id")
        await db.users.create_index("employee_id", sparse=True)
    except Exception:
        pass
