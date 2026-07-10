"""Developer-tab file storage: any format, any size (up to configured limit),
served back over HTTP with the correct content-type.

Backed by MongoDB GridFS so we don't touch the container filesystem — files
survive restarts, and no external S3/CDN dependency. Works identically on
any VPS: no LLM, no external network.
"""
from __future__ import annotations

import io
import logging
import mimetypes
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pydantic import BaseModel

logger = logging.getLogger("nivx.cms.files")


MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB per file (generous for logos, docs)


def _get_db():
    from server import db as _db
    return _db


def _gfs() -> AsyncIOMotorGridFSBucket:
    return AsyncIOMotorGridFSBucket(_get_db(), bucket_name="dev_files")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class FileMeta(BaseModel):
    id: str
    filename: str
    content_type: str
    size: int
    uploaded_at: str
    uploaded_by: Optional[str] = None
    url: str


def _serialize(doc: Dict[str, Any]) -> FileMeta:
    fid = str(doc["_id"])
    return FileMeta(
        id=fid,
        filename=doc.get("filename", "unnamed"),
        content_type=doc.get("metadata", {}).get("content_type", "application/octet-stream"),
        size=doc.get("length", 0),
        uploaded_at=doc.get("metadata", {}).get("uploaded_at", _now()),
        uploaded_by=doc.get("metadata", {}).get("uploaded_by"),
        url=f"/api/cms/files/{fid}/raw",
    )


def attach_file_routes(app_router: APIRouter, auth_dep):

    @app_router.post("/files", response_model=FileMeta, status_code=201)
    async def upload_file(file: UploadFile = File(...), user: dict = Depends(auth_dep)):
        """Accept any file format — logos, images, PDFs, videos, JSON, etc.

        Only limits: 25MB per file (guard against runaway uploads); filenames
        are used as-is (no rewriting).
        """
        # Stream in chunks so we don't buffer huge files in memory twice.
        gfs = _gfs()
        content_type = (
            file.content_type
            or mimetypes.guess_type(file.filename or "")[0]
            or "application/octet-stream"
        )
        # Read into memory to enforce the limit deterministically.
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413,
                                detail=f"File exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB limit")
        file_id = await gfs.upload_from_stream(
            file.filename or "file",
            io.BytesIO(data),
            metadata={
                "content_type": content_type,
                "uploaded_at": _now(),
                "uploaded_by": user.get("email"),
            },
        )
        doc = await _get_db()["dev_files.files"].find_one({"_id": file_id})
        return _serialize(doc)

    @app_router.get("/files", response_model=List[FileMeta])
    async def list_files(user: dict = Depends(auth_dep)):
        db = _get_db()
        docs = await db["dev_files.files"].find().sort("uploadDate", -1).to_list(500)
        return [_serialize(d) for d in docs]

    @app_router.delete("/files/{file_id}")
    async def delete_file(file_id: str, user: dict = Depends(auth_dep)):
        try:
            oid = ObjectId(file_id)
        except Exception:
            raise HTTPException(status_code=404, detail="file not found")
        try:
            await _gfs().delete(oid)
        except Exception as e:
            raise HTTPException(status_code=404, detail=f"file not found: {e}")
        return {"status": "deleted"}

    @app_router.get("/files/{file_id}/raw")
    async def stream_file(file_id: str):
        """Public serve — files are meant to be referenced from the site."""
        try:
            oid = ObjectId(file_id)
        except Exception:
            raise HTTPException(status_code=404, detail="file not found")
        db = _get_db()
        doc = await db["dev_files.files"].find_one({"_id": oid})
        if not doc:
            raise HTTPException(status_code=404, detail="file not found")
        ct = doc.get("metadata", {}).get("content_type", "application/octet-stream")

        async def _iter():
            grid_out = await _gfs().open_download_stream(oid)
            while True:
                chunk = await grid_out.readchunk()
                if not chunk:
                    break
                yield chunk

        headers = {
            "Cache-Control": "public, max-age=3600",
            "Content-Disposition": f'inline; filename="{doc.get("filename", "file")}"',
        }
        return StreamingResponse(_iter(), media_type=ct, headers=headers)
