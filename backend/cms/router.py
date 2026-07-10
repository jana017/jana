"""Site CMS subsystem: admin-tab visibility, landing-page section layout,
top-bar announcement, and custom Markdown pages.

Everything lives in the `cms_settings` collection (single-doc-per-feature)
or the `cms_pages` collection (one doc per page). No LLM dependencies —
this module continues to work on any VPS.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger("nivx.cms")

router = APIRouter(prefix="/api/cms", tags=["cms"])


def _get_db():
    from server import db as _db  # lazy
    return _db


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Defaults — served when nothing is in the DB yet
# ---------------------------------------------------------------------------
DEFAULT_ADMIN_TABS = [
    {"id": "overview", "label": "Overview", "visible": True, "locked": True},
    {"id": "settings", "label": "Settings", "visible": True, "locked": False},
    {"id": "cyberlab-rules", "label": "NivX Forge Rules", "visible": True, "locked": False},
    {"id": "webhooks", "label": "EDR / SIEM", "visible": True, "locked": False},
    {"id": "healthbot", "label": "HealthBot", "visible": True, "locked": False},
    {"id": "cms", "label": "Site CMS", "visible": True, "locked": True},
]

DEFAULT_LANDING_SECTIONS = [
    {"id": "hero", "label": "Hero", "enabled": True, "order": 0},
    {"id": "about", "label": "About / Manifesto", "enabled": True, "order": 1},
    {"id": "stats", "label": "Stats band", "enabled": True, "order": 2},
    {"id": "threat_landscape", "label": "Live Threat Landscape", "enabled": True, "order": 3},
    {"id": "global_attacks", "label": "Live Global Attacks map", "enabled": True, "order": 4},
    {"id": "attack_feed", "label": "Attack Feed", "enabled": True, "order": 5},
    {"id": "services", "label": "Services", "enabled": True, "order": 6},
    {"id": "gallery", "label": "Gallery", "enabled": True, "order": 7},
    {"id": "careers", "label": "Careers", "enabled": True, "order": 8},
    {"id": "contact", "label": "Contact", "enabled": True, "order": 9},
]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class AdminTab(BaseModel):
    id: str
    label: str
    visible: bool = True
    locked: bool = False  # cannot be hidden (e.g. Overview)


class LandingSection(BaseModel):
    id: str
    label: str
    enabled: bool = True
    order: int = 0


class Announcement(BaseModel):
    active: bool = False
    text: str = ""
    variant: str = "info"           # info | warning | success | promo
    href: Optional[str] = None
    dismissable: bool = True
    expires_at: Optional[str] = None  # ISO string


class PageCreate(BaseModel):
    slug: str = Field(..., pattern=r"^[a-z0-9][a-z0-9\-]{0,60}$")
    title: str = Field(..., min_length=1, max_length=120)
    markdown_body: str = ""
    published: bool = True
    show_in_nav: bool = False


class PageUpdate(BaseModel):
    title: Optional[str] = None
    markdown_body: Optional[str] = None
    published: Optional[bool] = None
    show_in_nav: Optional[bool] = None


class PageOut(BaseModel):
    id: str
    slug: str
    title: str
    markdown_body: str
    html_body: str
    published: bool
    show_in_nav: bool
    created_at: str
    updated_at: str


class BrandingPayload(BaseModel):
    logo_url: Optional[str] = ""
    favicon_url: Optional[str] = ""
    site_title: Optional[str] = ""
    custom_css: Optional[str] = ""
    custom_js: Optional[str] = ""


# ---------------------------------------------------------------------------
# Minimal, safe Markdown → HTML  (no external dep — offline-safe)
# ---------------------------------------------------------------------------
_HTML_ESCAPE = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"})


def _escape(s: str) -> str:
    return s.translate(_HTML_ESCAPE)


def markdown_to_html(md: str) -> str:
    """Very small, deterministic Markdown renderer — headings, bold, italic,
    inline code, code blocks, links, lists, paragraphs. Everything is
    escaped first so user input can't inject arbitrary HTML."""
    if not md:
        return ""
    escaped = _escape(md)
    # Code blocks (```)
    def _codeblock(m: re.Match) -> str:
        return f"<pre><code>{m.group(1)}</code></pre>"
    escaped = re.sub(r"```(?:[\w-]*)\n([\s\S]*?)```", _codeblock, escaped)
    # Inline code (`x`)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    # Headings
    escaped = re.sub(r"^###### (.+)$", r"<h6>\1</h6>", escaped, flags=re.MULTILINE)
    escaped = re.sub(r"^##### (.+)$",  r"<h5>\1</h5>", escaped, flags=re.MULTILINE)
    escaped = re.sub(r"^#### (.+)$",   r"<h4>\1</h4>", escaped, flags=re.MULTILINE)
    escaped = re.sub(r"^### (.+)$",    r"<h3>\1</h3>", escaped, flags=re.MULTILINE)
    escaped = re.sub(r"^## (.+)$",     r"<h2>\1</h2>", escaped, flags=re.MULTILINE)
    escaped = re.sub(r"^# (.+)$",      r"<h1>\1</h1>", escaped, flags=re.MULTILINE)
    # Bold + italic
    escaped = re.sub(r"\*\*([^*\n]+)\*\*", r"<strong>\1</strong>", escaped)
    escaped = re.sub(r"(?<![*_])_([^_\n]+)_(?![*_])", r"<em>\1</em>", escaped)
    # Links [text](url)
    escaped = re.sub(
        r"\[([^\]]+)\]\((https?://[^\s\)]+)\)",
        r'<a href="\2" rel="noreferrer nofollow" target="_blank">\1</a>',
        escaped,
    )
    # Unordered lists (- or *)
    def _ul_block(m: re.Match) -> str:
        items = re.findall(r"^[-*]\s+(.+)$", m.group(0), flags=re.MULTILINE)
        return "<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>"
    escaped = re.sub(r"(?:^[-*]\s+.+(?:\n|$))+", _ul_block, escaped, flags=re.MULTILINE)
    # Paragraphs — wrap any line runs that aren't already a block-level tag.
    parts = []
    for block in re.split(r"\n{2,}", escaped):
        block = block.strip()
        if not block:
            continue
        if re.match(r"^\s*<(?:h[1-6]|ul|ol|pre|blockquote|table|hr)", block):
            parts.append(block)
        else:
            parts.append("<p>" + block.replace("\n", "<br/>") + "</p>")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# CMS Settings helpers
# ---------------------------------------------------------------------------
async def _load(key: str, default: Any) -> Any:
    db = _get_db()
    doc = await db.cms_settings.find_one({"_id": key})
    if doc and "value" in doc:
        return doc["value"]
    return default


async def _save(key: str, value: Any) -> None:
    db = _get_db()
    await db.cms_settings.update_one(
        {"_id": key},
        {"$set": {"value": value, "updated_at": _now()}},
        upsert=True,
    )


# ---------------------------------------------------------------------------
# Route factory — bound to auth dep by server.py
# ---------------------------------------------------------------------------
def attach_routes(app_router: APIRouter, auth_dep):

    # ---- Admin tab visibility ------------------------------------------
    @app_router.get("/admin-tabs")
    async def get_admin_tabs():
        """Public — the frontend reads this on every /admin load."""
        tabs = await _load("admin_tabs", DEFAULT_ADMIN_TABS)
        # Merge with defaults so newly-added tabs (like `cms`) auto-appear
        # even when the stored list is older.
        by_id = {t["id"]: t for t in tabs}
        for default in DEFAULT_ADMIN_TABS:
            if default["id"] not in by_id:
                tabs.append(default)
        return tabs

    @app_router.put("/admin-tabs")
    async def put_admin_tabs(tabs: List[AdminTab], user: dict = Depends(auth_dep)):
        # Never allow a locked tab to be hidden.
        locked_ids = {t["id"] for t in DEFAULT_ADMIN_TABS if t.get("locked")}
        payload = [t.model_dump() for t in tabs]
        for t in payload:
            if t["id"] in locked_ids:
                t["visible"] = True
                t["locked"] = True
        await _save("admin_tabs", payload)
        return payload

    # ---- Landing page section layout -----------------------------------
    @app_router.get("/landing-sections")
    async def get_landing_sections():
        secs = await _load("landing_sections", DEFAULT_LANDING_SECTIONS)
        by_id = {s["id"]: s for s in secs}
        for default in DEFAULT_LANDING_SECTIONS:
            if default["id"] not in by_id:
                secs.append(default)
        # Always return sorted by `order`
        return sorted(secs, key=lambda s: s.get("order", 0))

    @app_router.put("/landing-sections")
    async def put_landing_sections(sections: List[LandingSection], user: dict = Depends(auth_dep)):
        payload = [s.model_dump() for s in sections]
        await _save("landing_sections", payload)
        return sorted(payload, key=lambda s: s.get("order", 0))

    # ---- Announcement banner -------------------------------------------
    @app_router.get("/announcement")
    async def get_announcement():
        """Public — the frontend polls this to render the top-bar banner."""
        ann = await _load("announcement", {})
        # Expire on the server so the client sees an empty state.
        expires = ann.get("expires_at")
        if expires:
            try:
                if datetime.fromisoformat(expires.replace("Z", "+00:00")) < datetime.now(timezone.utc):
                    ann = {**ann, "active": False}
            except Exception:
                pass
        return ann or {"active": False, "text": ""}

    @app_router.put("/announcement")
    async def put_announcement(ann: Announcement, user: dict = Depends(auth_dep)):
        await _save("announcement", ann.model_dump())
        return ann

    # ---- Custom pages CRUD ---------------------------------------------
    @app_router.get("/pages")
    async def list_pages(published_only: bool = False, user: Optional[dict] = None):
        """Public list — respects `published_only` when caller doesn't have
        an auth token."""
        db = _get_db()
        query = {"published": True} if published_only else {}
        docs = await db.cms_pages.find(query).sort("updated_at", -1).to_list(200)
        return [_serialize_page(d) for d in docs]

    @app_router.get("/pages/{slug}")
    async def get_page(slug: str):
        db = _get_db()
        doc = await db.cms_pages.find_one({"slug": slug})
        if not doc:
            raise HTTPException(status_code=404, detail="page not found")
        if not doc.get("published"):
            # Non-admin caller can't see unpublished — but rather than doing
            # auth here, the public frontend just gets 404 for drafts.
            raise HTTPException(status_code=404, detail="page not found")
        return _serialize_page(doc)

    @app_router.get("/admin/pages/{slug}")
    async def get_page_admin(slug: str, user: dict = Depends(auth_dep)):
        """Admin variant — reveals drafts too."""
        db = _get_db()
        doc = await db.cms_pages.find_one({"slug": slug})
        if not doc:
            raise HTTPException(status_code=404, detail="page not found")
        return _serialize_page(doc)

    @app_router.post("/pages", status_code=201)
    async def create_page(payload: PageCreate, user: dict = Depends(auth_dep)):
        db = _get_db()
        if await db.cms_pages.find_one({"slug": payload.slug}):
            raise HTTPException(status_code=409, detail="slug already exists")
        now = _now()
        doc = payload.model_dump()
        doc.update({"created_at": now, "updated_at": now, "created_by": user.get("email")})
        res = await db.cms_pages.insert_one(doc)
        doc["_id"] = res.inserted_id
        return _serialize_page(doc)

    @app_router.patch("/pages/{slug}")
    async def update_page(slug: str, patch: PageUpdate, user: dict = Depends(auth_dep)):
        db = _get_db()
        updates = {k: v for k, v in patch.model_dump(exclude_unset=True).items() if v is not None}
        if not updates:
            raise HTTPException(status_code=400, detail="nothing to update")
        updates["updated_at"] = _now()
        doc = await db.cms_pages.find_one_and_update(
            {"slug": slug}, {"$set": updates}, return_document=True,
        )
        if not doc:
            raise HTTPException(status_code=404, detail="page not found")
        return _serialize_page(doc)

    @app_router.delete("/pages/{slug}")
    async def delete_page(slug: str, user: dict = Depends(auth_dep)):
        db = _get_db()
        res = await db.cms_pages.delete_one({"slug": slug})
        if res.deleted_count == 0:
            raise HTTPException(status_code=404, detail="page not found")
        return {"status": "deleted"}

    # ---- Site branding + custom CSS/JS ---------------------------------
    @app_router.get("/branding")
    async def get_branding():
        """Public — read on every page load to apply logo/CSS."""
        return await _load("branding", {
            "logo_url": "", "favicon_url": "", "site_title": "",
            "custom_css": "", "custom_js": "",
        })

    @app_router.put("/branding")
    async def put_branding(payload: BrandingPayload, user: dict = Depends(auth_dep)):
        # Very light JS-injection safety: strip </script> tags (defense in
        # depth — the admin panel is trusted, but let's not aid mistakes).
        data = payload.model_dump()
        if data.get("custom_js"):
            data["custom_js"] = data["custom_js"].replace("</script>", "<\\/script>")
        await _save("branding", data)
        return data

    # ---- File uploads (attached via cms/files.py) ----------------------
    from .files import attach_file_routes as _attach_files
    _attach_files(app_router, auth_dep)


def _serialize_page(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(doc.get("_id")),
        "slug": doc["slug"],
        "title": doc["title"],
        "markdown_body": doc.get("markdown_body", ""),
        "html_body": markdown_to_html(doc.get("markdown_body", "")),
        "published": bool(doc.get("published", True)),
        "show_in_nav": bool(doc.get("show_in_nav", False)),
        "created_at": doc.get("created_at", _now()),
        "updated_at": doc.get("updated_at", _now()),
    }


async def ensure_indexes():
    db = _get_db()
    await db.cms_pages.create_index("slug", unique=True)
    await db.cms_pages.create_index([("updated_at", -1)])
