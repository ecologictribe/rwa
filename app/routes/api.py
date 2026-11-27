"""Small JSON/HTMX endpoints: theme persistence, health check, share summary."""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

from .. import db
from ..render import render
from ..security import get_principal

router = APIRouter()


class ThemePayload(BaseModel):
    theme: str


ALLOWED_THEMES = {
    "retro-paper", "high-contrast", "colorblind-safe",
    "monochrome-eink", "amber-crt",
}


@router.post("/api/theme")
def set_theme(payload: ThemePayload, request: Request):
    principal = get_principal(request)
    if payload.theme not in ALLOWED_THEMES:
        return JSONResponse({"ok": False, "detail": "unknown theme"}, status_code=400)
    if principal.is_authenticated:
        db.execute(
            "UPDATE users SET theme_preference = ? WHERE id = ?",
            (payload.theme, principal.id),
        )
    return {"ok": True, "theme": payload.theme}


@router.get("/api/health")
def health():
    try:
        n = db.scalar("SELECT COUNT(*) FROM societies", default=0)
        return {"status": "ok", "societies": n}
    except Exception as exc:  # pragma: no cover - defensive
        return JSONResponse({"status": "degraded", "detail": str(exc)}, status_code=503)


@router.get("/api/notice/{slug}/share")
def share_summary(request: Request, slug: str):
    """Pre-formatted WhatsApp / clipboard summary (spec 5.4 sharing toolkit)."""
    row = db.query_one("SELECT * FROM announcements WHERE slug = ?", (slug,))
    if row is None:
        return JSONResponse({"ok": False}, status_code=404)
    base = str(request.base_url).rstrip("/")
    url = f"{base}/notices/{slug}"
    society_name = db.scalar("SELECT name FROM societies LIMIT 1", default="")
    excerpt = " ".join(row["body_markdown"].split())[:280].strip()
    text = f"{row['title']}\n\n{excerpt}...\n\nRead the full notice: {url}\n\n-- {society_name}"
    encoded = quote(text, safe="")
    return {
        "ok": True,
        "title": row["title"],
        "url": url,
        "text": text,
        "whatsapp": f"https://wa.me/?text={encoded}",
        "priority": row["priority"],
        "published_at": row["published_at"],
    }


@router.get("/manifest")
def manifest():
    return JSONResponse(
        {
            "name": "RWA Governance Portal",
            "short_name": "RWA Portal",
            "start_url": "/",
            "display": "standalone",
            "background_color": "#F7F5EE",
            "theme_color": "#141413",
            "description": "Resident Welfare Association governance and operations portal.",
        }
    )
