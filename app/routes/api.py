"""Small JSON/HTMX endpoints: theme persistence, health check, share summary."""

from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

from .. import audit, db, invariants
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
    return {"ok": True, "status": "ok", "theme": payload.theme}


@router.get("/api/health")
def health():
    try:
        n = db.scalar("SELECT COUNT(*) FROM societies", default=0)
        return {"ok": True, "status": "ok", "societies": n}
    except Exception as exc:  # pragma: no cover - defensive
        return JSONResponse({"ok": False, "status": "degraded", "detail": str(exc)}, status_code=503)


@router.get("/api/notice/{slug}/share")
def share_summary(request: Request, slug: str):
    """Pre-formatted WhatsApp / clipboard summary with statutory citations (HRRS Act Sec. 10(2) & Rule 6)."""
    row = db.query_one("SELECT * FROM announcements WHERE slug = ?", (slug,))
    if row is None:
        return JSONResponse({"ok": False}, status_code=404)
    base = str(request.base_url).rstrip("/")
    url = f"{base}/notices/{slug}"
    soc = db.query_one("SELECT name, registration_number, registered_office_address FROM societies LIMIT 1") or {}
    society_name = soc.get("name") or "Resident Welfare Association"
    reg_no = soc.get("registration_number") or ""
    reg_str = f" (Reg. No: {reg_no})" if reg_no else ""
    excerpt = " ".join(row["body_markdown"].split())[:280].strip()
    text = (
        f"🏛️ {society_name}{reg_str}\n"
        f"📜 Official Statutory Notice [HRRS Act, 2012 Sec. 10(2) & Rule 6]\n\n"
        f"📌 {row['title']}\n\n"
        f"{excerpt}...\n\n"
        f"🔗 Read full notice & resolution records: {url}\n\n"
        f"-- Issued under authority of Governing Body (Sec. 34)"
    )
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


@router.get("/api/invariants")
def get_invariants():
    """Evaluate and report on all 8 core enterprise state invariants."""
    res = invariants.check_all_invariants()
    return JSONResponse(
        res,
        status_code=200 if res["all_passed"] else 422,
    )


@router.get("/api/audit/verify")
def verify_audit():
    """Verify cryptographic SHA-256 Merkle chain across all audit logs."""
    res = audit.verify_audit_hash_chain()
    return JSONResponse(
        res,
        status_code=200 if res["verified"] else 409,
    )


@router.get("/api/ready")
def readiness():
    """Readiness probe checking database connectivity, migrations, and basic invariants."""
    try:
        # Check DB connection
        db.scalar("SELECT 1")
        # Check basic table existence
        soc_count = db.scalar("SELECT COUNT(*) FROM societies", default=0)
        # Check audit chain integrity
        audit_res = audit.verify_audit_hash_chain()
        is_ready = bool(soc_count >= 1 and audit_res.get("verified"))
        return JSONResponse(
            {
                "ready": is_ready,
                "database": "connected",
                "societies_count": soc_count,
                "audit_chain": "verified" if audit_res.get("verified") else "corrupted",
            },
            status_code=200 if is_ready else 503,
        )
    except Exception as exc:
        return JSONResponse(
            {"ready": False, "detail": str(exc)},
            status_code=503,
        )
