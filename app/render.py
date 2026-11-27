"""Shared rendering + flash-message helpers.

Kept in its own module so route files can import them without a circular
import back through ``app.main``.
"""

from __future__ import annotations

import json

from fastapi import Request
from fastapi.templating import Jinja2Templates

from . import config, db
from .security import Principal

templates = Jinja2Templates(directory=config.TEMPLATE_DIR)

THEMES = [
    {"id": "retro-paper", "label": "Paper"},
    {"id": "high-contrast", "label": "Contrast"},
    {"id": "colorblind-safe", "label": "Colorblind"},
    {"id": "monochrome-eink", "label": "E-Ink"},
    {"id": "amber-crt", "label": "Amber"},
]


def society_context() -> dict:
    row = db.query_one("SELECT * FROM societies LIMIT 1")
    if row is None:
        # Before the first seed run the app must still render the shell.
        return {
            "name": config.SOCIETY_NAME,
            "registration_number": config.SOCIETY_REG_NO,
            "registered_office_address": config.SOCIETY_ADDRESS,
            "contact_email": config.SOCIETY_EMAIL,
            "contact_phone": config.SOCIETY_PHONE,
            "id": None,
            "active_member_count": 0,
        }
    return dict(row)


def render(request: Request, name: str, context: dict | None = None, status_code: int = 200):
    """Single rendering entry point so every page gets the same context."""
    principal = getattr(request.state, "principal", None)
    if principal is None:
        from .security import Principal
        principal = Principal(None)
    ctx = {
        "request": request,
        "principal": principal,
        "society": society_context(),
        "themes": THEMES,
        "messages": getattr(request.state, "messages", []),
    }
    if context:
        ctx.update(context)
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def flash(request: Request, text: str, kind: str = "success") -> None:
    request.state.messages.append({"kind": kind, "text": text})


def flash_cookie_payload(messages: list) -> str:
    """Encode flash messages for transport in a single cookie.

    Base64 rather than raw JSON: JSON contains commas and quotes, which force
    cookie-jars to value-quote the attribute and can corrupt the round trip.
    """
    import base64

    raw = json.dumps(
        [{"kind": m["kind"], "text": m["text"]} for m in messages], ensure_ascii=False
    ).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")[:2000]


def parse_flash_cookie(value: str) -> list:
    import base64

    if not value:
        return []
    try:
        padded = value + "=" * (-len(value) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, TypeError):
        return []
    return data if isinstance(data, list) else []
