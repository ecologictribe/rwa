"""Authentication, session management and RBAC guards (SRS section 2).

Design notes
------------
* **No SMS OTP** (spec 2.2): identity is the composite triad
  ``Flat Number + Mobile + Email``. Passwords are hashed with PBKDF2-HMAC-SHA256
  at a high iteration count (stdlib ``hashlib`` keeps the dependency footprint
  at zero -- important for the 1 GB / low-bandwidth target).
* Sessions are server-side rows keyed by a random token, delivered in an
  ``HttpOnly``, ``SameSite=Lax`` cookie (spec 9.1).
* CSRF: every state-changing request carries a per-session token that is
  injected into all HTMX calls via ``hx-headers`` and verified on ``POST``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from fastapi import Depends, HTTPException, Request, status

from . import config, db

# --- Password hashing -------------------------------------------------------

PBKDF2_ITERATIONS = 390_000  # OWASP-adjacent for PBKDF2-HMAC-SHA256
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored or "$" not in stored:
        return False
    try:
        algo, iterations, salt_hex, hash_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def generate_reset_code() -> str:
    """In-person clerk reset code issued after Form-XI / registry verification."""
    return secrets.token_hex(4).upper()


# --- Sessions ---------------------------------------------------------------

def create_session(user_id: str, ip_address: str | None = None) -> tuple[str, str]:
    """Returns ``(raw_token, csrf_token)``. Raw token only ever leaves the server
    inside the session cookie."""
    raw_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    db.execute(
        """INSERT INTO sessions (id, user_id, token_hash, csrf_token, ip_address,
                                 created_at, expires_at, last_seen_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (
            db.new_id(),
            user_id,
            token_hash,
            csrf_token,
            ip_address,
            db.utcnow(),
            (datetime.now(timezone.utc) + timedelta(seconds=config.SESSION_MAX_AGE)).isoformat(
                timespec="seconds"
            ),
            db.utcnow(),
        ),
    )
    return raw_token, csrf_token


def destroy_session(raw_token: str) -> None:
    if not raw_token:
        return
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def _load_session(raw_token: str) -> dict | None:
    if not raw_token:
        return None
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    row = db.query_one(
        """SELECT u.*, u.id AS u_id, s.token_hash, s.csrf_token, s.expires_at,
                  s.last_seen_at, s.ip_address
           FROM sessions s
           JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ? AND s.expires_at > ?""",
        (token_hash, datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )
    if row is None:
        return None
    db.execute("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (db.utcnow(), token_hash))
    return row


# --- Request-scoped principal ----------------------------------------------

ROLE_ORDER = {"PUBLIC": 0, "MEMBER": 1, "DATA_OPERATOR": 2, "SOCIETY_ADMIN": 3, "SUPER_ADMIN": 4}


class Principal:
    """Authenticated actor, or an anonymous PUBLIC visitor."""

    def __init__(self, row: dict | None = None):
        self.row = row

    # -- identity ---------------------------------------------------------
    @property
    def is_authenticated(self) -> bool:
        return self.row is not None

    @property
    def id(self) -> str | None:
        return self.row["u_id"] if self.row else None

    @property
    def name(self) -> str:
        return self.row["full_name"] if self.row else "Guest"

    @property
    def role(self) -> str:
        return self.row["role"] if self.row else "PUBLIC"

    @property
    def society_id(self) -> str | None:
        return self.row["society_id"] if self.row else None

    @property
    def unit_id(self) -> str | None:
        return self.row["unit_id"] if self.row else None

    @property
    def email(self) -> str:
        return self.row["email"] if self.row else ""

    @property
    def theme(self) -> str:
        return (self.row["theme_preference"] if self.row else None) or "retro-paper"

    @property
    def csrf_token(self) -> str:
        return self.row["csrf_token"] if self.row else ""

    # -- capability checks ------------------------------------------------
    def has_role(self, *roles: str) -> bool:
        return self.role in roles

    def at_least(self, minimum: str) -> bool:
        return ROLE_ORDER.get(self.role, 0) >= ROLE_ORDER.get(minimum, 99)

    def can(self, capability: str) -> bool:
        return capability in CAPABILITIES.get(self.role, set())

    def require(self, *roles: str) -> None:
        if self.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )


CAPABILITIES: dict[str, set[str]] = {
    "PUBLIC": set(),
    "MEMBER": {"view_notices", "raise_ticket", "view_own_unit", "download_documents"},
    "DATA_OPERATOR": {
        "view_notices",
        "raise_ticket",
        "view_own_unit",
        "download_documents",
        "enter_directory",
        "upload_documents",
        "log_walkin_ticket",
        "draft_announcement",
        "view_dashboard",
    },
    "SOCIETY_ADMIN": {
        "view_notices",
        "raise_ticket",
        "view_own_unit",
        "download_documents",
        "enter_directory",
        "upload_documents",
        "log_walkin_ticket",
        "draft_announcement",
        "view_dashboard",
        "approve_member",
        "publish_announcement",
        "manage_committee",
        "manage_initiatives",
        "sign_mom",
        "export_registers",
        "manage_users",
        "bulk_edit",
        "view_audit",
        "view_graph",
        "escalate_ticket",
    },
    "SUPER_ADMIN": {
        "view_notices",
        "raise_ticket",
        "view_own_unit",
        "download_documents",
        "enter_directory",
        "upload_documents",
        "log_walkin_ticket",
        "draft_announcement",
        "view_dashboard",
        "approve_member",
        "publish_announcement",
        "manage_committee",
        "manage_initiatives",
        "sign_mom",
        "export_registers",
        "manage_users",
        "bulk_edit",
        "view_audit",
        "view_graph",
        "escalate_ticket",
        "provision_society",
        "system_health",
    },
}


# --- FastAPI dependencies ---------------------------------------------------

def get_principal(request: Request) -> Principal:
    raw = request.cookies.get(config.SESSION_COOKIE_NAME, "")
    return Principal(_load_session(raw))


def require_roles(*roles: str):
    def guard(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.is_authenticated:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Login required.")
        if principal.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your role does not permit this action.",
            )
        return principal

    return Depends(guard)


def require_capability(capability: str):
    def guard(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.is_authenticated:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Login required.")
        if not principal.can(capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your role does not permit this action.",
            )
        return principal

    return Depends(guard)


def require_csrf(request: Request, principal: Principal) -> None:
    """Constant-time CSRF verification for every state-changing request (9.1)."""
    supplied = request.headers.get("x-csrf-token") or request.headers.get("X-CSRF-Token")
    if supplied is None:
        supplied = request.form_data.get("_csrf", "") if hasattr(request, "form_data") else ""
    if not supplied:
        # form fallback happens in routes that read the body first
        supplied = request.headers.get("hx-csrf", "")
    expected = principal.csrf_token
    if not expected or not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token mismatch.")


def verify_form_csrf(form_value: str | None, principal: Principal) -> None:
    expected = principal.csrf_token
    if not expected:
        return  # unauthenticated public forms are session-less
    if not form_value or not hmac.compare_digest(str(form_value), expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token mismatch.")
