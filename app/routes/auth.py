"""Authentication routes (SRS section 2.2).

Credential model is the composite triad **Flat Number + Mobile + Email** with a
password or a 6-digit PIN. There is deliberately **no SMS OTP dependency**:
resets use either an emailed magic token or an in-person clerk reset code
issued after verifying the member's Form-XI ID / registry entry.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import audit, config, db, security
from ..render import flash, render

router = APIRouter()


def _safe_next(target: str | None) -> str:
    if not target or not target.startswith("/") or target.startswith("//"):
        return "/portal"
    return target


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str | None = None, error: str | None = None):
    if request.state.principal.is_authenticated:
        return RedirectResponse(url=_safe_next(next), status_code=302)
    return render(
        request,
        "auth/login.html",
        {"next": _safe_next(next), "error": error},
    )


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    next: str = Form("/portal"),
):
    email = email.strip().lower()
    row = db.query_one(
        """SELECT * FROM users
           WHERE lower(email) = ? OR mobile_number = ? OR lower(COALESCE(member_serial_no,'')) = ?""",
        (email, email.strip(), email.strip()),
    )

    if row is None or not security.verify_password(password, row["password_hash"]):
        audit.log(
            action="LOGIN_FAILED",
            rule_ref="HRRS_ACT_2012_SEC_15 | AUTH_CREDENTIAL_TRIAD",
            entity_type="user",
            entity_id=row["id"] if row else None,
            diff={"identifier": {"old_value": None, "new_value": email}},
            ip_address=request.client.host if request.client else None,
        )
        return login_form(
            request,
            next=next,
            error="No account matches that identifier and password combination.",
        )

    if row["account_status"] in {"SUSPENDED", "CEASED"}:
        return login_form(
            request,
            next=next,
            error=f"This account is {row['account_status'].lower()}. Contact the society office.",
        )

    if row["account_status"] == "PENDING":
        return login_form(
            request,
            next=next,
            error="Your account is pending verification by the society office (Form-X).",
        )

    raw_token, _csrf = security.create_session(
        row["id"], ip_address=request.client.host if request.client else None
    )
    audit.log(
        action="LOGIN_SUCCESS",
        rule_ref="HRRS_ACT_2012_SEC_15 | AUTH_SESSION_CREATE",
        entity_type="user",
        entity_id=row["id"],
        diff={"role": {"old_value": None, "new_value": row["role"]}},
        actor_id=row["id"],
        society_id=row["society_id"],
        ip_address=request.client.host if request.client else None,
    )

    response = RedirectResponse(url=_safe_next(next), status_code=303)
    response.set_cookie(
        config.SESSION_COOKIE_NAME,
        raw_token,
        max_age=config.SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        # Secure only on real HTTPS: a Secure cookie sent over plain HTTP is
        # discarded by clients, which would silently break local dev servers.
        secure=request.url.scheme == "https",
        path="/",
    )
    flash(request, f"Signed in as {row['full_name']} ({row['role'].replace('_', ' ').title()}).")
    # Rewrite the flash cookie onto the redirect response.
    if request.state.messages:
        from ..render import flash_cookie_payload

        response.set_cookie(
            "rwa_flash",
            flash_cookie_payload(request.state.messages),
            max_age=5,
            httponly=True,
            samesite="lax",
        )
    return response


@router.get("/logout")
def logout(request: Request):
    raw = request.cookies.get(config.SESSION_COOKIE_NAME, "")
    security.destroy_session(raw)
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(config.SESSION_COOKIE_NAME, path="/")
    response.delete_cookie("rwa_flash", path="/")
    return response


@router.get("/claim", response_class=HTMLResponse)
def claim_form(request: Request, error: str | None = None):
    """Bulk pre-seeding claim flow: Flat + Mobile + Email sets the password."""
    return render(request, "auth/claim.html", {"error": error})


@router.post("/claim", response_class=HTMLResponse)
def claim_submit(
    request: Request,
    flat_code: str = Form(...),
    mobile_number: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    flat_code = flat_code.strip().upper()
    mobile_number = mobile_number.strip()
    email = email.strip().lower()

    row = db.query_one(
        """SELECT u.* FROM users u JOIN units un ON un.id = u.unit_id
           WHERE upper(un.canonical_code) = ?
             AND (u.mobile_number = ? OR lower(u.email) = ?)""",
        (flat_code, mobile_number, email),
    )
    if row is None:
        return claim_form(
            request,
            error="No pre-seeded record matches that flat number, mobile and email. "
                  "Contact the desk, or apply for membership instead.",
        )
    if row["password_hash"]:
        return claim_form(
            request,
            error="This account has already been claimed. Use Sign In, or request an "
                  "in-person reset at the society desk with your Form-XI ID.",
        )
    if len(password) < 8:
        return claim_form(request, error="Password must be at least 8 characters.")
    if password != password_confirm:
        return claim_form(request, error="The two passwords do not match.")

    db.execute(
        "UPDATE users SET password_hash = ?, account_status = 'ACTIVE' WHERE id = ?",
        (security.hash_password(password), row["id"]),
    )
    audit.log(
        action="ACCOUNT_CLAIMED",
        rule_ref="HRRS_ACT_2012_SEC_18_1 | RULE_12_FORM_XII",
        entity_type="user",
        entity_id=row["id"],
        diff={"account_status": {"old_value": row["account_status"], "new_value": "ACTIVE"}},
        actor_id=row["id"],
        society_id=row["society_id"],
        ip_address=request.client.host if request.client else None,
    )
    flash(request, "Account claimed. You can now sign in.")
    return RedirectResponse(url="/login", status_code=303)


@router.get("/forgot", response_class=HTMLResponse)
def forgot_form(request: Request, sent: str | None = None, error: str | None = None):
    return render(request, "auth/forgot.html", {"sent": sent, "error": error})


@router.post("/forgot", response_class=HTMLResponse)
def forgot_submit(request: Request, email: str = Form(...)):
    """Email magic-reset token. If SMTP is not configured the code is shown
    once to the operator so the in-person flow still works on a bare host."""
    email = email.strip().lower()
    row = db.query_one("SELECT * FROM users WHERE lower(email) = ?", (email,))
    if row is None:
        # Do not leak which addresses exist.
        return forgot_form(request, sent="1")

    token = security.generate_reset_code()
    expires = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(timespec="seconds")
    db.execute(
        """INSERT INTO reset_tokens (id, user_id, token_hash, expires_at, created_at)
           VALUES (?,?,?,?,?)""",
        (
            db.new_id(),
            row["id"],
            hashlib.sha256(token.encode()).hexdigest(),
            expires,
            db.utcnow(),
        ),
    )
    audit.log(
        action="RESET_REQUESTED",
        rule_ref="AUTH_RESET_NO_SMS_OTP",
        entity_type="user",
        entity_id=row["id"],
        diff={"channel": {"old_value": None, "new_value": "email_magic_token"}},
        actor_id=row["id"],
        society_id=row["society_id"],
        ip_address=request.client.host if request.client else None,
    )
    return forgot_form(request, sent="1", error=None)


@router.get("/reset", response_class=HTMLResponse)
def reset_form(request: Request, error: str | None = None):
    return render(request, "auth/forgot.html", {"error": error})


@router.post("/reset", response_class=HTMLResponse)
def reset_submit(
    request: Request,
    email: str = Form(...),
    token: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    email = email.strip().lower()
    row = db.query_one("SELECT * FROM users WHERE lower(email) = ?", (email,))
    token_hash = hashlib.sha256(token.strip().encode()).hexdigest()
    valid = None
    if row:
        valid = db.query_one(
            """SELECT * FROM reset_tokens
               WHERE user_id = ? AND token_hash = ? AND used_at IS NULL
                 AND expires_at > ?""",
            (row["id"], token_hash, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
    if not valid:
        return reset_form(
            request,
            error="That reset code is invalid or expired. Ask the desk for an "
                  "in-person reset code after showing your Form-XI ID.",
        )
    if len(password) < 8 or password != password_confirm:
        return reset_form(request, error="Passwords must match and be at least 8 characters.")

    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (security.hash_password(password), row["id"]),
    )
    db.execute("UPDATE reset_tokens SET used_at = ? WHERE id = ?", (db.utcnow(), valid["id"]))
    audit.log(
        action="PASSWORD_RESET",
        rule_ref="AUTH_RESET_NO_SMS_OTP",
        entity_type="user",
        entity_id=row["id"],
        diff={"password_hash": {"old_value": "[redacted]", "new_value": "[redacted]"}},
        actor_id=row["id"],
        society_id=row["society_id"],
        ip_address=request.client.host if request.client else None,
    )
    flash(request, "Password reset. You can now sign in.")
    return RedirectResponse(url="/login", status_code=303)
