"""FastAPI application entry point.

Ultra-lightweight server-driven web app: Jinja2 fragments swapped with HTMX,
Alpine.js only for local UI state, no client-side SPA bundle.
"""

from __future__ import annotations

import json
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from . import config, db, security
from .render import (  # noqa: E402
    flash,
    flash_cookie_payload,
    parse_flash_cookie,
    render,
)

app = FastAPI(
    title="RWA Governance Portal",
    docs_url="/api/docs" if config.DEBUG else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if config.DEBUG else None,
)

app.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")

FLASH_COOKIE = "rwa_flash"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attaches the principal, seeds flash messages, and persists any new ones.

    Flash messages ride a short-lived HttpOnly cookie so a POST -> redirect ->
    GET cycle can report the outcome without server-side session state.
    """

    async def dispatch(self, request: Request, call_next):
        request.state.principal = security.get_principal(request)
        request.state.messages = []

        seeded = 0
        if FLASH_COOKIE in request.cookies:
            pending = parse_flash_cookie(request.cookies[FLASH_COOKIE])
            request.state.messages.extend(pending)
            seeded = len(pending)

        response = await call_next(request)

        added = request.state.messages[seeded:]
        if added:
            response.set_cookie(
                FLASH_COOKIE,
                flash_cookie_payload(added),
                max_age=5,
                httponly=True,
                samesite="lax",
            )
        elif FLASH_COOKIE in request.cookies:
            response.delete_cookie(FLASH_COOKIE)

        # Statutory & OWASP Security Post-Flight Headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


app.add_middleware(RequestContextMiddleware)


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

from .routes import admin, api, auth, portal, public  # noqa: E402

app.include_router(public.router)
app.include_router(auth.router)
app.include_router(portal.router)
app.include_router(admin.router)
app.include_router(api.router)


def _wants_json(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return request.url.path.startswith("/api/") or "application/json" in accept


@app.exception_handler(401)
async def unauthorized_handler(request: Request, exc):
    if _wants_json(request):
        return JSONResponse({"status": "unauthorized", "detail": "Authentication required."}, status_code=401)
    return RedirectResponse(url=f"/login?next={request.url.path}", status_code=302)


@app.exception_handler(403)
async def forbidden_handler(request: Request, exc):
    detail = getattr(exc, "detail", "Your role does not permit this action.")
    if _wants_json(request):
        return JSONResponse({"status": "forbidden", "detail": detail}, status_code=403)
    return render(
        request,
        "error.html",
        {
            "error_code": "403",
            "error_title": "Permission denied",
            "error_text": detail,
        },
        status_code=403,
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    if _wants_json(request):
        return JSONResponse({"status": "not_found", "detail": "The requested resource was not found."}, status_code=404)
    return render(
        request,
        "error.html",
        {
            "error_code": "404",
            "error_title": "Page not found",
            "error_text": "The page you requested does not exist or is no longer published.",
        },
        status_code=404,
    )


@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    if _wants_json(request):
        return JSONResponse({"status": "error", "detail": "An unexpected server error occurred."}, status_code=500)
    return render(
        request,
        "error.html",
        {
            "error_code": "500",
            "error_title": "Unexpected error",
            "error_text": "The request could not be completed. Please retry or contact the society desk.",
        },
        status_code=500,
    )


@app.on_event("startup")
def on_startup() -> None:
    # Auto-create the schema on a fresh host (first deploy to a clean host).
    db.init_db()
    if os.environ.get("RWA_AUTO_SEED", "true").lower() in {"1", "true", "yes"}:
        from . import seed
        seed.build()


def main() -> None:  # pragma: no cover - local convenience runner
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=config.DEBUG)


if __name__ == "__main__":  # pragma: no cover
    main()
