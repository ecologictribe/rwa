"""Application configuration.

Everything is derived from the environment so the same build runs locally,
on Render, or on any other host. Secrets are generated once and persisted
into the runtime data directory (gitignored) when not supplied.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BASE_DIR / "app"
TEMPLATE_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"

# Runtime data (database, uploads, generated PDFs) lives inside the project
# but is gitignored -- never outside the repo.
DATA_DIR = Path(os.environ.get("RWA_DATA_DIR", BASE_DIR / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
BACKUP_DIR = DATA_DIR / "backups"
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def _load_or_create_secret() -> str:
    """Persist a stable signing secret across restarts on ephemeral disks."""
    env_secret = os.environ.get("RWA_SECRET_KEY")
    if env_secret:
        return env_secret
    secret_file = DATA_DIR / "secret_key"
    if secret_file.exists():
        value = secret_file.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = secrets.token_urlsafe(48)
    secret_file.write_text(value, encoding="utf-8")
    try:
        os.chmod(secret_file, 0o600)
    except OSError:  # pragma: no cover - platform dependent
        pass
    return value


SECRET_KEY = _load_or_create_secret()

DATABASE_PATH = Path(os.environ.get("RWA_DATABASE_PATH", DATA_DIR / "rwa.db"))

# Society identity (Sec. 10(2)) -- overridable per deployment.
SOCIETY_NAME = os.environ.get("RWA_SOCIETY_NAME", "Greenwood Residency RWA")
SOCIETY_REG_NO = os.environ.get("RWA_SOCIETY_REG_NO", "HRS/HR/2014/1187")
SOCIETY_ADDRESS = os.environ.get(
    "RWA_SOCIETY_ADDRESS",
    "Registered Office: A-Block Club House, Greenwood Residency, "
    "Sector 47, Gurugram, Haryana 122018",
)
SOCIETY_EMAIL = os.environ.get("RWA_SOCIETY_EMAIL", "office@greenwoodrwa.in")
SOCIETY_PHONE = os.environ.get("RWA_SOCIETY_PHONE", "+91 124 456 7890")

SESSION_COOKIE_NAME = "rwa_session"
SESSION_MAX_AGE = 60 * 60 * 24 * 14  # 14 days
ENVIRONMENT = os.environ.get("RWA_ENV", "production")
DEBUG = ENVIRONMENT.lower() in {"dev", "development", "debug"}

MAX_UPLOAD_BYTES = 15 * 1024 * 1024  # 15 MB cap per spec 9.1
