"""SQLite data access layer.

The schema is a SQLite-native translation of the PostgreSQL blueprint in
section 8.2 of the specification:

  * ``UUID``        -> ``TEXT`` (generated app-side with ``uuid4``)
  * ``TIMESTAMPTZ`` -> ``TEXT`` (ISO-8601 UTC)
  * ``JSONB``       -> ``TEXT`` (serialised JSON, validated app-side)
  * ``BIGSERIAL``   -> ``INTEGER PRIMARY KEY AUTOINCREMENT``
  * ``tsvector``    -> superseded by a plain LIKE/FTS-friendly text column

Foreign keys and WAL mode are enabled on every connection.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator, Sequence

from . import config

SCHEMA_PATH = config.APP_DIR / "schema.sql"


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def to_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def from_json(value: Any, default: Any = None) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DATABASE_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


@contextmanager
def connection() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    """Explicit atomic unit of work (used by the bulk edit grid)."""
    with connection() as conn:
        yield conn


def init_db() -> None:
    """Create the schema if it does not exist yet and ensure schema columns are present."""
    if not SCHEMA_PATH.exists():
        raise FileNotFoundError(f"Schema file missing: {SCHEMA_PATH}")
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    with connection() as conn:
        conn.executescript(schema)
        # Backward-compatible migrations for existing SQLite databases
        for tbl, col, typ in [
            ("users", "aadhaar_number", "TEXT"),
            ("users", "qualification", "TEXT"),
            ("users", "profile_photo_path", "TEXT"),
            ("form_x_applications", "occupation", "TEXT"),
            ("form_x_applications", "qualification", "TEXT"),
            ("form_x_applications", "aadhaar_number", "TEXT"),
            ("form_x_applications", "id_proof_path", "TEXT"),
            ("audit_logs", "prev_hash", "TEXT"),
            ("audit_logs", "entry_hash", "TEXT"),
        ]:
            try:
                existing_cols = [c[1] for c in conn.execute(f"PRAGMA table_info({tbl})").fetchall()]
                if col not in existing_cols:
                    conn.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {typ}")
            except Exception:
                pass
        conn.execute("ANALYZE")
        conn.execute("PRAGMA optimize")


def query_all(sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
    """Run a SELECT and return plain dicts.

    ``sqlite3.Row`` is immutable, and both the routes and the Jinja templates
    decorate result rows (term percentages, parsed JSON, rendering helpers), so
    every read is materialised into a dict at this boundary.
    """
    with connection() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def query_one(sql: str, params: Sequence[Any] = (), default: Any = None) -> Any:
    with connection() as conn:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row is not None else default


def execute(sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
    with connection() as conn:
        cur = conn.execute(sql, params)
        return cur


def scalar(sql: str, params: Sequence[Any] = (), default: Any = None) -> Any:
    row = query_one(sql, params)
    if row is None:
        return default
    value = next(iter(row.values()))
    return default if value is None else value
