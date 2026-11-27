"""Immutable audit logging (spec 5.2 Tab 6, section 3 schema).

Every state-changing action records ``actor``, ``rule_ref``, ``old_value`` and
``new_value`` so the trail is field-level and append-only. Rows are never
updated or deleted by application code.
"""

from __future__ import annotations

from typing import Any

from . import db


def log(
    *,
    action: str,
    rule_ref: str,
    entity_type: str,
    entity_id: str | None = None,
    diff: dict[str, Any] | None = None,
    actor_id: str | None = None,
    society_id: str | None = None,
    ip_address: str | None = None,
) -> None:
    db.execute(
        """INSERT INTO audit_logs
              (society_id, actor_id, action, rule_ref, entity_type, entity_id,
               diff_payload, ip_address, created_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            society_id,
            actor_id,
            action,
            rule_ref,
            entity_type,
            entity_id,
            db.to_json(diff or {}),
            ip_address,
            db.utcnow(),
        ),
    )


def diff(old: Any, new: Any, fields: list[str]) -> dict[str, Any]:
    """Field-level before/after snapshot for a row change."""
    changes: dict[str, Any] = {}
    for field in fields:
        before = old.get(field) if isinstance(old, dict) else (old[field] if old else None)
        after = new.get(field) if isinstance(new, dict) else new.get(field)
        if before != after:
            changes[field] = {"old_value": before, "new_value": after}
    return changes
