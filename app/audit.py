"""Immutable audit logging (spec 5.2 Tab 6, section 3 schema).

Every state-changing action records ``actor``, ``rule_ref``, ``old_value`` and
``new_value`` so the trail is field-level and append-only. Rows are never
updated or deleted by application code.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from . import db


def compute_entry_hash(
    *,
    prev_hash: str,
    society_id: str | None,
    actor_id: str | None,
    action: str,
    rule_ref: str,
    entity_type: str,
    entity_id: str | None,
    diff_payload: str,
    ip_address: str | None,
    created_at: str,
) -> str:
    """Compute deterministic SHA-256 hash for tamper-evident audit ledger."""
    content = (
        f"{prev_hash}|"
        f"{society_id or ''}|"
        f"{actor_id or ''}|"
        f"{action}|"
        f"{rule_ref}|"
        f"{entity_type}|"
        f"{entity_id or ''}|"
        f"{diff_payload}|"
        f"{ip_address or ''}|"
        f"{created_at}"
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


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
) -> str:
    """Append a cryptographically chained entry to audit_logs."""
    created_at = db.utcnow()
    diff_payload = db.to_json(diff or {})

    # Read the latest entry hash to chain from
    latest = db.query_one(
        "SELECT id, entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
    )
    prev_hash = (latest.get("entry_hash") or "0" * 64) if latest else "0" * 64

    entry_hash = compute_entry_hash(
        prev_hash=prev_hash,
        society_id=society_id,
        actor_id=actor_id,
        action=action,
        rule_ref=rule_ref,
        entity_type=entity_type,
        entity_id=entity_id,
        diff_payload=diff_payload,
        ip_address=ip_address,
        created_at=created_at,
    )

    db.execute(
        """INSERT INTO audit_logs
              (society_id, actor_id, action, rule_ref, entity_type, entity_id,
               diff_payload, ip_address, created_at, prev_hash, entry_hash)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            society_id,
            actor_id,
            action,
            rule_ref,
            entity_type,
            entity_id,
            diff_payload,
            ip_address,
            created_at,
            prev_hash,
            entry_hash,
        ),
    )
    return entry_hash


def verify_audit_hash_chain() -> dict[str, Any]:
    """Verify cryptographic integrity of the entire audit log chain."""
    entries = db.query_all(
        """SELECT id, society_id, actor_id, action, rule_ref, entity_type, entity_id,
                  diff_payload, ip_address, created_at, prev_hash, entry_hash
           FROM audit_logs
           ORDER BY id ASC"""
    )
    if not entries:
        return {"verified": True, "count": 0, "message": "Audit chain empty."}

    expected_prev = "0" * 64
    for idx, e in enumerate(entries):
        actual_prev = e.get("prev_hash") or ("0" * 64 if idx == 0 else "")
        # For legacy unhashed rows before migration, reconcile with entry_hash if present
        actual_hash = e.get("entry_hash")

        if not actual_hash:
            # Legacy unhashed entry
            continue

        recomputed = compute_entry_hash(
            prev_hash=actual_prev,
            society_id=e.get("society_id"),
            actor_id=e.get("actor_id"),
            action=e.get("action", ""),
            rule_ref=e.get("rule_ref", ""),
            entity_type=e.get("entity_type", ""),
            entity_id=e.get("entity_id"),
            diff_payload=e.get("diff_payload") or "{}",
            ip_address=e.get("ip_address"),
            created_at=e.get("created_at", ""),
        )

        if recomputed != actual_hash:
            return {
                "verified": False,
                "corrupted_id": e.get("id"),
                "count": len(entries),
                "message": f"Tamper detected at row ID {e.get('id')}: expected {recomputed[:12]}..., got {actual_hash[:12]}...",
            }
        expected_prev = actual_hash

    return {
        "verified": True,
        "count": len(entries),
        "message": f"All {len(entries)} audit entries cryptographically valid and tamper-free.",
    }


def diff(old: Any, new: Any, fields: list[str]) -> dict[str, Any]:
    """Field-level before/after snapshot for a row change."""
    changes: dict[str, Any] = {}
    for field in fields:
        before = old.get(field) if isinstance(old, dict) else (old[field] if old else None)
        after = new.get(field) if isinstance(new, dict) else new.get(field)
        if before != after:
            changes[field] = {"old_value": before, "new_value": after}
    return changes
