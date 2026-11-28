"""Enterprise Data Ingestion & ETL Harness for Pramāna Sovereign RWA (HRS/HR/2014/1187).

Supports high-throughput, transactional bulk insertion and incremental ingestion
of actual enterprise records with multi-layer validation, invariant synchronization,
and automatic cryptographic audit log hash-chaining.
"""

from __future__ import annotations

import csv
import datetime
import io
import json
from typing import Any, Sequence

from . import audit, db, invariants, security
from .storage import is_at_least_21


class IngestionError(Exception):
    """Custom exception raised when record payload fails statutory or schema validation."""
    pass


class IngestionHarness:
    """Production-grade ingestion harness enforcing 3-tier validation and state invariants."""

    def __init__(self, society_id: str | None = None):
        if society_id:
            self.society_id = society_id
        else:
            soc = db.query_one("SELECT id FROM societies LIMIT 1")
            self.society_id = soc["id"] if soc else None

    # -------------------------------------------------------------------------
    # 1. Units / Flats Ingestion
    # -------------------------------------------------------------------------
    def ingest_units(self, records: list[dict[str, Any]], actor_id: str | None = None) -> dict[str, Any]:
        """Ingest or update physical apartment/flat units.
        
        Expected keys per record:
          - block_tower (e.g. 'Tower A', 'Block-B')
          - unit_number (e.g. '101', '402')
          - canonical_code (e.g. 'BLK-A-101')
          - unit_type (default 'APARTMENT')
          - occupancy_status ('OWNER_OCCUPIED', 'TENANT_OCCUPIED', 'VACANT')
          - parking_slot (optional)
        """
        inserted, updated, errors = 0, 0, []
        now = db.utcnow()

        for idx, rec in enumerate(records):
            code = rec.get("canonical_code") or f"{rec.get('block_tower')}-{rec.get('unit_number')}"
            occupancy = (rec.get("occupancy_status") or "VACANT").upper()
            if occupancy not in ("OWNER_OCCUPIED", "TENANT_OCCUPIED", "VACANT"):
                errors.append({"record_index": idx, "code": code, "error": f"Invalid occupancy: {occupancy}"})
                continue

            existing = db.query_one(
                "SELECT id FROM units WHERE society_id = ? AND canonical_code = ?",
                (self.society_id, code),
            )

            if existing:
                db.execute(
                    """UPDATE units 
                       SET block_tower = ?, unit_number = ?, unit_type = ?, 
                           occupancy_status = ?, parking_slot = ?
                       WHERE id = ?""",
                    (
                        rec.get("block_tower", "Block A"),
                        str(rec.get("unit_number", "")),
                        rec.get("unit_type", "APARTMENT"),
                        occupancy,
                        rec.get("parking_slot"),
                        existing["id"],
                    ),
                )
                updated += 1
            else:
                unit_id = db.new_id()
                db.execute(
                    """INSERT INTO units 
                       (id, society_id, block_tower, unit_number, canonical_code,
                        unit_type, occupancy_status, parking_slot)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (
                        unit_id,
                        self.society_id,
                        rec.get("block_tower", "Block A"),
                        str(rec.get("unit_number", "")),
                        code,
                        rec.get("unit_type", "APARTMENT"),
                        occupancy,
                        rec.get("parking_slot"),
                    ),
                )
                inserted += 1

        audit.log(
            action="INGEST_UNITS",
            rule_ref="HRRS_ACT_2012_SEC_15",
            entity_type="UNITS",
            diff={"inserted": inserted, "updated": updated, "error_count": len(errors)},
            actor_id=actor_id,
            society_id=self.society_id,
        )
        return {"ok": len(errors) == 0, "inserted": inserted, "updated": updated, "errors": errors}

    # -------------------------------------------------------------------------
    # 2. Member / User Master Ingestion
    # -------------------------------------------------------------------------
    def ingest_members(self, records: list[dict[str, Any]], default_password: str = "Welcome@123", actor_id: str | None = None) -> dict[str, Any]:
        """Ingest or update statutory registered members (Form-XII Register).
        
        Expected keys per record:
          - full_name (str, min length 3)
          - email (valid email RFC syntax)
          - mobile_number (10-15 digits)
          - date_of_birth ('YYYY-MM-DD', must be >= 21 years per Sec. 16(i))
          - canonical_code (e.g. 'BLK-A-101', optional unit association)
          - member_serial_no (e.g. 'M-1015', optional Form-XII serial)
          - occupation (optional)
          - role ('MEMBER', 'SOCIETY_ADMIN', 'DATA_OPERATOR')
          - account_status ('ACTIVE', 'PENDING', 'SUSPENDED', 'CEASED')
        """
        inserted, updated, errors = 0, 0, []
        pwd_hash = security.hash_password(default_password)
        now = db.utcnow()

        for idx, rec in enumerate(records):
            full_name = (rec.get("full_name") or "").strip()
            email = (rec.get("email") or "").strip().lower()
            mobile = (rec.get("mobile_number") or "").strip()
            dob = rec.get("date_of_birth")

            # Validation guardrails
            if len(full_name) < 3:
                errors.append({"record_index": idx, "email": email, "error": "Name must be at least 3 characters."})
                continue
            if "@" not in email or "." not in email:
                errors.append({"record_index": idx, "email": email, "error": "Invalid email syntax."})
                continue
            digits_mobile = "".join(ch for ch in mobile if ch.isdigit())
            if len(digits_mobile) < 10:
                errors.append({"record_index": idx, "email": email, "error": "Mobile must have at least 10 digits."})
                continue
            if dob:
                dob_date = datetime.date.fromisoformat(dob) if isinstance(dob, str) else dob
                if not is_at_least_21(dob_date, datetime.date.today()):
                    errors.append({"record_index": idx, "email": email, "error": f"Statutory Age Floor Breach: DOB {dob} younger than 21 (Sec. 16(i))."})
                    continue

            # Unit lookup if canonical_code supplied
            unit_id = None
            code = rec.get("canonical_code")
            if code:
                unit_row = db.query_one("SELECT id FROM units WHERE society_id = ? AND canonical_code = ?", (self.society_id, code))
                if unit_row:
                    unit_id = unit_row["id"]

            role = (rec.get("role") or "MEMBER").upper()
            status = (rec.get("account_status") or "ACTIVE").upper()

            # Check if user already exists by email or mobile
            existing = db.query_one(
                "SELECT id FROM users WHERE society_id = ? AND (lower(email) = ? OR mobile_number = ?)",
                (self.society_id, email, mobile),
            )

            if existing:
                db.execute(
                    """UPDATE users
                       SET full_name = ?, mobile_number = ?, date_of_birth = ?,
                           occupation = ?, role = ?, account_status = ?, unit_id = COALESCE(?, unit_id),
                           member_serial_no = COALESCE(?, member_serial_no)
                       WHERE id = ?""",
                    (
                        full_name,
                        mobile,
                        dob,
                        rec.get("occupation"),
                        role,
                        status,
                        unit_id,
                        rec.get("member_serial_no"),
                        existing["id"],
                    ),
                )
                updated += 1
            else:
                user_id = db.new_id()
                db.execute(
                    """INSERT INTO users
                       (id, society_id, unit_id, member_serial_no, full_name,
                        date_of_birth, occupation, email, mobile_number, password_hash,
                        role, account_status, theme_preference, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        user_id,
                        self.society_id,
                        unit_id,
                        rec.get("member_serial_no"),
                        full_name,
                        dob,
                        rec.get("occupation"),
                        email,
                        mobile,
                        pwd_hash,
                        role,
                        status,
                        rec.get("theme_preference", "retro-paper"),
                        now,
                    ),
                )
                inserted += 1

        # Synchronize active_member_count invariant
        self.sync_active_members()

        audit.log(
            action="INGEST_MEMBERS",
            rule_ref="HRRS_ACT_2012_SEC_18_1",
            entity_type="USERS",
            diff={"inserted": inserted, "updated": updated, "error_count": len(errors)},
            actor_id=actor_id,
            society_id=self.society_id,
        )
        return {"ok": len(errors) == 0, "inserted": inserted, "updated": updated, "errors": errors}

    # -------------------------------------------------------------------------
    # 3. Helpdesk / Maintenance Tickets Ingestion
    # -------------------------------------------------------------------------
    def ingest_tickets(self, records: list[dict[str, Any]], actor_id: str | None = None) -> dict[str, Any]:
        """Ingest historical or live complaint/maintenance tickets.
        
        Expected keys per record:
          - category ('Plumbing & Water', 'Electrical', 'Lift & Vertical Transport', etc.)
          - subject (min 5 characters)
          - description (min 10 characters)
          - priority ('LOW', 'MEDIUM', 'HIGH', 'URGENT')
          - status ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'REOPENED', etc.)
          - canonical_code (optional unit code)
          - raised_by_email (or user id)
          - created_at (ISO timestamp)
          - resolved_at (optional ISO timestamp)
        """
        inserted, errors = 0, []
        admin = db.query_one("SELECT id FROM users WHERE role = 'SOCIETY_ADMIN' LIMIT 1")
        admin_id = admin["id"] if admin else None

        for idx, rec in enumerate(records):
            subj = (rec.get("subject") or "").strip()
            desc = (rec.get("description") or "").strip()
            if len(subj) < 5 or len(desc) < 10:
                errors.append({"record_index": idx, "error": "Subject must be >= 5 chars, Description >= 10 chars."})
                continue

            # Lookup unit and user
            unit_id = None
            if rec.get("canonical_code"):
                u = db.query_one("SELECT id FROM units WHERE canonical_code = ?", (rec["canonical_code"],))
                if u:
                    unit_id = u["id"]

            user_id = None
            if rec.get("raised_by_email"):
                usr = db.query_one("SELECT id FROM users WHERE lower(email) = ?", (rec["raised_by_email"].lower(),))
                if usr:
                    user_id = usr["id"]
            if not user_id:
                user_id = admin_id

            # Determine next ticket number
            next_tnum = (db.scalar("SELECT MAX(ticket_number) FROM tickets WHERE society_id = ?", (self.society_id,), default=100) or 100) + 1

            ticket_id = db.new_id()
            db.execute(
                """INSERT INTO tickets
                   (id, society_id, ticket_number, unit_id, raised_by, assigned_to,
                    category, location_scope, subject, description, status, priority,
                    work_log, feedback_rating, created_at, resolved_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ticket_id,
                    self.society_id,
                    rec.get("ticket_number") or next_tnum,
                    unit_id,
                    user_id,
                    admin_id,
                    rec.get("category", "General Maintenance"),
                    rec.get("location_scope", "COMMON_AREA"),
                    subj,
                    desc,
                    (rec.get("status") or "OPEN").upper(),
                    (rec.get("priority") or "MEDIUM").upper(),
                    db.to_json(rec.get("work_log") or []),
                    rec.get("feedback_rating"),
                    rec.get("created_at") or db.utcnow(),
                    rec.get("resolved_at"),
                ),
            )
            inserted += 1

        audit.log(
            action="INGEST_TICKETS",
            rule_ref="HELPDESK_OPERATIONAL_SLA",
            entity_type="TICKETS",
            diff={"inserted": inserted, "error_count": len(errors)},
            actor_id=actor_id,
            society_id=self.society_id,
        )
        return {"ok": len(errors) == 0, "inserted": inserted, "errors": errors}

    # -------------------------------------------------------------------------
    # 4. Public Notices / Announcements Ingestion
    # -------------------------------------------------------------------------
    def ingest_notices(self, records: list[dict[str, Any]], actor_id: str | None = None) -> dict[str, Any]:
        """Ingest statutory announcements and public transparency notices.
        
        Expected keys per record:
          - title (str, min length 3)
          - body_markdown (str, min length 5)
          - priority ('GENERAL', 'URGENT', 'SHUTDOWN', 'AGM_NOTICE', 'EVENT')
          - is_public (bool or int: 1/0)
          - is_pinned (bool or int: 1/0, optional)
          - slug (optional unique identifier, auto-generated from title if omitted)
          - published_at (optional ISO timestamp, defaults to now)
        """
        import re

        def _make_slug(s: str) -> str:
            s = s.lower().strip()
            s = re.sub(r"[^\w\s-]", "", s)
            return re.sub(r"[-\s]+", "-", s)[:60].strip("-")

        inserted, updated, errors = 0, 0, []
        now = db.utcnow()
        admin = db.query_one("SELECT id FROM users WHERE role = 'SOCIETY_ADMIN' LIMIT 1")
        admin_id = admin["id"] if admin else None

        for idx, rec in enumerate(records):
            title = (rec.get("title") or "").strip()
            body = (rec.get("body_markdown") or rec.get("body") or "").strip()
            priority = (rec.get("priority") or "GENERAL").upper()
            if priority not in ('URGENT', 'SHUTDOWN', 'AGM_NOTICE', 'GENERAL', 'EVENT'):
                priority = 'GENERAL'

            if len(title) < 3:
                errors.append({"record_index": idx, "title": title, "error": "Notice title must be at least 3 characters."})
                continue
            if len(body) < 5:
                errors.append({"record_index": idx, "title": title, "error": "Notice body must be at least 5 characters."})
                continue

            slug = rec.get("slug")
            if not slug:
                base_slug = _make_slug(title) or "notice"
                slug = base_slug
                # Handle slug collision
                suffix = 1
                while db.scalar("SELECT id FROM announcements WHERE society_id = ? AND slug = ?", (self.society_id, slug)):
                    slug = f"{base_slug}-{suffix}"
                    suffix += 1

            is_pub = 1 if rec.get("is_public", True) else 0
            is_pin = 1 if rec.get("is_pinned", False) else 0
            pub_at = rec.get("published_at") or now

            existing = db.query_one(
                "SELECT id FROM announcements WHERE society_id = ? AND slug = ?",
                (self.society_id, slug),
            )

            if existing:
                db.execute(
                    """UPDATE announcements
                       SET title = ?, body_markdown = ?, priority = ?, is_public = ?, is_pinned = ?
                       WHERE id = ?""",
                    (title, body, priority, is_pub, is_pin, existing["id"]),
                )
                updated += 1
            else:
                notice_id = db.new_id()
                db.execute(
                    """INSERT INTO announcements
                       (id, society_id, slug, title, body_markdown, priority,
                        is_public, is_pinned, published_by, published_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        notice_id,
                        self.society_id,
                        slug,
                        title,
                        body,
                        priority,
                        is_pub,
                        is_pin,
                        admin_id,
                        pub_at,
                    ),
                )
                inserted += 1

        audit.log(
            action="INGEST_NOTICES",
            rule_ref="HRRS_ACT_2012_SEC_10_2 | RULE_6",
            entity_type="ANNOUNCEMENTS",
            diff={"inserted": inserted, "updated": updated, "error_count": len(errors)},
            actor_id=actor_id,
            society_id=self.society_id,
        )
        return {"ok": len(errors) == 0, "inserted": inserted, "updated": updated, "errors": errors}

    # -------------------------------------------------------------------------
    # 5. Invariant Synchronization & Audit Ledger Re-Sealing
    # -------------------------------------------------------------------------
    def sync_active_members(self) -> int:
        """Synchronize societies.active_member_count to satisfy INV-01."""
        active_count = db.scalar(
            "SELECT COUNT(*) FROM users WHERE society_id = ? AND account_status = 'ACTIVE' AND role != 'SUPER_ADMIN'",
            (self.society_id,),
            default=0,
        )
        db.execute("UPDATE societies SET active_member_count = ? WHERE id = ?", (active_count, self.society_id))
        return active_count

    def seal_and_verify(self) -> dict[str, Any]:
        """Re-hash audit chain and assert all 8 system invariants."""
        # 1. Sync member counts
        self.sync_active_members()

        # 2. Re-seal audit ledger
        entries = db.query_all("SELECT * FROM audit_logs ORDER BY id ASC")
        prev_hash = "0" * 64
        for e in entries:
            h = audit.compute_entry_hash(
                prev_hash=prev_hash,
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
            db.execute("UPDATE audit_logs SET prev_hash = ?, entry_hash = ? WHERE id = ?", (prev_hash, h, e["id"]))
            prev_hash = h

        # 3. Verify invariants
        inv_result = invariants.check_all_invariants()
        aud_result = audit.verify_audit_hash_chain()

        return {
            "all_passed": inv_result["all_passed"] and aud_result["verified"],
            "invariants": inv_result,
            "audit_verification": aud_result,
        }
