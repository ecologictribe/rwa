"""Enterprise Invariant Sentinel for RWA State Integrity (HRRS 2012 / GFR 2017).

Design-by-Contract system enforcing 8 fundamental invariants across the RWA ledger.
"""

from __future__ import annotations

import datetime
from typing import Any

from . import audit, db


def check_inv_01_active_member_sync() -> dict[str, Any]:
    """INV-01: societies.active_member_count must equal COUNT(users WHERE account_status = 'ACTIVE' AND role != 'SUPER_ADMIN')."""
    societies = db.query_all("SELECT id, name, active_member_count FROM societies")
    violations = []
    for s in societies:
        actual = db.scalar(
            """SELECT COUNT(*) FROM users 
               WHERE society_id = ? AND account_status = 'ACTIVE' AND role != 'SUPER_ADMIN'""",
            (s["id"],),
            default=0,
        )
        expected = s.get("active_member_count") or 0
        if actual != expected:
            violations.append({
                "society_id": s["id"],
                "society_name": s["name"],
                "recorded_active_count": expected,
                "actual_active_users": actual,
            })
    return {
        "code": "INV-01",
        "title": "Active Member Synchronization",
        "description": "Society active_member_count matches live registered active members (HRRS Sec. 30)",
        "passed": len(violations) == 0,
        "violations": violations,
    }


def check_inv_02_governing_body_bounds() -> dict[str, Any]:
    """INV-02: Governing Body statutory size bounds: 3 <= N_GB <= 21 per HRRS Sec. 34(1)."""
    societies = db.query_all("SELECT id, name FROM societies")
    violations = []
    for s in societies:
        count = db.scalar(
            """SELECT COUNT(*) FROM committee_members 
               WHERE society_id = ? AND is_active = 1""",
            (s["id"],),
            default=0,
        )
        if count > 0 and not (3 <= count <= 21):
            violations.append({
                "society_id": s["id"],
                "society_name": s["name"],
                "gb_count": count,
                "allowed_range": "3 to 21 (HRRS Sec. 34(1))",
            })
    return {
        "code": "INV-02",
        "title": "Governing Body Statutory Size Bounds",
        "description": "Active Governing Body size must be between 3 and 21 (HRRS Sec. 34(1))",
        "passed": len(violations) == 0,
        "violations": violations,
    }


def check_inv_03_singleton_executive_bearers() -> dict[str, Any]:
    """INV-03: Singleton executive office bearers (Max 1 President, 1 Secretary, 1 Treasurer)."""
    duplicates = db.query_all(
        """SELECT society_id, designation, COUNT(*) as cnt
           FROM committee_members
           WHERE is_active = 1 AND designation IN ('PRESIDENT', 'GENERAL_SECRETARY', 'TREASURER')
           GROUP BY society_id, designation
           HAVING cnt > 1"""
    )
    return {
        "code": "INV-03",
        "title": "Singleton Executive Office Bearers",
        "description": "At most one active President, General Secretary, and Treasurer per society",
        "passed": len(duplicates) == 0,
        "violations": duplicates,
    }


def check_inv_04_cashless_admission() -> dict[str, Any]:
    """INV-04: Cashless admission invariant (Zero cash instruments in member register per Rule 11(1))."""
    # In form_x_applications, fee_instrument_ref must not denote cash
    all_apps = db.query_all("SELECT id, applicant_name, fee_instrument_ref FROM form_x_applications")
    cash_violations = []
    for app_row in all_apps:
        ref_str = app_row.get("fee_instrument_ref") or ""
        try:
            parsed = db.from_json(ref_str) if ref_str.startswith("{") else {}
            if parsed.get("type", "").upper() == "CASH" or parsed.get("cash_accepted") is True:
                cash_violations.append(app_row)
        except Exception:
            if "CASH" in ref_str.upper() and "CASH_ACCEPTED\":FALSE" not in ref_str.upper().replace(" ", ""):
                cash_violations.append(app_row)

    return {
        "code": "INV-04",
        "title": "Cashless Admission Invariant",
        "description": "Zero cash instruments for membership fee admission (HRRS Rule 11(1))",
        "passed": len(cash_violations) == 0,
        "violations": cash_violations,
    }


def check_inv_05_minutes_dual_signatory() -> dict[str, Any]:
    """INV-05: Minutes dual-signatory precedence (Sec. 37(2)/(3): No confirmation without Chairman + Secretary)."""
    unsigned_confirmed = db.query_all(
        """SELECT id, title, meeting_date, chairman_signed, secretary_signed
           FROM documents
           WHERE doc_category LIKE 'MOM_%' AND confirmed_in_next_meeting_date IS NOT NULL
             AND (chairman_signed = 0 OR secretary_signed = 0)"""
    )
    return {
        "code": "INV-05",
        "title": "Minutes Dual-Signatory Precedence",
        "description": "Confirmed minutes must have Chairman and Secretary dual signatures (HRRS Sec. 37)",
        "passed": len(unsigned_confirmed) == 0,
        "violations": unsigned_confirmed,
    }


def check_inv_06_rule16_quorum_floor() -> dict[str, Any]:
    """INV-06: Rule 16 Quorum Floor: For newly created/confirmed meetings, quorum_present must be >= quorum_required."""
    # In HRRS, an adjourned GBM may proceed with members present, but minutes created under normal Rule 16
    # must not be recorded as quorum_present < quorum_required unless explicitly marked adjourned.
    invalid_quorum = db.query_all(
        """SELECT id, title, quorum_present, quorum_required
           FROM documents
           WHERE doc_category = 'MOM_GBM' AND (chairman_signed = 1 OR secretary_signed = 1)
             AND quorum_present IS NOT NULL AND quorum_required IS NOT NULL
             AND quorum_present < quorum_required"""
    )
    return {
        "code": "INV-06",
        "title": "Rule 16 Quorum Floor",
        "description": "No signed meeting without fulfilling statutory quorum",
        "passed": len(invalid_quorum) == 0,
        "violations": invalid_quorum,
    }


def check_inv_07_statutory_age_floor() -> dict[str, Any]:
    """INV-07: Statutory age floor (Zero members < 21 years of age per HRRS Sec. 16(i))."""
    today = datetime.date.today()
    max_dob_21 = f"{today.year - 21:04d}-{today.month:02d}-{today.day:02d}"
    underage = db.query_all(
        """SELECT id, full_name, email, date_of_birth
           FROM users
           WHERE date_of_birth IS NOT NULL AND date_of_birth > ?""",
        (max_dob_21,),
    )
    return {
        "code": "INV-07",
        "title": "Statutory Age Floor",
        "description": "Zero members younger than 21 years of age (HRRS Sec. 16(i))",
        "passed": len(underage) == 0,
        "violations": underage,
    }


def check_inv_08_audit_chain_integrity() -> dict[str, Any]:
    """INV-08: Cryptographic audit chain integrity (100% of audit entries have valid SHA-256 hash pointers)."""
    result = audit.verify_audit_hash_chain()
    return {
        "code": "INV-08",
        "title": "Cryptographic Audit Chain Integrity",
        "description": "Tamper-evident SHA-256 Merkle chain across entire audit log ledger",
        "passed": result.get("verified", False),
        "count": result.get("count", 0),
        "message": result.get("message", ""),
        "violations": [] if result.get("verified") else [result],
    }


def check_all_invariants() -> dict[str, Any]:
    """Run all 8 enterprise invariants and return consolidated evaluation."""
    invs = [
        check_inv_01_active_member_sync(),
        check_inv_02_governing_body_bounds(),
        check_inv_03_singleton_executive_bearers(),
        check_inv_04_cashless_admission(),
        check_inv_05_minutes_dual_signatory(),
        check_inv_06_rule16_quorum_floor(),
        check_inv_07_statutory_age_floor(),
        check_inv_08_audit_chain_integrity(),
    ]
    all_passed = all(i["passed"] for i in invs)
    total_passed = sum(1 for i in invs if i["passed"])
    return {
        "all_passed": all_passed,
        "passed_count": total_passed,
        "total_count": len(invs),
        "invariants": invs,
    }
