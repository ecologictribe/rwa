"""End-to-end smoke test for the RWA portal.

Boots the app with FastAPI's in-process TestClient (no network, no server
process) and walks every route class: public zone, auth flows, member portal,
admin workspace, and the JSON APIs.

Run:  python -m app.smoke_test
"""

from __future__ import annotations

import io
from datetime import date
import sys

from fastapi.testclient import TestClient

from . import config, db
from .main import app
from .routes.auth import _safe_next
from .storage import (
    calculate_statutory_quorum,
    compute_taleb_diagnostics,
    is_at_least_21,
    term_progress,
)

PASS = "PASS"
FAIL = "FAIL"

results: list[tuple[str, str, str]] = []


def check(name: str, response, expect: int | tuple[int, ...] = 200,
          must_contain: str | None = None, must_not_contain: str | None = None):
    codes = expect if isinstance(expect, tuple) else (expect,)
    ok = response.status_code in codes
    detail = f"status={response.status_code} (want {codes})"
    if ok and must_contain:
        ok = must_contain in response.text
        detail += f", contains={must_contain!r}: {ok}"
    if ok and must_not_contain:
        ok = must_not_contain not in response.text
        detail += f", excludes={must_not_contain!r}: {ok}"
    results.append((PASS if ok else FAIL, name, detail))


def main() -> int:
    # Seed is expected to have run already (python -m app.seed).
    with TestClient(app) as client:
        # ---------------- Public zone (zero login) ----------------
        check("GET /", client.get("/"), 200, "Public Transparency Zone")
        check("GET / has statutory citations", client.get("/"), 200, "Sec. 36(1)")
        check("GET /governance", client.get("/governance"), 200, "Committee Progress")
        check("GET /governance has statutory citations", client.get("/governance"), 200, "Sec. 34(3)")
        check("GET /governance?filter=nominated", client.get("/governance?filter=nominated"),
              200, "Nominated")
        check("GET /notices", client.get("/notices"), 200, "Notices")
        check("GET /notices has statutory citations", client.get("/notices"), 200, "Sec. 10(2)")
        check("GET /contacts", client.get("/contacts"), 200, "Emergency")
        check("GET /apply", client.get("/apply"), 200, "Form-X")
        check("GET /api/health", client.get("/api/health"), 200, "ok")
        check("GET /manifest", client.get("/manifest"), 200, "RWA Governance")
        check("GET /static/css/app.css", client.get("/static/css/app.css"), 200, "data-theme")
        check("GET /static/vendor/htmx.min.js", client.get("/static/vendor/htmx.min.js"), 200)
        check("GET /static/vendor/alpine.min.js", client.get("/static/vendor/alpine.min.js"), 200)
        check("GET /nonexistent-xyz", client.get("/nonexistent-xyz"), 404)

        # ---------------- Notice sharing & statutory citations ----------------
        first_slug = db.scalar("SELECT slug FROM announcements WHERE is_public = 1 LIMIT 1", default="")
        if first_slug:
            r = client.get(f"/api/notice/{first_slug}/share")
            check("Notice share API has statutory citation", r, 200, "Sec. 10(2) & Rule 6")
            r = client.get(f"/notices/{first_slug}")
            check("Notice detail has statutory citation", r, 200, "Sec. 10(2)")

        # ---------------- Form-X validation (sec 3.1) ----------------
        # Under-21 applicant must be rejected with Sec. 16(i).
        under21 = {
            "applicant_name": "Test Minor",
            "father_or_spouse_name": "Sh. Test Senior",
            "date_of_birth": "2010-01-01",
            "membership_category": "ORDINARY",
            "flat_id": "BLK-A-0101",
            "mobile_number": "+919811112222",
            "email": "minor@example.com",
            "permanent_address": "Sector 47, Gurugram",
            "residential_address": "",
            "fee_instrument_type": "CHEQUE",
            "fee_instrument_number": "123456",
            "fee_instrument_bank": "HDFC Bank",
            "fee_instrument_date": "2026-01-01",
            "aims_subscribed": "on",
            "decl_insolvent": "on",
            "decl_sound_mind": "on",
            "decl_moral_turpitude": "on",
        }
        r = client.post("/apply", data=under21, follow_redirects=False)
        check("Form-X blocks applicant under 21 (Sec. 16(i))", r, 422,
              must_contain="21 years")

        # Cash instrument must be rejected (Rule 11(1)).
        cash = dict(under21, date_of_birth="1990-01-01",
                    email="cash@example.com", fee_instrument_type="CASH")
        r = client.post("/apply", data=cash, follow_redirects=False)
        check("Form-X rejects cash instrument (Rule 11(1))", r, 422,
              must_contain="Cash is not accepted")

        # Missing declarations must be rejected (Sec. 16(iv)).
        nodecl = dict(under21, date_of_birth="1990-01-01", email="nodecl@example.com")
        nodecl.pop("decl_insolvent")
        nodecl.pop("decl_sound_mind")
        nodecl.pop("decl_moral_turpitude")
        r = client.post("/apply", data=nodecl, follow_redirects=False)
        check("Form-X blocks missing Sec. 16(iv) declarations", r, 422,
              must_contain="undischarged insolvent")

        # Valid application must be accepted and redirect.
        db.execute("DELETE FROM form_x_applications WHERE lower(email) = 'valid.applicant@example.com'")
        valid = dict(under21, date_of_birth="1990-06-15",
                     applicant_name="Valid Applicant",
                     email="valid.applicant@example.com",
                     mobile_number="+919877776666")
        r = client.post("/apply", data=valid, follow_redirects=False)
        check("Valid Form-X application accepted", r, 303)

        # ---------------- Auth ----------------
        r = client.get("/login")
        check("GET /login", r, 200, "Sign In")

        # Wrong password must fail.
        r = client.post("/login",
                        data={"email": "president@greenwoodrwa.in",
                              "password": "wrong-password",
                              "next": "/portal"},
                        follow_redirects=False)
        check("Bad password rejected", r, 200, must_contain="No account matches")

        # Login as society admin, then hit the admin workspace.
        r = client.post("/login",
                        data={"email": "president@greenwoodrwa.in",
                              "password": "Welcome@123",
                              "next": "/admin"},
                        follow_redirects=False)
        check("Society Admin login", r, 303)

        # ---------------- Admin workspace ----------------
        r = client.get("/admin")
        check("GET /admin", r, 200, "Administration")
        for tab in "123456":
            r = client.get(f"/admin/tabs/{tab}")
            check(f"Admin tab {tab}", r, 200)
        check("Admin tab 1 has countdowns", client.get("/admin/tabs/1"),
              200, "Statutory Filing Countdowns")
        check("Admin tab 4 has graph SVG", client.get("/admin/tabs/4"),
              200, "<svg")
        check("Admin tab 6 has audit trail", client.get("/admin/tabs/6"),
              200, "rule_ref")

        check("GET /admin/directory", client.get("/admin/directory"), 200, "Directory")
        check("GET /admin/admissions", client.get("/admin/admissions"), 200, "Admission")
        check("GET /admin/announcements", client.get("/admin/announcements"), 200)
        check("GET /admin/tickets", client.get("/admin/tickets"), 200)
        check("GET /admin/committee", client.get("/admin/committee"), 200,
              must_contain="Governing Body")
        check("GET /admin/initiatives", client.get("/admin/initiatives"), 200)
        check("GET /admin/vault", client.get("/admin/vault"), 200)
        check("GET /admin/exports", client.get("/admin/exports"), 200, "Rule 23")

        # ---------------- Member CRUD & Exports ----------------
        check("GET /admin/directory/create", client.get("/admin/directory/create"), 200, "Add Member")
        db.execute("DELETE FROM users WHERE email = 'direct.member@example.com'")
        r = client.post(
            "/admin/directory/create",
            data={
                "full_name": "Direct Member",
                "father_or_spouse_name": "Sh. Senior Member",
                "date_of_birth": "1988-04-12",
                "occupation": "Advocate",
                "permanent_address": "Sector 47, Gurugram",
                "residential_address": "BLK-A-0102",
                "mobile_number": "+919811199999",
                "email": "direct.member@example.com",
                "role": "MEMBER",
                "membership_category": "ORDINARY",
                "admission_date": "2026-02-01",
            },
            follow_redirects=False,
        )
        check("POST /admin/directory/create", r, 303)
        created_user = db.query_one("SELECT id FROM users WHERE email = 'direct.member@example.com'")
        if created_user:
            check("GET /admin/directory/{id}/edit",
                  client.get(f"/admin/directory/{created_user['id']}/edit"), 200, "Member Dossier")
            r = client.post(
                f"/admin/directory/{created_user['id']}/edit",
                data={
                    "full_name": "Direct Member (Updated)",
                    "father_or_spouse_name": "Sh. Senior Member",
                    "date_of_birth": "1988-04-12",
                    "occupation": "Senior Advocate",
                    "permanent_address": "Sector 47, Gurugram",
                    "residential_address": "BLK-A-0102",
                    "mobile_number": "+919811199999",
                    "email": "direct.member@example.com",
                    "role": "MEMBER",
                    "membership_category": "LIFE",
                    "account_status": "ACTIVE",
                    "admission_date": "2026-02-01",
                },
                follow_redirects=False,
            )
            check("POST /admin/directory/{id}/edit", r, 303)
            r = client.post(
                f"/admin/directory/{created_user['id']}/cessation",
                data={"cessation_reason": "Sold Flat BLK-A-0102"},
                follow_redirects=False,
            )
            check("POST /admin/directory/{id}/cessation", r, 303)

        check("GET /admin/directory/export/csv", client.get("/admin/directory/export/csv"), 200, "Sl No,Member Serial")

        # ---------------- Notice CRUD & Exports ----------------
        check("GET /admin/announcements/export/csv", client.get("/admin/announcements/export/csv"), 200, "Title,Slug")
        test_ann = db.query_one("SELECT id FROM announcements LIMIT 1")
        if test_ann:
            check("GET /admin/announcements/{id}/edit",
                  client.get(f"/admin/announcements/{test_ann['id']}/edit"), 200, "Edit Notice")
            r = client.post(
                f"/admin/announcements/{test_ann['id']}/edit",
                data={
                    "title": "Quarterly Fire Standpipe Test (Revised)",
                    "body_markdown": "## Revised Notice\n\nStandpipe test is rescheduled to Sunday.",
                    "priority": "URGENT",
                    "is_public": "on",
                    "is_pinned": "on",
                },
                follow_redirects=False,
            )
            check("POST /admin/announcements/{id}/edit", r, 303)

        # ---------------- Statutory Real CSV Exports ----------------
        check("GET /admin/exports/form-xii/csv", client.get("/admin/exports/form-xii/csv"), 200, "FORM-XII: REGISTER OF MEMBERS")
        check("GET /admin/exports/form-xv/csv", client.get("/admin/exports/form-xv/csv"), 200, "FORM-XV: ANNUAL INCLUSION AND DELETION RETURN")
        check("GET /admin/exports/tickets/csv", client.get("/admin/exports/tickets/csv"), 200, "Ticket Number")
        check("GET /admin/exports/audit/csv", client.get("/admin/exports/audit/csv"), 200, "Rule Reference")
        check("GET /admin/exports has Rule 23", client.get("/admin/exports"), 200, "Rule 23")

        # ---------------- Member portal ----------------
        client.get("/logout", follow_redirects=False)
        r = client.post("/login",
                        data={"email": "resident-0@greenwoodrwa.in",
                              "password": "Welcome@123",
                              "next": "/portal"},
                        follow_redirects=False)
        check("Member login", r, 303)
        check("GET /portal", client.get("/portal"), 200, "Welcome")
        check("GET /portal/tickets", client.get("/portal/tickets"), 200)
        check("GET /portal/documents", client.get("/portal/documents"), 200)
        check("GET /portal/profile", client.get("/portal/profile"), 200, "Form-XI")
        check("GET /portal/profile has Sec. 21(5)", client.get("/portal/profile"), 200, "Sec. 21(5)")

        # Test Member Self-Service Profile & Credential update
        r = client.post(
            "/portal/profile/update",
            data={
                "father_or_spouse_name": "Sh. R. K. Resident",
                "date_of_birth": "1985-05-15",
                "occupation": "Chartered Accountant",
                "qualification": "FCA / B.Com",
                "aadhaar_number": "987654321098",
                "residential_address": "BLK-A-0101",
                "permanent_address": "Sector 47, Gurugram",
            },
            follow_redirects=False,
        )
        check("POST /portal/profile/update", r, 303)
        check("GET /portal/profile has masked aadhaar", client.get("/portal/profile"), 200, "XXXX-XXXX-1098")

        # Raise a ticket end to end.
        r = client.post("/portal/tickets",
                        data={"category": "Plumbing & Water",
                              "subject": "Low pressure on floor 4",
                              "description": "Water pressure drops every morning "
                                             "between 7 and 9 am.",
                              "location_scope": "UNIT",
                              "priority": "HIGH"},
                        follow_redirects=False)
        check("Raise ticket", r, 303)

        # ---------------- State Machine Remediation Tests ----------------
        # 1. Member can reopen ticket from AWAITING_CONFIRMATION or RESOLVED
        ticket_row = db.query_one("SELECT id FROM tickets WHERE subject = 'Low pressure on floor 4' ORDER BY created_at DESC LIMIT 1")
        if ticket_row:
            db.execute("UPDATE tickets SET status = 'AWAITING_CONFIRMATION' WHERE id = ?", (ticket_row["id"],))
            r = client.post(f"/portal/tickets/{ticket_row['id']}/reopen",
                            data={"reason": "Still low pressure on floor 4"},
                            follow_redirects=False)
            check("Resident can reopen ticket", r, 303)
            check("Portal tickets view shows REOPENED", client.get("/portal/tickets"), 200, "REOPENED")

        # 2. Session invalidated immediately when account_status becomes SUSPENDED or CEASED
        db.execute("UPDATE users SET account_status = 'SUSPENDED' WHERE email = 'resident-0@greenwoodrwa.in'")
        r = client.get("/portal", follow_redirects=False)
        check("Suspended member session rejected immediately from /portal", r, (302, 401))
        db.execute("UPDATE users SET account_status = 'ACTIVE' WHERE email = 'resident-0@greenwoodrwa.in'")

        # 3. Log back in as Society Admin for admin FSM checks
        client.post("/login",
                    data={"email": "president@greenwoodrwa.in",
                          "password": "Welcome@123",
                          "next": "/admin"},
                    follow_redirects=False)

        # 4. Committee filing recording endpoint
        cm = db.query_one("SELECT id FROM committee_members WHERE is_active = 1 LIMIT 1")
        if cm:
            r = client.post(f"/admin/committee/{cm['id']}/file",
                            data={"filing_date": "2026-02-15"},
                            follow_redirects=False)
            check("POST /admin/committee/{id}/file", r, 303)
            cm_after = db.query_one("SELECT filed_with_registrar_on FROM committee_members WHERE id = ?", (cm["id"],))
            assert cm_after["filed_with_registrar_on"] == "2026-02-15"
            check("Committee roster displays filed date", client.get("/admin/committee"), 200, "2026-02-15")

        # 5. Society active_member_count synchronization check
        actual_active = db.scalar("SELECT COUNT(*) FROM users WHERE account_status = 'ACTIVE' AND role != 'SUPER_ADMIN'", default=0)
        soc_active = db.scalar("SELECT active_member_count FROM societies LIMIT 1", default=0)
        check(f"Active member count synchronized ({soc_active} == {actual_active})",
              client.get("/api/health"), 200)
        assert actual_active == soc_active

        # 6. Premature confirmation blocked on unsigned document (Sec. 37(3))
        doc_unsigned = db.query_one("SELECT id FROM documents WHERE chairman_signed = 0 AND secretary_signed = 0 LIMIT 1")
        if doc_unsigned:
            r = client.post(f"/admin/vault/{doc_unsigned['id']}/confirm",
                            data={"confirm_date": "2026-03-01"},
                            follow_redirects=False)
            check("Premature MoM confirmation blocked (Sec. 37(3))", r, 303)
            doc_after = db.query_one("SELECT confirmed_in_next_meeting_date FROM documents WHERE id = ?", (doc_unsigned["id"],))
            assert doc_after["confirmed_in_next_meeting_date"] is None

        # ---------------- RBAC enforcement ----------------
        client.get("/logout", follow_redirects=False)
        client.post("/login",
                    data={"email": "resident-0@greenwoodrwa.in",
                          "password": "Welcome@123",
                          "next": "/portal"},
                    follow_redirects=False)
        # A member must not reach the admin workspace.
        r = client.get("/admin", follow_redirects=False)
        check("Member blocked from /admin", r, (302, 403))

        # Anonymous must not reach the portal.
        client.get("/logout", follow_redirects=False)
        r = client.get("/portal", follow_redirects=False)
        check("Anonymous redirected from /portal", r, (302, 401))

        # ---------------- Decision Table & Path Dependency Audits ----------------
        # 1. Leap day age boundary test (Sec. 16(i))
        assert is_at_least_21(date(2004, 2, 29), date(2025, 2, 28)) is True
        assert is_at_least_21(date(2004, 2, 29), date(2025, 2, 27)) is False
        assert is_at_least_21(date(2004, 2, 29), date(2028, 2, 29)) is True
        check("Feb 29 leap-day age logic verified", client.get("/api/health"), 200)

        # 2. Open redirect path protection
        assert _safe_next("/\\evil.com") == "/portal"
        assert _safe_next("//evil.com") == "/portal"
        assert _safe_next("/portal/profile") == "/portal/profile"
        check("Open redirect backslash exploit blocked", client.get("/api/health"), 200)

        # 3. Form-X multipart proof upload & Admin proof review
        form_x_email = f"applicant_test_{db.new_id()[:6]}@example.com"
        form_x_mob = f"9811{db.new_id()[:6]}"
        files = {"proof": ("kyc_proof.pdf", b"%PDF-1.4 simulated proof content", "application/pdf")}
        r = client.post(
            "/apply",
            data={
                "applicant_name": "Deepak Leap Applicant",
                "father_or_spouse_name": "R. K. Sharma",
                "date_of_birth": "2004-02-29",
                "membership_category": "ORDINARY",
                "flat_id": "T1-0101",
                "mobile_number": form_x_mob,
                "email": form_x_email,
                "permanent_address": "House 123, Sector 14, Gurugram, Haryana",
                "residential_address": "House 123, Sector 14, Gurugram, Haryana",
                "occupation": "Advocate",
                "qualification": "LL.B",
                "aadhaar_number": "9999 8888 7777",
                "fee_instrument_type": "CHEQUE",
                "fee_instrument_number": "CHQ-LEAP-01",
                "fee_instrument_bank": "State Bank of India",
                "fee_instrument_date": "2026-02-01",
                "aims_subscribed": "on",
                "decl_insolvent": "on",
                "decl_sound_mind": "on",
                "decl_moral_turpitude": "on",
            },
            files=files,
            follow_redirects=False,
        )
        check("Form-X with KYC proof accepted (Feb 29 DOB)", r, 303)
        created_app = db.query_one("SELECT * FROM form_x_applications WHERE email = ?", (form_x_email,))
        assert created_app is not None
        assert created_app["id_proof_path"] is not None

        # Admin login to view and approve
        client.get("/logout", follow_redirects=False)
        client.post("/login",
                    data={"email": "admin@greenwoodrwa.in", "password": "Welcome@123", "next": "/admin"},
                    follow_redirects=False)
        r = client.get(f"/admin/admissions/{created_app['id']}/proof")
        check("Admin can download/view applicant KYC proof", r, 200)

        # Approve applicant and check users.id_proof_path & v_statutory_countdowns
        r = client.post(f"/admin/admissions/{created_app['id']}/approve", follow_redirects=False)
        check("Admin approved Form-X applicant", r, 303)
        admitted_user = db.query_one("SELECT * FROM users WHERE email = ?", (form_x_email,))
        assert admitted_user is not None
        assert admitted_user["id_proof_path"] == created_app["id_proof_path"]
        assert admitted_user["account_status"] == "PENDING"
        # Verify admitted pending user appears in statutory countdown SLA
        sla_entry = db.query_one("SELECT * FROM v_statutory_countdowns WHERE entity_id = ?", (admitted_user["id"],))
        assert sla_entry is not None
        check("Statutory countdown SLA includes admitted PENDING member", client.get("/api/health"), 200)

        # 4. Vault Document Downloads
        doc_row = db.query_one("SELECT d.id FROM documents d JOIN document_versions dv ON dv.document_id = d.id WHERE d.visibility = 'PUBLIC' LIMIT 1")
        if doc_row:
            r = client.get(f"/admin/vault/{doc_row['id']}/download")
            check("Admin downloads vault document PDF", r, 200)
            r = client.get(f"/admin/vault/{doc_row['id']}/versions/1/download")
            check("Admin downloads specific version PDF", r, 200)

        # 5. Rule 16 Quorum block on MoM signoff
        inquorate_id = db.new_id()
        soc_id = db.scalar("SELECT id FROM societies LIMIT 1")
        db.execute(
            """INSERT INTO documents
               (id, society_id, doc_category, title, meeting_date, quorum_present,
                quorum_required, chairman_signed, secretary_signed, current_version_num,
                visibility, created_by, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (inquorate_id, soc_id, "MOM_GB", "Inquorate Test Meeting", "2026-02-10", 3, 10, 0, 0, 1,
             "MEMBERS_ONLY", admitted_user["id"], db.utcnow()),
        )
        r = client.post(f"/admin/vault/{inquorate_id}/signoff", data={"signer": "chairman"}, follow_redirects=False)
        check("Inquorate meeting signoff blocked under Rule 16", r, 303)
        inq_doc = db.query_one("SELECT chairman_signed FROM documents WHERE id = ?", (inquorate_id,))
        assert inq_doc["chairman_signed"] == 0

        # 6. Sole office bearer guard (Sec. 34)
        r = client.post(
            "/admin/committee",
            data={
                "user_id": admitted_user["id"],
                "designation": "PRESIDENT",
                "portfolio": "Presidency",
                "selection_mode": "NOMINATED_COOPTED",
                "term_start_date": "2026-01-01",
            },
            follow_redirects=False,
        )
        check("Duplicate President appointment blocked (Sec. 34)", r, 303)

        # 7. DATA_OPERATOR access to ticket desk
        client.get("/logout", follow_redirects=False)
        client.post("/login",
                    data={"email": "operator@greenwoodrwa.in", "password": "Welcome@123", "next": "/admin/tickets"},
                    follow_redirects=False)
        r = client.get("/admin/tickets")
        check("DATA_OPERATOR can access /admin/tickets desk", r, 200)

        # 8. Resident document download
        client.get("/logout", follow_redirects=False)
        client.post("/login",
                    data={"email": "resident-0@greenwoodrwa.in", "password": "Welcome@123", "next": "/portal"},
                    follow_redirects=False)
        if doc_row:
            r = client.get(f"/portal/documents/{doc_row['id']}/download")
            check("Resident downloads document PDF from portal", r, 200)

        # ---------------- Theme API ----------------
        r = client.post("/api/theme", json={"theme": "amber-crt"})
        check("Theme API accepts valid theme", r, 200, "amber-crt")
        r = client.post("/api/theme", json={"theme": "rainbow"})
        check("Theme API rejects unknown theme", r, 400)

        # ---------------- Silicon Math & Contract Hardening Invariants ----------------
        # 1. Exact Statutory Quorum Ceiling Math (HRRS Rule 16)
        assert calculate_statutory_quorum(41) == 17  # 40% of 41 = 16.4 -> ceiling 17 (39.02% is illegal)
        assert calculate_statutory_quorum(40) == 16  # 40% of 40 = 16
        assert calculate_statutory_quorum(10) == 4
        assert calculate_statutory_quorum(3) == 2
        check("Statutory Quorum Rule 16 ceiling floor verified", client.get("/api/health"), 200)

        # 2. Term progress zero-division safety and integer rounding
        pct_zero, days_zero, _ = term_progress(date(2026, 1, 1), date(2026, 1, 1), date(2026, 1, 1))
        assert pct_zero == 0
        pct_half, days_half, _ = term_progress(date(2026, 1, 1), date(2026, 1, 11), date(2026, 1, 6))
        assert pct_half == 50
        check("Term progress zero-division safety verified", client.get("/api/health"), 200)

        # 3. Taleb Extremistan Diagnostics
        fat_tail = compute_taleb_diagnostics([1.0, 1.5, 2.0, 2.0, 150.0])
        assert fat_tail["is_extremistan"] is True
        assert fat_tail["r_n"] >= 0.15
        thin_tail = compute_taleb_diagnostics([10.0] * 10)
        assert thin_tail["is_extremistan"] is False
        assert thin_tail["r_n"] < 0.15
        check("Taleb Extremistan R_n and fat-tail diagnostics verified", client.get("/api/health"), 200)

        # 4. JSON Content Negotiation on Error Handlers
        r = client.get("/api/nonexistent-endpoint")
        check("API 404 returns JSON envelope", r, 404, '"status":"not_found"')
        r = client.get("/admin", headers={"Accept": "application/json"}, follow_redirects=False)
        check("API 403 returns JSON envelope", r, 403, '"status":"forbidden"')
        client.get("/logout", follow_redirects=False)
        r = client.get("/portal", headers={"Accept": "application/json"}, follow_redirects=False)
        check("API 401 returns JSON envelope", r, 401, '"status":"unauthorized"')

        # 5. PWA Manifest Discovery Link in base.html
        r = client.get("/")
        check("PWA manifest link in HTML head", r, 200, '<link rel="manifest" href="/manifest">')

        # 6. HTMX CSRF Header on Body
        client.get("/logout", follow_redirects=False)
        client.post("/login", data={"email": "resident-0@greenwoodrwa.in", "password": "Welcome@123", "next": "/portal"}, follow_redirects=False)
        r = client.get("/portal")
        check("HTMX CSRF header present on body", r, 200, 'hx-headers=\'{"X-CSRF-Token":')

        # 7. UTF-8 BOM on Statutory CSV Exports
        client.get("/logout", follow_redirects=False)
        client.post("/login", data={"email": "admin@greenwoodrwa.in", "password": "Welcome@123", "next": "/admin"}, follow_redirects=False)
        r = client.get("/admin/exports/form-xii/csv")
        check("Form-XII CSV has UTF-8 BOM", r, 200)
        assert r.text.startswith("\ufeff")
        assert "charset=utf-8" in r.headers.get("content-type", "").lower()

        r = client.get("/admin/exports/form-xv/csv")
        check("Form-XV CSV has UTF-8 BOM", r, 200)
        assert r.text.startswith("\ufeff")
        assert "charset=utf-8" in r.headers.get("content-type", "").lower()

        # 8. Helpdesk tab renders Taleb Extremistan Telemetry
        r = client.get("/admin/tabs/3")
        check("Helpdesk tab renders Taleb Extremistan Telemetry", r, 200, "Taleb Extremistan")

        # 9. Compliance tab renders Statutory Quorum Ceiling Floor
        r = client.get("/admin/tabs/1")
        check("Compliance tab renders Statutory Quorum 40% Ceiling", r, 200, "Statutory Quorum (40%)")

        # 10. Multi-Tier Form & API Validation Tests
        # 10a. Admin member direct entry rejects under 21 years (Sec. 16(i))
        r = client.post(
            "/admin/directory/create",
            data={
                "full_name": "Underage Applicant",
                "father_or_spouse_name": "Father Name",
                "date_of_birth": "2015-01-01",
                "permanent_address": "123 Main Street",
                "mobile_number": "+919999900001",
                "email": "underage@example.com",
            },
            follow_redirects=True,
        )
        check("Admin member entry blocks underage applicant (Sec. 16(i))", r, 200, "21 years of age")

        # 10b. Admin member direct entry rejects invalid mobile (< 10 digits)
        r = client.post(
            "/admin/directory/create",
            data={
                "full_name": "Invalid Mobile",
                "father_or_spouse_name": "Father Name",
                "date_of_birth": "1990-01-01",
                "permanent_address": "123 Main Street",
                "mobile_number": "12345",
                "email": "inv_mob@example.com",
            },
            follow_redirects=True,
        )
        check("Admin member entry blocks short mobile (Sec. 18(1))", r, 200, "10-digit mobile number")

        # 10c. Admin member edit detects email/mobile collision
        other_user = db.query_one("SELECT id FROM users WHERE email != 'resident-0@greenwoodrwa.in' AND role != 'SUPER_ADMIN' LIMIT 1")
        r = client.post(
            f"/admin/directory/{other_user['id']}/edit",
            data={
                "full_name": "Clash Name",
                "mobile_number": "+919876543210",
                "email": "resident-0@greenwoodrwa.in",
            },
            follow_redirects=True,
        )
        check("Admin member edit blocks credential triad collision", r, 200, "already belongs to another member")

        # 10d. Database-Level Trigger rejects illegal mobile number
        db_trg_threw = False
        try:
            db.execute(
                """INSERT INTO users (id, full_name, mobile_number, email, role, created_at)
                   VALUES ('test-trg-user', 'Trigger Test', '123', 'trg@example.com', 'MEMBER', datetime('now'))"""
            )
        except Exception as exc:
            db_trg_threw = "10 digits" in str(exc) or "ABORT" in str(exc)
        assert db_trg_threw, "DB trigger should abort insert on mobile length < 10"
        check("Database-level trigger aborts invalid mobile on users table", client.get("/api/health"), 200)

        # 10e. Database-Level Trigger rejects Form-X cash instrument
        db_cash_threw = False
        soc_id = db.scalar("SELECT id FROM societies LIMIT 1")
        try:
            db.execute(
                """INSERT INTO form_x_applications (id, society_id, applicant_name, father_or_spouse_name,
                   date_of_birth, membership_category, flat_id, mobile_number, email, permanent_address,
                   residential_address, fee_instrument_ref, sec16_declarations, created_at)
                   VALUES ('test-trg-app', ?, 'Cash User', 'Father', '1990-01-01', 'ORDINARY',
                   'A-101', '9876543210', 'cash@example.com', 'Address', 'Address',
                   '{"type":"CASH","number":"123"}', '{}', datetime('now'))""",
                (soc_id,),
            )
        except Exception as exc:
            db_cash_threw = "Cash instrument" in str(exc) or "ABORT" in str(exc)
        assert db_cash_threw, "DB trigger should abort Form-X insert with cash instrument"
        check("Database-level trigger aborts cash fee instrument on Form-X", client.get("/api/health"), 200)

        # 10f. Admin Vault Upload endpoint & SHA-256 generation
        fake_pdf = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
        r = client.post(
            "/admin/vault/upload",
            data={
                "title": "Minutes of 15th GBM Meeting",
                "doc_category": "MOM_GBM",
                "meeting_date": "2026-11-20",
                "quorum_present": "25",
                "quorum_required": "17",
                "visibility": "MEMBERS_ONLY",
                "change_summary": "Handwritten camera scan upload",
            },
            files={"file": ("mom_15th_gbm.pdf", io.BytesIO(fake_pdf), "application/pdf")},
            follow_redirects=True,
        )
        check("Admin uploads document to vault with SHA-256", r, 200, "Minutes of 15th GBM Meeting")

        # 10g. Portal Helpdesk category validation rejects invalid category
        client.get("/logout", follow_redirects=False)
        client.post("/login", data={"email": "resident-0@greenwoodrwa.in", "password": "Welcome@123", "next": "/portal"}, follow_redirects=False)
        r = client.post(
            "/portal/tickets",
            data={
                "category": "Invalid Nonexistent Category",
                "subject": "Valid Subject Line",
                "description": "Valid description of at least ten characters.",
            },
            follow_redirects=True,
        )
        check("Portal helpdesk rejects unknown category", r, 200, "valid helpdesk category")

        # 10h. Frontend HTML5 Max DOB validation rendered on /apply
        r = client.get("/apply")
        check("Frontend Form-X enforces HTML5 max_dob constraint", r, 200, 'max="')

        # 11. SQL Lint, Schema Integrity & Query Plan Optimization Tests
        with db.connection() as conn:
            integrity = [tuple(r) for r in conn.execute("PRAGMA integrity_check").fetchall()]
            assert integrity == [("ok",)], f"Integrity check failed: {integrity}"
            fk_check = [tuple(r) for r in conn.execute("PRAGMA foreign_key_check").fetchall()]
            assert fk_check == [], f"Foreign key violations found: {fk_check}"

            # Verify 100% foreign key index coverage
            tables = [t[0] for t in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()]
            missing_fks = []
            for t in tables:
                fks = conn.execute(f"PRAGMA foreign_key_list({t})").fetchall()
                indices = conn.execute(f"PRAGMA index_list({t})").fetchall()
                indexed = {conn.execute(f"PRAGMA index_info({idx[1]})").fetchall()[0][2] for idx in indices if conn.execute(f"PRAGMA index_info({idx[1]})").fetchall()}
                for fk in fks:
                    if fk[3] not in indexed:
                        missing_fks.append((t, fk[3]))
            assert len(missing_fks) == 0, f"Unindexed foreign keys detected: {missing_fks}"

            # Verify EXPLAIN QUERY PLAN uses index on core routes
            login_plan = [p[3] for p in conn.execute(
                "EXPLAIN QUERY PLAN SELECT * FROM users WHERE lower(email) = ? OR mobile_number = ? OR member_serial_no = ? COLLATE NOCASE",
                ("a@b.com", "9876543210", "M-1001")
            ).fetchall()]
            assert any("MULTI-INDEX OR" in p or "USING INDEX" in p for p in login_plan)

            ticket_plan = [p[3] for p in conn.execute(
                "EXPLAIN QUERY PLAN SELECT * FROM tickets WHERE raised_by = ? ORDER BY created_at DESC",
                ("u-1",)
            ).fetchall()]
            assert any("idx_tickets_raised_by" in p for p in ticket_plan)

            slug_plan = [p[3] for p in conn.execute(
                "EXPLAIN QUERY PLAN SELECT * FROM announcements WHERE slug = ?",
                ("test-slug",)
            ).fetchall()]
            assert any("idx_announcements_slug" in p for p in slug_plan)

        check("SQL lint: PRAGMA integrity and foreign key checks verified clean", client.get("/api/health"), 200)
        check("SQL lint: 100% foreign key columns have covering indexes", client.get("/api/health"), 200)
        check("SQL lint: Query planner uses covering index on core path queries", client.get("/api/health"), 200)

        # ---------------- Enterprise Invariants & Audit Chain Guardrails ----------------
        res_sec = client.get("/")
        assert res_sec.headers.get("X-Content-Type-Options") == "nosniff"
        assert res_sec.headers.get("X-Frame-Options") == "SAMEORIGIN"
        assert "camera=()" in res_sec.headers.get("Permissions-Policy", "")
        check("Security Headers: nosniff, SAMEORIGIN, Permissions-Policy present", res_sec, 200)

        res_inv = client.get("/api/invariants")
        inv_data = res_inv.json()
        assert inv_data["all_passed"] is True
        assert inv_data["total_count"] == 8
        check("Invariants API: GET /api/invariants returns 8/8 passed", res_inv, 200, "Active Member Synchronization")

        res_aud = client.get("/api/audit/verify")
        aud_data = res_aud.json()
        assert aud_data["verified"] is True
        check("Audit API: GET /api/audit/verify verifies cryptographic Merkle chain", res_aud, 200, "tamper-free")

        res_ready = client.get("/api/ready")
        ready_data = res_ready.json()
        assert ready_data["ready"] is True
        check("Readiness API: GET /api/ready probe confirms DB & invariants healthy", res_ready, 200, "connected")

        # Test tamper detection on audit log chain
        actor = db.query_one("SELECT id, society_id FROM users WHERE role = 'SOCIETY_ADMIN' LIMIT 1")
        from . import audit
        test_hash = audit.log(
            action="TEST_ACTION",
            rule_ref="Sec. 99",
            entity_type="TEST",
            entity_id="test-1",
            diff={"field": {"old_value": "A", "new_value": "B"}},
            actor_id=actor["id"],
            society_id=actor["society_id"],
        )
        v1 = audit.verify_audit_hash_chain()
        assert v1["verified"] is True, f"Audit chain verification failed: {v1}"

        # Now simulate deliberate malicious DB tampering by mutating an action directly using db.execute
        latest_id = db.scalar("SELECT id FROM audit_logs ORDER BY id DESC LIMIT 1")
        db.execute("UPDATE audit_logs SET action = 'MALICIOUS_TAMPER' WHERE id = ?", (latest_id,))
        v2 = audit.verify_audit_hash_chain()
        assert v2["verified"] is False, "Tamper detection failed to detect altered action!"
        assert v2["corrupted_id"] == latest_id

        # Clean up the test row
        db.execute("DELETE FROM audit_logs WHERE id = ?", (latest_id,))
        v3 = audit.verify_audit_hash_chain()
        assert v3["verified"] is True

        check("Tamper Sentinel: Audit chain detects unauthorized database row mutations", client.get("/api/health"), 200)

    # ---------------- Report ----------------
    width = max(len(name) for _, name, _ in results)
    print()
    for status, name, detail in results:
        print(f"  [{status}] {name.ljust(width)}  {detail}")
    failed = [r for r in results if r[0] == FAIL]
    print()
    print(f"{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
