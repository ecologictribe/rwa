"""End-to-end smoke test for the RWA portal.

Boots the app with FastAPI's in-process TestClient (no network, no server
process) and walks every route class: public zone, auth flows, member portal,
admin workspace, and the JSON APIs.

Run:  python -m app.smoke_test
"""

from __future__ import annotations

import sys

from fastapi.testclient import TestClient

from . import db
from .main import app

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
        check("GET /governance", client.get("/governance"), 200, "Committee Progress")
        check("GET /governance?filter=nominated", client.get("/governance?filter=nominated"),
              200, "Nominated")
        check("GET /notices", client.get("/notices"), 200, "Notices")
        check("GET /contacts", client.get("/contacts"), 200, "Emergency")
        check("GET /apply", client.get("/apply"), 200, "Form-X")
        check("GET /api/health", client.get("/api/health"), 200, "ok")
        check("GET /manifest", client.get("/manifest"), 200, "RWA Governance")
        check("GET /static/css/app.css", client.get("/static/css/app.css"), 200, "data-theme")
        check("GET /static/vendor/htmx.min.js", client.get("/static/vendor/htmx.min.js"), 200)
        check("GET /static/vendor/alpine.min.js", client.get("/static/vendor/alpine.min.js"), 200)
        check("GET /nonexistent-xyz", client.get("/nonexistent-xyz"), 404)

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
        check("Form-X blocks applicant under 21 (Sec. 16(i))", r, 200,
              must_contain="21 years")

        # Cash instrument must be rejected (Rule 11(1)).
        cash = dict(under21, date_of_birth="1990-01-01",
                    email="cash@example.com", fee_instrument_type="CASH")
        r = client.post("/apply", data=cash, follow_redirects=False)
        check("Form-X rejects cash instrument (Rule 11(1))", r, 200,
              must_contain="Cash is not accepted")

        # Missing declarations must be rejected (Sec. 16(iv)).
        nodecl = dict(under21, date_of_birth="1990-01-01", email="nodecl@example.com")
        nodecl.pop("decl_insolvent")
        nodecl.pop("decl_sound_mind")
        nodecl.pop("decl_moral_turpitude")
        r = client.post("/apply", data=nodecl, follow_redirects=False)
        check("Form-X blocks missing Sec. 16(iv) declarations", r, 200,
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

        # ---------------- RBAC enforcement ----------------
        # A member must not reach the admin workspace.
        r = client.get("/admin", follow_redirects=False)
        check("Member blocked from /admin", r, (302, 403))

        # Anonymous must not reach the portal.
        client.get("/logout", follow_redirects=False)
        r = client.get("/portal", follow_redirects=False)
        check("Anonymous redirected from /portal", r, (302, 401))

        # ---------------- Theme API ----------------
        r = client.post("/api/theme", json={"theme": "amber-crt"})
        check("Theme API accepts valid theme", r, 200, "amber-crt")
        r = client.post("/api/theme", json={"theme": "rainbow"})
        check("Theme API rejects unknown theme", r, 400)

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
