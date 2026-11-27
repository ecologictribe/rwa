"""Public Transparency Zone -- zero login required (SRS section 1.1, 4).

Pages: home, governance dashboard, notices, emergency contacts, Form-X
self-registration application.
"""

from __future__ import annotations

from datetime import date, datetime

import markdown as md
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import audit, config, db, security
from ..render import flash, render

router = APIRouter()

CATEGORY_LABELS = {
    "FOUNDER": "Founder",
    "LIFE": "Life",
    "ORDINARY": "Ordinary",
    "ASSOCIATE": "Associate",
    "TENURE": "Tenure",
    "HONORARY": "Honorary",
}

DESIGNATION_LABELS = {
    "PRESIDENT": "President",
    "VICE_PRESIDENT": "Vice-President",
    "GENERAL_SECRETARY": "General Secretary",
    "JOINT_SECRETARY": "Joint Secretary",
    "TREASURER": "Treasurer",
    "EXECUTIVE_MEMBER": "Executive Member",
}

STATUS_LABELS = {
    "PROPOSED": "Proposed",
    "APPROVED": "Approved in GB/GBM",
    "IN_PROGRESS": "In Progress",
    "COMPLETED": "Completed & Verified",
}

# Health of a statutory countdown, rendered as shape + text (colourblind-safe).
HEALTH_SHAPE = {"ON_TRACK": "[OK]", "FILED": "[OK]", "DUE_SOON": "[DUE]",
                "CRITICAL": "[!]", "OVERDUE": "[X]", "NOT_APPLICABLE": "[-]"}


def days_between(a: date, b: date) -> int:
    return (b - a).days


def term_progress(start: date, end: date, today: date) -> tuple[int, int, int]:
    """Returns (elapsed_pct, days_left, total_days)."""
    total = max((end - start).days, 1)
    elapsed = min(max((today - start).days, 0), total)
    return round(elapsed * 100 / total), total - elapsed, total


# ---------------------------------------------------------------------------
# Home
# ---------------------------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
def home(request: Request):
    society = db.query_one("SELECT * FROM societies LIMIT 1")
    today = date.today()

    notices = db.query_all(
        """SELECT * FROM announcements
           WHERE is_public = 1 OR is_pinned = 1
           ORDER BY is_pinned DESC, published_at DESC LIMIT 5"""
    )
    initiatives = db.query_all(
        """SELECT * FROM committee_initiatives
           WHERE is_public = 1 ORDER BY completion_pct DESC LIMIT 4"""
    )
    committee = db.query_all(
        """SELECT cm.*, u.full_name FROM committee_members cm
           JOIN users u ON u.id = cm.user_id
           WHERE cm.is_active = 1
           ORDER BY CASE cm.designation
                      WHEN 'PRESIDENT' THEN 1 WHEN 'VICE_PRESIDENT' THEN 2
                      WHEN 'GENERAL_SECRETARY' THEN 3 WHEN 'JOINT_SECRETARY' THEN 4
                      WHEN 'TREASURER' THEN 5 ELSE 6 END"""
    )

    stats = _governance_stats(committee, today)

    # Helpdesk SLA without resident PII (spec 4.2).
    sla = db.query_one(
        """SELECT COUNT(*) AS total,
                  SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END) AS resolved,
                  AVG(CASE WHEN resolved_at IS NOT NULL
                           THEN julianday(resolved_at) - julianday(created_at) END) AS mean_days
           FROM tickets"""
    )

    return render(
        request,
        "public/home.html",
        {
            "notices": notices,
            "initiatives": initiatives,
            "committee": committee,
            "stats": stats,
            "sla": sla,
            "designation_labels": DESIGNATION_LABELS,
            "status_labels": STATUS_LABELS,
            "active_members": society["active_member_count"] if society else 0,
        },
    )


def _governance_stats(committee, today: date) -> dict:
    if not committee:
        return {}
    ends = [date.fromisoformat(c["term_end_date"]) for c in committee]
    starts = [date.fromisoformat(c["term_start_date"]) for c in committee]
    worst_left = min(days_between(today, e) for e in ends)
    avg_pct, _, _ = term_progress(min(starts), max(ends), today)

    meetings = db.scalar(
        """SELECT COUNT(*) FROM documents
           WHERE doc_category LIKE 'MOM_%'
             AND substr(meeting_date, 1, 4) = ?""",
        (str(today.year),),
        default=0,
    )
    filings_due = db.scalar(
        "SELECT COUNT(*) FROM committee_members WHERE is_active = 1 "
        "AND filed_with_registrar_on IS NULL",
        default=0,
    )
    filings_overdue = db.scalar(
        "SELECT COUNT(*) FROM committee_members WHERE is_active = 1 "
        "AND filed_with_registrar_on IS NULL AND date(filing_due_date) < date('now')",
        default=0,
    )
    return {
        "term_avg_pct": avg_pct,
        "term_days_left": worst_left,
        "meetings_held": meetings,
        "meetings_required": 4,  # Sec. 36(1): at least once per quarter
        "filings_due": filings_due,
        "filings_overdue": filings_overdue,
        "collegium_active": (db.scalar(
            "SELECT active_member_count FROM societies LIMIT 1", default=0
        ) or 0) > 300,
    }


# ---------------------------------------------------------------------------
# Governance dashboard (public, Form-XVII view)
# ---------------------------------------------------------------------------

@router.get("/governance", response_class=HTMLResponse)
def governance(request: Request, filter: str = "all"):
    today = date.today()
    society = db.query_one("SELECT * FROM societies LIMIT 1")

    where = "cm.is_active = 1"
    params: list = []
    if filter == "elected_bearers":
        where += " AND cm.designation IN ('PRESIDENT','VICE_PRESIDENT','GENERAL_SECRETARY','JOINT_SECRETARY','TREASURER')"
    elif filter == "elected_executive":
        where += " AND cm.designation = 'EXECUTIVE_MEMBER'"
    elif filter == "nominated":
        where += " AND cm.selection_mode = 'NOMINATED_COOPTED'"

    cols = "cm.*, u.full_name"
    committee = db.query_all(
        f"""SELECT {cols}
            FROM committee_members cm JOIN users u ON u.id = cm.user_id
            WHERE {where}
            ORDER BY CASE cm.designation
                       WHEN 'PRESIDENT' THEN 1 WHEN 'VICE_PRESIDENT' THEN 2
                       WHEN 'GENERAL_SECRETARY' THEN 3 WHEN 'JOINT_SECRETARY' THEN 4
                       WHEN 'TREASURER' THEN 5 ELSE 6 END""",
        params,
    )

    for c in committee:
        start = date.fromisoformat(c["term_start_date"])
        end = date.fromisoformat(c["term_end_date"])
        c["term_pct"], c["term_days_left"], c["term_total"] = term_progress(start, end, today)
        c["designation_label"] = DESIGNATION_LABELS.get(c["designation"], c["designation"])
        c["selection_label"] = {
            "ELECTED_GBM": "Elected - General Body",
            "ELECTED_COLLEGIUM": "Elected - Collegium",
            "NOMINATED_COOPTED": "Nominated / Co-Opted",
        }[c["selection_mode"]]
        if c["filed_with_registrar_on"]:
            c["filing_label"] = f"FILED: {c['filed_with_registrar_on']}"
            c["filing_class"] = "pill--ok"
            c["filing_shape"] = "[OK]"
        else:
            due = date.fromisoformat(c["filing_due_date"])
            delta = days_between(today, due)
            if delta < 0:
                c["filing_label"] = f"OVERDUE BY {-delta} DAYS"
                c["filing_class"] = "pill--over"
                c["filing_shape"] = "[X]"
            elif delta <= 30:
                c["filing_label"] = f"DUE WITHIN {delta} DAYS"
                c["filing_class"] = "pill--due"
                c["filing_shape"] = "[DUE]"
            else:
                c["filing_label"] = f"DUE {c['filing_due_date']}"
                c["filing_class"] = "pill--muted"
                c["filing_shape"] = "[-]"
        # Privacy guardrail (4.1): only the opt-in official contact is shown.
        c["show_contact"] = bool(c["public_contact_email"]) and True

    initiatives = db.query_all(
        """SELECT ci.*, cm.designation AS lead_designation, u.full_name AS lead_name
           FROM committee_initiatives ci
           LEFT JOIN committee_members cm ON cm.id = ci.lead_committee_member_id
           LEFT JOIN users u ON u.id = cm.user_id
           WHERE ci.is_public = 1 ORDER BY ci.completion_pct DESC"""
    )
    for i in initiatives:
        i["status_label"] = STATUS_LABELS[i["status"]]
        i["stage_index"] = ["PROPOSED", "APPROVED", "IN_PROGRESS", "COMPLETED"].index(i["status"])

    circulars = db.query_all(
        """SELECT * FROM announcements WHERE is_public = 1
           ORDER BY published_at DESC LIMIT 6"""
    )

    stats = _governance_stats(
        db.query_all("SELECT * FROM committee_members WHERE is_active = 1"), today
    )

    sla = db.query_one(
        """SELECT COUNT(*) AS total,
                  SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END) AS resolved,
                  AVG(CASE WHEN resolved_at IS NOT NULL
                           THEN julianday(resolved_at) - julianday(created_at) END) AS mean_days
           FROM tickets"""
    )

    return render(
        request,
        "public/governance.html",
        {
            "committee": committee,
            "initiatives": initiatives,
            "circulars": circulars,
            "stats": stats,
            "sla": sla,
            "active_filter": filter,
            "status_labels": STATUS_LABELS,
            "active_members": society["active_member_count"] if society else 0,
            "collegium_threshold": 300,
        },
    )


# ---------------------------------------------------------------------------
# Notices
# ---------------------------------------------------------------------------

@router.get("/notices", response_class=HTMLResponse)
def notices(request: Request):
    rows = db.query_all(
        """SELECT a.*, u.full_name AS publisher
           FROM announcements a JOIN users u ON u.id = a.published_by
           ORDER BY a.is_pinned DESC, a.published_at DESC"""
    )
    for r in rows:
        r["body_html"] = md.markdown(r["body_markdown"], extensions=["tables", "fenced_code"])
    return render(request, "public/notices.html", {"notices": rows})


@router.get("/notices/{slug}", response_class=HTMLResponse)
def notice_detail(request: Request, slug: str):
    row = db.query_one(
        """SELECT a.*, u.full_name AS publisher
           FROM announcements a JOIN users u ON u.id = a.published_by
           WHERE a.slug = ?""",
        (slug,),
    )
    if row is None:
        return render(
            request,
            "error.html",
            {"error_code": "404", "error_title": "Notice not found",
             "error_text": "This notice has been withdrawn or never existed."},
            status_code=404,
        )
    row["body_html"] = md.markdown(row["body_markdown"], extensions=["tables", "fenced_code"])
    return render(request, "public/notice_detail.html", {"notice": row})


# ---------------------------------------------------------------------------
# Contacts & emergency numbers
# ---------------------------------------------------------------------------

@router.get("/contacts", response_class=HTMLResponse)
def contacts(request: Request):
    society = db.query_one("SELECT * FROM societies LIMIT 1")
    committee = db.query_all(
        """SELECT cm.*, u.full_name FROM committee_members cm
           JOIN users u ON u.id = cm.user_id
           WHERE cm.is_active = 1 ORDER BY cm.designation"""
    )
    for c in committee:
        c["designation_label"] = DESIGNATION_LABELS.get(c["designation"], c["designation"])
        # Privacy guardrail: personal numbers are never published.
        c["show_contact"] = bool(c["public_contact_email"])

    emergency = [
        ("Police Control Room", "112", "All emergencies"),
        ("Fire & Rescue", "101", "Fire, rescue, evacuation"),
        ("Ambulance", "108", "Medical emergency"),
        ("Women Helpline", "1091", "Women in distress"),
        ("Gurugram Police Control", "0124-2455111", "City control room"),
        ("Electricity (DHBVN)", "1912", "Power outage / shock"),
        ("Gas Leak (HP Gas)", "1800-233-3555", "LPG emergency"),
        ("Society Security -- Gate 1", "0124-4567890", "24x7 gate desk"),
        ("Society Security -- Gate 2", "0124-4567891", "24x7 gate desk"),
    ]
    return render(
        request,
        "public/contacts.html",
        {"committee": committee, "emergency": emergency, "society": society},
    )


# ---------------------------------------------------------------------------
# Form-X self-registration (spec 2.2 workflow 2, section 3.1)
# ---------------------------------------------------------------------------

@router.get("/apply", response_class=HTMLResponse)
def apply_form(request: Request, errors: list[str] | None = None, values: dict | None = None):
    units = db.query_all(
        """SELECT u.*, (SELECT COUNT(*) FROM users x WHERE x.unit_id = u.id) AS occupants
           FROM units u ORDER BY u.canonical_code"""
    )
    return render(
        request,
        "public/apply.html",
        {
            "errors": errors or [],
            "values": values or {},
            "units": units,
            "categories": CATEGORY_LABELS,
            "today": date.today().isoformat(),
        },
    )


@router.post("/apply", response_class=HTMLResponse)
def apply_submit(
    request: Request,
    applicant_name: str = Form(...),
    father_or_spouse_name: str = Form(...),
    date_of_birth: str = Form(...),
    membership_category: str = Form(...),
    flat_id: str = Form(...),
    mobile_number: str = Form(...),
    email: str = Form(...),
    permanent_address: str = Form(...),
    residential_address: str = Form(""),
    fee_instrument_type: str = Form(...),
    fee_instrument_number: str = Form(...),
    fee_instrument_bank: str = Form(...),
    fee_instrument_date: str = Form(...),
    aims_subscribed: str = Form(""),
    decl_insolvent: str = Form(""),
    decl_sound_mind: str = Form(""),
    decl_moral_turpitude: str = Form(""),
):
    errors: list[str] = []
    values = {
        "applicant_name": applicant_name,
        "father_or_spouse_name": father_or_spouse_name,
        "date_of_birth": date_of_birth,
        "membership_category": membership_category,
        "flat_id": flat_id,
        "mobile_number": mobile_number,
        "email": email,
        "permanent_address": permanent_address,
        "residential_address": residential_address,
        "fee_instrument_type": fee_instrument_type,
        "fee_instrument_number": fee_instrument_number,
        "fee_instrument_bank": fee_instrument_bank,
        "fee_instrument_date": fee_instrument_date,
    }

    # --- Sec. 16(i): minimum age 21 on the date of admission ---------------
    try:
        dob = date.fromisoformat(date_of_birth)
    except ValueError:
        dob = None
        errors.append("Date of birth is not a valid date.")
    today = date.today()
    if dob:
        twenty_first = dob.replace(year=dob.year + 21)
        if twenty_first > today:
            errors.append(
                "Sec. 16(i): an applicant must have completed 21 years of age "
                "on the date of admission."
            )

    # --- Required fields (Rule 11(1)) -------------------------------------
    if not applicant_name.strip():
        errors.append("Applicant full legal name is required (Sec. 18(1)).")
    if not father_or_spouse_name.strip():
        errors.append("Father's / spouse's name is required (Rule 11(1)).")
    if membership_category not in CATEGORY_LABELS:
        errors.append("Select a membership category registered under the bye-laws (Sec. 15).")
    if not flat_id:
        errors.append("Flat / house / plot ID is required.")
    if len(mobile_number.replace(" ", "").replace("+", "")) < 10:
        errors.append("A valid 10-digit mobile number is required (Sec. 18(1)).")
    if "@" not in email or "." not in email.split("@")[-1]:
        errors.append("A valid email address is required.")
    if not permanent_address.strip():
        errors.append("Permanent address is required (Sec. 21(5)).")
    if not residential_address.strip():
        residential_address = permanent_address

    # --- Rule 11(1): cash is strictly disabled ---------------------------
    if fee_instrument_type.upper() in {"CASH", "CASH_", "NOTES"}:
        errors.append(
            "Rule 11(1): admission fee must be paid from the applicant's own "
            "bank account by cheque / demand draft / pay order. Cash is not accepted."
        )
    if fee_instrument_type not in {"CHEQUE", "DEMAND_DRAFT", "PAY_ORDER"}:
        errors.append("Select a non-cash bank instrument (cheque, demand draft or pay order).")
    if not fee_instrument_number.strip():
        errors.append("Bank instrument number is required (Rule 11(1)).")
    if not fee_instrument_bank.strip():
        errors.append("Issuing bank name is required (Rule 11(1)).")
    try:
        date.fromisoformat(fee_instrument_date)
    except ValueError:
        errors.append("Instrument date must be a valid date (Rule 11(1)).")

    # --- Sec. 16(ii)/20(1): aims subscription -----------------------------
    if aims_subscribed != "on":
        errors.append("You must subscribe to the Society's aims, objects and bye-laws (Sec. 16(ii)).")

    # --- Sec. 16(iv): three disqualification attestations ------------------
    if decl_insolvent != "on":
        errors.append("Declaration (a): you must attest that you are not an undischarged insolvent.")
    if decl_sound_mind != "on":
        errors.append("Declaration (b): you must attest that you are not of unsound mind.")
    if decl_moral_turpitude != "on":
        errors.append(
            "Declaration (c): you must attest that you have not been convicted of an "
            "offence involving moral turpitude punishable with imprisonment of one year or more."
        )

    # --- Duplicate credential triad check ---------------------------------
    if not errors:
        dup = db.query_one(
            "SELECT id FROM users WHERE lower(email) = lower(?) OR mobile_number = ?",
            (email.strip(), mobile_number.strip()),
        )
        if dup:
            errors.append(
                "An account already exists for this mobile number or email. "
                "Contact the society desk for an in-person reset."
            )
    dup_app = db.query_one(
        "SELECT id FROM form_x_applications WHERE lower(email) = lower(?) AND status = 'PENDING_VERIFICATION'",
        (email.strip(),),
    )
    if dup_app:
        errors.append("A Form-X application from this email is already awaiting verification.")

    if errors:
        return apply_form(request, errors=errors, values=values)

    # --- Persist ----------------------------------------------------------
    society_id = db.scalar("SELECT id FROM societies LIMIT 1")
    app_id = db.new_id()
    db.execute(
        """INSERT INTO form_x_applications
           (id, society_id, applicant_name, father_or_spouse_name, date_of_birth,
            membership_category, flat_id, mobile_number, email, permanent_address,
            residential_address, fee_instrument_ref, sec16_declarations,
            aims_subscribed, status, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            app_id,
            society_id,
            applicant_name.strip(),
            father_or_spouse_name.strip(),
            date_of_birth,
            membership_category,
            flat_id,
            mobile_number.strip(),
            email.strip().lower(),
            permanent_address.strip(),
            residential_address.strip(),
            db.to_json({
                "type": fee_instrument_type,
                "number": fee_instrument_number.strip(),
                "bank": fee_instrument_bank.strip(),
                "date": fee_instrument_date,
                "cash_accepted": False,  # strictly disabled per Rule 11(1)
            }),
            db.to_json({
                "not_insolvent": decl_insolvent == "on",
                "sound_mind": decl_sound_mind == "on",
                "no_moral_turpitude": decl_moral_turpitude == "on",
            }),
            1 if aims_subscribed == "on" else 0,
            "PENDING_VERIFICATION",
            db.utcnow(),
        ),
    )
    audit.log(
        action="FORM_X_SUBMIT",
        rule_ref="HRRS_ACT_2012_SEC_18_1 | RULE_11_1_FORM_X",
        entity_type="form_x_application",
        entity_id=app_id,
        diff={"status": {"old_value": None, "new_value": "PENDING_VERIFICATION"}},
        society_id=society_id,
        ip_address=request.client.host if request.client else None,
    )

    flash(
        request,
        "Form-X application received. It will be verified by the society "
        "office and you will be notified within the statutory cycle. "
        f"Reference: {app_id[:8].upper()}",
    )
    return RedirectResponse(url="/apply?submitted=1", status_code=303)
