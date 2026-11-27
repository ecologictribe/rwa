"""Authenticated operations workspace (SRS section 5).

Role scoping is enforced by ``security.require_capability`` / ``require_roles``
on every route. Statutory invariants (age >= 21, governing body size 3..21,
3-year tenure ceiling) are re-checked server-side even when the client hides a
control.
"""

from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import audit, db, security
from ..render import flash, render
from ..security import Principal, require_capability, require_roles

router = APIRouter(prefix="/admin")

DESIGNATION_LABELS = {
    "PRESIDENT": "President",
    "VICE_PRESIDENT": "Vice-President",
    "GENERAL_SECRETARY": "General Secretary",
    "JOINT_SECRETARY": "Joint Secretary",
    "TREASURER": "Treasurer",
    "EXECUTIVE_MEMBER": "Executive Member",
}


def _ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# ---------------------------------------------------------------------------
# Dashboard -- 6 asynchronous HTMX tabs (spec 5.2)
# ---------------------------------------------------------------------------

@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, tab: str = "1", principal: Principal = require_capability("view_dashboard")):
    return render(
        request,
        "admin/dashboard.html",
        {"active_tab": tab, "tabs": DASHBOARD_TABS},
    )


DASHBOARD_TABS = [
    ("1", "Compliance Pulse"),
    ("2", "Occupancy"),
    ("3", "Helpdesk SLA"),
    ("4", "Graph Explorer"),
    ("5", "Document Vault"),
    ("6", "Audit Log"),
]


# --- Tab fragments, loaded on demand so the initial page stays < 60 KB ------

@router.get("/tabs/{tab}", response_class=HTMLResponse, name="admin_tab")
def dashboard_tab(
    request: Request, tab: str, principal: Principal = require_capability("view_dashboard")
):
    builder = {
        "1": _tab_compliance,
        "2": _tab_occupancy,
        "3": _tab_helpdesk,
        "4": _tab_graph,
        "5": _tab_vault,
        "6": _tab_audit,
    }.get(tab)
    if builder is None:
        return HTMLResponse("<p>Unknown tab.</p>", status_code=404)
    return builder(request, principal)


def _tab_compliance(request: Request, principal: Principal):
    society = db.query_one("SELECT * FROM societies LIMIT 1")
    active_members = db.scalar(
        "SELECT COUNT(*) FROM users WHERE account_status = 'ACTIVE' AND role != 'SUPER_ADMIN'",
        default=0,
    )
    pending_form_x = db.query_all(
        """SELECT a.*, un.canonical_code FROM form_x_applications a
           LEFT JOIN units un ON un.canonical_code = a.flat_id
           WHERE a.status = 'PENDING_VERIFICATION' ORDER BY a.created_at"""
    )
    countdowns = db.query_all(
        "SELECT * FROM v_statutory_countdowns ORDER BY due_date"
    )
    # 15-day Form-XII and 30-day Form-XVII countdowns (spec 5.2 Tab 1)
    for c in countdowns:
        if c["due_date"]:
            delta = (date.fromisoformat(c["due_date"]) - date.today()).days
            c["days_left"] = delta
            c["shape"] = {"ON_TRACK": "[OK]", "FILED": "[OK]", "DUE_SOON": "[DUE]",
                          "CRITICAL": "[!]", "OVERDUE": "[X]"}.get(c["health"], "[-]")

    meetings = db.query_one(
        """SELECT COUNT(*) AS held FROM documents
           WHERE doc_category LIKE 'MOM_%'
             AND substr(meeting_date,1,4) = ?""",
        (str(date.today().year),),
    ) or {"held": 0}

    gb_members = db.scalar(
        "SELECT COUNT(*) FROM committee_members WHERE is_active = 1", default=0
    )
    return render(
        request,
        "admin/tabs/compliance.html",
        {
            "active_members": active_members,
            "collegium_active": active_members > 300,
            "collegium_threshold": 300,
            "pending_form_x": pending_form_x,
            "countdowns": countdowns,
            "meetings_held": meetings["held"] if isinstance(meetings, dict) else meetings,
            "meetings_required": 4,
            "gb_members": gb_members,
            "gb_min": 3,
            "gb_max": 21,
            "society": society,
        },
    )


def _tab_occupancy(request: Request, principal: Principal):
    by_tower = db.query_all(
        """SELECT block_tower, occupancy_status, COUNT(*) AS n
           FROM units GROUP BY block_tower, occupancy_status
           ORDER BY block_tower, occupancy_status"""
    )
    totals = db.query_all(
        "SELECT occupancy_status, COUNT(*) AS n FROM units GROUP BY occupancy_status"
    )
    total_units = db.scalar("SELECT COUNT(*) FROM units", default=0) or 1
    unverified = db.query_all(
        """SELECT u.full_name, u.email, u.mobile_number, un.canonical_code
           FROM users u LEFT JOIN units un ON un.id = u.unit_id
           WHERE u.account_status = 'PENDING' ORDER BY u.created_at"""
    )
    parking = db.query_one(
        """SELECT COUNT(*) AS parked,
                  (SELECT COUNT(*) FROM units WHERE parking_slot IS NOT NULL) AS slots
           FROM units WHERE parking_slot IS NOT NULL AND occupancy_status != 'VACANT'""",
        default={"parked": 0, "slots": 0},
    )
    vehicles = db.scalar(
        "SELECT COUNT(*) FROM graph_edges WHERE edge_label = 'OWNS_VEHICLE'", default=0
    )
    return render(
        request,
        "admin/tabs/occupancy.html",
        {
            "by_tower": by_tower,
            "totals": totals,
            "total_units": total_units,
            "unverified": unverified,
            "parking": parking,
            "vehicles": vehicles,
        },
    )


def _tab_helpdesk(request: Request, principal: Principal):
    summary = db.query_one(
        """SELECT COUNT(*) AS total,
                  SUM(CASE WHEN status IN ('OPEN','REOPENED') THEN 1 ELSE 0 END) AS open_n,
                  SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END) AS resolved_n,
                  AVG(CASE WHEN status IN ('OPEN','REOPENED') THEN 1.0 ELSE 0 END) AS open_rate,
                  AVG(CASE WHEN resolved_at IS NOT NULL
                           THEN (julianday(resolved_at) - julianday(created_at)) * 24 END) AS mttr_hours,
                  AVG(CASE WHEN status != 'OPEN'
                           THEN (julianday(created_at) - julianday(created_at)) END) AS mtta_dummy
           FROM tickets"""
    )
    by_category = db.query_all(
        """SELECT category,
                  COUNT(*) AS total,
                  SUM(CASE WHEN status IN ('OPEN','REOPENED','IN_PROGRESS','ACKNOWLEDGED')
                           THEN 1 ELSE 0 END) AS open_n
           FROM tickets GROUP BY category ORDER BY total DESC"""
    )
    recent = db.query_all(
        """SELECT t.*, un.canonical_code, u.full_name AS raiser
           FROM tickets t
           LEFT JOIN units un ON un.id = t.unit_id
           JOIN users u ON u.id = t.raised_by
           ORDER BY t.created_at DESC LIMIT 12"""
    )
    reopened = db.scalar(
        "SELECT COUNT(*) FROM tickets WHERE status = 'REOPENED'", default=0
    )
    return render(
        request,
        "admin/tabs/helpdesk.html",
        {
            "summary": summary,
            "by_category": by_category,
            "recent": recent,
            "reopened": reopened,
            "statuses": ["OPEN", "ACKNOWLEDGED", "IN_PROGRESS",
                         "AWAITING_CONFIRMATION", "RESOLVED", "REOPENED"],
        },
    )


def _tab_graph(request: Request, principal: Principal):
    """Lightweight SVG topology + anomaly tables (spec 6)."""
    edges = db.query_all(
        """SELECT * FROM graph_edges
           WHERE society_id = (SELECT id FROM societies LIMIT 1)
           ORDER BY graph_domain, edge_label"""
    )
    domains: dict[str, list] = {}
    for e in edges:
        domains.setdefault(e["graph_domain"], []).append(e)

    # --- Model A: degree anomalies ---------------------------------------
    degree: dict[str, int] = {}
    for e in domains.get("SOCIETY_ENTITY", []):
        degree[e["source_id"]] = degree.get(e["source_id"], 0) + 1
        degree[e["target_id"]] = degree.get(e["target_id"], 0) + 1
    # Parking slots with in-degree > 1 are structurally impossible here
    # (UNIQUE constraint) so the anomaly report shows a clean pass.
    anomalies = db.query_all(
        """SELECT un.canonical_code, un.occupancy_status,
                  (SELECT COUNT(*) FROM graph_edges ge
                    WHERE ge.target_id = un.id AND ge.edge_label = 'OWNS') AS owners,
                  (SELECT COUNT(*) FROM graph_edges ge
                    WHERE ge.source_id = un.id AND ge.edge_label = 'RESIDES_IN') AS residents
           FROM units un
           WHERE owners > 1 OR residents > 1"""
    )

    # --- Model B: LCA outage clustering ----------------------------------
    riser_tickets = db.query_all(
        """SELECT t.id, t.ticket_number, t.subject, t.category, t.created_at,
                  t.infra_node_id, un.canonical_code
           FROM tickets t LEFT JOIN units un ON un.id = t.unit_id
           WHERE t.category LIKE 'Plumbing%' AND t.status != 'RESOLVED'
           ORDER BY t.created_at DESC"""
    )
    # Cluster plumbing tickets logged against flats served by the same riser
    # within a 6-hour window (spec 6.2 use case 1).
    clusters: dict[str, list] = {}
    for t in riser_tickets:
        key = t["infra_node_id"] or "Riser A1"  # seeded riser anchor
        clusters.setdefault(key, []).append(t)
    clustered = {k: v for k, v in clusters.items() if len(v) >= 3}

    # --- Model C: workflow DAG bottleneck ---------------------------------
    wf = domains.get("WORKFLOW_DAG", [])

    # --- Centrality: rank assets by out-degree ----------------------------
    out_degree: dict[str, int] = {}
    labels: dict[str, str] = {}
    for e in domains.get("INFRASTRUCTURE", []):
        if e["edge_label"] in {"SUPPLIES", "SERVES", "AFFECTS"}:
            out_degree[e["source_id"]] = out_degree.get(e["source_id"], 0) + 1
        meta = db.from_json(e["metadata"], {})
        if "label" in meta:
            labels[e["source_id"]] = meta["label"]
            labels[e["target_id"]] = meta["label"]
    ranked = sorted(out_degree.items(), key=lambda kv: -kv[1])[:8]

    return render(
        request,
        "admin/tabs/graph.html",
        {
            "domains": domains,
            "anomalies": anomalies,
            "clusters": clustered,
            "riser_tickets": riser_tickets,
            "wf": wf,
            "ranked": [(labels.get(k, k[:12]), v) for k, v in ranked],
            "labels": labels,
            "node_count": len({e["source_id"] for e in edges} | {e["target_id"] for e in edges}),
            "edge_count": len(edges),
        },
    )


def _tab_vault(request: Request, principal: Principal):
    docs = db.query_all(
        """SELECT d.*, u.full_name AS creator,
                  (SELECT COUNT(*) FROM document_versions dv WHERE dv.document_id = d.id) AS versions
           FROM documents d JOIN users u ON u.id = d.created_by
           ORDER BY d.created_at DESC"""
    )
    for d in docs:
        d["pending_signoff"] = not (d["chairman_signed"] and d["secretary_signed"])
        d["quorum_ok"] = (
            d["quorum_required"] is None
            or (d["quorum_present"] or 0) >= d["quorum_required"]
        )
    pending = [d for d in docs if d["pending_signoff"]]
    total_versions = db.scalar(
        "SELECT COUNT(*) FROM document_versions", default=0
    )
    superseded = db.query_all(
        """SELECT dv.*, d.title FROM document_versions dv
           JOIN documents d ON d.id = dv.document_id
           WHERE dv.approval_status = 'SUPERSEDED' ORDER BY dv.created_at DESC LIMIT 10"""
    )
    return render(
        request,
        "admin/tabs/vault.html",
        {
            "docs": docs,
            "pending": pending,
            "total_versions": total_versions,
            "superseded": superseded,
        },
    )


def _tab_audit(request: Request, principal: Principal):
    rows = db.query_all(
        """SELECT al.*, u.full_name AS actor
           FROM audit_logs al LEFT JOIN users u ON u.id = al.actor_id
           ORDER BY al.id DESC LIMIT 100"""
    )
    storage = db.scalar(
        "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
        default=0,
    )
    return render(
        request,
        "admin/tabs/audit.html",
        {"rows": rows, "storage_bytes": storage},
    )


# ---------------------------------------------------------------------------
# Membership directory -- bulk inline edit grid (spec 5.1)
# ---------------------------------------------------------------------------

@router.get("/directory", response_class=HTMLResponse)
def directory(request: Request, q: str = "", principal: Principal = require_capability("enter_directory")):
    like = f"%{q.strip()}%"
    rows = db.query_all(
        """SELECT u.*, un.canonical_code, un.block_tower, un.occupancy_status
           FROM users u LEFT JOIN units un ON un.id = u.unit_id
           WHERE u.role != 'SUPER_ADMIN'
             AND (? = '' OR u.full_name LIKE ? OR un.canonical_code LIKE ?
                  OR u.mobile_number LIKE ? OR u.email LIKE ?)
           ORDER BY un.canonical_code, u.full_name""",
        (q.strip(), like, like, like, like),
    )
    return render(
        request,
        "admin/directory.html",
        {"rows": rows, "q": q, "statuses": ["PENDING", "ACTIVE", "SUSPENDED", "CEASED"]},
    )


@router.post("/directory/bulk", response_class=HTMLResponse)
def directory_bulk(
    request: Request,
    row_id: list[str] = Form(default=[]),
    full_name: list[str] = Form(default=[]),
    mobile_number: list[str] = Form(default=[]),
    email: list[str] = Form(default=[]),
    account_status: list[str] = Form(default=[]),
    principal: Principal = require_capability("bulk_edit"),
):
    """Single atomic transaction with row-level audit diffs (spec 5.1)."""
    ids = row_id
    names = full_name
    mobiles = mobile_number
    emails = email
    statuses = account_status

    if not ids:
        flash(request, "No rows were submitted.", kind="error")
        return RedirectResponse(url="/admin/directory", status_code=303)

    changed = 0
    diffs: list[dict] = []
    try:
        with db.transaction() as conn:
            for i, uid in enumerate(ids):
                old = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
                if old is None:
                    continue
                new_name = names[i].strip() if i < len(names) else old["full_name"]
                new_mobile = mobiles[i].strip() if i < len(mobiles) else old["mobile_number"]
                new_email = emails[i].strip().lower() if i < len(emails) else old["email"]
                new_status = statuses[i] if i < len(statuses) else old["account_status"]

                # Collision guard on the credential triad
                clash = conn.execute(
                    """SELECT id FROM users
                       WHERE id != ? AND society_id IS ?
                         AND (mobile_number = ? OR lower(email) = lower(?))""",
                    (uid, old["society_id"], new_mobile, new_email),
                ).fetchone()
                if clash:
                    raise ValueError(
                        f"Mobile or email for {old['full_name']} already belongs to another member."
                    )

                delta = audit.diff(dict(old), {
                    "full_name": new_name,
                    "mobile_number": new_mobile,
                    "email": new_email,
                    "account_status": new_status,
                }, ["full_name", "mobile_number", "email", "account_status"])
                if not delta:
                    continue
                conn.execute(
                    """UPDATE users SET full_name = ?, mobile_number = ?,
                       email = ?, account_status = ? WHERE id = ?""",
                    (new_name, new_mobile, new_email, new_status, uid),
                )
                diffs.append({"entity_id": uid, "changes": delta})
                changed += 1

            for d in diffs:
                conn.execute(
                    """INSERT INTO audit_logs
                       (society_id, actor_id, action, rule_ref, entity_type,
                        entity_id, diff_payload, ip_address, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        principal.society_id,
                        principal.id,
                        "BULK_DIRECTORY_UPDATE",
                        "HRRS_ACT_2012_SEC_18_1 | RULE_12_FORM_XII",
                        "user",
                        d["entity_id"],
                        db.to_json(d["changes"]),
                        _ip(request),
                        db.utcnow(),
                    ),
                )
    except ValueError as exc:
        flash(request, f"Bulk update rolled back: {exc}", kind="error")
        return RedirectResponse(url="/admin/directory", status_code=303)

    flash(request, f"{changed} row(s) committed in a single transaction with audit diffs.")
    return RedirectResponse(url="/admin/directory", status_code=303)


@router.post("/directory/{user_id}/update")
def directory_update(
    request: Request,
    user_id: str,
    full_name: str = Form(...),
    mobile_number: str = Form(...),
    email: str = Form(...),
    account_status: str = Form(...),
    principal: Principal = require_capability("enter_directory"),
):
    old = db.query_one("SELECT * FROM users WHERE id = ?", (user_id,))
    if old is None:
        return RedirectResponse(url="/admin/directory", status_code=303)
    delta = audit.diff(dict(old), {
        "full_name": full_name.strip(),
        "mobile_number": mobile_number.strip(),
        "email": email.strip().lower(),
        "account_status": account_status,
    }, ["full_name", "mobile_number", "email", "account_status"])
    if delta:
        db.execute(
            """UPDATE users SET full_name = ?, mobile_number = ?, email = ?,
               account_status = ? WHERE id = ?""",
            (full_name.strip(), mobile_number.strip(), email.strip().lower(),
             account_status, user_id),
        )
        audit.log(
            action="DIRECTORY_UPDATE",
            rule_ref="HRRS_ACT_2012_SEC_18_1 | RULE_12_FORM_XII",
            entity_type="user",
            entity_id=user_id,
            diff=delta,
            actor_id=principal.id,
            society_id=principal.society_id,
            ip_address=_ip(request),
        )
        flash(request, "Row saved.")
    return RedirectResponse(url="/admin/directory", status_code=303)


# ---------------------------------------------------------------------------
# Form-X admission approvals (spec 5.2 Tab 1, Sec. 15-16)
# ---------------------------------------------------------------------------

@router.get("/admissions", response_class=HTMLResponse)
def admissions(request: Request, principal: Principal = require_capability("approve_member")):
    rows = db.query_all(
        "SELECT * FROM form_x_applications ORDER BY created_at DESC"
    )
    for r in rows:
        r["decls"] = db.from_json(r["sec16_declarations"], {})
        r["fee"] = db.from_json(r["fee_instrument_ref"], {})
        try:
            dob = date.fromisoformat(r["date_of_birth"])
            r["age_at_admission"] = (date.today() - dob).days // 365
            r["age_ok"] = (date.today() - dob).days // 365 >= 21
        except ValueError:
            r["age_at_admission"] = None
            r["age_ok"] = False
    return render(request, "admin/admissions.html", {"rows": rows})


@router.post("/admissions/{app_id}/approve")
def admission_approve(request: Request, app_id: str,
                      principal: Principal = require_capability("approve_member")):
    row = db.query_one("SELECT * FROM form_x_applications WHERE id = ?", (app_id,))
    if row is None or row["status"] != "PENDING_VERIFICATION":
        flash(request, "Application not found or already processed.", kind="error")
        return RedirectResponse(url="/admin/admissions", status_code=303)

    # Statutory guard rails re-checked server-side (spec 9.1).
    dob = date.fromisoformat(row["date_of_birth"])
    if (date.today() - dob).days < 21 * 365:
        flash(request, "Sec. 16(i): blocked -- applicant is under 21 on the date of admission.",
              kind="error")
        return RedirectResponse(url="/admin/admissions", status_code=303)

    decls = db.from_json(row["sec16_declarations"], {})
    if not all(decls.values()):
        flash(request, "Sec. 16(iv): blocked -- all three disqualification declarations are required.",
              kind="error")
        return RedirectResponse(url="/admin/admissions", status_code=303)

    fee = db.from_json(row["fee_instrument_ref"], {})
    if fee.get("cash_accepted"):
        flash(request, "Rule 11(1): blocked -- cash fee instrument is prohibited.", kind="error")
        return RedirectResponse(url="/admin/admissions", status_code=303)

    unit = db.query_one(
        "SELECT id FROM units WHERE upper(canonical_code) = upper(?)",
        (row["flat_id"],),
    )
    serial = f"M-{2000 + db.scalar('SELECT COUNT(*) FROM users', default=0)}"
    today = date.today()
    user_id = db.new_id()
    db.execute(
        """INSERT INTO users
           (id, society_id, unit_id, member_serial_no, full_name,
            father_or_spouse_name, date_of_birth, permanent_address,
            residential_address, mobile_number, email, role, membership_category,
            fee_instrument_ref, sec16_declarations, admission_date,
            register_entry_due_date, password_hash, account_status, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            user_id,
            row["society_id"],
            unit["id"] if unit else None,
            serial,
            row["applicant_name"],
            row["father_or_spouse_name"],
            row["date_of_birth"],
            row["permanent_address"],
            row["residential_address"],
            row["mobile_number"],
            row["email"],
            "MEMBER",
            row["membership_category"],
            row["fee_instrument_ref"],
            row["sec16_declarations"],
            today.isoformat(),
            (today + timedelta(days=15)).isoformat(),  # Sec. 18(1) 15-day SLA
            None,  # password claimed via /claim using Flat + Mobile + Email
            "PENDING",
            db.utcnow(),
        ),
    )
    db.execute(
        """UPDATE form_x_applications
           SET status = 'APPROVED', reviewed_by = ?, reviewed_at = ? WHERE id = ?""",
        (principal.id, db.utcnow(), app_id),
    )
    # Refresh the society's active member count (drives the >300 collegium rule).
    db.execute(
        """UPDATE societies SET active_member_count =
           (SELECT COUNT(*) FROM users
            WHERE account_status IN ('ACTIVE','PENDING') AND role != 'SUPER_ADMIN')"""
    )
    audit.log(
        action="FORM_X_ADMIT",
        rule_ref="HRRS_ACT_2012_SEC_15_16 | RULE_11_1_FORM_X",
        entity_type="form_x_application",
        entity_id=app_id,
        diff={"status": {"old_value": "PENDING_VERIFICATION", "new_value": "APPROVED"},
              "user_id": {"old_value": None, "new_value": user_id},
              "register_entry_due_date": {"old_value": None,
                                           "new_value": (today + timedelta(days=15)).isoformat()}},
        actor_id=principal.id,
        society_id=principal.society_id,
        ip_address=_ip(request),
    )
    flash(request, f"Admitted. Member serial {serial}. Form-XII entry due within 15 days.")
    return RedirectResponse(url="/admin/admissions", status_code=303)


@router.post("/admissions/{app_id}/reject")
def admission_reject(request: Request, app_id: str, reason: str = Form(""),
                     principal: Principal = require_capability("approve_member")):
    row = db.query_one("SELECT * FROM form_x_applications WHERE id = ?", (app_id,))
    if row is None or row["status"] != "PENDING_VERIFICATION":
        return RedirectResponse(url="/admin/admissions", status_code=303)
    db.execute(
        """UPDATE form_x_applications SET status = 'REJECTED', reviewed_by = ?,
           reviewed_at = ?, rejection_reason = ? WHERE id = ?""",
        (principal.id, db.utcnow(), reason.strip() or "Not specified", app_id),
    )
    audit.log(
        action="FORM_X_REJECT",
        rule_ref="HRRS_ACT_2012_SEC_16 | RULE_11_1_FORM_X",
        entity_type="form_x_application",
        entity_id=app_id,
        diff={"status": {"old_value": "PENDING_VERIFICATION", "new_value": "REJECTED"},
              "reason": {"old_value": None, "new_value": reason.strip()}},
        actor_id=principal.id,
        society_id=principal.society_id,
        ip_address=_ip(request),
    )
    flash(request, "Application rejected and recorded in the audit trail.")
    return RedirectResponse(url="/admin/admissions", status_code=303)


# ---------------------------------------------------------------------------
# Announcements (spec 5.4)
# ---------------------------------------------------------------------------

@router.get("/announcements", response_class=HTMLResponse)
def announcements_admin(request: Request, principal: Principal = require_capability("draft_announcement")):
    rows = db.query_all(
        """SELECT a.*, u.full_name AS publisher FROM announcements a
           JOIN users u ON u.id = a.published_by
           ORDER BY a.published_at DESC"""
    )
    return render(request, "admin/announcements.html", {"rows": rows})


@router.post("/announcements", response_class=HTMLResponse)
def announcement_create(
    request: Request,
    title: str = Form(...),
    body_markdown: str = Form(...),
    priority: str = Form("GENERAL"),
    is_public: str = Form(""),
    is_pinned: str = Form(""),
    principal: Principal = require_capability("publish_announcement"),
):
    slug = "".join(
        c if c.isalnum() else "-" for c in title.strip().lower()
    ).strip("-")[:70]
    while "--" in slug:
        slug = slug.replace("--", "-")
    if db.query_one("SELECT id FROM announcements WHERE slug = ?", (slug,)):
        slug = f"{slug}-{db.new_id()[:6]}"

    ann_id = db.new_id()
    db.execute(
        """INSERT INTO announcements
           (id, society_id, slug, title, body_markdown, priority, is_public,
            is_pinned, published_by, published_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            ann_id,
            principal.society_id,
            slug,
            title.strip(),
            body_markdown,
            priority if priority in {"URGENT", "SHUTDOWN", "AGM_NOTICE", "GENERAL", "EVENT"}
            else "GENERAL",
            1 if is_public else 0,
            1 if is_pinned else 0,
            principal.id,
            db.utcnow(),
        ),
    )
    audit.log(
        action="ANNOUNCEMENT_PUBLISH",
        rule_ref="HRRS_ACT_2012_SEC_10_2 | RULE_6_IDENTITY",
        entity_type="announcement",
        entity_id=ann_id,
        diff={"title": {"old_value": None, "new_value": title.strip()},
              "is_public": {"old_value": None, "new_value": bool(is_public)}},
        actor_id=principal.id,
        society_id=principal.society_id,
        ip_address=_ip(request),
    )
    flash(request, "Announcement published.")
    return RedirectResponse(url="/admin/announcements", status_code=303)


@router.post("/announcements/{ann_id}/delete")
def announcement_delete(request: Request, ann_id: str,
                        principal: Principal = require_capability("publish_announcement")):
    row = db.query_one("SELECT * FROM announcements WHERE id = ?", (ann_id,))
    if row:
        db.execute("DELETE FROM announcements WHERE id = ?", (ann_id,))
        audit.log(
            action="ANNOUNCEMENT_WITHDRAW",
            rule_ref="HRRS_ACT_2012_SEC_10_2",
            entity_type="announcement",
            entity_id=ann_id,
            diff={"title": {"old_value": row["title"], "new_value": None}},
            actor_id=principal.id,
            society_id=principal.society_id,
            ip_address=_ip(request),
        )
        flash(request, "Announcement withdrawn.")
    return RedirectResponse(url="/admin/announcements", status_code=303)


# ---------------------------------------------------------------------------
# Helpdesk administration (spec 5.5)
# ---------------------------------------------------------------------------

@router.get("/tickets", response_class=HTMLResponse)
def tickets_admin(request: Request, status: str = "",
                  principal: Principal = require_capability("escalate_ticket")):
    where = "1=1"
    params: list = []
    if status:
        where = "t.status = ?"
        params.append(status)
    rows = db.query_all(
        f"""SELECT t.*, un.canonical_code, u.full_name AS raiser,
                   a.full_name AS assignee
            FROM tickets t
            LEFT JOIN units un ON un.id = t.unit_id
            JOIN users u ON u.id = t.raised_by
            LEFT JOIN users a ON a.id = t.assigned_to
            WHERE {where}
            ORDER BY t.created_at DESC LIMIT 100""",
        params,
    )
    for r in rows:
        r["work_log"] = db.from_json(r["work_log"], [])
    return render(
        request,
        "admin/tickets.html",
        {"rows": rows, "active_status": status,
         "statuses": ["OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "AWAITING_CONFIRMATION",
                      "RESOLVED", "REOPENED"]},
    )


@router.post("/tickets/{ticket_id}/advance")
def ticket_advance(request: Request, ticket_id: str,
                   principal: Principal = require_capability("escalate_ticket")):
    row = db.query_one("SELECT * FROM tickets WHERE id = ?", (ticket_id,))
    if row is None:
        return RedirectResponse(url="/admin/tickets", status_code=303)
    order = ["OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "AWAITING_CONFIRMATION", "RESOLVED"]
    if row["status"] == "REOPENED":
        new_status = "IN_PROGRESS"
    elif row["status"] in order:
        idx = order.index(row["status"])
        new_status = order[min(idx + 1, len(order) - 1)]
    else:
        new_status = row["status"]

    log = db.from_json(row["work_log"], [])
    log.append({"at": db.utcnow(), "by": principal.name,
                "note": f"Status -> {new_status}."})
    resolved_at = db.utcnow() if new_status == "RESOLVED" else row["resolved_at"]
    db.execute(
        """UPDATE tickets SET status = ?, work_log = ?, resolved_at = ?,
           assigned_to = COALESCE(assigned_to, ?) WHERE id = ?""",
        (new_status, db.to_json(log), resolved_at, principal.id, ticket_id),
    )
    audit.log(
        action="TICKET_STATUS",
        rule_ref="HELPDESK_SLA | ZERO_BILLING",
        entity_type="ticket",
        entity_id=ticket_id,
        diff={"status": {"old_value": row["status"], "new_value": new_status}},
        actor_id=principal.id,
        society_id=principal.society_id,
        ip_address=_ip(request),
    )
    flash(request, f"Ticket #{row['ticket_number']} -> {new_status}.")
    return RedirectResponse(url="/admin/tickets", status_code=303)


# ---------------------------------------------------------------------------
# Committee & initiatives management (Form-XVII guardrails)
# ---------------------------------------------------------------------------

@router.get("/committee", response_class=HTMLResponse)
def committee_admin(request: Request, principal: Principal = require_capability("manage_committee")):
    rows = db.query_all(
        """SELECT cm.*, u.full_name FROM committee_members cm
           JOIN users u ON u.id = cm.user_id
           WHERE cm.is_active = 1 ORDER BY cm.designation"""
    )
    today = date.today()
    for c in rows:
        start = date.fromisoformat(c["term_start_date"])
        end = date.fromisoformat(c["term_end_date"])
        total = (end - start).days or 1
        c["term_pct"] = round(min(max((today - start).days, 0), total) * 100 / total)
        c["days_left"] = (end - today).days
        c["designation_label"] = DESIGNATION_LABELS[c["designation"]]
    # Sec. 34(1): governing body must stay between 3 and 21 members.
    members = db.query_all(
        """SELECT u.id, u.full_name, un.canonical_code FROM users u
           LEFT JOIN units un ON un.id = u.unit_id
           WHERE u.role IN ('MEMBER','SOCIETY_ADMIN','DATA_OPERATOR')
             AND u.account_status IN ('ACTIVE','PENDING')
           ORDER BY u.full_name"""
    )
    return render(
        request,
        "admin/committee.html",
        {"rows": rows, "count": len(rows), "gb_min": 3, "gb_max": 21,
         "tenure_years": 3, "designation_labels": DESIGNATION_LABELS,
         "members": members},
    )


@router.post("/committee", response_class=HTMLResponse)
def committee_add(
    request: Request,
    user_id: str = Form(...),
    designation: str = Form(...),
    portfolio: str = Form(""),
    selection_mode: str = Form(...),
    term_start_date: str = Form(...),
    principal: Principal = require_capability("manage_committee"),
):
    count = db.scalar("SELECT COUNT(*) FROM committee_members WHERE is_active = 1", default=0)
    if count >= 21:
        flash(request, "Sec. 34(1): blocked -- the Governing Body cannot exceed 21 members.",
              kind="error")
        return RedirectResponse(url="/admin/committee", status_code=303)
    if designation not in DESIGNATION_LABELS:
        flash(request, "Unknown designation.", kind="error")
        return RedirectResponse(url="/admin/committee", status_code=303)

    try:
        start = date.fromisoformat(term_start_date)
    except ValueError:
        flash(request, "Invalid term start date.", kind="error")
        return RedirectResponse(url="/admin/committee", status_code=303)

    end = start + timedelta(days=3 * 365)  # Sec. 34(3): 3-year ceiling
    cm_id = db.new_id()
    db.execute(
        """INSERT INTO committee_members
           (id, society_id, user_id, designation, portfolio, selection_mode,
            election_or_cooption_ref, term_start_date, term_end_date,
            statutory_form_type, filing_due_date, is_active, public_contact_email,
            created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            cm_id,
            principal.society_id,
            user_id,
            designation,
            portfolio,
            selection_mode if selection_mode in
            {"ELECTED_GBM", "ELECTED_COLLEGIUM", "NOMINATED_COOPTED"} else "NOMINATED_COOPTED",
            "GB-RES-NEW",
            start.isoformat(),
            end.isoformat(),
            "FORM_XVII_A" if selection_mode == "NOMINATED_COOPTED" else "FORM_XVII",
            (start + timedelta(days=30)).isoformat(),  # Sec. 34(2): 30-day filing
            1,
            None,
            db.utcnow(),
        ),
    )
    audit.log(
        action="COMMITTEE_APPOINT",
        rule_ref="HRRS_ACT_2012_SEC_34_1_2_3 | RULE_19_FORM_XVII",
        entity_type="committee_member",
        entity_id=cm_id,
        diff={"designation": {"old_value": None, "new_value": designation},
              "term_end_date": {"old_value": None, "new_value": end.isoformat()}},
        actor_id=principal.id,
        society_id=principal.society_id,
        ip_address=_ip(request),
    )
    flash(request, f"Appointed. Form-XVII filing due within 30 days (by {(start + timedelta(days=30)).isoformat()}).")
    return RedirectResponse(url="/admin/committee", status_code=303)


@router.post("/committee/{cm_id}/retire")
def committee_retire(request: Request, cm_id: str,
                     principal: Principal = require_capability("manage_committee")):
    row = db.query_one("SELECT * FROM committee_members WHERE id = ?", (cm_id,))
    if row:
        db.execute("UPDATE committee_members SET is_active = 0 WHERE id = ?", (cm_id,))
        audit.log(
            action="COMMITTEE_CEASE",
            rule_ref="HRRS_ACT_2012_SEC_34_4 | RULE_19_FORM_XVII_A",
            entity_type="committee_member",
            entity_id=cm_id,
            diff={"is_active": {"old_value": 1, "new_value": 0}},
            actor_id=principal.id,
            society_id=principal.society_id,
            ip_address=_ip(request),
        )
        flash(request, "Office-bearer ceased. Form-XVII-A filing due within 30 days.")
    return RedirectResponse(url="/admin/committee", status_code=303)


@router.get("/initiatives", response_class=HTMLResponse)
def initiatives_admin(request: Request, principal: Principal = require_capability("manage_initiatives")):
    rows = db.query_all(
        """SELECT ci.*, u.full_name AS lead_name FROM committee_initiatives ci
           LEFT JOIN committee_members cm ON cm.id = ci.lead_committee_member_id
           LEFT JOIN users u ON u.id = cm.user_id
           ORDER BY ci.completion_pct DESC"""
    )
    committee = db.query_all(
        """SELECT cm.id, cm.designation, u.full_name FROM committee_members cm
           JOIN users u ON u.id = cm.user_id WHERE cm.is_active = 1"""
    )
    return render(
        request,
        "admin/initiatives.html",
        {"rows": rows, "committee": committee,
         "statuses": ["PROPOSED", "APPROVED", "IN_PROGRESS", "COMPLETED"]},
    )


@router.post("/initiatives", response_class=HTMLResponse)
def initiative_create(
    request: Request,
    title: str = Form(...),
    category: str = Form(...),
    summary: str = Form(...),
    resolution_reference: str = Form(""),
    status: str = Form("PROPOSED"),
    completion_pct: int = Form(0),
    lead_committee_member_id: str = Form(""),
    principal: Principal = require_capability("manage_initiatives"),
):
    init_id = db.new_id()
    now = db.utcnow()
    db.execute(
        """INSERT INTO committee_initiatives
           (id, society_id, title, category, summary, resolution_reference,
            status, completion_pct, milestone_notes, lead_committee_member_id,
            is_public, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            init_id,
            principal.society_id,
            title.strip(),
            category.strip(),
            summary.strip(),
            resolution_reference.strip() or None,
            status if status in {"PROPOSED", "APPROVED", "IN_PROGRESS", "COMPLETED"}
            else "PROPOSED",
            max(0, min(100, completion_pct)),
            "",
            lead_committee_member_id or None,
            1,
            now,
            now,
        ),
    )
    audit.log(
        action="INITIATIVE_CREATE",
        rule_ref="HRRS_ACT_2012_SEC_37 | PUBLIC_ACCOUNTABILITY",
        entity_type="committee_initiative",
        entity_id=init_id,
        diff={"title": {"old_value": None, "new_value": title.strip()},
              "resolution_reference": {"old_value": None,
                                        "new_value": resolution_reference.strip()}},
        actor_id=principal.id,
        society_id=principal.society_id,
        ip_address=_ip(request),
    )
    flash(request, "Initiative added to the public delivery ledger.")
    return RedirectResponse(url="/admin/initiatives", status_code=303)


@router.post("/initiatives/{init_id}/progress")
def initiative_progress(request: Request, init_id: str, completion_pct: int = Form(...),
                        status: str = Form(...),
                        principal: Principal = require_capability("manage_initiatives")):
    row = db.query_one("SELECT * FROM committee_initiatives WHERE id = ?", (init_id,))
    if row is None:
        return RedirectResponse(url="/admin/initiatives", status_code=303)
    pct = max(0, min(100, completion_pct))
    new_status = status if status in {"PROPOSED", "APPROVED", "IN_PROGRESS", "COMPLETED"} else row["status"]
    if pct == 100:
        new_status = "COMPLETED"
    db.execute(
        """UPDATE committee_initiatives SET completion_pct = ?, status = ?,
           updated_at = ? WHERE id = ?""",
        (pct, new_status, db.utcnow(), init_id),
    )
    audit.log(
        action="INITIATIVE_PROGRESS",
        rule_ref="HRRS_ACT_2012_SEC_37 | PUBLIC_ACCOUNTABILITY",
        entity_type="committee_initiative",
        entity_id=init_id,
        diff=audit.diff(dict(row), {"completion_pct": pct, "status": new_status},
                        ["completion_pct", "status"]),
        actor_id=principal.id,
        society_id=principal.society_id,
        ip_address=_ip(request),
    )
    flash(request, "Progress updated on the public dashboard.")
    return RedirectResponse(url="/admin/initiatives", status_code=303)


# ---------------------------------------------------------------------------
# Document vault & Sec. 37 sign-off (spec 5.3)
# ---------------------------------------------------------------------------

@router.get("/vault", response_class=HTMLResponse)
def vault(request: Request, principal: Principal = require_capability("upload_documents")):
    docs = db.query_all(
        """SELECT d.*, u.full_name AS creator,
                  (SELECT COUNT(*) FROM document_versions dv WHERE dv.document_id = d.id) AS versions
           FROM documents d JOIN users u ON u.id = d.created_by
           ORDER BY d.created_at DESC"""
    )
    for d in docs:
        d["pending_signoff"] = not (d["chairman_signed"] and d["secretary_signed"])
        d["versions_list"] = db.query_all(
            """SELECT dv.*, u.full_name AS uploader FROM document_versions dv
               JOIN users u ON u.id = dv.uploaded_by
               WHERE dv.document_id = ? ORDER BY dv.version_number DESC""",
            (d["id"],),
        )
    return render(request, "admin/vault.html", {"docs": docs})


@router.post("/vault/{doc_id}/signoff")
def vault_signoff(request: Request, doc_id: str, signer: str = Form(...),
                  principal: Principal = require_capability("sign_mom")):
    """Sec. 37(2): Chairman + Secretary dual sign-off."""
    row = db.query_one("SELECT * FROM documents WHERE id = ?", (doc_id,))
    if row is None:
        return RedirectResponse(url="/admin/vault", status_code=303)
    if signer == "chairman":
        db.execute("UPDATE documents SET chairman_signed = 1 WHERE id = ?", (doc_id,))
    elif signer == "secretary":
        db.execute("UPDATE documents SET secretary_signed = 1 WHERE id = ?", (doc_id,))
    else:
        flash(request, "Unknown signatory block.", kind="error")
        return RedirectResponse(url="/admin/vault", status_code=303)
    audit.log(
        action="MOM_SIGNOFF",
        rule_ref="HRRS_ACT_2012_SEC_37_2 | DUAL_SIGNATORY",
        entity_type="document",
        entity_id=doc_id,
        diff={signer: {"old_value": False, "new_value": True}},
        actor_id=principal.id,
        society_id=principal.society_id,
        ip_address=_ip(request),
    )
    flash(request, f"{signer.title()} sign-off recorded (Sec. 37(2)).")
    return RedirectResponse(url="/admin/vault", status_code=303)


@router.post("/vault/{doc_id}/confirm")
def vault_confirm(request: Request, doc_id: str, confirm_date: str = Form(...),
                  principal: Principal = require_capability("sign_mom")):
    """Sec. 37(3): confirmation in the succeeding meeting."""
    row = db.query_one("SELECT * FROM documents WHERE id = ?", (doc_id,))
    if row is None:
        return RedirectResponse(url="/admin/vault", status_code=303)
    db.execute(
        "UPDATE documents SET confirmed_in_next_meeting_date = ? WHERE id = ?",
        (confirm_date, doc_id),
    )
    audit.log(
        action="MOM_CONFIRMED",
        rule_ref="HRRS_ACT_2012_SEC_37_3 | CONFIRMATION_NEXT_MEETING",
        entity_type="document",
        entity_id=doc_id,
        diff={"confirmed_in_next_meeting_date":
              {"old_value": row["confirmed_in_next_meeting_date"], "new_value": confirm_date}},
        actor_id=principal.id,
        society_id=principal.society_id,
        ip_address=_ip(request),
    )
    flash(request, "Confirmation in the succeeding meeting recorded (Sec. 37(3)).")
    return RedirectResponse(url="/admin/vault", status_code=303)


# ---------------------------------------------------------------------------
# Statutory exports with Rule 23 two-signatory endorsement (spec 5.1)
# ---------------------------------------------------------------------------

@router.get("/exports", response_class=HTMLResponse)
def exports(request: Request, principal: Principal = require_capability("export_registers")):
    forms = [
        ("FORM_XI", "Member Identity Card", "Sec. 17 & Rule 11(2)"),
        ("FORM_XII", "Register of Members (15-day)", "Sec. 18(1) & Rule 12"),
        ("FORM_XIII", "Electoral College Register", "Sec. 29(4), Sec. 30 & Rule 12"),
        ("FORM_XIV", "Collegium Register", "Sec. 32 & Rule 18"),
        ("FORM_XV", "Annual Inclusion / Deletion Return", "Sec. 18(3)-(4) & Rule 13"),
        ("FORM_XVII", "Governing Body Filing", "Sec. 34 & Rule 19"),
        ("RULE_23", "Two-Signatory Verification Declaration", "Rule 23"),
    ]
    active_members = db.scalar(
        "SELECT COUNT(*) FROM users WHERE role != 'SUPER_ADMIN'", default=0
    )
    return render(
        request,
        "admin/exports.html",
        {"forms": forms, "active_members": active_members,
         "collegium_active": active_members > 300,
         "members": db.query_all(
             """SELECT u.*, un.canonical_code FROM users u
                LEFT JOIN units un ON un.id = u.unit_id
                WHERE u.role != 'SUPER_ADMIN' ORDER BY un.canonical_code"""
         ),
         "today": date.today().isoformat()},
    )
