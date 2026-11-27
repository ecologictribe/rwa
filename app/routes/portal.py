"""Authenticated member portal (spec 2.1 ``MEMBER`` scope).

Members see only their own unit's occupancy lineage, the notices, the approved
documents and their own tickets. No accounting or payment surfaces exist.
"""

from __future__ import annotations

from datetime import date

import markdown as md
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import audit, db, security
from ..render import flash, render
from ..security import Principal, require_capability

router = APIRouter(prefix="/portal")

TICKET_CATEGORIES = [
    "Plumbing & Water", "Electrical", "Lift & Vertical Transport",
    "Housekeeping", "Security & Gate", "Common Area", "Landscaping",
    "Carpentry & Paint", "Pest Control", "Other",
]


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
def portal_home(request: Request, principal: Principal = require_capability("view_notices")):
    unit = None
    lineage = []
    if principal.unit_id:
        unit = db.query_one("SELECT * FROM units WHERE id = ?", (principal.unit_id,))
        # Temporal occupancy & ownership lineage (spec 6.1 use case 2)
        lineage = db.query_all(
            """SELECT u.full_name, ge.edge_label, ge.valid_from, ge.valid_to, ge.metadata
               FROM graph_edges ge JOIN users u ON u.id = ge.source_id
               WHERE ge.target_id = ? AND ge.graph_domain = 'SOCIETY_ENTITY'
               ORDER BY ge.valid_from DESC""",
            (principal.unit_id,),
        )
        for edge in lineage:
            edge["meta"] = db.from_json(edge["metadata"], {})

    notices = db.query_all(
        """SELECT * FROM announcements
           WHERE is_public = 1 OR priority != 'GENERAL'
           ORDER BY is_pinned DESC, published_at DESC LIMIT 6"""
    )
    for n in notices:
        n["body_html"] = md.markdown(n["body_markdown"])

    my_tickets = db.query_all(
        """SELECT * FROM tickets WHERE raised_by = ? ORDER BY created_at DESC LIMIT 8""",
        (principal.id,),
    )
    docs = db.query_all(
        """SELECT d.*, (SELECT MAX(version_number) FROM document_versions dv
                        WHERE dv.document_id = d.id) AS ver
           FROM documents d
           WHERE d.visibility IN ('PUBLIC','MEMBERS_ONLY')
           ORDER BY d.created_at DESC LIMIT 8"""
    )

    form_xii_due = None
    if principal.row and principal.row.get("register_entry_due_date"):
        due = date.fromisoformat(principal.row["register_entry_due_date"])
        form_xii_due = (due - date.today()).days

    return render(
        request,
        "portal/home.html",
        {
            "unit": unit,
            "lineage": lineage,
            "notices": notices,
            "tickets": my_tickets,
            "docs": docs,
            "form_xii_due": form_xii_due,
            "categories": TICKET_CATEGORIES,
            "member": principal.row,
        },
    )


@router.get("/tickets", response_class=HTMLResponse)
def my_tickets(request: Request, principal: Principal = require_capability("raise_ticket")):
    rows = db.query_all(
        """SELECT * FROM tickets WHERE raised_by = ? ORDER BY created_at DESC""",
        (principal.id,),
    )
    for r in rows:
        r["work_log"] = db.from_json(r["work_log"], [])
    return render(
        request,
        "portal/tickets.html",
        {"rows": rows, "categories": TICKET_CATEGORIES},
    )


@router.post("/tickets", response_class=HTMLResponse)
def ticket_create(
    request: Request,
    category: str = Form(...),
    subject: str = Form(...),
    description: str = Form(...),
    location_scope: str = Form("COMMON_AREA"),
    priority: str = Form("MEDIUM"),
    principal: Principal = require_capability("raise_ticket"),
):
    if len(subject.strip()) < 5 or len(description.strip()) < 10:
        flash(request, "Please give a subject and a description of at least 10 characters.",
              kind="error")
        return RedirectResponse(url="/portal/tickets", status_code=303)

    # Spec 6.2: plumbing tickets anchor to the riser for LCA outage clustering.
    infra_anchor = "Riser A1" if category.startswith("Plumbing") else None

    ticket_id = db.new_id()
    next_no = (db.scalar("SELECT MAX(ticket_number) FROM tickets", default=400) or 400) + 1
    db.execute(
        """INSERT INTO tickets
           (id, society_id, ticket_number, unit_id, infra_node_id, raised_by,
            category, location_scope, subject, description, status, priority,
            work_log, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            ticket_id,
            principal.society_id,
            next_no,
            principal.unit_id,
            infra_anchor,
            principal.id,
            category,
            location_scope if location_scope in {"UNIT", "COMMON_AREA"} else "COMMON_AREA",
            subject.strip(),
            description.strip(),
            "OPEN",
            priority if priority in {"LOW", "MEDIUM", "HIGH", "URGENT"} else "MEDIUM",
            db.to_json([{"at": db.utcnow(), "by": principal.name,
                         "note": "Ticket raised by resident."}]),
            db.utcnow(),
        ),
    )
    audit.log(
        action="TICKET_CREATE",
        rule_ref="HELPDESK_SLA | ZERO_BILLING",
        entity_type="ticket",
        entity_id=ticket_id,
        diff={"subject": {"old_value": None, "new_value": subject.strip()}},
        actor_id=principal.id,
        society_id=principal.society_id,
        ip_address=request.client.host if request.client else None,
    )
    flash(request, f"Ticket #{next_no} logged. The desk will acknowledge it shortly.")
    return RedirectResponse(url="/portal/tickets", status_code=303)


@router.post("/tickets/{ticket_id}/confirm")
def ticket_confirm(request: Request, ticket_id: str,
                   principal: Principal = require_capability("raise_ticket")):
    row = db.query_one(
        "SELECT * FROM tickets WHERE id = ? AND raised_by = ?", (ticket_id, principal.id)
    )
    if row is None:
        return RedirectResponse(url="/portal/tickets", status_code=303)
    if row["status"] == "AWAITING_CONFIRMATION":
        log = db.from_json(row["work_log"], [])
        log.append({"at": db.utcnow(), "by": principal.name,
                    "note": "Resident confirmed resolution. Ticket closed."})
        db.execute(
            "UPDATE tickets SET status = 'RESOLVED', work_log = ?, resolved_at = ? WHERE id = ?",
            (db.to_json(log), db.utcnow(), ticket_id),
        )
        flash(request, f"Ticket #{row['ticket_number']} confirmed as resolved. Thank you.")
    return RedirectResponse(url="/portal/tickets", status_code=303)


@router.get("/documents", response_class=HTMLResponse)
def my_documents(request: Request, principal: Principal = require_capability("download_documents")):
    docs = db.query_all(
        """SELECT d.*,
                  (SELECT COUNT(*) FROM document_versions dv WHERE dv.document_id = d.id) AS versions
           FROM documents d
           WHERE d.visibility IN ('PUBLIC','MEMBERS_ONLY')
           ORDER BY d.doc_category, d.title"""
    )
    return render(request, "portal/documents.html", {"docs": docs})


@router.get("/profile", response_class=HTMLResponse)
def profile(request: Request, principal: Principal = require_capability("view_own_unit")):
    unit = None
    if principal.unit_id:
        unit = db.query_one("SELECT * FROM units WHERE id = ?", (principal.unit_id,))
    # Statutory right of inspection: Sec. 19 / Sec. 20(3)
    return render(
        request,
        "portal/profile.html",
        {"member": principal.row, "unit": unit},
    )
