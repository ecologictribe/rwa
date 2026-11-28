"""Authenticated member portal (spec 2.1 ``MEMBER`` scope).

Members see only their own unit's occupancy lineage, the notices, the approved
documents and their own tickets. No accounting or payment surfaces exist.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
import shutil

import markdown as md
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from .. import audit, config, db, security
from ..render import flash, render
from ..security import Principal, require_capability
from ..storage import ensure_pdf_file_exists, get_safe_upload_path, is_at_least_21

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
    clean_cat = category.strip()
    if clean_cat not in TICKET_CATEGORIES:
        flash(request, "Please select a valid helpdesk category.", kind="error")
        return RedirectResponse(url="/portal/tickets", status_code=303)

    if len(subject.strip()) < 5 or len(description.strip()) < 10:
        flash(request, "Please give a subject of at least 5 and a description of at least 10 characters.",
              kind="error")
        return RedirectResponse(url="/portal/tickets", status_code=303)

    # Spec 6.2: plumbing tickets anchor to the riser for LCA outage clustering.
    infra_anchor = "Riser A1" if clean_cat.startswith("Plumbing") else None

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
            clean_cat,
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


@router.post("/tickets/{ticket_id}/reopen")
def ticket_reopen(
    request: Request,
    ticket_id: str,
    reason: str = Form(""),
    principal: Principal = require_capability("raise_ticket"),
):
    row = db.query_one(
        "SELECT * FROM tickets WHERE id = ? AND raised_by = ?", (ticket_id, principal.id)
    )
    if row is None:
        return RedirectResponse(url="/portal/tickets", status_code=303)
    if row["status"] in {"AWAITING_CONFIRMATION", "RESOLVED"}:
        log = db.from_json(row["work_log"], [])
        note_text = f"Resident reported issue not resolved / reopened: {reason.strip()}" if reason.strip() else "Resident reported issue is not resolved. Reopened."
        log.append({"at": db.utcnow(), "by": principal.name, "note": note_text})
        db.execute(
            "UPDATE tickets SET status = 'REOPENED', resolved_at = NULL, work_log = ? WHERE id = ?",
            (db.to_json(log), ticket_id),
        )
        audit.log(
            action="TICKET_REOPEN",
            rule_ref="HELPDESK_SLA | ZERO_BILLING",
            entity_type="ticket",
            entity_id=ticket_id,
            diff={"status": {"old_value": row["status"], "new_value": "REOPENED"}},
            actor_id=principal.id,
            society_id=principal.society_id,
            ip_address=request.client.host if request.client else None,
        )
        flash(request, f"Ticket #{row['ticket_number']} reopened. The desk has been notified.")
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


@router.get("/documents/{doc_id}/download")
def download_document(doc_id: str, principal: Principal = require_capability("download_documents")):
    doc = db.query_one("SELECT * FROM documents WHERE id = ?", (doc_id,))
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found.")
    if doc["visibility"] == "COMMITTEE_ONLY" and not principal.has_role("SOCIETY_ADMIN", "SUPER_ADMIN"):
        raise HTTPException(status_code=403, detail="Sec. 20(3): This document is restricted to the Governing Body.")
    version = db.query_one(
        "SELECT * FROM document_versions WHERE document_id = ? ORDER BY version_number DESC LIMIT 1",
        (doc_id,),
    )
    if not version:
        raise HTTPException(status_code=404, detail="No versions available for this document.")
    target_path = get_safe_upload_path(version["storage_path"])
    if not target_path:
        raise HTTPException(status_code=400, detail="Invalid document storage path.")
    ensure_pdf_file_exists(
        target_path,
        doc["title"],
        doc["doc_category"],
        version["version_number"],
        version["sha256_checksum"],
    )
    download_name = f"{doc['doc_category'].lower()}_v{version['version_number']}.pdf"
    return FileResponse(target_path, media_type=version.get("mime_type") or "application/pdf", filename=download_name)


@router.get("/profile", response_class=HTMLResponse)
def profile(request: Request, principal: Principal = require_capability("view_own_unit")):
    unit = None
    if principal.unit_id:
        unit = db.query_one("SELECT * FROM units WHERE id = ?", (principal.unit_id,))
    # Fetch fresh member record from database
    member_record = db.query_one("SELECT * FROM users WHERE id = ?", (principal.id,)) or principal.row
    return render(
        request,
        "portal/profile.html",
        {"member": member_record, "unit": unit},
    )


@router.post("/profile/update", response_class=HTMLResponse)
async def profile_update(
    request: Request,
    father_or_spouse_name: str = Form(""),
    date_of_birth: str = Form(""),
    occupation: str = Form(""),
    qualification: str = Form(""),
    aadhaar_number: str = Form(""),
    permanent_address: str = Form(""),
    residential_address: str = Form(""),
    id_proof: UploadFile = File(None),
    profile_photo: UploadFile = File(None),
    principal: Principal = require_capability("view_own_unit"),
):
    user = db.query_one("SELECT * FROM users WHERE id = ?", (principal.id,))
    if not user:
        return RedirectResponse(url="/portal/profile", status_code=303)

    clean_aadhaar = aadhaar_number.replace(" ", "").replace("-", "").strip()
    if clean_aadhaar and (len(clean_aadhaar) != 12 or not clean_aadhaar.isdigit()):
        flash(request, "Aadhaar number must be exactly 12 digits (or leave blank).", kind="error")
        return RedirectResponse(url="/portal/profile", status_code=303)

    if date_of_birth.strip():
        try:
            dob = date.fromisoformat(date_of_birth.strip())
            if not is_at_least_21(dob, date.today()):
                flash(request, "Sec. 16(i): Member must have completed 21 years of age.", kind="error")
                return RedirectResponse(url="/portal/profile", status_code=303)
        except ValueError:
            flash(request, "Date of birth is not a valid date.", kind="error")
            return RedirectResponse(url="/portal/profile", status_code=303)

    id_proof_path = user.get("id_proof_path")
    if id_proof and id_proof.filename:
        ext = Path(id_proof.filename).suffix.lower()
        if ext in {".pdf", ".jpg", ".jpeg", ".png"}:
            dest_filename = f"id_proof_{principal.id}{ext}"
            dest_path = config.UPLOAD_DIR / dest_filename
            with open(dest_path, "wb") as buffer:
                shutil.copyfileobj(id_proof.file, buffer)
            id_proof_path = dest_filename

    profile_photo_path = user.get("profile_photo_path")
    if profile_photo and profile_photo.filename:
        ext = Path(profile_photo.filename).suffix.lower()
        if ext in {".jpg", ".jpeg", ".png"}:
            dest_filename = f"photo_{principal.id}{ext}"
            dest_path = config.UPLOAD_DIR / dest_filename
            with open(dest_path, "wb") as buffer:
                shutil.copyfileobj(profile_photo.file, buffer)
            profile_photo_path = dest_filename

    delta = audit.diff(dict(user), {
        "father_or_spouse_name": father_or_spouse_name.strip() or None,
        "date_of_birth": date_of_birth.strip() or None,
        "occupation": occupation.strip() or None,
        "qualification": qualification.strip() or None,
        "aadhaar_number": clean_aadhaar or None,
        "permanent_address": permanent_address.strip() or None,
        "residential_address": residential_address.strip() or None,
        "id_proof_path": id_proof_path,
        "profile_photo_path": profile_photo_path,
    }, [
        "father_or_spouse_name", "date_of_birth", "occupation",
        "qualification", "aadhaar_number", "permanent_address",
        "residential_address", "id_proof_path", "profile_photo_path"
    ])

    if delta:
        db.execute(
            """UPDATE users SET
               father_or_spouse_name = ?, date_of_birth = ?, occupation = ?,
               qualification = ?, aadhaar_number = ?, permanent_address = ?,
               residential_address = ?, id_proof_path = ?, profile_photo_path = ?
               WHERE id = ?""",
            (
                father_or_spouse_name.strip() or None,
                date_of_birth.strip() or None,
                occupation.strip() or None,
                qualification.strip() or None,
                clean_aadhaar or None,
                permanent_address.strip() or None,
                residential_address.strip() or None,
                id_proof_path,
                profile_photo_path,
                principal.id,
            ),
        )
        audit.log(
            action="MEMBER_SELF_UPDATE",
            rule_ref="HRRS_ACT_2012_SEC_18_1 | MEMBER_SELF_SERVICE",
            entity_type="user",
            entity_id=principal.id,
            diff=delta,
            actor_id=principal.id,
            society_id=principal.society_id,
            ip_address=request.client.host if request.client else None,
        )
        flash(request, "Your profile and documents have been updated successfully.")
    else:
        flash(request, "No changes detected.")
    return RedirectResponse(url="/portal/profile", status_code=303)


@router.get("/profile/id-proof")
def download_my_id_proof(principal: Principal = require_capability("view_own_unit")):
    user = db.query_one("SELECT id_proof_path FROM users WHERE id = ?", (principal.id,))
    if not user or not user.get("id_proof_path"):
        raise HTTPException(status_code=404, detail="No ID proof document on file.")
    path = get_safe_upload_path(user["id_proof_path"])
    if path is None or not path.is_file():
        raise HTTPException(status_code=404, detail="File not found on server.")
    return FileResponse(path)


@router.get("/profile/photo")
def download_my_photo(principal: Principal = require_capability("view_own_unit")):
    user = db.query_one("SELECT profile_photo_path FROM users WHERE id = ?", (principal.id,))
    if not user or not user.get("profile_photo_path"):
        raise HTTPException(status_code=404, detail="No photo on file.")
    path = get_safe_upload_path(user["profile_photo_path"])
    if path is None or not path.is_file():
        raise HTTPException(status_code=404, detail="File not found on server.")
    return FileResponse(path)
