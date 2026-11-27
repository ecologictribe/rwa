"""Seed data for the demo deployment.

Everything here is **fictional**. The society, registration number, committee
members, residents and initiatives are invented so that every screen has
realistic content without exposing anybody's personal data.

Run with::

    python -m app.seed           # create schema + seed (idempotent)
"""

from __future__ import annotations

import uuid
from datetime import date, timedelta

from . import db, security

NS = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")


def sid(key: str) -> str:
    """Deterministic UUID so reseeding stays stable."""
    return str(uuid.uuid5(NS, key))


TODAY = date.today()


def iso(d: date) -> str:
    return d.isoformat()


# ---------------------------------------------------------------------------
# Society identity (Sec. 10(2))
# ---------------------------------------------------------------------------

SOCIETY_ID = sid("society-greenwood")
CLUB_SECRETARY = "user-clerk"
PRESIDENT = "user-president"

PASSWORD = "Welcome@123"  # demo credentials, printed by the seed script


def build() -> None:
    db.init_db()

    existing = db.scalar("SELECT COUNT(*) FROM societies", default=0)
    if existing:
        print("Database already seeded -- nothing to do.")
        return

    now = db.utcnow()

    # -- 1. Society -------------------------------------------------------
    db.execute(
        """INSERT INTO societies
           (id, name, registration_number, registered_office_address,
            contact_email, contact_phone, active_member_count, config, created_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            SOCIETY_ID,
            "Greenwood Residency Welfare Association",
            "HRS/HR/2014/1187",
            "Registered Office: A-Block Club House, Greenwood Residency, "
            "Sector 47, Gurugram, Haryana 122018",
            "office@greenwoodrwa.in",
            "+91 124 456 7890",
            0,
            db.to_json({"collegium_threshold": 300}),
            now,
        ),
    )

    # -- 2. Units: two towers, eight floors, four units each (64 total) ----
    unit_ids: list[str] = []
    for block in ("A", "B"):
        for floor in range(1, 9):
            for seq in range(1, 5):
                code = f"{floor}{seq:02d}"
                uid = sid(f"unit-{block}-{code}")
                unit_ids.append(uid)
                db.execute(
                    """INSERT INTO units
                       (id, society_id, block_tower, unit_number, canonical_code,
                        unit_type, occupancy_status, parking_slot)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (
                        uid,
                        SOCIETY_ID,
                        block,
                        code,
                        f"BLK-{block}-{code}",
                        "APARTMENT",
                        "VACANT",
                        f"P-{block}-{code}",
                    ),
                )

    # -- 3. Users ----------------------------------------------------------
    mobile_seq = 0

    def add_user(
        key: str,
        name: str,
        role: str,
        *,
        unit_idx: int | None = None,
        category: str = "ORDINARY",
        dob_years: int = 38,
        mobile: str | None = None,
        email: str | None = None,
        status: str = "ACTIVE",
        father: str = "",
        occupation: str = "Service",
        serial: str | None = None,
        password: str | None = None,
        theme: str = "retro-paper",
        public_contact: bool = False,
    ) -> str:
        uid = sid(f"user-{key}")
        unit_id = unit_ids[unit_idx] if unit_idx is not None else None
        admission = TODAY - timedelta(days=1200 + (unit_idx or 0) * 7)
        nonlocal mobile_seq
        mobile_seq += 1
        # Deterministic, collision-free 10-digit E.164 normalised number.
        mobile = mobile or f"+9198{1000000 + mobile_seq * 7919 % 8999999:07d}"
        email = email or f"{key.replace('user-', '')}@greenwoodrwa.in"
        db.execute(
            """INSERT INTO users
               (id, society_id, unit_id, member_serial_no, full_name,
                father_or_spouse_name, date_of_birth, occupation,
                permanent_address, residential_address, mobile_number, email,
                role, membership_category, admission_date, register_entry_due_date,
                password_hash, account_status, theme_preference,
                is_public_contact_optin, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                uid,
                SOCIETY_ID,
                unit_id,
                serial or (f"M-{1000 + (unit_idx or 0)}" if unit_id else None),
                name,
                father or "Sh. Ramesh Kumar",
                iso(date(TODAY.year - dob_years, 4, 12)),
                occupation,
                f"H.No. {unit_idx or 1}, Sector 47, Gurugram",
                f"H.No. {unit_idx or 1}, Sector 47, Gurugram",
                mobile,
                email,
                role,
                category,
                iso(admission),
                iso(admission + timedelta(days=15)),
                security.hash_password(password or PASSWORD),
                status,
                theme,
                1 if public_contact else 0,
                now,
            ),
        )
        return uid

    president_id = add_user(
        "president",
        "Rajiv Malhotra",
        "SOCIETY_ADMIN",
        unit_idx=0,
        category="LIFE",
        dob_years=52,
        father="Sh. Devender Malhotra",
        occupation="Chartered Accountant",
        serial="M-1001",
        public_contact=True,
        email="president@greenwoodrwa.in",
    )
    add_user(
        "secretary",
        "Sunita Kapoor",
        "SOCIETY_ADMIN",
        unit_idx=4,
        category="LIFE",
        dob_years=46,
        father="Sh. Mohan Lal",
        occupation="Government Service",
        serial="M-1005",
        public_contact=True,
        email="secretary@greenwoodrwa.in",
    )
    add_user(
        "treasurer",
        "Arun Verma",
        "SOCIETY_ADMIN",
        unit_idx=8,
        category="ORDINARY",
        dob_years=49,
        father="Sh. Kishan Verma",
        occupation="Banker",
        serial="M-1009",
        email="treasurer@greenwoodrwa.in",
    )
    add_user(
        "vice-president",
        "Meenakshi Rao",
        "SOCIETY_ADMIN",
        unit_idx=12,
        category="LIFE",
        dob_years=44,
        father="Sh. S. Raghavan",
        occupation="Doctor",
        serial="M-1013",
        email="vp@greenwoodrwa.in",
    )
    add_user(
        "clerk",
        "Deepak Yadav",
        "DATA_OPERATOR",
        unit_idx=None,
        category="NONE",
        dob_years=31,
        father="Sh. Ram Avtar",
        occupation="Estate Clerk",
        email="clerk@greenwoodrwa.in",
    )
    add_user(
        "superadmin",
        "Puneet Arora",
        "SUPER_ADMIN",
        unit_idx=None,
        category="NONE",
        dob_years=35,
        father="Sh. S. K. Arora",
        occupation="Platform Owner",
        email="admin@greenwoodrwa.in",
    )

    # Ordinary residents -- owners and tenants across both towers.
    surnames = [
        "Aggarwal", "Bansal", "Chawla", "Deshmukh", "Gupta", "Handa", "Jain",
        "Kapoor", "Luthra", "Mehra", "Narang", "Oberoi", "Phogat", "Qureshi",
        "Rastogi", "Saxena", "Tandon", "Uppal", "Vohra", "Wadhwa", "Chopra",
        "Dutta", "Sethi", "Mittal", "Goel", "Suri", "Batra", "Kohli",
        "Malhotra", "Bhardwaj", "Chhabra", "Grover", "Sareen", "Arora",
        "Kakkar", "Sabharwal",
    ]
    firsts = [
        "Vikas", "Neha", "Rohit", "Priya", "Karan", "Anjali", "Sameer", "Ritu",
        "Nikhil", "Shweta", "Gaurav", "Pooja", "Manish", "Divya", "Tarun",
        "Kavita", "Ashok", "Neelam", "Rahul", "Sneha", "Amit", "Ruchi",
        "Sanjay", "Bhavna", "Yogesh", "Preeti", "Harish", "Mona", "Kapil",
        "Rina", "Naveen", "Jyoti", "Varun", "Shalini", "Rajesh", "Anita",
    ]
    for i, (first, last) in enumerate(zip(firsts, surnames)):
        unit_idx = 16 + i
        if unit_idx >= len(unit_ids):
            break
        is_tenant = i % 5 == 3
        uid = add_user(
            f"resident-{i}",
            f"{first} {last}",
            "MEMBER",
            unit_idx=unit_idx,
            category=("ASSOCIATE" if is_tenant else ("FOUNDER" if i < 4 else "ORDINARY")),
            dob_years=28 + (i * 3) % 30,
            father=f"Sh. {last} Senior",
            occupation="IT Professional" if i % 3 == 0 else "Business",
            serial=f"M-{1100 + i}",
            password=PASSWORD,
        )
        db.execute(
            "UPDATE units SET occupancy_status = ? WHERE id = ?",
            ("TENANT_OCCUPIED" if is_tenant else "OWNER_OCCUPIED", unit_ids[unit_idx]),
        )
        # Entity graph edges (spec 6.1): OWNS / RESIDES_IN
        db.execute(
            """INSERT INTO graph_edges
               (id, society_id, graph_domain, source_type, source_id, edge_label,
                target_type, target_id, metadata, valid_from)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                sid(f"edge-owns-{i}"),
                SOCIETY_ID,
                "SOCIETY_ENTITY",
                "Person",
                uid,
                "OWNS" if not is_tenant else "RESIDES_IN",
                "Unit",
                unit_ids[unit_idx],
                db.to_json({"from": iso(TODAY - timedelta(days=1100))}),
                now,
            ),
        )

    # Mark a couple of units vacant for occupancy analytics
    for idx in (-2, -1):
        db.execute(
            "UPDATE units SET occupancy_status = 'VACANT' WHERE id = ?", (unit_ids[idx],)
        )

    # -- 4. Committee roster (Form-XVII) ----------------------------------
    committee = [
        ("president", president_id, "PRESIDENT", "Overall Governance & Statutory Compliance",
         "ELECTED_GBM", "GB-RES-2024-11", 0),
        ("vice-president", sid("user-vice-president"), "VICE_PRESIDENT", "Civil & Structural",
         "ELECTED_GBM", "GB-RES-2024-12", 1),
        ("secretary", sid("user-secretary"), "GENERAL_SECRETARY", "Statutory Compliance & Filing",
         "ELECTED_GBM", "GB-RES-2024-13", 2),
        ("treasurer", sid("user-treasurer"), "TREASURER", "Budget & Vendor Contracts",
         "ELECTED_GBM", "GB-RES-2024-14", 3),
        ("resident-0", sid("user-resident-0"), "JOINT_SECRETARY", "Security & Gate",
         "NOMINATED_COOPTED", "GB-RES-2025-03", 4),
        ("resident-1", sid("user-resident-1"), "EXECUTIVE_MEMBER", "Horticulture & Green Belt",
         "NOMINATED_COOPTED", "GB-RES-2025-04", 5),
        ("resident-2", sid("user-resident-2"), "EXECUTIVE_MEMBER", "Lift & MEP Maintenance",
         "ELECTED_COLLEGIUM", "COL-RES-2025-02", 6),
        ("resident-3", sid("user-resident-3"), "EXECUTIVE_MEMBER", "Culture & Community Events",
         "ELECTED_COLLEGIUM", "COL-RES-2025-03", 7),
    ]
    term_start = TODAY - timedelta(days=430)  # ~14 months into a 3 year term
    for i, (key, user_id, designation, portfolio, mode, ref, lag) in enumerate(committee):
        start = term_start - timedelta(days=lag * 11)
        end = start + timedelta(days=3 * 365)
        filing_due = start + timedelta(days=30)
        filed = filing_due - timedelta(days=6) if i != 4 else None
        db.execute(
            """INSERT INTO committee_members
               (id, society_id, user_id, designation, portfolio, selection_mode,
                election_or_cooption_ref, term_start_date, term_end_date,
                statutory_form_type, filing_due_date, filed_with_registrar_on,
                is_active, public_bio, public_contact_email, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                sid(f"committee-{key}"),
                SOCIETY_ID,
                user_id,
                designation,
                portfolio,
                mode,
                ref,
                iso(start),
                iso(end),
                "FORM_XVII" if mode != "NOMINATED_COOPTED" else "FORM_XVII_A",
                iso(filing_due),
                iso(filed) if filed else None,
                1,
                f"{portfolio} portfolio holder. Focused on transparent, "
                f"rule-bound execution of the approved annual plan.",
                f"{designation.lower().replace('_', '.')}@greenwoodrwa.in",
                now,
            ),
        )

    # -- 5. Civic initiatives (resolution-linked) --------------------------
    initiatives = [
        ("STP Plant Automation Upgrade", "Utilities",
         "Automation of the sewage treatment plant with remote level sensors "
         "and a SCADA dashboard to eliminate manual overflow checks.",
         "GB-RES-2025-31", "IN_PROGRESS", 72,
         "Level sensors installed on both sumps; SCADA commissioning pending vendor visit."),
        ("Lift Modernisation -- Tower B", "Vertical Transport",
         "Complete retrofit of both Tower B lifts with new VFD drives, "
         "auto-door sensors and emergency communication panels.",
         "GB-RES-2025-28", "APPROVED", 30,
         "Tender opened; two bids received, technical evaluation in progress."),
        ("Rainwater Harvesting -- Phase II", "Sustainability",
         "Six recharge pits across the north lawn and borewell recharging "
         "to reduce tanker dependency during the monsoon season.",
         "GB-RES-2024-47", "COMPLETED", 100,
         "All six pits commissioned and verified by the executing agency."),
        ("Visitor Management Rollout", "Security",
         "Gate-level QR based visitor passes with OTP-free resident approval "
         "and a maintainable digital register at both gates.",
         "GB-RES-2025-19", "IN_PROGRESS", 55,
         "Pilot live at Gate 1 for 42 flats; Gate 2 rollout next quarter."),
        ("Solar Rooftop -- Common Areas", "Sustainability",
         "Grid-tied 45 kWp rooftop array over the clubhouse to offset common "
         "area lighting and pump loads.",
         "GB-RES-2025-36", "PROPOSED", 10,
         "Awaiting DISCOM net-metering approval before tendering."),
        ("Playground Resurfacing & Shade Net", "Amenities",
         "Resurface the children's play area with EPDM flooring and install "
         "shade structures over the seating benches.",
         "GB-RES-2025-41", "APPROVED", 45,
         "EPDM samples shortlisted; shade net structural drawings under review."),
    ]
    for i, (title, category, summary, res, status, pct, notes) in enumerate(initiatives):
        db.execute(
            """INSERT INTO committee_initiatives
               (id, society_id, title, category, summary, resolution_reference,
                status, completion_pct, milestone_notes, lead_committee_member_id,
                is_public, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                sid(f"initiative-{i}"),
                SOCIETY_ID,
                title,
                category,
                summary,
                res,
                status,
                pct,
                notes,
                sid(f"committee-{committee[i % len(committee)][0]}"),
                1,
                now,
                now,
            ),
        )

    # -- 6. Announcements --------------------------------------------------
    notices = [
        ("water-supply-interruption-tower-b",
         "Water Supply Interruption -- Tower B, 14 Nov 06:00-10:00",
         "## Notice\n\nWater supply to **Tower B** will remain suspended on "
         "*14 November, 06:00 to 10:00* while the STP automation vendor "
         "recommissiones the overhead tank inlet valve.\n\n"
         "Please store sufficient water the previous night. Tanker standby "
         "will be available at the clubhouse gate.\n\n"
         "Issued under the authority of the General Body resolution "
         "*GB-RES-2025-31*.",
         "SHUTDOWN", 1, 1),
        ("agm-notice-fy-2025-26",
         "Notice of Annual General Meeting -- FY 2025-26",
         "## Notice of AGM\n\nNotice is hereby given that the Annual General "
         "Meeting of the Association will be held on **Sunday, 21 December, "
         "10:00 AM** at the A-Block Club House.\n\n"
         "### Agenda\n"
         "1. Confirmation of the minutes of the preceding AGM\n"
         "2. Annual report of the Governing Body\n"
         "3. Approval of the annual budget\n"
         "4. Appointment of the auditor for the ensuing year\n"
         "5. Any other matter with the permission of the Chair\n\n"
         "Members may inspect the Register of Members and the Minutes Book "
         "on working days after reasonable notice (Sec. 19, Sec. 20(3)).",
         "AGM_NOTICE", 1, 0),
        ("diwali-celebration-2026",
         "Diwali Celebration & Lighting Competition -- 4 November",
         "## Community Event\n\nThe Cultural Committee invites all residents "
         "to the annual Diwali celebration at the central lawn on "
         "*4 November, 18:00 onwards*.\n\n"
         "- Best decorated balcony competition (register at the clubhouse)\n"
         "- Community lamp lighting at 19:00\n"
         "- Prizes for the top three balconies\n\n"
         "Volunteers for the event may contact the Cultural portfolio holder.",
         "EVENT", 0, 0),
        ("parking-sticker-renewal",
         "Annual Vehicle Sticker Renewal -- Due 30 November",
         "## Circular\n\nAll residents are requested to renew their vehicle "
         "parking stickers for the coming year before *30 November*.\n\n"
         "Carry: vehicle RC copy, flat number, and the existing sticker. "
         "The desk operates 10:00-16:00 on weekdays.\n\n"
         "Vehicles without a valid sticker will not be permitted inside the "
         "gates after the cut-off date.",
         "GENERAL", 0, 0),
        ("standpipe-maintenance",
         "Quarterly Standpipe & Hydrant Inspection Completed",
         "## Notice\n\nThe quarterly fire safety inspection of standpipes and "
         "hydrants across both towers has been completed. Three nozzle "
         "couplings in Tower A have been replaced.\n\n"
         "No action is required from residents.",
         "GENERAL", 0, 0),
    ]
    for slug, title, body, priority, pinned, is_public in notices:
        db.execute(
            """INSERT INTO announcements
               (id, society_id, slug, title, body_markdown, priority,
                is_public, is_pinned, published_by, published_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                sid(f"notice-{slug}"),
                SOCIETY_ID,
                slug,
                title,
                body,
                priority,
                is_public,
                pinned,
                sid("user-secretary"),
                now,
            ),
        )

    # -- 7. Documents & versioned MoM (Sec. 37) ---------------------------
    docs = [
        ("MOM_GB_2025_12", "Minutes -- General Body Meeting, 12 October 2025",
         "2025-10-12", 41, 60, 1, 1, "2025-11-09", "PUBLIC"),
        ("MOM_GBM_2025_09", "Minutes -- Governing Body Meeting, 21 September 2025",
         "2025-09-21", 6, 6, 1, 1, "2025-10-12", "MEMBERS_ONLY"),
        ("MOM_GB_2025_07", "Minutes -- General Body Meeting, 03 August 2025",
         "2025-08-03", 38, 60, 1, 1, "2025-09-21", "PUBLIC"),
        ("BYE_LAWS", "Registered Bye-Laws of the Association",
         None, None, None, 1, 1, None, "PUBLIC"),
        ("CIRCULAR_STP", "STP Automation -- Vendor Comparative Statement",
         None, None, None, 0, 0, None, "COMMITTEE_ONLY"),
    ]
    for i, (cat, title, mdate, qp, qr, ch, sec, conf, vis) in enumerate(docs):
        doc_id = sid(f"doc-{i}")
        db.execute(
            """INSERT INTO documents
               (id, society_id, doc_category, title, meeting_date, quorum_present,
                quorum_required, chairman_signed, secretary_signed,
                confirmed_in_next_meeting_date, current_version_num, visibility,
                search_text, created_by, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                doc_id,
                SOCIETY_ID,
                cat,
                title,
                mdate,
                qp,
                qr,
                ch,
                sec,
                conf,
                2 if i == 1 else 1,
                vis,
                title,
                sid("user-secretary"),
                now,
            ),
        )
        versions = 2 if i == 1 else 1
        for v in range(1, versions + 1):
            db.execute(
                """INSERT INTO document_versions
                   (id, document_id, version_number, storage_path, mime_type,
                    file_size_bytes, sha256_checksum, change_summary,
                    approval_status, uploaded_by, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sid(f"docver-{i}-{v}"),
                    doc_id,
                    v,
                    f"uploads/{cat.lower()}_v{v}.pdf",
                    "application/pdf",
                    420_000 + i * 17_000,
                    uuid.uuid5(NS, f"checksum-{i}-{v}").hex * 2,
                    "Initial archival upload." if v == 1 else
                    "Corrected attendee list and quorum count; re-signed.",
                    "SUPERSEDED" if v < versions else "APPROVED",
                    sid("user-secretary"),
                    now,
                ),
            )

    # -- 8. Helpdesk tickets ---------------------------------------------
    categories = [
        ("Plumbing & Water", "LOW", "RESOLVED"),
        ("Electrical", "MEDIUM", "IN_PROGRESS"),
        ("Lift & Vertical Transport", "HIGH", "ACKNOWLEDGED"),
        ("Housekeeping", "LOW", "RESOLVED"),
        ("Security & Gate", "MEDIUM", "OPEN"),
        ("Plumbing & Water", "HIGH", "OPEN"),
        ("Common Area", "MEDIUM", "AWAITING_CONFIRMATION"),
        ("Electrical", "LOW", "RESOLVED"),
        ("Plumbing & Water", "MEDIUM", "OPEN"),
        ("Landscaping", "LOW", "REOPENED"),
    ]
    subjects = [
        "Low water pressure on the 4th floor of Tower A",
        "Corridor light flickering near flat 203",
        "Lift 2 in Tower B stopping short of the landing",
        "Housekeeping missed the north staircase yesterday",
        "Gate intercom not connecting to the security cabin",
        "Water seepage in the basement near the electrical room",
        "Clubhouse projector needed for the AGM",
        "Street lamp out at the visitors' parking bay",
        "Kitchen drain choking in flat 304",
        "Sapling damaged at the east boundary wall",
    ]
    for i, ((cat, prio, stat), subj) in enumerate(zip(categories, subjects)):
        created = TODAY - timedelta(days=i * 3 + 1)
        resolved = created + timedelta(days=2) if stat == "RESOLVED" else None
        db.execute(
            """INSERT INTO tickets
               (id, society_id, ticket_number, unit_id, raised_by, assigned_to,
                category, location_scope, subject, description, status, priority,
                work_log, created_at, resolved_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                sid(f"ticket-{i}"),
                SOCIETY_ID,
                401 + i,
                unit_ids[16 + i] if 16 + i < len(unit_ids) else None,
                sid(f"user-resident-{i % 36}"),
                sid("user-clerk"),
                cat,
                "COMMON_AREA" if i % 2 else "UNIT",
                subj,
                f"{subj}. Reported by the resident and logged at the front desk. "
                f"Category: {cat}.",
                stat,
                prio,
                db.to_json([
                    {"at": iso(created), "by": "Resident", "note": "Ticket raised."},
                    {"at": iso(created + timedelta(days=1)), "by": "Desk",
                     "note": "Acknowledged and assigned."},
                ]),
                iso(created) + "T09:15:00+00:00",
                iso(resolved) + "T14:30:00+00:00" if resolved else None,
            ),
        )

    # -- 9. Infrastructure graph edges (spec 6.2) -------------------------
    infra_nodes = [
        ("Overhead Tank A", "Tank"), ("Overhead Tank B", "Tank"),
        ("Main Sump", "Sump"), ("Riser A1", "Riser"), ("Riser A2", "Riser"),
        ("Riser B1", "Riser"), ("Electrical Feeder B", "Feeder"),
        ("Lift 1", "Lift"), ("Lift 2", "Lift"),
    ]
    for i, (label, ntype) in enumerate(infra_nodes):
        db.execute(
            """INSERT INTO graph_edges
               (id, society_id, graph_domain, source_type, source_id, edge_label,
                target_type, target_id, metadata, valid_from)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                sid(f"infra-node-{i}"),
                SOCIETY_ID,
                "INFRASTRUCTURE",
                "Asset",
                sid(f"asset-{i}"),
                "NODE",
                ntype,
                sid(f"asset-{i}"),
                db.to_json({"label": label}),
                now,
            ),
        )
    # Riser A1 supplies flats A-101..A-801 (the LCA clustering demo target)
    riser_edges = [
        ("Riser A1", "SUPPLIES", unit_ids[0]), ("Riser A1", "SUPPLIES", unit_ids[4]),
        ("Riser A1", "SUPPLIES", unit_ids[8]), ("Riser A1", "SUPPLIES", unit_ids[12]),
        ("Overhead Tank A", "SUPPLIES", "Riser A1"),
        ("Main Sump", "SUPPLIES", "Overhead Tank A"),
        ("Main Sump", "SUPPLIES", "Overhead Tank B"),
        ("Electrical Feeder B", "SERVES", "Lift 2"),
    ]
    for i, (src, label, tgt) in enumerate(riser_edges):
        db.execute(
            """INSERT INTO graph_edges
               (id, society_id, graph_domain, source_type, source_id, edge_label,
                target_type, target_id, metadata, valid_from)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                sid(f"infra-edge-{i}"),
                SOCIETY_ID,
                "INFRASTRUCTURE",
                "Asset",
                src,
                label,
                "Unit" if tgt.startswith("unit") or len(tgt) == 36 and tgt in unit_ids else "Asset",
                tgt if len(tgt) == 36 else sid(f"asset-name-{tgt}"),
                db.to_json({}),
                now,
            ),
        )

    # -- 10. Workflow DAG edges (spec 6.3) --------------------------------
    wf = [
        ("DATA_OPERATOR", "ENTERS", "SOCIETY_ADMIN"),
        ("SOCIETY_ADMIN", "REVIEWS", "SOCIETY_ADMIN"),
        ("SOCIETY_ADMIN", "SIGNS_OFF", "REGISTRAR_FILING"),
        ("SOCIETY_ADMIN", "ENDORSES_RULE23", "EXPORT"),
    ]
    for i, (src, label, tgt) in enumerate(wf):
        db.execute(
            """INSERT INTO graph_edges
               (id, society_id, graph_domain, source_type, source_id, edge_label,
                target_type, target_id, metadata, valid_from)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                sid(f"wf-edge-{i}"),
                SOCIETY_ID,
                "WORKFLOW_DAG",
                "Role",
                src,
                label,
                "Role" if tgt.isupper() and "_" in tgt and tgt != "REGISTRAR_FILING" else "Stage",
                tgt,
                db.to_json({}),
                now,
            ),
        )

    # -- 11. Audit trail ---------------------------------------------------
    db.execute(
        """INSERT INTO audit_logs
           (society_id, actor_id, action, rule_ref, entity_type, entity_id,
            diff_payload, ip_address, created_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            SOCIETY_ID,
            sid("user-superadmin"),
            "SEED_DATABASE",
            "HRRS_ACT_2012_SEC_10_2 | RULE_6_IDENTITY",
            "society",
            SOCIETY_ID,
            db.to_json({"note": "Initial demonstration dataset created."}),
            "127.0.0.1",
            now,
        ),
    )

    count = db.scalar("SELECT COUNT(*) FROM units", default=0)
    members = db.scalar("SELECT COUNT(*) FROM users WHERE role = 'MEMBER'", default=0)
    print("Seed complete.")
    print(f"  Units: {count}")
    print(f"  Members: {members}")
    print(f"  Committee: {db.scalar('SELECT COUNT(*) FROM committee_members')}")
    print(f"  Tickets: {db.scalar('SELECT COUNT(*) FROM tickets')}")
    print()
    print("Demo logins (password for all: %s)" % PASSWORD)
    print("  Super Admin   admin@greenwoodrwa.in")
    print("  Society Admin president@greenwoodrwa.in")
    print("  Data Operator clerk@greenwoodrwa.in")
    print("  Member        resident-0@greenwoodrwa.in")


if __name__ == "__main__":
    build()
