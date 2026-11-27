-- ============================================================================
-- RWA Governance Portal -- SQLite schema
-- Translation of the PostgreSQL blueprint in SRS v2.0.0 section 8.2.
-- Type mapping: UUID->TEXT, TIMESTAMPTZ->TEXT(ISO-8601 UTC), JSONB->TEXT,
--               BIGSERIAL->INTEGER PK AUTOINCREMENT, tsvector->TEXT.
-- Every rule_ref tag points at the Haryana Registration and Regulation of
-- Societies Act, 2012 / Rules, 2012.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- 1. Societies (Sec. 10(2) & Rule 6/9 Identity)
CREATE TABLE IF NOT EXISTS societies (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    registration_number     TEXT NOT NULL UNIQUE,
    registered_office_address TEXT NOT NULL,
    contact_email           TEXT,
    contact_phone           TEXT,
    active_member_count     INTEGER NOT NULL DEFAULT 0,
    -- collegium_mode_active: active_member_count > 300 (Sec. 30 & Rule 18)
    config                  TEXT NOT NULL DEFAULT '{}',
    created_at              TEXT NOT NULL
);

-- 2. Residential Units / Flats
CREATE TABLE IF NOT EXISTS units (
    id               TEXT PRIMARY KEY,
    society_id       TEXT NOT NULL REFERENCES societies(id) ON DELETE CASCADE,
    block_tower      TEXT NOT NULL,
    unit_number      TEXT NOT NULL,
    canonical_code   TEXT NOT NULL,           -- e.g. 'BLK-A-0402'
    unit_type        TEXT NOT NULL DEFAULT 'APARTMENT',
    occupancy_status TEXT NOT NULL DEFAULT 'VACANT'
                     CHECK (occupancy_status IN ('OWNER_OCCUPIED','TENANT_OCCUPIED','VACANT')),
    parking_slot     TEXT,
    UNIQUE (society_id, canonical_code)
);

-- 3. Users & Statutory Member Register (Sec. 15-18, Form-X/XI/XII)
CREATE TABLE IF NOT EXISTS users (
    id                      TEXT PRIMARY KEY,
    society_id              TEXT REFERENCES societies(id) ON DELETE CASCADE,
    unit_id                 TEXT REFERENCES units(id) ON DELETE SET NULL,
    member_serial_no        TEXT,             -- Form-XII & Form-XI serial
    full_name               TEXT NOT NULL,
    father_or_spouse_name   TEXT,             -- Rule 11(1) Form-X
    date_of_birth           TEXT,             -- must be >= 21 yrs at admission (Sec. 16(i))
    occupation              TEXT,
    permanent_address       TEXT,
    residential_address     TEXT,
    id_proof_path           TEXT,             -- Sec. 21(5) identity/address proof
    mobile_number           TEXT NOT NULL,
    email                   TEXT NOT NULL,
    role                    TEXT NOT NULL DEFAULT 'MEMBER'
                            CHECK (role IN ('SUPER_ADMIN','SOCIETY_ADMIN','DATA_OPERATOR','MEMBER')),
    membership_category     TEXT
                            CHECK (membership_category IN ('FOUNDER','LIFE','ORDINARY','ASSOCIATE','TENURE','HONORARY','NONE')),
    fee_instrument_ref      TEXT,             -- Rule 11(1) non-cash bank instrument only
    sec16_declarations      TEXT,             -- Sec. 16(iv) three attestations
    admission_date          TEXT,
    register_entry_due_date TEXT,             -- admission_date + 15 days (Sec. 18(1))
    cessation_date          TEXT,
    cessation_reason        TEXT,             -- Sec. 21
    password_hash           TEXT,             -- NULL until account is claimed
    account_status          TEXT NOT NULL DEFAULT 'PENDING'
                            CHECK (account_status IN ('PENDING','ACTIVE','SUSPENDED','CEASED')),
    theme_preference        TEXT NOT NULL DEFAULT 'retro-paper',
    is_public_contact_optin INTEGER NOT NULL DEFAULT 0, -- 4.1 privacy guardrail
    created_at              TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_society_mobile
    ON users(society_id, mobile_number);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_society_email
    ON users(society_id, email);

-- 4. Governing Body & Committee Roster (Sec. 34, Form-XVII series)
CREATE TABLE IF NOT EXISTS committee_members (
    id                    TEXT PRIMARY KEY,
    society_id            TEXT NOT NULL REFERENCES societies(id) ON DELETE CASCADE,
    user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    designation           TEXT NOT NULL
                          CHECK (designation IN ('PRESIDENT','VICE_PRESIDENT','GENERAL_SECRETARY',
                                                 'JOINT_SECRETARY','TREASURER','EXECUTIVE_MEMBER')),
    portfolio             TEXT,
    selection_mode        TEXT NOT NULL
                          CHECK (selection_mode IN ('ELECTED_GBM','ELECTED_COLLEGIUM','NOMINATED_COOPTED')),
    election_or_cooption_ref TEXT,            -- GB-RES-2026-04 style reference
    term_start_date       TEXT NOT NULL,
    term_end_date         TEXT NOT NULL,      -- max 3 years (Sec. 34(3))
    statutory_form_type   TEXT NOT NULL DEFAULT 'FORM_XVII',
    filing_due_date       TEXT NOT NULL,      -- term_start + 30 days (Sec. 34(2), Rule 19)
    filed_with_registrar_on TEXT,
    is_active             INTEGER NOT NULL DEFAULT 1,
    public_bio            TEXT,
    public_contact_email  TEXT,
    created_at            TEXT NOT NULL
);

-- 5. Public Committee Civic Initiatives & Manifesto Progress Ledger
CREATE TABLE IF NOT EXISTS committee_initiatives (
    id                        TEXT PRIMARY KEY,
    society_id                TEXT NOT NULL REFERENCES societies(id) ON DELETE CASCADE,
    title                     TEXT NOT NULL,
    category                  TEXT NOT NULL,
    summary                   TEXT NOT NULL,
    resolution_reference      TEXT,           -- e.g. 'GB-RES-2026-04' (Sec. 37)
    authorizing_document_id   TEXT,
    status                    TEXT NOT NULL DEFAULT 'PROPOSED'
                              CHECK (status IN ('PROPOSED','APPROVED','IN_PROGRESS','COMPLETED')),
    completion_pct            INTEGER NOT NULL DEFAULT 0
                              CHECK (completion_pct BETWEEN 0 AND 100),
    milestone_notes           TEXT,
    lead_committee_member_id  TEXT REFERENCES committee_members(id),
    is_public                 INTEGER NOT NULL DEFAULT 1,
    created_at                TEXT NOT NULL,
    updated_at                TEXT NOT NULL
);

-- 6. Graph Edges (Society Entity, Infrastructure Dependency & Workflow DAG)
CREATE TABLE IF NOT EXISTS graph_edges (
    id           TEXT PRIMARY KEY,
    society_id   TEXT NOT NULL REFERENCES societies(id) ON DELETE CASCADE,
    graph_domain TEXT NOT NULL
                 CHECK (graph_domain IN ('SOCIETY_ENTITY','INFRASTRUCTURE','WORKFLOW_DAG')),
    source_type  TEXT NOT NULL,
    source_id    TEXT NOT NULL,
    edge_label   TEXT NOT NULL,
    target_type  TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    metadata     TEXT NOT NULL DEFAULT '{}',
    valid_from   TEXT NOT NULL,
    valid_to     TEXT
);
CREATE INDEX IF NOT EXISTS idx_graph_edges_src ON graph_edges(society_id, graph_domain, source_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_tgt ON graph_edges(society_id, graph_domain, target_id);

-- 7. Versioned Documents & Handwritten MoM (Sec. 37)
CREATE TABLE IF NOT EXISTS documents (
    id                       TEXT PRIMARY KEY,
    society_id               TEXT NOT NULL REFERENCES societies(id) ON DELETE CASCADE,
    doc_category             TEXT NOT NULL,   -- MOM_GB, MOM_GBM, MOM_COLLEGIUM, BYE_LAW, CIRCULAR...
    title                    TEXT NOT NULL,
    meeting_date             TEXT,
    quorum_present           INTEGER,         -- Rule 16: >= 40% check
    quorum_required          INTEGER,
    chairman_signed          INTEGER NOT NULL DEFAULT 0,  -- Sec. 37(2)
    secretary_signed         INTEGER NOT NULL DEFAULT 0,  -- Sec. 37(2)
    confirmed_in_next_meeting_date TEXT,                 -- Sec. 37(3)
    current_version_num      INTEGER NOT NULL DEFAULT 1,
    visibility               TEXT NOT NULL DEFAULT 'MEMBERS_ONLY'
                             CHECK (visibility IN ('PUBLIC','MEMBERS_ONLY','COMMITTEE_ONLY')),
    search_text              TEXT,
    created_by               TEXT NOT NULL REFERENCES users(id),
    created_at               TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS document_versions (
    id               TEXT PRIMARY KEY,
    document_id      TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    version_number   INTEGER NOT NULL,
    storage_path     TEXT NOT NULL,
    raw_source_path  TEXT,                    -- raw mobile camera scans retained
    mime_type        TEXT NOT NULL,
    file_size_bytes  INTEGER NOT NULL,
    sha256_checksum  TEXT NOT NULL,
    change_summary   TEXT NOT NULL,
    typed_transcript TEXT,
    approval_status  TEXT NOT NULL DEFAULT 'DRAFT'
                     CHECK (approval_status IN ('DRAFT','APPROVED','SUPERSEDED')),
    uploaded_by      TEXT NOT NULL REFERENCES users(id),
    approved_by      TEXT REFERENCES users(id),
    created_at       TEXT NOT NULL,
    UNIQUE (document_id, version_number)
);

-- 8. Announcements
CREATE TABLE IF NOT EXISTS announcements (
    id                 TEXT PRIMARY KEY,
    society_id         TEXT NOT NULL REFERENCES societies(id) ON DELETE CASCADE,
    slug               TEXT NOT NULL,
    title              TEXT NOT NULL,
    body_markdown      TEXT NOT NULL,
    priority           TEXT NOT NULL DEFAULT 'GENERAL'
                       CHECK (priority IN ('URGENT','SHUTDOWN','AGM_NOTICE','GENERAL','EVENT')),
    is_public          INTEGER NOT NULL DEFAULT 0,
    is_pinned          INTEGER NOT NULL DEFAULT 0,
    attachment_doc_id  TEXT REFERENCES documents(id),
    published_by       TEXT NOT NULL REFERENCES users(id),
    published_at       TEXT NOT NULL,
    UNIQUE (society_id, slug)
);

-- 9. Helpdesk / Complaint Tickets (zero billing)
CREATE TABLE IF NOT EXISTS tickets (
    id                     TEXT PRIMARY KEY,
    society_id             TEXT NOT NULL REFERENCES societies(id) ON DELETE CASCADE,
    ticket_number          INTEGER NOT NULL,
    unit_id                TEXT REFERENCES units(id),
    infra_node_id          TEXT,              -- Graph Model B anchor
    raised_by              TEXT NOT NULL REFERENCES users(id),
    assigned_to            TEXT REFERENCES users(id),
    category               TEXT NOT NULL,
    location_scope         TEXT NOT NULL DEFAULT 'COMMON_AREA'
                           CHECK (location_scope IN ('UNIT','COMMON_AREA')),
    subject                TEXT NOT NULL,
    description            TEXT NOT NULL,
    status                 TEXT NOT NULL DEFAULT 'OPEN'
                           CHECK (status IN ('OPEN','ACKNOWLEDGED','IN_PROGRESS',
                                             'AWAITING_CONFIRMATION','RESOLVED','REOPENED')),
    priority               TEXT NOT NULL DEFAULT 'MEDIUM'
                           CHECK (priority IN ('LOW','MEDIUM','HIGH','URGENT')),
    cluster_root_ticket_id TEXT REFERENCES tickets(id),
    work_log               TEXT NOT NULL DEFAULT '[]',
    feedback_rating        INTEGER,
    created_at             TEXT NOT NULL,
    resolved_at            TEXT,
    UNIQUE (society_id, ticket_number)
);

-- 10. Immutable statutory & operational audit log
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    society_id  TEXT,
    actor_id    TEXT,
    action      TEXT NOT NULL,
    rule_ref    TEXT NOT NULL,                -- e.g. 'HRRS_ACT_2012_SEC_18_1 | RULE_12_FORM_XII'
    entity_type TEXT NOT NULL,
    entity_id   TEXT,
    diff_payload TEXT NOT NULL DEFAULT '{}',
    ip_address  TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_logs(entity_type, entity_id);

-- 11. Server-side sessions (spec 9.1: HttpOnly, SameSite=Lax signed cookies;
--     the raw token never touches the database, only its SHA-256 hash).
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL UNIQUE,
    csrf_token    TEXT NOT NULL,
    ip_address    TEXT,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- 12. Password reset tokens (no SMS OTP -- email magic token or in-person code)
CREATE TABLE IF NOT EXISTS reset_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reset_tokens_user ON reset_tokens(user_id);

-- 13. Self-service Form-X admission queue (spec 2.2 onboarding workflow 2)
CREATE TABLE IF NOT EXISTS form_x_applications (
    id                    TEXT PRIMARY KEY,
    society_id            TEXT NOT NULL REFERENCES societies(id) ON DELETE CASCADE,
    applicant_name        TEXT NOT NULL,
    father_or_spouse_name TEXT NOT NULL,
    date_of_birth         TEXT NOT NULL,
    membership_category   TEXT NOT NULL,
    flat_id               TEXT NOT NULL,
    mobile_number         TEXT NOT NULL,
    email                 TEXT NOT NULL,
    permanent_address     TEXT NOT NULL,
    residential_address   TEXT NOT NULL,
    fee_instrument_ref    TEXT NOT NULL,      -- Rule 11(1): cash strictly disabled
    sec16_declarations    TEXT NOT NULL,      -- Sec. 16(iv): three attestations
    aims_subscribed       INTEGER NOT NULL DEFAULT 0, -- Sec. 16(ii)/20(1)
    proof_filename        TEXT,
    status                TEXT NOT NULL DEFAULT 'PENDING_VERIFICATION'
                          CHECK (status IN ('PENDING_VERIFICATION','APPROVED','REJECTED')),
    reviewed_by           TEXT REFERENCES users(id),
    reviewed_at           TEXT,
    rejection_reason      TEXT,
    created_at            TEXT NOT NULL
);

-- Statutory filing / SLA countdown helper view (Sec. 18(1), Sec. 34(2), Rule 19)
CREATE VIEW IF NOT EXISTS v_statutory_countdowns AS
SELECT 'FORM_XII' AS form_ref,
       id AS entity_id,
       full_name AS label,
       register_entry_due_date AS due_date,
       CASE WHEN register_entry_due_date IS NULL THEN 'NOT_APPLICABLE'
            WHEN date(register_entry_due_date) < date('now') THEN 'OVERDUE'
            WHEN julianday(register_entry_due_date) - julianday('now') <= 3 THEN 'CRITICAL'
            ELSE 'ON_TRACK' END AS health,
       'HRRS_ACT_2012_SEC_18_1 | RULE_12_FORM_XII' AS rule_ref
FROM users
WHERE register_entry_due_date IS NOT NULL AND account_status = 'ACTIVE'
UNION ALL
SELECT 'FORM_XVII', id, designation || ' - ' || IFNULL(portfolio,''),
       filing_due_date,
       CASE WHEN filed_with_registrar_on IS NOT NULL THEN 'FILED'
            WHEN date(filing_due_date) < date('now') THEN 'OVERDUE'
            WHEN julianday(filing_due_date) - julianday('now') <= 3 THEN 'CRITICAL'
            ELSE 'DUE_SOON' END,
       'HRRS_ACT_2012_SEC_34_2 | RULE_19_FORM_XVII'
FROM committee_members
WHERE is_active = 1 AND filed_with_registrar_on IS NULL;
