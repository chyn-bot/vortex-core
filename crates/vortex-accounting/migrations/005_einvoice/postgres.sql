-- Migration 005: LHDN MyInvois e-invoicing
--
-- Satellite tables only — acc_move's guard triggers are untouched
-- because e-invoice state lives beside the move, never on it.
--
--   - acc_einvoice: one row per e-invoiceable document (status
--     lifecycle, LHDN identifiers, evidence pointers)
--   - acc_einvoice_settings: per-company API credentials (secret
--     AES-GCM encrypted via VORTEX_SECRET_KEY) + mode/environment
--   - acc_lhdn_code: LHDN SDK code tables (doc types, state codes,
--     classification, MSIC, UOM, countries) — critical small sets
--     seeded here, large sets synced from sdk.myinvois.hasil.gov.my
--     by the accounting.lhdn.sync_codes job
--   - acc_invoice_line gains classification_code + uom_code

CREATE TABLE IF NOT EXISTS acc_einvoice (
    id               UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    move_id          UUID         NOT NULL REFERENCES acc_move(id),
    direction        VARCHAR(24)  NOT NULL DEFAULT 'outbound',
    -- LHDN document type: 01 invoice, 02 credit note, 03 debit note,
    -- 04 refund note, 11-14 self-billed variants
    doc_type_code    VARCHAR(4)   NOT NULL DEFAULT '01',
    -- Monthly consolidated B2C document?
    consolidated     BOOLEAN      NOT NULL DEFAULT FALSE,
    status           VARCHAR(12)  NOT NULL DEFAULT 'ready',
    -- LHDN identifiers (populated as the flow progresses)
    submission_uid   VARCHAR(64),
    lhdn_uuid        VARCHAR(64),
    long_id          VARCHAR(128),
    validation_link  VARCHAR(300),
    -- Evidence: SHA-256 of the exact submitted payload + FileStore key
    payload_sha256   VARCHAR(64),
    payload_file_key VARCHAR(512),
    response_file_key VARCHAR(512),
    error_json       JSONB,
    submitted_at     TIMESTAMPTZ,
    validated_at     TIMESTAMPTZ,
    cancelled_at     TIMESTAMPTZ,
    company_id       UUID         REFERENCES companies(id),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_acc_einv_status CHECK (status IN
        ('ready', 'exported', 'submitted', 'valid', 'invalid', 'cancelled')),
    CONSTRAINT chk_acc_einv_direction CHECK (direction IN
        ('outbound', 'inbound_self_billed')),
    CONSTRAINT uq_acc_einv_move UNIQUE (move_id)
);

CREATE INDEX IF NOT EXISTS idx_acc_einv_status ON acc_einvoice (status);
CREATE INDEX IF NOT EXISTS idx_acc_einv_uuid ON acc_einvoice (lhdn_uuid)
    WHERE lhdn_uuid IS NOT NULL;

DROP TRIGGER IF EXISTS trg_acc_einv_updated_at ON acc_einvoice;
CREATE TRIGGER trg_acc_einv_updated_at
    BEFORE UPDATE ON acc_einvoice
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS acc_einvoice_settings (
    id                     UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id             UUID        REFERENCES companies(id),
    -- 'portal' = generate + manual upload; 'api' = direct submission
    mode                   VARCHAR(8)  NOT NULL DEFAULT 'portal',
    environment            VARCHAR(12) NOT NULL DEFAULT 'sandbox',
    client_id              VARCHAR(120),
    client_secret_enc      BYTEA,
    -- Submit automatically when a document posts
    auto_submit            BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Consolidated B2C: partner representing "General Public"
    consolidated_partner_id UUID       REFERENCES contacts(id),
    -- e-invoice version: 1.0 (unsigned) is the supported path today
    doc_version            VARCHAR(4)  NOT NULL DEFAULT '1.0',
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_acc_einvs_mode CHECK (mode IN ('portal', 'api')),
    CONSTRAINT chk_acc_einvs_env CHECK (environment IN ('sandbox', 'production')),
    CONSTRAINT uq_acc_einvs_company UNIQUE (company_id)
);

DROP TRIGGER IF EXISTS trg_acc_einvs_updated_at ON acc_einvoice_settings;
CREATE TRIGGER trg_acc_einvs_updated_at
    BEFORE UPDATE ON acc_einvoice_settings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

INSERT INTO acc_einvoice_settings (id, company_id) VALUES
    ('acc00000-0000-4000-8000-e00000000001', NULL)
ON CONFLICT (id) DO NOTHING;

-- LHDN code registry. code_type ∈ doc_type | id_type | state | country |
-- classification | msic | uom | tax_type | payment_mode
CREATE TABLE IF NOT EXISTS acc_lhdn_code (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    code_type   VARCHAR(24)  NOT NULL,
    code        VARCHAR(24)  NOT NULL,
    description VARCHAR(300) NOT NULL,
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_acc_lhdn_code UNIQUE (code_type, code)
);

DROP TRIGGER IF EXISTS trg_acc_lhdn_code_updated_at ON acc_lhdn_code;
CREATE TRIGGER trg_acc_lhdn_code_updated_at
    BEFORE UPDATE ON acc_lhdn_code
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Critical small sets seeded statically (air-gap friendly); the
-- classification/MSIC/UOM/country catalogues sync via the
-- accounting.lhdn.sync_codes job from sdk.myinvois.hasil.gov.my.
INSERT INTO acc_lhdn_code (code_type, code, description) VALUES
    ('doc_type', '01', 'Invoice'),
    ('doc_type', '02', 'Credit Note'),
    ('doc_type', '03', 'Debit Note'),
    ('doc_type', '04', 'Refund Note'),
    ('doc_type', '11', 'Self-billed Invoice'),
    ('doc_type', '12', 'Self-billed Credit Note'),
    ('doc_type', '13', 'Self-billed Debit Note'),
    ('doc_type', '14', 'Self-billed Refund Note'),
    ('id_type', 'BRN', 'Business Registration Number'),
    ('id_type', 'NRIC', 'National Registration Identity Card'),
    ('id_type', 'PASSPORT', 'Passport Number'),
    ('id_type', 'ARMY', 'Army Number'),
    ('state', '01', 'Johor'), ('state', '02', 'Kedah'),
    ('state', '03', 'Kelantan'), ('state', '04', 'Melaka'),
    ('state', '05', 'Negeri Sembilan'), ('state', '06', 'Pahang'),
    ('state', '07', 'Pulau Pinang'), ('state', '08', 'Perak'),
    ('state', '09', 'Perlis'), ('state', '10', 'Selangor'),
    ('state', '11', 'Terengganu'), ('state', '12', 'Sabah'),
    ('state', '13', 'Sarawak'), ('state', '14', 'Wilayah Persekutuan Kuala Lumpur'),
    ('state', '15', 'Wilayah Persekutuan Labuan'), ('state', '16', 'Wilayah Persekutuan Putrajaya'),
    ('state', '17', 'Not Applicable / Others'),
    ('country', 'MYS', 'Malaysia'), ('country', 'SGP', 'Singapore'),
    ('country', 'IDN', 'Indonesia'), ('country', 'THA', 'Thailand'),
    ('country', 'CHN', 'China'), ('country', 'USA', 'United States'),
    ('classification', '022', 'Others'),
    ('uom', 'C62', 'Unit / piece')
ON CONFLICT (code_type, code) DO NOTHING;

-- Commercial-line e-invoice attributes (draft-time data; the existing
-- acc_invoice_line_guard blanket rule already covers posted docs)
ALTER TABLE acc_invoice_line ADD COLUMN IF NOT EXISTS classification_code VARCHAR(8);
ALTER TABLE acc_invoice_line ADD COLUMN IF NOT EXISTS uom_code VARCHAR(8);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            acc_einvoice, acc_einvoice_settings, acc_lhdn_code
            TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE acc_einvoice IS
    'LHDN MyInvois lifecycle per document: ready → exported (portal) or submitted → valid/invalid; cancelled within the 72h window. Satellite of acc_move — the move itself never changes after posting.';
COMMENT ON COLUMN acc_einvoice.payload_sha256 IS
    'SHA-256 hex of the exact submitted UBL payload (also the documentHash sent to LHDN) — resubmission idempotency + audit evidence, with the payload archived in the FileStore under payload_file_key.';

-- LHDN codes for partner state/country (contacts carry free-text
-- address; the profile pins the LHDN-coded values e-invoices need)
ALTER TABLE acc_partner_tax_profile ADD COLUMN IF NOT EXISTS state_code VARCHAR(4) DEFAULT '17';
ALTER TABLE acc_partner_tax_profile ADD COLUMN IF NOT EXISTS country_code VARCHAR(4) DEFAULT 'MYS';

-- Company address + contact identity for the supplier block
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_address1 VARCHAR(200);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_address2 VARCHAR(200);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_city VARCHAR(80);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_postcode VARCHAR(12);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_state_code VARCHAR(4) DEFAULT '14';
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_country_code VARCHAR(4) DEFAULT 'MYS';
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_phone VARCHAR(30);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_email VARCHAR(160);
