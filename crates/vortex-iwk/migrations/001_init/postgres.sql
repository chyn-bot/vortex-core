-- IWK (Indah Water Konsortium) — sewerage billing vertical.
--
-- Models the "Bil Perkhidmatan Pembetungan" (sewerage services bill):
--   iwk_tariff       — versioned rate card (category × system type → RM/month)
--   iwk_account      — a customer's sewerage account (links to contacts)
--   iwk_bill         — one semi-annual bill (the document on the paper bill)
--   iwk_bill_line    — the charge breakdown lines (minimum charge, adjustments)
--
-- The model registry (ir_model / ir_model_field) for iwk_bill is populated
-- from `#[derive(Model)]` via `Plugin::models()` on `db migrate` — not seeded
-- here.

-- ── Tariff / rate card ──────────────────────────────────────────────────────
-- Data-driven so rates can change over time without code (effective_from gives
-- a simple versioning). Sample bill: domestic + connected = RM5.00/month.
CREATE TABLE IF NOT EXISTS iwk_tariff (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category       VARCHAR(16) NOT NULL,        -- domestic | commercial
    system_type    VARCHAR(16) NOT NULL,        -- connected | individual
    monthly_rate   NUMERIC(12,2) NOT NULL,
    effective_from DATE NOT NULL DEFAULT '2023-01-01',
    active         BOOLEAN NOT NULL DEFAULT true,
    UNIQUE (category, system_type, effective_from)
);

INSERT INTO iwk_tariff (category, system_type, monthly_rate) VALUES
    ('domestic',   'connected',  5.00),   -- matches the sample bill
    ('domestic',   'individual', 4.00),
    ('commercial', 'connected', 28.00),
    ('commercial', 'individual', 20.00)
ON CONFLICT (category, system_type, effective_from) DO NOTHING;

-- ── Sewerage account ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS iwk_account (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_no  VARCHAR(20) NOT NULL UNIQUE,      -- Nombor Akaun Pembetungan
    contact_id  UUID NOT NULL REFERENCES contacts(id),
    category    VARCHAR(16) NOT NULL DEFAULT 'domestic',
    system_type VARCHAR(16) NOT NULL DEFAULT 'connected',
    units       INT NOT NULL DEFAULT 1,           -- billable units at the premises
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_iwk_account_contact ON iwk_account(contact_id);

-- ── Bill (the document) ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS iwk_bill (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bill_no        VARCHAR(24) NOT NULL UNIQUE,    -- No. Bil
    account_id     UUID NOT NULL REFERENCES iwk_account(id),
    contact_id     UUID NOT NULL REFERENCES contacts(id),
    account_no     VARCHAR(20) NOT NULL,           -- denormalized for list/search
    category       VARCHAR(16) NOT NULL,
    system_type    VARCHAR(16) NOT NULL,
    units          INT NOT NULL DEFAULT 1,
    months         INT NOT NULL DEFAULT 6,         -- semi-annual cycle
    period_start   DATE NOT NULL,
    period_end     DATE NOT NULL,
    bill_date      DATE NOT NULL,                  -- Tarikh Bil
    due_date       DATE NOT NULL,                  -- Sila bayar sebelum
    prev_balance   NUMERIC(12,2) NOT NULL DEFAULT 0,   -- Baki Terdahulu
    payments       NUMERIC(12,2) NOT NULL DEFAULT 0,   -- Bayaran Telah Diterima
    current_charge NUMERIC(12,2) NOT NULL DEFAULT 0,   -- Jumlah Semasa
    adjustments    NUMERIC(12,2) NOT NULL DEFAULT 0,   -- Pelarasan
    rounding       NUMERIC(12,2) NOT NULL DEFAULT 0,   -- Penggenapan
    total          NUMERIC(12,2) NOT NULL DEFAULT 0,   -- Jumlah selepas penggenapan
    jompay_biller  VARCHAR(12) NOT NULL DEFAULT '68602',
    jompay_ref     VARCHAR(24),
    run_id         UUID,                           -- batch run that generated it
    record_state   VARCHAR(32) NOT NULL DEFAULT 'issued',  -- issued|paid|cancelled
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- List/browse + search indexes, following the list-scalability pattern:
--   default sort is bill_no with an id tiebreaker → (bill_no, id) index scan;
--   free-text search on bill_no / account_no is trigram-accelerated.
CREATE INDEX IF NOT EXISTS idx_iwk_bill_browse      ON iwk_bill (bill_no, id);
CREATE INDEX IF NOT EXISTS idx_iwk_bill_account_no  ON iwk_bill (account_no);
CREATE INDEX IF NOT EXISTS idx_iwk_bill_state       ON iwk_bill (record_state);
CREATE INDEX IF NOT EXISTS idx_iwk_bill_run         ON iwk_bill (run_id);
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_iwk_bill_billno_trgm
    ON iwk_bill USING gin ((COALESCE(bill_no::text, '')) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_iwk_bill_acctno_trgm
    ON iwk_bill USING gin ((COALESCE(account_no::text, '')) gin_trgm_ops);

-- ── Bill charge lines ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS iwk_bill_line (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bill_id     UUID NOT NULL REFERENCES iwk_bill(id) ON DELETE CASCADE,
    sequence    INT NOT NULL DEFAULT 1,
    line_type   VARCHAR(24) NOT NULL DEFAULT 'min_charge',  -- min_charge|adjustment
    description VARCHAR(255) NOT NULL,
    rate        NUMERIC(12,2) NOT NULL DEFAULT 0,
    months      INT NOT NULL DEFAULT 0,
    units       INT NOT NULL DEFAULT 0,
    amount      NUMERIC(12,2) NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_iwk_bill_line_bill ON iwk_bill_line(bill_id);

-- Status-bar stages for the bill record page.
INSERT INTO record_stages (model, code, label, color, sequence, always_visible) VALUES
    ('iwk_bill', 'issued',    'Issued',    'info',    10, true),
    ('iwk_bill', 'paid',      'Paid',      'success', 20, true),
    ('iwk_bill', 'cancelled', 'Cancelled', 'error',   30, false)
ON CONFLICT (model, code) DO NOTHING;
