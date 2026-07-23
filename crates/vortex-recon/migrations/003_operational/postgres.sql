-- Reconciliation — operational tables (staging + match + preview + PV batch).
--
-- These are internal working tables, not registered models: they are written
-- by the ingest/match/preview pipeline (phases 2–6), not maintained by hand.
-- Registered-model screens can come later if a table needs a browse UI.

-- Extracted supplier-invoice lines (OCR / e-invoice output). `raw_json` keeps
-- the untouched provider payload for audit and re-normalization.
CREATE TABLE IF NOT EXISTS recon_inv_line (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id         UUID NOT NULL REFERENCES recon_batch(id) ON DELETE CASCADE,
    line_no          INTEGER,
    supplier_sku     VARCHAR(64),
    description      TEXT,
    uom              VARCHAR(16),
    qty              NUMERIC(18, 4),
    unit_price_excl  NUMERIC(18, 4),   -- supplier price EXCLUDES SST
    sales_tax        NUMERIC(18, 4),
    line_total       NUMERIC(18, 2),
    -- normalized-for-matching values (computed in the normalization pass)
    norm_lseo_sku    VARCHAR(64),
    norm_qty_base    NUMERIC(18, 4),   -- qty converted to LSEO base UOM
    norm_unit_incl   NUMERIC(18, 4),   -- price incl. SST, rounded 2dp
    raw_json         JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_recon_inv_line_batch ON recon_inv_line(batch_id);

-- Imported M3 voucher / payment-info lines (the ErpSource staging).
CREATE TABLE IF NOT EXISTS recon_m3_line (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id         UUID NOT NULL REFERENCES recon_batch(id) ON DELETE CASCADE,
    m3_voucher_no    VARCHAR(32),
    division         VARCHAR(16),
    lseo_sku         VARCHAR(64),
    description      TEXT,
    base_uom         VARCHAR(16),
    qty              NUMERIC(18, 4),
    unit_price_incl  NUMERIC(18, 4),   -- M3 price INCLUDES SST
    line_total       NUMERIC(18, 2),
    po_no            VARCHAR(32),
    do_no            VARCHAR(32),
    event_id         VARCHAR(32),
    raw_json         JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_recon_m3_line_batch ON recon_m3_line(batch_id);

-- The match: links (possibly consolidated) invoice lines to M3 lines, with a
-- status + confidence + the deltas that drove it.
CREATE TABLE IF NOT EXISTS recon_match (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id       UUID NOT NULL REFERENCES recon_batch(id) ON DELETE CASCADE,
    inv_line_id    UUID REFERENCES recon_inv_line(id) ON DELETE SET NULL,
    m3_line_id     UUID REFERENCES recon_m3_line(id) ON DELETE SET NULL,
    -- matched | within_tolerance | price_variance | needs_review | unmatched
    status         VARCHAR(24) NOT NULL DEFAULT 'needs_review',
    confidence     NUMERIC(5, 4),
    delta_qty      NUMERIC(18, 4),
    delta_price    NUMERIC(18, 4),
    delta_amount   NUMERIC(18, 2),
    reason_code    VARCHAR(64),
    note           TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_recon_match_batch  ON recon_match(batch_id);
CREATE INDEX IF NOT EXISTS idx_recon_match_status ON recon_match(status);

-- Double-entry preview rows (BRD §1.3.3). Σ(debit)=Σ(credit)=invoice total
-- is the pass/fail gate before approval.
CREATE TABLE IF NOT EXISTS recon_de_line (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id     UUID NOT NULL REFERENCES recon_batch(id) ON DELETE CASCADE,
    acct_id      VARCHAR(32),
    location     VARCHAR(16),
    description  TEXT,
    inv_no       VARCHAR(64),
    dept         VARCHAR(16),
    sku          VARCHAR(64),
    ecv          VARCHAR(32),
    qty          NUMERIC(18, 4),
    event_id     VARCHAR(32),
    debit        NUMERIC(18, 2),
    credit       NUMERIC(18, 2),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_recon_de_line_batch ON recon_de_line(batch_id);

-- PV batch, keyed by M3 Proposal Number (P3PRPN); groups approved invoices
-- for supplier-matrix routing and the printed Payment Voucher.
CREATE TABLE IF NOT EXISTS recon_pv_batch (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proposal_no    VARCHAR(32) NOT NULL UNIQUE,   -- P3PRPN
    supplier_no    VARCHAR(32),
    division       VARCHAR(16),
    voucher_no     VARCHAR(32),
    currency       VARCHAR(8),
    pay_amount     NUMERIC(18, 2),
    invoice_date   DATE,
    due_date       DATE,
    payment_date   DATE,
    record_state   VARCHAR(32) NOT NULL DEFAULT 'draft',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_recon_pv_batch_supplier ON recon_pv_batch(supplier_no);
