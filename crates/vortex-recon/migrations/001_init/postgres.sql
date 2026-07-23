-- Reconciliation — initial schema: the batch workbench record.
--
-- One `recon_batch` per uploaded supplier invoice document. The model is
-- registered in `ir_model` / `ir_model_field` automatically from
-- `#[derive(Model)]` (see `src/model.rs` + `Plugin::models()`) — do NOT
-- hand-seed the registry here. Keep columns in sync with the struct.

CREATE TABLE IF NOT EXISTS recon_batch (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- stamped from the sequence right after insert (nullable so the
    -- form engine's INSERT doesn't need to know about it)
    code VARCHAR(32) UNIQUE,

    -- extracted invoice header
    supplier_no           VARCHAR(32)  NOT NULL,
    supplier_name         VARCHAR(255),
    invoice_no            VARCHAR(64),
    invoice_no_canonical  VARCHAR(64),
    invoice_date          DATE,
    currency              VARCHAR(8),
    currency_rate         NUMERIC(18, 6),
    doc_total             NUMERIC(18, 2),

    -- ingest provenance + lifecycle
    source_provider       VARCHAR(16),   -- myinvois | ocr_self | ocr_vision | manual
    phase                 VARCHAR(16),   -- phase1 | phase2
    proposal_no           VARCHAR(32),   -- M3 P3PRPN, for PV batch grouping

    -- link to the stored scanned copy (FileStore attachment)
    scan_file_id          UUID,

    record_state VARCHAR(32) NOT NULL DEFAULT 'draft',
    active       BOOLEAN NOT NULL DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recon_batch_state       ON recon_batch(record_state);
CREATE INDEX IF NOT EXISTS idx_recon_batch_supplier    ON recon_batch(supplier_no);
CREATE INDEX IF NOT EXISTS idx_recon_batch_inv_canon   ON recon_batch(invoice_no_canonical);
CREATE INDEX IF NOT EXISTS idx_recon_batch_proposal    ON recon_batch(proposal_no);

-- NOTE: the model registry (ir_model / ir_model_field) is populated from
-- `#[derive(Model)]` via `Plugin::models()` on `db migrate` — not seeded here.

-- Status bar stages (users can add/reorder in Settings ▸ Stages).
INSERT INTO record_stages (model, code, label, color, sequence, always_visible) VALUES
    ('recon_batch', 'draft',     'Draft',     'neutral', 10, true),
    ('recon_batch', 'extracted', 'Extracted', 'info',    20, true),
    ('recon_batch', 'matched',   'Matched',   'primary', 30, true),
    ('recon_batch', 'validated', 'Validated', 'warning', 40, true),
    ('recon_batch', 'approved',  'Approved',  'success', 50, true),
    ('recon_batch', 'rejected',  'Rejected',  'error',   60, false)
ON CONFLICT (model, code) DO NOTHING;
