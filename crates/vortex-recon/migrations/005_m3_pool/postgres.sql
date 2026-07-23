-- Reconciliation — M3 (ERP) data as a bulk pool.
--
-- M3 EDI-voucher / payment-info extracts are uploaded as one file covering many
-- invoices, independently of any single scanned PDF. Lines land in the pool with
-- batch_id = NULL; matching later links each line to an uploaded invoice batch
-- (by invoice-no / PO / voucher-no) and sets batch_id.

-- Pool: a line no longer must belong to a batch at import time.
ALTER TABLE recon_m3_line ALTER COLUMN batch_id DROP NOT NULL;

-- Linking keys carried on each M3 line (used by matching to find its invoice).
ALTER TABLE recon_m3_line ADD COLUMN IF NOT EXISTS invoice_no    VARCHAR(64);
ALTER TABLE recon_m3_line ADD COLUMN IF NOT EXISTS supplier_no   VARCHAR(32);
ALTER TABLE recon_m3_line ADD COLUMN IF NOT EXISTS currency      VARCHAR(8);
ALTER TABLE recon_m3_line ADD COLUMN IF NOT EXISTS currency_rate NUMERIC(18, 6);
-- Which import run produced this line (for audit / re-import / rollback).
ALTER TABLE recon_m3_line ADD COLUMN IF NOT EXISTS import_id     UUID;

CREATE INDEX IF NOT EXISTS idx_recon_m3_line_invoice  ON recon_m3_line(invoice_no);
CREATE INDEX IF NOT EXISTS idx_recon_m3_line_supplier ON recon_m3_line(supplier_no);
CREATE INDEX IF NOT EXISTS idx_recon_m3_line_import   ON recon_m3_line(import_id);
CREATE INDEX IF NOT EXISTS idx_recon_m3_line_voucher  ON recon_m3_line(m3_voucher_no);

-- One row per uploaded M3 extract file — makes each import auditable and
-- lets the pool be filtered/rolled back by run.
CREATE TABLE IF NOT EXISTS recon_m3_import (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename    VARCHAR(255) NOT NULL,
    format      VARCHAR(8),              -- csv | xlsx
    row_count   INTEGER NOT NULL DEFAULT 0,
    note        TEXT,
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
