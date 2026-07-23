-- Reconciliation — extraction self-check (Part 1: does the extraction match
-- the physical invoice?).
--
-- Before any M3 matching, each uploaded invoice is validated against ITSELF:
-- extraction yields per-line qty + unit price; we compute Σ(qty × unit price)
-- (+ any per-line tax) and compare it to the invoice's own printed grand total
-- (recon_batch.doc_total). A mismatch beyond the rounding tolerance is flagged
-- as an exception for a human to handle — it means the OCR read something wrong,
-- not that M3 disagrees.
--
-- recon_inv_line already exists (003_operational); this migration only records
-- the self-check verdict on the batch header.

ALTER TABLE recon_batch ADD COLUMN IF NOT EXISTS computed_total   NUMERIC(18, 2);
ALTER TABLE recon_batch ADD COLUMN IF NOT EXISTS total_variance   NUMERIC(18, 2);
-- pending  : lines not yet self-checked
-- passed   : Σ(lines) == printed total within tolerance
-- exception: mismatch beyond tolerance — needs human review
ALTER TABLE recon_batch ADD COLUMN IF NOT EXISTS validation_status VARCHAR(16) NOT NULL DEFAULT 'pending';
ALTER TABLE recon_batch ADD COLUMN IF NOT EXISTS validated_at     TIMESTAMPTZ;
ALTER TABLE recon_batch ADD COLUMN IF NOT EXISTS validated_by     UUID REFERENCES users(id);

CREATE INDEX IF NOT EXISTS idx_recon_batch_validation ON recon_batch(validation_status);
