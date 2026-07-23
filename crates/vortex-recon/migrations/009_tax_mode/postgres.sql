-- Reconciliation — remember the SST layout so the grid round-trips correctly.
--
-- We always allocate an invoice-level SST across lines (so line_total stays
-- SST-inclusive for the matcher). But that means the per-line sales_tax column
-- holds allocated amounts even for invoice-level invoices — which, on reload,
-- would make the grid look per-line. This flag records the original intent so
-- the review grid re-seeds in the right mode (per-line tax vs footer SST).

ALTER TABLE recon_batch ADD COLUMN IF NOT EXISTS tax_per_line BOOLEAN NOT NULL DEFAULT false;
