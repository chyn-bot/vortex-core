-- Reconciliation — decouple upload from reconciliation.
--
-- A batch can now be created by uploading a scanned PDF *before* the supplier
-- (or any header field) is known; extraction/matching fills the rest in later.
-- So `supplier_no` becomes nullable, and we record where the scan came from.

ALTER TABLE recon_batch ALTER COLUMN supplier_no DROP NOT NULL;

-- Original uploaded filename, for display in the inbox/list.
ALTER TABLE recon_batch ADD COLUMN IF NOT EXISTS scan_filename VARCHAR(255);
-- When the scan was uploaded (distinct from row creation, though usually equal).
ALTER TABLE recon_batch ADD COLUMN IF NOT EXISTS uploaded_at TIMESTAMPTZ;
