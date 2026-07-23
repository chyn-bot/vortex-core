-- Reconciliation — carry the M3 IFSITE (vendor / PO item code) on each pool line.
--
-- The real M3 export has an IFSITE column (e.g. 4000001373) that equals the item
-- code PRINTED ON THE SUPPLIER INVOICE, whereas M3's own `SKU` is the internal
-- LSEO item code (e.g. LNC360G00). So IFSITE is the natural join key between an
-- uploaded invoice line and its M3 pool line.

ALTER TABLE recon_m3_line ADD COLUMN IF NOT EXISTS vendor_item_code VARCHAR(64);
CREATE INDEX IF NOT EXISTS idx_recon_m3_line_vendoritem ON recon_m3_line(vendor_item_code);
