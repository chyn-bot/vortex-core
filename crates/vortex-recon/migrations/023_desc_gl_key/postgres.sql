-- Reconciliation — description as the item key for code-less invoices.
--
-- Many vendors print description-only invoices (no item-code column at all).
-- Keying goods lines on supplier_sku alone collapsed every line of such an
-- invoice into ONE GL debit row (and one "UNKNOWN" match bucket). The GL builder
-- and the M3 matcher now fall back to the line description as the item key.
--
-- That key flows into three VARCHAR(64) columns which are far too narrow for a
-- product description, so widen them. Widening a varchar is a catalog-only
-- change in PostgreSQL — no table rewrite, no lock beyond ACCESS EXCLUSIVE for
-- the metadata update.
--
-- Also introduces recon_gl_map.match_type = 'desc': exact description → debit
-- (goods) account, the description-keyed sibling of the existing 'sku' rule.

ALTER TABLE recon_gl_map       ALTER COLUMN match_value   TYPE VARCHAR(200);
ALTER TABLE vendor_item_alias  ALTER COLUMN supplier_sku  TYPE VARCHAR(200);
ALTER TABLE recon_inv_line     ALTER COLUMN norm_lseo_sku TYPE VARCHAR(200);
