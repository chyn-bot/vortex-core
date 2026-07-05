-- Migration 015: product reference on document lines
--
-- Lines can point at an inventory product (picker seeds description /
-- price; later: COGS + stock integration). Plain UUID, NO foreign key
-- — accounting migrations run before inventory's on a fresh tenant,
-- and accounting must not hard-depend on the inventory plugin.

ALTER TABLE acc_invoice_line ADD COLUMN IF NOT EXISTS product_id UUID;

COMMENT ON COLUMN acc_invoice_line.product_id IS
    'Optional stock_product reference (soft link — no FK; inventory is an optional plugin).';
