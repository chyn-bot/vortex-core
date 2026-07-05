-- Migration 005: per-side trade descriptions
--
-- What you print on a customer invoice ("Premium aircond servicing,
-- incl. parts") differs from what you order from a vendor ("Servicing
-- package SKU-various"). Documents pick the side-appropriate text and
-- fall back to the product name when empty.

ALTER TABLE stock_product ADD COLUMN IF NOT EXISTS sales_description TEXT;
ALTER TABLE stock_product ADD COLUMN IF NOT EXISTS purchase_description TEXT;

COMMENT ON COLUMN stock_product.sales_description IS
    'Line text on customer documents (invoices; sales orders later); NULL = product name.';
COMMENT ON COLUMN stock_product.purchase_description IS
    'Line text on vendor documents (POs, bills); NULL = product name.';
