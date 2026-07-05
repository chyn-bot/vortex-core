-- Migration 007: sale price on the product master
--
-- AR lines price from list_price (falling back to cost while unset);
-- purchase side keeps pricing from cost.

ALTER TABLE stock_product ADD COLUMN IF NOT EXISTS list_price NUMERIC(20,4) NOT NULL DEFAULT 0;

COMMENT ON COLUMN stock_product.list_price IS
    'Sale price seeded onto customer document lines; 0 = fall back to cost.';
