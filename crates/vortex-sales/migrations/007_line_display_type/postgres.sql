-- 007_line_display_type — Odoo-style section & note rows on quote lines.
--
-- A line is now one of three kinds:
--   * product line — display_type NULL, has a product/qty/price (as before)
--   * section      — display_type 'section', a bold header grouping the lines
--                    below it; text lives in `description`, no product
--   * note         — display_type 'note', a free-text comment row
--
-- Section/note rows carry no product, quantity or tax, so product_id becomes
-- nullable and the positive-quantity check is relaxed for display rows.
ALTER TABLE sales_order_line
    ADD COLUMN IF NOT EXISTS display_type TEXT
    CHECK (display_type IN ('section', 'note'));

ALTER TABLE sales_order_line ALTER COLUMN product_id DROP NOT NULL;

ALTER TABLE sales_order_line DROP CONSTRAINT IF EXISTS chk_sol_qty;
ALTER TABLE sales_order_line ADD CONSTRAINT chk_sol_qty
    CHECK (display_type IS NOT NULL OR quantity > 0);

-- A real product line must still reference a product.
ALTER TABLE sales_order_line DROP CONSTRAINT IF EXISTS chk_sol_product;
ALTER TABLE sales_order_line ADD CONSTRAINT chk_sol_product
    CHECK (display_type IS NOT NULL OR product_id IS NOT NULL);
