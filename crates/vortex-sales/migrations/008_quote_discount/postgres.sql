-- 008_quote_discount — a whole-quote (document-level) discount.
--
-- In addition to the per-line `discount_percent`, an order can carry ONE
-- global discount applied to the whole quote:
--   * type 'percent' — value is a percentage 0..100 off the subtotal
--   * type 'fixed'   — value is an absolute amount in the order currency
--
-- Both are applied by scaling every line's net (already per-line-discounted)
-- price by a single uniform factor, so per-line tax stays proportional and the
-- customer-invoice bridge (which bills partial delivered quantities) can apply
-- the exact same factor without the pieces drifting apart.
ALTER TABLE sales_order
    ADD COLUMN IF NOT EXISTS global_discount_type TEXT
        CHECK (global_discount_type IN ('percent', 'fixed')),
    ADD COLUMN IF NOT EXISTS global_discount_value NUMERIC(14, 4) NOT NULL DEFAULT 0
        CHECK (global_discount_value >= 0);
