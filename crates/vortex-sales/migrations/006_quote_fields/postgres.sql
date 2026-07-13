-- 006_quote_fields — Xero-style quote authoring fields.
--
-- * title / summary  — a headline and an intro paragraph shown at the top of
--   the quotation (framing text, distinct from the per-document Note/terms).
-- * discount_percent — per-line discount applied before tax, matching how the
--   inline line-item grid and the accounting bridge compute net amounts.
ALTER TABLE sales_order ADD COLUMN IF NOT EXISTS title   TEXT;
ALTER TABLE sales_order ADD COLUMN IF NOT EXISTS summary TEXT;

ALTER TABLE sales_order_line
    ADD COLUMN IF NOT EXISTS discount_percent NUMERIC(6,3) NOT NULL DEFAULT 0
    CHECK (discount_percent >= 0 AND discount_percent <= 100);
