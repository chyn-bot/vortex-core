-- 009_line_uom — a per-line unit of measure.
--
-- A quote line can now state the unit it is sold in (e.g. "box", "kg", "hour")
-- independently of the product's default unit, purely for how the quote reads
-- and prints. There is no conversion: the quantity and unit price are taken as
-- entered against the chosen unit. When left blank the product's own unit is
-- shown as a fallback at render time.
ALTER TABLE sales_order_line
    ADD COLUMN IF NOT EXISTS uom_id UUID REFERENCES uoms(id);
