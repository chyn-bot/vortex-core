-- 005_line_description_text — allow multi-line, unbounded line descriptions.
--
-- Quotation / sales-order lines (and the delivery lines copied from them)
-- previously capped `description` at VARCHAR(255) single-line. Widen to TEXT so
-- users can enter several lines / bullet points in the line editor, and so a
-- long order-line description can't truncate when copied onto a delivery.
ALTER TABLE sales_order_line    ALTER COLUMN description TYPE TEXT;
ALTER TABLE sales_delivery_line ALTER COLUMN description TYPE TEXT;
