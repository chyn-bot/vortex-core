-- 011_payment_term — a quotation/order carries a payment term.
--
-- References the accounting-owned `payment_term` master (created by accounting
-- migration 016). Sales registers after accounting, so the table exists by the
-- time this runs. The term pre-fills from the customer's default and flows
-- through to the customer invoice's due date.
ALTER TABLE sales_order
    ADD COLUMN IF NOT EXISTS payment_term_id UUID REFERENCES payment_term(id);
