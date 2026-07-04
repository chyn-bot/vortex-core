-- Migration 003: link purchase orders to accounting vendor bills.
-- Registration order guarantees acc_move exists (accounting registers
-- before purchase).

ALTER TABLE purchase_order
    ADD COLUMN IF NOT EXISTS vendor_bill_move_id UUID REFERENCES acc_move(id);

COMMENT ON COLUMN purchase_order.vendor_bill_move_id IS
    'The acc_move (vendor_bill) created from this order — the purchase→accounting bridge.';
