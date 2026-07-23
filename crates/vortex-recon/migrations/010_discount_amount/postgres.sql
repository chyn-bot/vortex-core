-- Reconciliation — line discount as a money amount (not only a percentage).
--
-- Some invoices print discount as an amount, not a %: e.g. Ocean Sixty 6
-- (757 DIVE GEAR) shows Sub-Total 342.00 − Discount 136.80 = Total Excl 205.20.
-- Net becomes: qty × unit_price × (1 − disc%/100) − disc_amount.

ALTER TABLE recon_inv_line ADD COLUMN IF NOT EXISTS discount_amt NUMERIC(18, 4) NOT NULL DEFAULT 0;
