-- Reconciliation — carry the M3 GL account on each pool line.
--
-- The GL-detail export has Acct_ID + Acct_Desp (the posting account, e.g.
-- "Trade Creditors - Accrued (RNI)", "Price Variance - Lion"). Acct_Desp is used
-- as the line description for non-product lines that have no Item_Desp (e.g. the
-- price-variance adjustment), so they read clearly instead of blank.

ALTER TABLE recon_m3_line ADD COLUMN IF NOT EXISTS acct_id   VARCHAR(32);
ALTER TABLE recon_m3_line ADD COLUMN IF NOT EXISTS acct_desp VARCHAR(255);
