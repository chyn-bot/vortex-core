-- Reconciliation — line discount + document-level SST.
--
-- Two supplier-invoice layouts must reconcile to the same grand total:
--   (a) per-line tax  — each line prints its own Sales Tax; grand = Σ(net + line tax).
--   (b) invoice-level SST + discount — lines print U.Price, DISC%, and a net
--       AMOUNT excl SST; SST is a single footer figure (e.g. 5% of the subtotal);
--       grand = subtotal + SST.
-- We store the line discount and, for layout (b), the document SST + subtotal.
-- The app allocates a document-level SST across lines pro-rata by net so that
-- `line_total` stays SST-inclusive (the M3 matcher compares incl amounts) and
-- Σ(line_total) equals the printed grand total (the self-check compares to it).

ALTER TABLE recon_inv_line ADD COLUMN IF NOT EXISTS discount_pct NUMERIC(9, 4) NOT NULL DEFAULT 0;
-- Line amount AFTER discount, EXCLUDING tax (the invoice's "AMOUNT" column).
ALTER TABLE recon_inv_line ADD COLUMN IF NOT EXISTS line_net     NUMERIC(18, 2);

-- Invoice-level SST total (layout b) and the printed excl-SST subtotal, for the
-- header breakdown and cross-check. doc_total stays the grand total incl SST.
ALTER TABLE recon_batch ADD COLUMN IF NOT EXISTS doc_tax      NUMERIC(18, 2);
ALTER TABLE recon_batch ADD COLUMN IF NOT EXISTS doc_subtotal NUMERIC(18, 2);
