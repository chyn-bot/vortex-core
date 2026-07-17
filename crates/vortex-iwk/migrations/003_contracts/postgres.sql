-- IWK contract lifecycle: turn iwk_account into a real *contract* and make
-- billing a recurring output of it (register customer → contract → cycle bills).
--
-- iwk_account was thin (category/system/units/active). A contract needs a
-- status, a billing cycle, and a "when is the next bill due" cursor so the
-- recurring generator knows what to bill and never double-bills a period.

ALTER TABLE iwk_account
    ADD COLUMN IF NOT EXISTS status          VARCHAR(16)  NOT NULL DEFAULT 'active',       -- active | suspended | terminated
    ADD COLUMN IF NOT EXISTS billing_cycle   VARCHAR(16)  NOT NULL DEFAULT 'semi_annual',  -- monthly | quarterly | semi_annual
    ADD COLUMN IF NOT EXISTS connection_date DATE,
    ADD COLUMN IF NOT EXISTS next_bill_date  DATE,
    ADD COLUMN IF NOT EXISTS deposit         NUMERIC(12,2) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS premises        VARCHAR(255);

-- Backfill the 400k demo contracts: they were billed Jan–Jun 2023, so their
-- next cycle starts 2023-07-01. Left in the past on purpose so a manual
-- "generate bills" run has something due to demonstrate.
UPDATE iwk_account
   SET connection_date = COALESCE(connection_date, created_at::date),
       next_bill_date  = COALESCE(next_bill_date, DATE '2023-07-01'),
       status          = COALESCE(NULLIF(status, ''), 'active'),
       billing_cycle   = COALESCE(NULLIF(billing_cycle, ''), 'semi_annual')
 WHERE next_bill_date IS NULL;

-- The recurring generator scans "active contracts whose next_bill_date is due".
CREATE INDEX IF NOT EXISTS idx_iwk_account_due ON iwk_account (status, next_bill_date);

-- Number sequences for newly registered accounts and generated bills, seeded
-- past the demo data (account_no = PB+10 digits, bill_no = 60+14 digits).
CREATE SEQUENCE IF NOT EXISTS iwk_account_seq;
CREATE SEQUENCE IF NOT EXISTS iwk_bill_seq;
SELECT setval('iwk_account_seq', GREATEST(400000, (SELECT COUNT(*) FROM iwk_account)));
SELECT setval('iwk_bill_seq',    GREATEST(400000, (SELECT COUNT(*) FROM iwk_bill)));
