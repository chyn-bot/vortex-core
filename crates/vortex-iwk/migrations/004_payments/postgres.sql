-- IWK payments: the collection side of the subledger + summarized GL feed.
--
-- Mirror of billing. A payment settles open bills (open-item, FIFO) in the
-- subledger; the GL gets ONE summarized journal per collection batch:
--     Dr  Bank                       Σ received
--       Cr Sewerage Receivables         Σ allocated to bills
--       Cr Customer Advances            Σ overpayment (held as credit)
-- Overpayment becomes account credit (a liability until consumed); the bill
-- generator applies it to the customer's next bill.

-- Advance/credit balance carried on the contract.
ALTER TABLE iwk_account
    ADD COLUMN IF NOT EXISTS credit_balance NUMERIC(12,2) NOT NULL DEFAULT 0;

-- Customer Advances liability (the GL home of unconsumed credit). Seeded only
-- when accounting is present.
DO $$
BEGIN
    IF to_regclass('acc_account') IS NOT NULL THEN
        INSERT INTO acc_account (code, name, account_type, reconcile, active, company_id)
        VALUES ('2050', 'Customer Advances (Sewerage)', 'liability_current', false, true, NULL)
        ON CONFLICT (company_id, code) DO NOTHING;
    END IF;
END $$;

-- A captured payment (subledger).
CREATE TABLE IF NOT EXISTS iwk_payment (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payment_no   VARCHAR(24) NOT NULL UNIQUE,
    account_id   UUID NOT NULL REFERENCES iwk_account(id),
    contact_id   UUID NOT NULL REFERENCES contacts(id),
    amount       NUMERIC(12,2) NOT NULL,               -- total received
    allocated    NUMERIC(12,2) NOT NULL DEFAULT 0,     -- applied to bills
    credit       NUMERIC(12,2) NOT NULL DEFAULT 0,     -- overpayment → account credit
    method       VARCHAR(16) NOT NULL DEFAULT 'counter', -- jompay|counter|bank|cash|import
    reference    VARCHAR(64),
    payment_date DATE NOT NULL,
    run_id       UUID,                                 -- collection batch (bulk import)
    gl_batch_id  UUID,                                 -- summarized posting it belongs to
    posted       BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_iwk_payment_account ON iwk_payment(account_id);
CREATE INDEX IF NOT EXISTS idx_iwk_payment_unposted ON iwk_payment(posted) WHERE NOT posted;
CREATE INDEX IF NOT EXISTS idx_iwk_payment_date ON iwk_payment(payment_date);
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_iwk_payment_no_trgm
    ON iwk_payment USING gin ((COALESCE(payment_no::text, '')) gin_trgm_ops);

-- Open-item allocation: which bill each payment settled (audit + unwinding).
CREATE TABLE IF NOT EXISTS iwk_payment_alloc (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payment_id UUID NOT NULL REFERENCES iwk_payment(id) ON DELETE CASCADE,
    bill_id    UUID NOT NULL REFERENCES iwk_bill(id),
    amount     NUMERIC(12,2) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iwk_payment_alloc_payment ON iwk_payment_alloc(payment_id);
CREATE INDEX IF NOT EXISTS idx_iwk_payment_alloc_bill ON iwk_payment_alloc(bill_id);

-- Summarized GL posting ledger for collection batches (mirror of iwk_gl_batch).
CREATE TABLE IF NOT EXISTS iwk_gl_payment_batch (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    posting_date  DATE NOT NULL,
    payment_count INT NOT NULL DEFAULT 0,
    bank_total    NUMERIC(16,2) NOT NULL DEFAULT 0,  -- Dr Bank
    ar_total      NUMERIC(16,2) NOT NULL DEFAULT 0,  -- Cr Sewerage Receivables
    advance_total NUMERIC(16,2) NOT NULL DEFAULT 0,  -- Cr Customer Advances
    move_id       UUID,
    move_number   VARCHAR(64),
    posted_by     UUID,
    posted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE SEQUENCE IF NOT EXISTS iwk_payment_seq;
