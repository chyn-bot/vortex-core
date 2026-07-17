-- IWK → General Ledger integration (summarized posting, FI-CA style).
--
-- The utility-billing pattern: iwk_bill IS the receivables *subledger*
-- (per-customer, per-bill detail). The general ledger must NOT carry one
-- entry per bill — at 400k+ bills that makes the GL unusable. Instead a
-- billing run posts ONE balanced journal of period totals:
--     Dr  Sewerage Receivables (control)     Σ current_charge
--       Cr Sewerage Revenue — Domestic          Σ domestic
--       Cr Sewerage Revenue — Commercial        Σ commercial
-- and the control account's GL balance is reconciled against the subledger.

-- ── Dedicated GL accounts ────────────────────────────────────────────────
-- Seeded only when the accounting schema is present (IWK registers after
-- vortex-accounting, so acc_account exists on a normal migrate). A dedicated
-- receivables *control* account (reconcile = true) keeps the sewerage
-- subledger reconcilable on its own, not mixed into trade AR (1200).
DO $$
BEGIN
    IF to_regclass('acc_account') IS NOT NULL THEN
        INSERT INTO acc_account (code, name, account_type, reconcile, active, company_id)
        VALUES
            ('1220', 'Sewerage Receivables',            'asset_receivable', true,  true, NULL),
            ('4200', 'Sewerage Revenue — Domestic',     'income',           false, true, NULL),
            ('4210', 'Sewerage Revenue — Commercial',   'income',           false, true, NULL)
        ON CONFLICT (company_id, code) DO NOTHING;
    END IF;
END $$;

-- ── GL posting ledger ────────────────────────────────────────────────────
-- One row per billing run that has been posted to the GL. `run_id` is UNIQUE
-- so a run can only post once (idempotency); re-posting is a no-op. Stores
-- the resulting journal entry + the amounts that made it up, so the posting
-- is auditable and the reconciliation view is cheap.
CREATE TABLE IF NOT EXISTS iwk_gl_batch (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id         UUID NOT NULL UNIQUE,        -- batch_run.id that was posted
    move_id        UUID NOT NULL,               -- acc_move created
    move_number    VARCHAR(64),                 -- posted journal number
    bill_count     INT NOT NULL DEFAULT 0,
    ar_total       NUMERIC(16,2) NOT NULL DEFAULT 0,  -- Dr Sewerage Receivables
    rev_domestic   NUMERIC(16,2) NOT NULL DEFAULT 0,  -- Cr Domestic revenue
    rev_commercial NUMERIC(16,2) NOT NULL DEFAULT 0,  -- Cr Commercial revenue
    posted_by      UUID,
    posted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_iwk_gl_batch_move ON iwk_gl_batch(move_id);
