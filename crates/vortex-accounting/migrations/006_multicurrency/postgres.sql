-- Migration 006: Multi-currency (MFRS 121)
--
-- Foreign-currency documents and payments: transaction-date rates,
-- realized FX on settlement, unrealized revaluation at period end.
--
-- GUARD LEDGER — both guards re-declared here:
--   acc_move_line deny-list: account_id, partner_id, debit, credit,
--     tax_id, move_id, tax_base_amount, currency_id, amount_currency
--     [mutable: reconciled]
--   acc_move deny-list: state, number, journal_id, move_date,
--     move_type, partner_id, untaxed_amount, tax_amount, total_amount,
--     currency_id, currency_rate
--     [mutable: payment_state, amount_residual, amount_residual_currency,
--      reversed_move_id, updated_by]

ALTER TABLE acc_move_line ADD COLUMN IF NOT EXISTS currency_id UUID REFERENCES currencies(id);
-- Signed document-currency amount: positive on the debit side,
-- negative on the credit side (Odoo convention).
ALTER TABLE acc_move_line ADD COLUMN IF NOT EXISTS amount_currency NUMERIC(20,4);

-- MYR per 1 unit of document currency, fixed at posting (audit trail).
ALTER TABLE acc_move ADD COLUMN IF NOT EXISTS currency_rate NUMERIC(20,10);
-- Residual in document currency (payment bookkeeping — mutable).
ALTER TABLE acc_move ADD COLUMN IF NOT EXISTS amount_residual_currency NUMERIC(20,4);

ALTER TABLE acc_partial_reconcile ADD COLUMN IF NOT EXISTS debit_amount_currency NUMERIC(20,4);
ALTER TABLE acc_partial_reconcile ADD COLUMN IF NOT EXISTS credit_amount_currency NUMERIC(20,4);
ALTER TABLE acc_partial_reconcile ADD COLUMN IF NOT EXISTS exchange_move_id UUID REFERENCES acc_move(id);

ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS realized_gain_account_id UUID REFERENCES acc_account(id);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS realized_loss_account_id UUID REFERENCES acc_account(id);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS unrealized_gain_account_id UUID REFERENCES acc_account(id);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS unrealized_loss_account_id UUID REFERENCES acc_account(id);

INSERT INTO acc_account (id, code, name, account_type, reconcile) VALUES
    ('acc00000-0000-4000-8000-000000004950', '4950', 'Realized FX Gain',    'income_other', FALSE),
    ('acc00000-0000-4000-8000-000000006950', '6950', 'Realized FX Loss',    'expense',      FALSE),
    ('acc00000-0000-4000-8000-000000004960', '4960', 'Unrealized FX Gain',  'income_other', FALSE),
    ('acc00000-0000-4000-8000-000000006960', '6960', 'Unrealized FX Loss',  'expense',      FALSE)
ON CONFLICT (id) DO NOTHING;

UPDATE acc_config SET
    realized_gain_account_id   = COALESCE(realized_gain_account_id,   'acc00000-0000-4000-8000-000000004950'),
    realized_loss_account_id   = COALESCE(realized_loss_account_id,   'acc00000-0000-4000-8000-000000006950'),
    unrealized_gain_account_id = COALESCE(unrealized_gain_account_id, 'acc00000-0000-4000-8000-000000004960'),
    unrealized_loss_account_id = COALESCE(unrealized_loss_account_id, 'acc00000-0000-4000-8000-000000006960');

-- Re-declare the LINE guard (full deny-list, incl. Phase 1 + FX cols)
CREATE OR REPLACE FUNCTION acc_move_line_guard() RETURNS trigger AS $$
DECLARE
    mid        UUID;
    move_state VARCHAR(12);
BEGIN
    IF TG_OP = 'INSERT' THEN
        mid := NEW.move_id;
    ELSE
        mid := OLD.move_id;
    END IF;
    SELECT state INTO move_state FROM acc_move WHERE id = mid;
    IF move_state = 'posted' THEN
        IF TG_OP = 'INSERT' THEN
            RAISE EXCEPTION 'acc_move_line: cannot add lines to a posted entry';
        ELSIF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'acc_move_line: lines of a posted entry cannot be deleted';
        ELSIF NEW.account_id IS DISTINCT FROM OLD.account_id
           OR NEW.partner_id IS DISTINCT FROM OLD.partner_id
           OR NEW.debit IS DISTINCT FROM OLD.debit
           OR NEW.credit IS DISTINCT FROM OLD.credit
           OR NEW.tax_id IS DISTINCT FROM OLD.tax_id
           OR NEW.move_id IS DISTINCT FROM OLD.move_id
           OR NEW.tax_base_amount IS DISTINCT FROM OLD.tax_base_amount
           OR NEW.currency_id IS DISTINCT FROM OLD.currency_id
           OR NEW.amount_currency IS DISTINCT FROM OLD.amount_currency THEN
            RAISE EXCEPTION 'acc_move_line: lines of a posted entry are immutable';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Re-declare the MOVE guard: adds currency_rate AND closes the
-- pre-existing currency_id gap (it was mutable-on-posted until now).
CREATE OR REPLACE FUNCTION acc_move_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.state = 'posted' THEN
            RAISE EXCEPTION 'acc_move %: posted entries cannot be deleted — post a reversal',
                OLD.number;
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.state = 'posted' THEN
        IF NEW.state IS DISTINCT FROM OLD.state
           OR NEW.number IS DISTINCT FROM OLD.number
           OR NEW.journal_id IS DISTINCT FROM OLD.journal_id
           OR NEW.move_date IS DISTINCT FROM OLD.move_date
           OR NEW.move_type IS DISTINCT FROM OLD.move_type
           OR NEW.partner_id IS DISTINCT FROM OLD.partner_id
           OR NEW.untaxed_amount IS DISTINCT FROM OLD.untaxed_amount
           OR NEW.tax_amount IS DISTINCT FROM OLD.tax_amount
           OR NEW.total_amount IS DISTINCT FROM OLD.total_amount
           OR NEW.currency_id IS DISTINCT FROM OLD.currency_id
           OR NEW.currency_rate IS DISTINCT FROM OLD.currency_rate THEN
            RAISE EXCEPTION 'acc_move %: posted entries are immutable — post a reversal',
                OLD.number;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON COLUMN acc_move_line.amount_currency IS
    'Signed document-currency amount (positive = debit side). NULL on company-currency lines.';
COMMENT ON COLUMN acc_move.currency_rate IS
    'MYR per 1 unit of document currency, fixed at posting. NULL for company-currency documents.';
