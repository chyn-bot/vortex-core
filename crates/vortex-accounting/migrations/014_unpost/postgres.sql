-- Migration 014: explicit unpost path (reset posted document to draft)
--
-- Malaysian practice (AutoCount/SQL Account): until an e-invoice has
-- been submitted to LHDN, a posted document may be reset to draft,
-- corrected and reposted under the SAME number. Posted immutability
-- stays the default — the ONLY way through the guard is the
-- transaction-local setting `vortex.unpost`, which nothing but
-- `service::unpost_move` sets, and every unpost lands on the WORM
-- audit ledger.
--
-- Re-declared MOVE guard. FULL deny-list on posted rows (unchanged
-- from 006): state, number, journal_id, move_date, move_type,
-- partner_id, untaxed_amount, tax_amount, total_amount, currency_id,
-- currency_rate. New: the unpost bypass admits exactly one mutation —
-- posted → draft.

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
        -- Explicit unpost: only the posted→draft transition, only
        -- inside a transaction that set vortex.unpost.
        IF current_setting('vortex.unpost', true) = 'on' AND NEW.state = 'draft' THEN
            RETURN NEW;
        END IF;
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
