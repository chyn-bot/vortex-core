-- Migration: AR/AP document layer (vortex-accounting plugin)
--
-- Invoice/bill document lines and payment reconciliation on top of the
-- unified move model from 001. A document line is commercial data
-- (qty × price × tax); posting expands it into balanced GL lines.
-- Reconciliation matches receivable/payable move lines pairwise
-- (Odoo's partial-reconcile model) and drives amount_residual /
-- payment_state / aged balances.

-- ============================================================================
-- 1. acc_invoice_line — commercial document lines
-- ============================================================================
CREATE TABLE IF NOT EXISTS acc_invoice_line (
    id          UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    move_id     UUID          NOT NULL REFERENCES acc_move(id) ON DELETE CASCADE,
    sequence    INTEGER       NOT NULL DEFAULT 10,
    description VARCHAR(255)  NOT NULL,
    quantity    NUMERIC(20,4) NOT NULL DEFAULT 1,
    unit_price  NUMERIC(20,4) NOT NULL DEFAULT 0,
    tax_id      UUID          REFERENCES taxes(id),
    -- Income (customer docs) / expense (vendor docs) account override.
    -- NULL falls back to acc_config defaults at posting time.
    account_id  UUID          REFERENCES acc_account(id),
    company_id  UUID          REFERENCES companies(id),
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_acc_il_qty CHECK (quantity > 0)
);

CREATE INDEX IF NOT EXISTS idx_acc_il_move ON acc_invoice_line (move_id, sequence);

-- Document lines follow the same immutability rule as GL lines.
CREATE OR REPLACE FUNCTION acc_invoice_line_guard() RETURNS trigger AS $$
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
        RAISE EXCEPTION 'acc_invoice_line: document lines of a posted entry are immutable';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_acc_invoice_line_guard ON acc_invoice_line;
CREATE TRIGGER trg_acc_invoice_line_guard
    BEFORE INSERT OR UPDATE OR DELETE ON acc_invoice_line
    FOR EACH ROW EXECUTE FUNCTION acc_invoice_line_guard();

-- ============================================================================
-- 2. acc_partial_reconcile — payment ↔ document matching
-- ============================================================================
CREATE TABLE IF NOT EXISTS acc_partial_reconcile (
    id             UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- The receivable/payable line being settled (debit side for AR,
    -- credit side for AP) and the line settling it.
    debit_line_id  UUID          NOT NULL REFERENCES acc_move_line(id),
    credit_line_id UUID          NOT NULL REFERENCES acc_move_line(id),
    amount         NUMERIC(20,2) NOT NULL,
    company_id     UUID          REFERENCES companies(id),
    created_by     UUID          REFERENCES users(id),
    created_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_acc_pr_amount CHECK (amount > 0),
    CONSTRAINT chk_acc_pr_distinct CHECK (debit_line_id <> credit_line_id)
);

CREATE INDEX IF NOT EXISTS idx_acc_pr_debit  ON acc_partial_reconcile (debit_line_id);
CREATE INDEX IF NOT EXISTS idx_acc_pr_credit ON acc_partial_reconcile (credit_line_id);

-- ============================================================================
-- 3. Runtime role grants
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            acc_invoice_line, acc_partial_reconcile TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE acc_invoice_line IS
    'Commercial lines of an invoice/bill (qty × price × tax). Expanded into balanced GL lines when the document posts. Immutable once posted.';
COMMENT ON TABLE acc_partial_reconcile IS
    'Pairwise matching of receivable/payable move lines (invoice line vs payment line). Sum of matches drives acc_move.amount_residual and payment_state.';
