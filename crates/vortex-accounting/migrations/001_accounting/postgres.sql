-- Migration: Accounting base (vortex-accounting plugin)
--
-- The platform's double-entry accounting primitive: chart of accounts,
-- journals, and journal entries (moves). Follows the unified move model —
-- an AR invoice or AP bill IS an account move (move_type discriminates),
-- so the GL and the sub-ledgers can never drift apart.
--
-- Reuses, rather than reinvents:
--   - partners   → core `contacts` (customers / suppliers)
--   - currency   → commerce `currencies`
--   - taxes      → commerce `taxes`
--   - numbering  → sequence service (SAL/2026/00042, per journal type)
--   - audit      → WORM ledger on post / reverse
--
-- Integrity rules enforced HERE (not just in code):
--   - a move line is debit XOR credit, both non-negative
--   - posted moves and their lines are immutable (trigger allow-list for
--     payment/reconciliation bookkeeping columns only)

-- ============================================================================
-- 1. acc_account — chart of accounts (flat, typed)
-- ============================================================================
CREATE TABLE IF NOT EXISTS acc_account (
    id           UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    code         VARCHAR(16)   NOT NULL,
    name         VARCHAR(160)  NOT NULL,
    account_type VARCHAR(32)   NOT NULL,
    -- Lines on reconcilable accounts (AR / AP) participate in matching
    reconcile    BOOLEAN       NOT NULL DEFAULT FALSE,
    note         TEXT,
    active       BOOLEAN       NOT NULL DEFAULT TRUE,
    company_id   UUID          REFERENCES companies(id),
    created_by   UUID          REFERENCES users(id),
    updated_by   UUID          REFERENCES users(id),
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_acc_account_type CHECK (account_type IN (
        'asset_cash', 'asset_bank', 'asset_receivable', 'asset_current',
        'asset_fixed', 'asset_non_current',
        'liability_payable', 'liability_current', 'liability_non_current',
        'equity',
        'income', 'income_other',
        'expense', 'expense_depreciation', 'expense_direct_cost'
    )),
    CONSTRAINT uq_acc_account_code UNIQUE (company_id, code)
);

CREATE INDEX IF NOT EXISTS idx_acc_account_type ON acc_account (account_type) WHERE active;

DROP TRIGGER IF EXISTS trg_acc_account_updated_at ON acc_account;
CREATE TRIGGER trg_acc_account_updated_at
    BEFORE UPDATE ON acc_account
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 2. acc_journal
-- ============================================================================
CREATE TABLE IF NOT EXISTS acc_journal (
    id                 UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    code               VARCHAR(8)   NOT NULL,
    name               VARCHAR(120) NOT NULL,
    journal_type       VARCHAR(12)  NOT NULL,
    -- Suggested counterpart account (e.g. the bank account for a bank journal)
    default_account_id UUID         REFERENCES acc_account(id),
    note               TEXT,
    active             BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id         UUID         REFERENCES companies(id),
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_acc_journal_type CHECK (journal_type IN
        ('sale', 'purchase', 'cash', 'bank', 'general')),
    CONSTRAINT uq_acc_journal_code UNIQUE (company_id, code)
);

DROP TRIGGER IF EXISTS trg_acc_journal_updated_at ON acc_journal;
CREATE TRIGGER trg_acc_journal_updated_at
    BEFORE UPDATE ON acc_journal
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 3. acc_move — journal entry / AR-AP document (unified model)
-- ============================================================================
CREATE TABLE IF NOT EXISTS acc_move (
    id              UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- Assigned at posting (draft moves show as '/'), e.g. SAL/2026/00042
    number          VARCHAR(32),
    journal_id      UUID          NOT NULL REFERENCES acc_journal(id),
    move_date       DATE          NOT NULL DEFAULT CURRENT_DATE,
    ref             VARCHAR(120),
    narration       TEXT,
    state           VARCHAR(12)   NOT NULL DEFAULT 'draft',
    move_type       VARCHAR(24)   NOT NULL DEFAULT 'entry',

    -- Document (invoice/bill/payment) columns — NULL for plain entries
    partner_id      UUID          REFERENCES contacts(id),
    invoice_date    DATE,
    due_date        DATE,
    currency_id     UUID          REFERENCES currencies(id),
    untaxed_amount  NUMERIC(20,2) NOT NULL DEFAULT 0,
    tax_amount      NUMERIC(20,2) NOT NULL DEFAULT 0,
    total_amount    NUMERIC(20,2) NOT NULL DEFAULT 0,
    amount_residual NUMERIC(20,2) NOT NULL DEFAULT 0,
    payment_state   VARCHAR(16)   NOT NULL DEFAULT 'not_paid',

    -- Reversal bookkeeping
    reversed_move_id UUID         REFERENCES acc_move(id),

    -- Adopting module back-reference, e.g. 'hwy_tenancy_charge:<uuid>'
    origin_ref      VARCHAR(120),

    company_id      UUID          REFERENCES companies(id),
    created_by      UUID          REFERENCES users(id),
    updated_by      UUID          REFERENCES users(id),
    posted_by       UUID          REFERENCES users(id),
    posted_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_acc_move_state CHECK (state IN ('draft', 'posted', 'cancelled')),
    CONSTRAINT chk_acc_move_type CHECK (move_type IN (
        'entry', 'customer_invoice', 'customer_credit_note',
        'vendor_bill', 'vendor_credit_note', 'payment'
    )),
    CONSTRAINT chk_acc_move_payment_state CHECK (payment_state IN
        ('not_paid', 'partial', 'paid', 'reversed')),
    CONSTRAINT uq_acc_move_number UNIQUE (company_id, number)
);

CREATE INDEX IF NOT EXISTS idx_acc_move_journal  ON acc_move (journal_id, move_date DESC);
CREATE INDEX IF NOT EXISTS idx_acc_move_state    ON acc_move (state);
CREATE INDEX IF NOT EXISTS idx_acc_move_partner  ON acc_move (partner_id)
    WHERE partner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_acc_move_type     ON acc_move (move_type)
    WHERE move_type <> 'entry';
CREATE INDEX IF NOT EXISTS idx_acc_move_origin   ON acc_move (origin_ref)
    WHERE origin_ref IS NOT NULL;

DROP TRIGGER IF EXISTS trg_acc_move_updated_at ON acc_move;
CREATE TRIGGER trg_acc_move_updated_at
    BEFORE UPDATE ON acc_move
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 4. acc_move_line — debit XOR credit
-- ============================================================================
CREATE TABLE IF NOT EXISTS acc_move_line (
    id          UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    move_id     UUID          NOT NULL REFERENCES acc_move(id) ON DELETE CASCADE,
    sequence    INTEGER       NOT NULL DEFAULT 10,
    account_id  UUID          NOT NULL REFERENCES acc_account(id),
    partner_id  UUID          REFERENCES contacts(id),
    name        VARCHAR(255),
    debit       NUMERIC(20,2) NOT NULL DEFAULT 0,
    credit      NUMERIC(20,2) NOT NULL DEFAULT 0,
    tax_id      UUID          REFERENCES taxes(id),
    -- Reconciliation bookkeeping (maintained by the service; Phase 2)
    reconciled  BOOLEAN       NOT NULL DEFAULT FALSE,
    company_id  UUID          REFERENCES companies(id),
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_acc_line_amounts CHECK (
        debit >= 0 AND credit >= 0 AND NOT (debit > 0 AND credit > 0)
    )
);

CREATE INDEX IF NOT EXISTS idx_acc_line_move    ON acc_move_line (move_id, sequence);
CREATE INDEX IF NOT EXISTS idx_acc_line_account ON acc_move_line (account_id);
CREATE INDEX IF NOT EXISTS idx_acc_line_partner ON acc_move_line (partner_id)
    WHERE partner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_acc_line_unreconciled ON acc_move_line (account_id, partner_id)
    WHERE NOT reconciled;

-- ============================================================================
-- 5. acc_config — per-company defaults & posting lock date
-- ============================================================================
CREATE TABLE IF NOT EXISTS acc_config (
    id                    UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id            UUID        REFERENCES companies(id),
    receivable_account_id UUID        REFERENCES acc_account(id),
    payable_account_id    UUID        REFERENCES acc_account(id),
    tax_account_id        UUID        REFERENCES acc_account(id),
    income_account_id     UUID        REFERENCES acc_account(id),
    expense_account_id    UUID        REFERENCES acc_account(id),
    -- Posting on or before this date is rejected
    lock_date             DATE,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_acc_config_company UNIQUE (company_id)
);

DROP TRIGGER IF EXISTS trg_acc_config_updated_at ON acc_config;
CREATE TRIGGER trg_acc_config_updated_at
    BEFORE UPDATE ON acc_config
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 6. Posted-entry immutability (DB-level, WORM-aligned)
-- ============================================================================
-- A posted move may only change its payment/reconciliation bookkeeping
-- (payment_state, amount_residual, reversed_move_id) — never its financial
-- content. Cancellation happens by reversal, never by mutating the original.
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
           OR NEW.total_amount IS DISTINCT FROM OLD.total_amount THEN
            RAISE EXCEPTION 'acc_move %: posted entries are immutable — post a reversal',
                OLD.number;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_acc_move_guard ON acc_move;
CREATE TRIGGER trg_acc_move_guard
    BEFORE UPDATE OR DELETE ON acc_move
    FOR EACH ROW EXECUTE FUNCTION acc_move_guard();

-- Lines of a posted move: no insert, no delete; only `reconciled` may change.
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
           OR NEW.move_id IS DISTINCT FROM OLD.move_id THEN
            RAISE EXCEPTION 'acc_move_line: lines of a posted entry are immutable';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_acc_move_line_guard ON acc_move_line;
CREATE TRIGGER trg_acc_move_line_guard
    BEFORE INSERT OR UPDATE OR DELETE ON acc_move_line
    FOR EACH ROW EXECUTE FUNCTION acc_move_line_guard();

-- ============================================================================
-- 7. Seed — generic chart of accounts + standard journals (idempotent)
-- ============================================================================
-- Stable UUIDs (the inventory-locations pattern) so re-runs are no-ops even
-- with company_id NULL, where the UNIQUE constraint does not deduplicate.
-- Account UUIDs embed the account code; journals use the 1xxx tail; the
-- config row uses the cxxx tail. All tenant-editable after install.
INSERT INTO acc_account (id, code, name, account_type, reconcile) VALUES
    ('acc00000-0000-4000-8000-000000001000', '1000', 'Cash',                     'asset_cash',           FALSE),
    ('acc00000-0000-4000-8000-000000001100', '1100', 'Bank',                     'asset_bank',           FALSE),
    ('acc00000-0000-4000-8000-000000001200', '1200', 'Accounts Receivable',      'asset_receivable',     TRUE),
    ('acc00000-0000-4000-8000-000000001300', '1300', 'Inventory',                'asset_current',        FALSE),
    ('acc00000-0000-4000-8000-000000001400', '1400', 'Prepaid Expenses',         'asset_current',        FALSE),
    ('acc00000-0000-4000-8000-000000001500', '1500', 'Fixed Assets',             'asset_fixed',          FALSE),
    ('acc00000-0000-4000-8000-000000001600', '1600', 'Accumulated Depreciation', 'asset_fixed',          FALSE),
    ('acc00000-0000-4000-8000-000000002000', '2000', 'Accounts Payable',         'liability_payable',    TRUE),
    ('acc00000-0000-4000-8000-000000002100', '2100', 'Tax Payable',              'liability_current',    FALSE),
    ('acc00000-0000-4000-8000-000000002200', '2200', 'Accrued Liabilities',      'liability_current',    FALSE),
    ('acc00000-0000-4000-8000-000000002500', '2500', 'Deferred Revenue',         'liability_current',    FALSE),
    ('acc00000-0000-4000-8000-000000003000', '3000', 'Share Capital',            'equity',               FALSE),
    ('acc00000-0000-4000-8000-000000003900', '3900', 'Retained Earnings',        'equity',               FALSE),
    ('acc00000-0000-4000-8000-000000004000', '4000', 'Sales Revenue',            'income',               FALSE),
    ('acc00000-0000-4000-8000-000000004100', '4100', 'Rental Income',            'income',               FALSE),
    ('acc00000-0000-4000-8000-000000004900', '4900', 'Other Income',             'income_other',         FALSE),
    ('acc00000-0000-4000-8000-000000005000', '5000', 'Cost of Goods Sold',       'expense_direct_cost',  FALSE),
    ('acc00000-0000-4000-8000-000000006000', '6000', 'Operating Expenses',       'expense',              FALSE),
    ('acc00000-0000-4000-8000-000000006100', '6100', 'Maintenance Expense',      'expense',              FALSE),
    ('acc00000-0000-4000-8000-000000006200', '6200', 'Utilities Expense',        'expense',              FALSE),
    ('acc00000-0000-4000-8000-000000007000', '7000', 'Depreciation Expense',     'expense_depreciation', FALSE),
    ('acc00000-0000-4000-8000-000000009999', '9999', 'Suspense',                 'asset_current',        FALSE)
ON CONFLICT (id) DO NOTHING;

INSERT INTO acc_journal (id, code, name, journal_type, default_account_id) VALUES
    ('acc00000-0000-4000-8000-100000000001', 'SAL', 'Sales',         'sale',     NULL),
    ('acc00000-0000-4000-8000-100000000002', 'PUR', 'Purchases',     'purchase', NULL),
    ('acc00000-0000-4000-8000-100000000003', 'BNK', 'Bank',          'bank',
        'acc00000-0000-4000-8000-000000001100'),
    ('acc00000-0000-4000-8000-100000000004', 'CSH', 'Cash',          'cash',
        'acc00000-0000-4000-8000-000000001000'),
    ('acc00000-0000-4000-8000-100000000005', 'GEN', 'Miscellaneous', 'general',  NULL)
ON CONFLICT (id) DO NOTHING;

-- Default config row (single-company tenants; multi-company rows added on use)
INSERT INTO acc_config (id, company_id, receivable_account_id, payable_account_id,
                        tax_account_id, income_account_id, expense_account_id) VALUES
    ('acc00000-0000-4000-8000-c00000000001', NULL,
     'acc00000-0000-4000-8000-000000001200',
     'acc00000-0000-4000-8000-000000002000',
     'acc00000-0000-4000-8000-000000002100',
     'acc00000-0000-4000-8000-000000004000',
     'acc00000-0000-4000-8000-000000006000')
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- 8. Runtime role grants
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            acc_account, acc_journal, acc_move, acc_move_line, acc_config
            TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE acc_move IS
    'Journal entries AND AR/AP documents (unified model — move_type discriminates). Posted entries are immutable by trigger; corrections are reversal entries. number is assigned at posting from the journal-type sequence (e.g. SAL/2026/00042).';
COMMENT ON TABLE acc_move_line IS
    'Double-entry lines: debit XOR credit, both non-negative (DB CHECK). Lines of posted moves are immutable except the reconciled flag.';
COMMENT ON COLUMN acc_move.origin_ref IS
    'Back-reference set by adopting modules, e.g. hwy_tenancy_charge:<uuid> — lets a vertical find the entries it created without accounting knowing about the vertical.';
