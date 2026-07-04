-- Migration 007: Banking + AR/AP operations
--
-- Bank statement import/reconciliation, post-dated cheques, AR↔AP
-- contra, configurable aging buckets, credit control. All satellite
-- tables — the posted-move guards are untouched.

CREATE TABLE IF NOT EXISTS acc_bank_statement (
    id              UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    journal_id      UUID          NOT NULL REFERENCES acc_journal(id),
    name            VARCHAR(120),
    statement_date  DATE          NOT NULL DEFAULT CURRENT_DATE,
    opening_balance NUMERIC(20,2) NOT NULL DEFAULT 0,
    closing_balance NUMERIC(20,2) NOT NULL DEFAULT 0,
    state           VARCHAR(12)   NOT NULL DEFAULT 'open',
    file_key        VARCHAR(512),
    company_id      UUID          REFERENCES companies(id),
    created_by      UUID          REFERENCES users(id),
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_acc_bstmt_state CHECK (state IN ('open', 'reconciled'))
);

CREATE TABLE IF NOT EXISTS acc_bank_statement_line (
    id              UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    statement_id    UUID          NOT NULL REFERENCES acc_bank_statement(id) ON DELETE CASCADE,
    line_date       DATE          NOT NULL,
    description     VARCHAR(300)  NOT NULL DEFAULT '',
    -- Signed: positive = money in
    amount          NUMERIC(20,2) NOT NULL,
    partner_hint    VARCHAR(160),
    matched_line_id UUID          REFERENCES acc_move_line(id),
    matched_by      UUID          REFERENCES users(id),
    matched_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_acc_bstmt_line ON acc_bank_statement_line (statement_id);

DROP TRIGGER IF EXISTS trg_acc_bstmt_updated_at ON acc_bank_statement;
CREATE TRIGGER trg_acc_bstmt_updated_at
    BEFORE UPDATE ON acc_bank_statement
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS acc_pdc (
    id               UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    direction        VARCHAR(8)    NOT NULL,
    partner_id       UUID          NOT NULL REFERENCES contacts(id),
    cheque_no        VARCHAR(40)   NOT NULL,
    bank_name        VARCHAR(120),
    amount           NUMERIC(20,2) NOT NULL,
    maturity_date    DATE          NOT NULL,
    state            VARCHAR(10)   NOT NULL DEFAULT 'holding',
    holding_move_id  UUID          REFERENCES acc_move(id),
    clearing_move_id UUID          REFERENCES acc_move(id),
    memo             VARCHAR(200),
    company_id       UUID          REFERENCES companies(id),
    created_by       UUID          REFERENCES users(id),
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_acc_pdc_dir CHECK (direction IN ('received', 'issued')),
    CONSTRAINT chk_acc_pdc_state CHECK (state IN ('holding', 'cleared', 'bounced', 'cancelled')),
    CONSTRAINT chk_acc_pdc_amount CHECK (amount > 0)
);

CREATE INDEX IF NOT EXISTS idx_acc_pdc_maturity ON acc_pdc (maturity_date) WHERE state = 'holding';

DROP TRIGGER IF EXISTS trg_acc_pdc_updated_at ON acc_pdc;
CREATE TRIGGER trg_acc_pdc_updated_at
    BEFORE UPDATE ON acc_pdc
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- PDC holding accounts
INSERT INTO acc_account (id, code, name, account_type, reconcile) VALUES
    ('acc00000-0000-4000-8000-000000001150', '1150', 'Post-dated Cheques Received', 'asset_current',     FALSE),
    ('acc00000-0000-4000-8000-000000002150', '2150', 'Post-dated Cheques Issued',   'liability_current', FALSE)
ON CONFLICT (id) DO NOTHING;

-- Aging buckets + credit policy
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS aging_buckets JSONB NOT NULL DEFAULT '[30,60,90,120]';
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS credit_limit_policy VARCHAR(8) NOT NULL DEFAULT 'off';

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            acc_bank_statement, acc_bank_statement_line, acc_pdc
            TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE acc_pdc IS
    'Post-dated cheques: recorded into a holding account, cleared to bank on maturity (daily scheduled action), bounced by reversal.';
