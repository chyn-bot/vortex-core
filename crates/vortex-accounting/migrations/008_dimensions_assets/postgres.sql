-- Migration 008: Dimensions, budgets, recurring entries, fixed assets
--
-- Analytic dimensions (project/department) land ON acc_move_line and
-- are therefore added to the LINE guard deny-list: retagging a posted
-- line is a reclass entry, by design. Budgets, recurring templates and
-- the asset register are satellites — no other guard churn.

-- ─── Analytic dimensions ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS acc_dimension (
    id         UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    dim_type   VARCHAR(12)  NOT NULL,
    code       VARCHAR(24)  NOT NULL,
    name       VARCHAR(120) NOT NULL,
    active     BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id UUID         REFERENCES companies(id),
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_acc_dim_type CHECK (dim_type IN ('project', 'department')),
    CONSTRAINT uq_acc_dim UNIQUE (company_id, dim_type, code)
);

ALTER TABLE acc_move_line ADD COLUMN IF NOT EXISTS project_id    UUID REFERENCES acc_dimension(id);
ALTER TABLE acc_move_line ADD COLUMN IF NOT EXISTS department_id UUID REFERENCES acc_dimension(id);

CREATE INDEX IF NOT EXISTS idx_acc_line_project    ON acc_move_line (project_id)    WHERE project_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_acc_line_department ON acc_move_line (department_id) WHERE department_id IS NOT NULL;

-- Re-declare the LINE guard with the FULL deny-list. Current list
-- (001 + 004 tax_base_amount + 006 currency_id/amount_currency) plus
-- NEW: project_id, department_id.
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
           OR NEW.amount_currency IS DISTINCT FROM OLD.amount_currency
           OR NEW.project_id IS DISTINCT FROM OLD.project_id
           OR NEW.department_id IS DISTINCT FROM OLD.department_id THEN
            RAISE EXCEPTION 'acc_move_line: lines of a posted entry are immutable';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ─── Budgets ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS acc_budget (
    id         UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name       VARCHAR(120) NOT NULL,
    date_from  DATE         NOT NULL,
    date_to    DATE         NOT NULL,
    state      VARCHAR(10)  NOT NULL DEFAULT 'draft',
    company_id UUID         REFERENCES companies(id),
    created_by UUID         REFERENCES users(id),
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_acc_budget_state CHECK (state IN ('draft', 'confirmed', 'done')),
    CONSTRAINT chk_acc_budget_dates CHECK (date_to >= date_from)
);

CREATE TABLE IF NOT EXISTS acc_budget_line (
    id         UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    budget_id  UUID          NOT NULL REFERENCES acc_budget(id) ON DELETE CASCADE,
    account_id UUID          NOT NULL REFERENCES acc_account(id),
    -- First day of the month this amount budgets.
    period     DATE          NOT NULL,
    project_id UUID          REFERENCES acc_dimension(id),
    amount     NUMERIC(20,2) NOT NULL DEFAULT 0,
    CONSTRAINT uq_acc_budget_line UNIQUE (budget_id, account_id, period, project_id)
);

CREATE INDEX IF NOT EXISTS idx_acc_budget_line ON acc_budget_line (budget_id);

DROP TRIGGER IF EXISTS trg_acc_budget_updated_at ON acc_budget;
CREATE TRIGGER trg_acc_budget_updated_at
    BEFORE UPDATE ON acc_budget
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Recurring entries ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS acc_recurring (
    id           UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name         VARCHAR(120) NOT NULL,
    journal_code VARCHAR(12)  NOT NULL DEFAULT 'GEN',
    -- Months between generations: 1 monthly, 3 quarterly, 12 yearly.
    interval_months INT       NOT NULL DEFAULT 1,
    next_date    DATE         NOT NULL,
    end_date     DATE,
    auto_post    BOOLEAN      NOT NULL DEFAULT FALSE,
    ref          VARCHAR(120),
    -- Line template: [{"account_code", "name", "debit", "credit",
    --                  "partner_id"?, "project_id"?, "department_id"?}]
    lines        JSONB        NOT NULL,
    active       BOOLEAN      NOT NULL DEFAULT TRUE,
    last_move_id UUID         REFERENCES acc_move(id),
    company_id   UUID         REFERENCES companies(id),
    created_by   UUID         REFERENCES users(id),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_acc_recurring_interval CHECK (interval_months BETWEEN 1 AND 12)
);

DROP TRIGGER IF EXISTS trg_acc_recurring_updated_at ON acc_recurring;
CREATE TRIGGER trg_acc_recurring_updated_at
    BEFORE UPDATE ON acc_recurring
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Fixed assets (MFRS 116, straight-line v1) ────────────────────────

CREATE TABLE IF NOT EXISTS acc_asset (
    id                      UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                    VARCHAR(160)  NOT NULL,
    reference               VARCHAR(60),
    asset_account_id        UUID          NOT NULL REFERENCES acc_account(id),
    depreciation_account_id UUID          NOT NULL REFERENCES acc_account(id),
    expense_account_id      UUID          NOT NULL REFERENCES acc_account(id),
    cost                    NUMERIC(20,2) NOT NULL,
    salvage_value           NUMERIC(20,2) NOT NULL DEFAULT 0,
    life_months             INT           NOT NULL,
    -- Depreciation starts this month (full-month convention).
    start_date              DATE          NOT NULL,
    method                  VARCHAR(16)   NOT NULL DEFAULT 'straight_line',
    state                   VARCHAR(18)   NOT NULL DEFAULT 'draft',
    acquisition_move_id     UUID          REFERENCES acc_move(id),
    disposal_move_id        UUID          REFERENCES acc_move(id),
    origin_ref              VARCHAR(160),
    project_id              UUID          REFERENCES acc_dimension(id),
    department_id           UUID          REFERENCES acc_dimension(id),
    company_id              UUID          REFERENCES companies(id),
    created_by              UUID          REFERENCES users(id),
    created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_acc_asset_method CHECK (method IN ('straight_line')),
    CONSTRAINT chk_acc_asset_state CHECK (state IN
        ('draft', 'running', 'fully_depreciated', 'disposed')),
    CONSTRAINT chk_acc_asset_cost CHECK (cost > 0),
    CONSTRAINT chk_acc_asset_salvage CHECK (salvage_value >= 0 AND salvage_value <= cost),
    CONSTRAINT chk_acc_asset_life CHECK (life_months BETWEEN 1 AND 1200)
);

CREATE TABLE IF NOT EXISTS acc_asset_depreciation (
    id         UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id   UUID          NOT NULL REFERENCES acc_asset(id) ON DELETE CASCADE,
    seq        INT           NOT NULL,
    dep_date   DATE          NOT NULL,
    amount     NUMERIC(20,2) NOT NULL,
    cumulative NUMERIC(20,2) NOT NULL,
    move_id    UUID          REFERENCES acc_move(id),
    state      VARCHAR(8)    NOT NULL DEFAULT 'planned',
    CONSTRAINT chk_acc_dep_state CHECK (state IN ('planned', 'posted')),
    CONSTRAINT uq_acc_dep UNIQUE (asset_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_acc_dep_due ON acc_asset_depreciation (dep_date) WHERE state = 'planned';

DROP TRIGGER IF EXISTS trg_acc_asset_updated_at ON acc_asset;
CREATE TRIGGER trg_acc_asset_updated_at
    BEFORE UPDATE ON acc_asset
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Disposal gain/loss presented separately (MFRS 116 ¶68).
INSERT INTO acc_account (id, code, name, account_type, reconcile) VALUES
    ('acc00000-0000-4000-8000-000000004970', '4970', 'Gain on Asset Disposal', 'income_other', FALSE),
    ('acc00000-0000-4000-8000-000000006970', '6970', 'Loss on Asset Disposal', 'expense',      FALSE)
ON CONFLICT (id) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            acc_dimension, acc_budget, acc_budget_line, acc_recurring,
            acc_asset, acc_asset_depreciation
            TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE acc_dimension IS
    'Analytic dimensions (project/department) tagged on journal-entry lines; posted tags are immutable — retag via reclass entry.';
COMMENT ON TABLE acc_asset IS
    'Fixed asset register: straight-line schedule generated on confirm, monthly depreciation posted by scheduled action, disposal posts gain/loss.';
