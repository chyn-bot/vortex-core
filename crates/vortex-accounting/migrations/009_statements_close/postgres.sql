-- Migration 009: MFRS statement pack + year-end close
--
-- Account groups give the statements their note-level structure
-- (MPERS-shaped defaults seeded from the 15 account types); the
-- two-tier lock adds a tax lock (documents) under the general lock.
-- No guard churn — satellites and acc_config columns only.

CREATE TABLE IF NOT EXISTS acc_account_group (
    id         UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    code       VARCHAR(24)  NOT NULL,
    name       VARCHAR(120) NOT NULL,
    -- Which statement the group belongs to and where.
    section    VARCHAR(32)  NOT NULL,
    sequence   INT          NOT NULL DEFAULT 100,
    company_id UUID         REFERENCES companies(id),
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_acc_group UNIQUE (company_id, code),
    CONSTRAINT chk_acc_group_section CHECK (section IN (
        'current_assets', 'non_current_assets',
        'current_liabilities', 'non_current_liabilities',
        'equity',
        'revenue', 'other_income', 'cost_of_sales', 'expenses', 'depreciation'
    ))
);

ALTER TABLE acc_account ADD COLUMN IF NOT EXISTS group_id UUID REFERENCES acc_account_group(id);

-- MPERS-shaped default groups.
INSERT INTO acc_account_group (id, code, name, section, sequence) VALUES
    ('accb0000-0000-4000-8000-000000000010', 'CASH',  'Cash and Cash Equivalents',   'current_assets',          10),
    ('accb0000-0000-4000-8000-000000000020', 'TRADE', 'Trade and Other Receivables', 'current_assets',          20),
    ('accb0000-0000-4000-8000-000000000030', 'OCA',   'Other Current Assets',        'current_assets',          30),
    ('accb0000-0000-4000-8000-000000000040', 'PPE',   'Property, Plant & Equipment', 'non_current_assets',      40),
    ('accb0000-0000-4000-8000-000000000050', 'ONCA',  'Other Non-current Assets',    'non_current_assets',      50),
    ('accb0000-0000-4000-8000-000000000060', 'AP',    'Trade and Other Payables',    'current_liabilities',     60),
    ('accb0000-0000-4000-8000-000000000070', 'OCL',   'Other Current Liabilities',   'current_liabilities',     70),
    ('accb0000-0000-4000-8000-000000000080', 'NCL',   'Non-current Liabilities',     'non_current_liabilities', 80),
    ('accb0000-0000-4000-8000-000000000090', 'EQTY',  'Equity',                      'equity',                  90),
    ('accb0000-0000-4000-8000-000000000100', 'REV',   'Revenue',                     'revenue',                100),
    ('accb0000-0000-4000-8000-000000000110', 'OINC',  'Other Income',                'other_income',           110),
    ('accb0000-0000-4000-8000-000000000120', 'COS',   'Cost of Sales',               'cost_of_sales',          120),
    ('accb0000-0000-4000-8000-000000000130', 'OPEX',  'Operating Expenses',          'expenses',               130),
    ('accb0000-0000-4000-8000-000000000140', 'DEP',   'Depreciation & Amortisation', 'depreciation',           140)
ON CONFLICT (id) DO NOTHING;

-- Default mapping: account_type → group (only where unset).
UPDATE acc_account a SET group_id = g.id
FROM acc_account_group g
WHERE a.group_id IS NULL AND g.code = CASE a.account_type
    WHEN 'asset_cash'            THEN 'CASH'
    WHEN 'asset_bank'            THEN 'CASH'
    WHEN 'asset_receivable'      THEN 'TRADE'
    WHEN 'asset_current'         THEN 'OCA'
    WHEN 'asset_fixed'           THEN 'PPE'
    WHEN 'asset_non_current'     THEN 'ONCA'
    WHEN 'liability_payable'     THEN 'AP'
    WHEN 'liability_current'     THEN 'OCL'
    WHEN 'liability_non_current' THEN 'NCL'
    WHEN 'equity'                THEN 'EQTY'
    WHEN 'income'                THEN 'REV'
    WHEN 'income_other'          THEN 'OINC'
    WHEN 'expense_direct_cost'   THEN 'COS'
    WHEN 'expense'               THEN 'OPEX'
    WHEN 'expense_depreciation'  THEN 'DEP'
END;

-- Two-tier lock + fiscal-year-end configuration.
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS fiscal_year_end_month INT NOT NULL DEFAULT 12;
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS tax_lock_date DATE;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_acc_config_fye') THEN
        ALTER TABLE acc_config ADD CONSTRAINT chk_acc_config_fye
            CHECK (fiscal_year_end_month BETWEEN 1 AND 12);
    END IF;
END$$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON acc_account_group TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE acc_account_group IS
    'Statement-note grouping for the MFRS pack (SOFP/SOPL/SOCIE/cash flow); accounts map to groups, groups to statement sections.';
