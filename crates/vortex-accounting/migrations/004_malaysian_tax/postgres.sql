-- Migration 004: Malaysian tax engine + fiscal calendar
--
-- Foundations for SST accounting and MFRS-grade period control:
--   - acc_tax_config: per-tax GL account + SST category + MyInvois tax
--     type code (satellite over commerce `taxes` — core stays generic)
--   - acc_partner_tax_profile: TIN / ID / SST registration / MSIC per
--     partner (satellite over core `contacts`)
--   - company tax identity on acc_config
--   - acc_fiscal_year: open/closed years; posting into a closed year is
--     rejected by the service layer
--   - acc_move_line.tax_base_amount: taxable base carried on generated
--     tax lines so SST-02 reads straight off the GL
--
-- GUARD LEDGER: this migration re-declares acc_move_line_guard() adding
-- `tax_base_amount` to the posted-immutable deny-list. Full line
-- deny-list after this migration: account_id, partner_id, debit,
-- credit, tax_id, move_id, tax_base_amount (mutable: reconciled).

-- ============================================================================
-- 1. acc_tax_config — accounting behaviour of a commerce tax
-- ============================================================================
CREATE TABLE IF NOT EXISTS acc_tax_config (
    id                    UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    tax_id                UUID         NOT NULL REFERENCES taxes(id),
    -- GL account tax lines post to (falls back to acc_config.tax_account_id)
    tax_account_id        UUID         REFERENCES acc_account(id),
    -- SST bucket for the SST-02 return
    sst_category          VARCHAR(24)  NOT NULL DEFAULT 'out_of_scope',
    -- LHDN e-invoice TaxCategory code: 01 sales, 02 service, E exempt, 06 n/a
    myinvois_tax_type     VARCHAR(4)   NOT NULL DEFAULT '06',
    exemption_reason      VARCHAR(160),
    company_id            UUID         REFERENCES companies(id),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_acc_tax_cfg_category CHECK (sst_category IN (
        'sales_tax_5', 'sales_tax_10', 'service_tax_6', 'service_tax_8',
        'exempt', 'zero_rated', 'out_of_scope'
    )),
    CONSTRAINT uq_acc_tax_cfg UNIQUE (tax_id, company_id)
);

DROP TRIGGER IF EXISTS trg_acc_tax_cfg_updated_at ON acc_tax_config;
CREATE TRIGGER trg_acc_tax_cfg_updated_at
    BEFORE UPDATE ON acc_tax_config
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 2. acc_partner_tax_profile — Malaysian tax identity of a partner
-- ============================================================================
CREATE TABLE IF NOT EXISTS acc_partner_tax_profile (
    id               UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    contact_id       UUID         NOT NULL REFERENCES contacts(id),
    tin              VARCHAR(20),
    id_type          VARCHAR(10),
    id_value         VARCHAR(30),
    sst_registration VARCHAR(30),
    msic_code        VARCHAR(10),
    einvoice_email   VARCHAR(160),
    -- Partner opted out of individual e-invoices (goes to consolidated)
    einvoice_optout  BOOLEAN      NOT NULL DEFAULT FALSE,
    company_id       UUID         REFERENCES companies(id),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_acc_ptp_id_type CHECK (id_type IS NULL OR id_type IN
        ('BRN', 'NRIC', 'PASSPORT', 'ARMY')),
    CONSTRAINT uq_acc_ptp UNIQUE (contact_id, company_id)
);

DROP TRIGGER IF EXISTS trg_acc_ptp_updated_at ON acc_partner_tax_profile;
CREATE TRIGGER trg_acc_ptp_updated_at
    BEFORE UPDATE ON acc_partner_tax_profile
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 3. Company tax identity + SST period on acc_config
-- ============================================================================
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_tin VARCHAR(20);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_id_type VARCHAR(10);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_id_value VARCHAR(30);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_sst_registration VARCHAR(30);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_msic_code VARCHAR(10);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS company_business_activity VARCHAR(200);
ALTER TABLE acc_config ADD COLUMN IF NOT EXISTS sst_period_months SMALLINT NOT NULL DEFAULT 2;

-- ============================================================================
-- 4. acc_fiscal_year
-- ============================================================================
CREATE TABLE IF NOT EXISTS acc_fiscal_year (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    code            VARCHAR(16)  NOT NULL,
    date_from       DATE         NOT NULL,
    date_to         DATE         NOT NULL,
    state           VARCHAR(8)   NOT NULL DEFAULT 'open',
    -- Set by year-end close (phase 6); reversal on reopen
    closing_move_id UUID         REFERENCES acc_move(id),
    company_id      UUID         REFERENCES companies(id),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_acc_fy_state CHECK (state IN ('open', 'closed')),
    CONSTRAINT chk_acc_fy_range CHECK (date_to > date_from),
    CONSTRAINT uq_acc_fy_code UNIQUE (company_id, code)
);

-- Overlap between fiscal years is enforced in the service layer
-- (fiscal_year_overlapping) — a GiST exclusion constraint would drag in
-- the btree_gist extension as a per-tenant dependency for little gain.

DROP TRIGGER IF EXISTS trg_acc_fy_updated_at ON acc_fiscal_year;
CREATE TRIGGER trg_acc_fy_updated_at
    BEFORE UPDATE ON acc_fiscal_year
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 5. tax_base_amount on move lines + guard re-declaration
-- ============================================================================
ALTER TABLE acc_move_line ADD COLUMN IF NOT EXISTS tax_base_amount NUMERIC(20,2);

-- Re-declare the line guard with tax_base_amount in the deny-list.
-- FULL deny-list (keep in sync when later migrations extend it):
--   account_id, partner_id, debit, credit, tax_id, move_id,
--   tax_base_amount        [mutable: reconciled]
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
           OR NEW.tax_base_amount IS DISTINCT FROM OLD.tax_base_amount THEN
            RAISE EXCEPTION 'acc_move_line: lines of a posted entry are immutable';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 6. Seeds — Malaysian tax set + SST GL accounts + tax configs
-- ============================================================================
INSERT INTO acc_account (id, code, name, account_type, reconcile) VALUES
    ('acc00000-0000-4000-8000-000000002110', '2110', 'SST Output Tax Payable', 'liability_current', FALSE),
    ('acc00000-0000-4000-8000-000000001450', '1450', 'SST Input Tax',          'asset_current',     FALSE)
ON CONFLICT (id) DO NOTHING;

-- Current Malaysian rates (post July-2025 expansion). Existing generic
-- seeds (SST 6%, Service Tax 10%, Purchase SST 6%, Exempt) stay valid;
-- these add the full current set.
INSERT INTO taxes (name, description, amount_type, amount, type_tax_use, price_include) VALUES
    ('Sales Tax 5%',           'Malaysian sales tax 5% (manufacturer/import)',  'percent', 5,  'sale',     FALSE),
    ('Sales Tax 10%',          'Malaysian sales tax 10% (manufacturer/import)', 'percent', 10, 'sale',     FALSE),
    ('Service Tax 8%',         'Malaysian service tax 8% (standard)',           'percent', 8,  'sale',     FALSE),
    ('Service Tax 6%',         'Malaysian service tax 6% (F&B, telco, parking, logistics)', 'percent', 6, 'sale', FALSE),
    ('Purchase Sales Tax 5%',  'Sales tax 5% on purchases',                     'percent', 5,  'purchase', FALSE),
    ('Purchase Sales Tax 10%', 'Sales tax 10% on purchases',                    'percent', 10, 'purchase', FALSE),
    ('Purchase Service Tax 8%','Service tax 8% on purchases',                   'percent', 8,  'purchase', FALSE)
ON CONFLICT (name) DO NOTHING;

-- Tax configs: category + MyInvois code + GL account per seeded tax.
-- 01 = Sales Tax, 02 = Service Tax, E = exempt, 06 = not applicable.
INSERT INTO acc_tax_config (id, tax_id, tax_account_id, sst_category, myinvois_tax_type)
SELECT
    ('acc00000-0000-4000-8000-a' || lpad(to_hex(row_number() OVER (ORDER BY t.name)), 11, '0'))::uuid,
    t.id,
    CASE WHEN t.type_tax_use = 'purchase'
         THEN 'acc00000-0000-4000-8000-000000001450'::uuid
         ELSE 'acc00000-0000-4000-8000-000000002110'::uuid END,
    CASE
        WHEN t.name IN ('Sales Tax 5%',  'Purchase Sales Tax 5%')  THEN 'sales_tax_5'
        WHEN t.name IN ('Sales Tax 10%', 'Purchase Sales Tax 10%', 'Service Tax 10%') THEN 'sales_tax_10'
        WHEN t.name IN ('Service Tax 8%','Purchase Service Tax 8%') THEN 'service_tax_8'
        WHEN t.name IN ('Service Tax 6%','SST 6%', 'Purchase SST 6%') THEN 'service_tax_6'
        WHEN t.name = 'Exempt' THEN 'exempt'
        ELSE 'out_of_scope'
    END,
    CASE
        WHEN t.name LIKE '%Sales Tax%' THEN '01'
        WHEN t.name LIKE '%Service Tax%' OR t.name LIKE '%SST%' THEN '02'
        WHEN t.name = 'Exempt' THEN 'E'
        ELSE '06'
    END
FROM taxes t
WHERE t.name IN ('Sales Tax 5%','Sales Tax 10%','Service Tax 8%','Service Tax 6%',
                 'Purchase Sales Tax 5%','Purchase Sales Tax 10%','Purchase Service Tax 8%',
                 'SST 6%','Service Tax 10%','Purchase SST 6%','Exempt')
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- 7. Runtime role grants
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            acc_tax_config, acc_partner_tax_profile, acc_fiscal_year
            TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE acc_tax_config IS
    'Accounting behaviour of a commerce tax: GL account, SST-02 category, MyInvois tax type code. Satellite table — commerce `taxes` stays industry-neutral.';
COMMENT ON TABLE acc_fiscal_year IS
    'Fiscal years. Posting into a closed year is rejected by the posting service; closing entry linked via closing_move_id (year-end close, migration 009 phase).';
COMMENT ON COLUMN acc_move_line.tax_base_amount IS
    'On generated tax lines: the taxable base this tax amount was computed from — SST-02 taxable value reads straight off the GL.';
