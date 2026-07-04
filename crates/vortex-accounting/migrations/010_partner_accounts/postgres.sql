-- Migration 010: per-contact receivable/payable control accounts
--
-- AutoCount/Odoo pattern: a contact can carry its own AR/AP control
-- account (non-trade customers, utility vendors, staff advances…);
-- document posting, payments, PDC and contra resolve the partner's
-- account first and fall back to the company default. Satellite
-- columns only — no guard churn.

ALTER TABLE acc_partner_tax_profile
    ADD COLUMN IF NOT EXISTS receivable_account_id UUID REFERENCES acc_account(id);
ALTER TABLE acc_partner_tax_profile
    ADD COLUMN IF NOT EXISTS payable_account_id UUID REFERENCES acc_account(id);

-- Ready-made non-trade control accounts (reconcilable, like 1200/2000).
INSERT INTO acc_account (id, code, name, account_type, reconcile) VALUES
    ('acc00000-0000-4000-8000-000000001210', '1210', 'Non-trade Receivables', 'asset_receivable',  TRUE),
    ('acc00000-0000-4000-8000-000000002010', '2010', 'Non-trade Payables',    'liability_payable', TRUE)
ON CONFLICT (id) DO NOTHING;

COMMENT ON COLUMN acc_partner_tax_profile.receivable_account_id IS
    'Partner-specific AR control account; NULL = company default from acc_config.';
COMMENT ON COLUMN acc_partner_tax_profile.payable_account_id IS
    'Partner-specific AP control account; NULL = company default from acc_config.';
