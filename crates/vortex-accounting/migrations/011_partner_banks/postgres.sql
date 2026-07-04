-- Migration 011: partner bank accounts
--
-- Bank details on the contact (vendor payment instructions, customer
-- refunds; the future payment-voucher / bank-file export reads these).
-- Satellite table — no guard churn.

CREATE TABLE IF NOT EXISTS acc_partner_bank (
    id             UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    contact_id     UUID         NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    bank_name      VARCHAR(120) NOT NULL,
    account_number VARCHAR(40)  NOT NULL,
    account_holder VARCHAR(160),
    swift_code     VARCHAR(20),
    is_default     BOOLEAN      NOT NULL DEFAULT FALSE,
    company_id     UUID         REFERENCES companies(id),
    created_by     UUID         REFERENCES users(id),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_acc_partner_bank ON acc_partner_bank (contact_id);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON acc_partner_bank TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE acc_partner_bank IS
    'Bank accounts per contact — payment instructions for vendors, refund details for customers.';
