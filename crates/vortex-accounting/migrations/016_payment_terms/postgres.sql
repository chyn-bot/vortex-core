-- 016_payment_terms — reusable payment terms (Net 30, Due on Receipt, …).
--
-- A payment term is a named due-date rule: an invoice/quotation carries a term,
-- and the due date is `document date + due_days`. Terms are shared by sales
-- (quotation → order → invoice) and accounting (customer invoices, vendor
-- bills), so the master lives in accounting — the lowest layer both build on.
-- Maintained under Accounting Setup ▸ Payment Terms.
CREATE TABLE IF NOT EXISTS payment_term (
    id         UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name       VARCHAR(120) NOT NULL,
    -- Days from the document date until payment is due (0 = due on receipt).
    due_days   INTEGER      NOT NULL DEFAULT 0 CHECK (due_days >= 0),
    -- Optional free-text explanation printed on documents.
    note       TEXT         NOT NULL DEFAULT '',
    active     BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id UUID,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payment_term_active ON payment_term(active);

-- Each partner (customer/vendor) can carry a default term, surfaced on the
-- contact's Accounting panel and used to pre-fill new quotations.
ALTER TABLE acc_partner_tax_profile
    ADD COLUMN IF NOT EXISTS payment_term_id UUID REFERENCES payment_term(id);

-- Seed the common terms once (only when the table is empty, so re-running the
-- migration on an existing tenant never duplicates or clobbers edits).
INSERT INTO payment_term (name, due_days, note)
SELECT v.name, v.due_days, v.note
FROM (VALUES
    ('Due on Receipt', 0,  'Payment due upon receipt of the invoice.'),
    ('Net 15',         15, 'Payment due within 15 days.'),
    ('Net 30',         30, 'Payment due within 30 days.'),
    ('Net 60',         60, 'Payment due within 60 days.'),
    ('Net 90',         90, 'Payment due within 90 days.')
) AS v(name, due_days, note)
WHERE NOT EXISTS (SELECT 1 FROM payment_term);
