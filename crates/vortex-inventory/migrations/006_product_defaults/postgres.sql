-- Migration 006: document defaults on the product master
--
-- Picking a product on an invoice/bill line should bring everything
-- with it: LHDN classification, the GL account per side, and the tax
-- per side. GL columns are soft links (no FK — acc_account belongs to
-- the accounting plugin; inventory stays loosely coupled). Taxes are
-- core commerce, so those reference properly.

ALTER TABLE stock_product ADD COLUMN IF NOT EXISTS classification_code VARCHAR(8);
ALTER TABLE stock_product ADD COLUMN IF NOT EXISTS income_account_id UUID;
ALTER TABLE stock_product ADD COLUMN IF NOT EXISTS expense_account_id UUID;
ALTER TABLE stock_product ADD COLUMN IF NOT EXISTS sales_tax_id UUID REFERENCES taxes(id);
ALTER TABLE stock_product ADD COLUMN IF NOT EXISTS purchase_tax_id UUID REFERENCES taxes(id);

COMMENT ON COLUMN stock_product.classification_code IS
    'Default LHDN e-invoice classification for lines of this product.';
COMMENT ON COLUMN stock_product.income_account_id IS
    'Default revenue GL account on customer documents (soft link to acc_account).';
COMMENT ON COLUMN stock_product.expense_account_id IS
    'Default expense/asset GL account on vendor documents (soft link to acc_account).';
