-- Reconciliation — GL double-entry generation (BRD double-entry preview; the
-- core Phase-2 output: turn a PDF invoice into a balanced, postable M3 voucher).
--
-- Model matches how M3 actually posts these invoices (see LSEO2.xlsx): goods are
-- posted SST-INCLUSIVE (SST capitalised, not separately claimed), a price-variance
-- line absorbs rounding, and the AP/creditor line is the invoice total:
--   Dr goods (per product's GL account, incl SST)   Σ line_total
--   Dr price variance                                residual
--        Cr trade creditors (AP)                          invoice total
--   Σ Dr = Σ Cr = invoice total.

-- Chart-of-accounts subset (for labels + pickers).
CREATE TABLE IF NOT EXISTS recon_gl_account (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code   VARCHAR(32) NOT NULL UNIQUE,
    name   VARCHAR(160) NOT NULL,
    kind   VARCHAR(24),          -- asset | liability | expense | income | tax
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Product / supplier → GL account resolution (self-learning). match_type:
--   'sku'         exact invoice item code → debit (goods) account
--   'prefix'      item-code prefix        → debit (goods) account
--   'supplier_ap' supplier_no             → that supplier's AP (credit) account
CREATE TABLE IF NOT EXISTS recon_gl_map (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    match_type  VARCHAR(16) NOT NULL,
    match_value VARCHAR(64) NOT NULL,
    gl_code     VARCHAR(32) NOT NULL,
    note        VARCHAR(160),
    active      BOOLEAN NOT NULL DEFAULT true,
    updated_by  UUID REFERENCES users(id),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (match_type, match_value)
);
CREATE INDEX IF NOT EXISTS idx_recon_gl_map_lookup ON recon_gl_map(match_type, match_value) WHERE active;

-- Global defaults (singleton).
CREATE TABLE IF NOT EXISTS recon_gl_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    default_goods_code    VARCHAR(32),  -- fallback Dr account for goods
    default_ap_code       VARCHAR(32),  -- Cr creditor/AP account
    default_variance_code VARCHAR(32),  -- Dr/Cr rounding / price variance
    default_sst_code      VARCHAR(32),  -- optional Dr SST input tax (if ever separated)
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed the accounts + defaults observed in the real M3 export so it works out
-- of the box; admins edit these from Configuration ▸ GL Mapping.
INSERT INTO recon_gl_account (code, name, kind) VALUES
    ('14011501', 'Trade Creditors - Accrued (RNI)', 'liability'),
    ('14011101', 'Trade Creditors - Finished Goods', 'liability'),
    ('32022106', 'Price Variance - Lion', 'expense')
ON CONFLICT (code) DO NOTHING;

INSERT INTO recon_gl_config (default_goods_code, default_ap_code, default_variance_code)
SELECT '14011501', '14011101', '32022106'
WHERE NOT EXISTS (SELECT 1 FROM recon_gl_config);
