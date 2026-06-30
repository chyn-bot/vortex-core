-- Migration: Purchasing (vortex-purchase plugin)
--
-- The first module that *consumes* the generic inventory primitive:
-- a purchase order's receipt posts validated stock moves from the
-- Vendors (supplier) location into a destination internal location via
-- `vortex_inventory::post_move`.
--
-- Reuses, rather than reinvents:
--   - vendors        → core `contacts` (contact_type supplier/both)
--   - products       → inventory `stock_product`
--   - receiving bin  → inventory `stock_location`
--   - currency       → commerce `currencies`
--
-- Depends on the inventory plugin's tables (stock_product,
-- stock_location); the purchase plugin is registered AFTER inventory so
-- those exist when this migration runs.

-- ============================================================================
-- 1. purchase_order
-- ============================================================================
CREATE TABLE IF NOT EXISTS purchase_order (
    id               UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    number           VARCHAR(32)   NOT NULL,
    vendor_id        UUID          NOT NULL REFERENCES contacts(id),
    order_date       DATE          NOT NULL DEFAULT CURRENT_DATE,
    expected_date    DATE,
    state            VARCHAR(12)   NOT NULL DEFAULT 'draft',
    currency_id      UUID          REFERENCES currencies(id),
    dest_location_id UUID          REFERENCES stock_location(id),
    note             TEXT,
    untaxed_amount   NUMERIC(20,2) NOT NULL DEFAULT 0,
    tax_amount       NUMERIC(20,2) NOT NULL DEFAULT 0,
    total_amount     NUMERIC(20,2) NOT NULL DEFAULT 0,
    company_id       UUID          REFERENCES companies(id),
    created_by       UUID          REFERENCES users(id),
    updated_by       UUID          REFERENCES users(id),
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_po_state CHECK (state IN ('draft', 'confirmed', 'received', 'cancelled')),
    CONSTRAINT uq_po_number UNIQUE (company_id, number)
);

CREATE INDEX IF NOT EXISTS idx_po_vendor ON purchase_order (vendor_id, order_date DESC);
CREATE INDEX IF NOT EXISTS idx_po_state  ON purchase_order (state);

DROP TRIGGER IF EXISTS trg_purchase_order_updated_at ON purchase_order;
CREATE TRIGGER trg_purchase_order_updated_at
    BEFORE UPDATE ON purchase_order
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 2. purchase_order_line
-- ============================================================================
CREATE TABLE IF NOT EXISTS purchase_order_line (
    id           UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id     UUID          NOT NULL REFERENCES purchase_order(id) ON DELETE CASCADE,
    sequence     INTEGER       NOT NULL DEFAULT 10,
    product_id   UUID          NOT NULL REFERENCES stock_product(id),
    description  VARCHAR(255),
    quantity     NUMERIC(20,4) NOT NULL DEFAULT 1,
    unit_price   NUMERIC(20,4) NOT NULL DEFAULT 0,
    tax_percent  NUMERIC(7,4)  NOT NULL DEFAULT 0,
    qty_received NUMERIC(20,4) NOT NULL DEFAULT 0,
    company_id   UUID          REFERENCES companies(id),
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_pol_qty CHECK (quantity > 0),
    CONSTRAINT chk_pol_received CHECK (qty_received >= 0)
);

CREATE INDEX IF NOT EXISTS idx_pol_order   ON purchase_order_line (order_id, sequence);
CREATE INDEX IF NOT EXISTS idx_pol_product ON purchase_order_line (product_id);

-- ============================================================================
-- 3. Runtime role grants
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            purchase_order, purchase_order_line TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE purchase_order IS
    'Purchase orders. Vendor is a core contact (supplier/both). Receiving a confirmed order posts validated stock moves into dest_location_id via the inventory primitive. number is tenant-scoped (PO/000001).';
COMMENT ON COLUMN purchase_order_line.qty_received IS
    'Running total received across receipts; the line is fully received when qty_received >= quantity. The PO flips to state=received when all lines are.';
