-- Migration: Inventory / Stock (vortex-inventory plugin)
--
-- A GENERIC, reusable inventory primitive — not utility-specific. Any
-- vertical that handles physical goods (maintenance spare parts,
-- procurement receipts, manufacturing, retail) builds on these tables
-- instead of reinventing them. Modelled on the classic double-entry
-- stock ledger: every movement debits a source location and credits a
-- destination location; on-hand is the running balance per
-- (product, location) held in stock_quant.
--
-- Tables:
--   stock_product_category  — hierarchical product/part grouping
--   stock_location          — hierarchical warehouse/virtual locations
--   stock_product           — the catalogue of stockable items / parts
--   stock_move              — the movement ledger (draft -> done/cancelled)
--   stock_quant             — on-hand balance per (product, location)
--
-- Units of measure are reused from the core commerce primitives
-- (migration 119): stock_product.uom_id / stock_move.uom_id -> uoms(id).

-- ============================================================================
-- 1. stock_product_category
-- ============================================================================
CREATE TABLE IF NOT EXISTS stock_product_category (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(120) NOT NULL,
    parent_id   UUID         REFERENCES stock_product_category(id) ON DELETE SET NULL,
    company_id  UUID         REFERENCES companies(id),
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_stock_product_category_parent
    ON stock_product_category (parent_id);

DROP TRIGGER IF EXISTS trg_stock_product_category_updated_at ON stock_product_category;
CREATE TRIGGER trg_stock_product_category_updated_at
    BEFORE UPDATE ON stock_product_category
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 2. stock_location
-- ============================================================================
-- location_type semantics (Odoo-style double-entry):
--   internal  — real on-hand storage owned by the company
--   supplier  — virtual counterpart for incoming goods (receipts)
--   customer  — virtual counterpart for outgoing goods (deliveries)
--   inventory — virtual counterpart for adjustments / losses
--   transit   — goods in transit between internal locations
CREATE TABLE IF NOT EXISTS stock_location (
    id             UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    code           VARCHAR(32)  NOT NULL,
    name           VARCHAR(160) NOT NULL,
    parent_id      UUID         REFERENCES stock_location(id) ON DELETE SET NULL,
    location_type  VARCHAR(16)  NOT NULL DEFAULT 'internal',
    company_id     UUID         REFERENCES companies(id),
    notes          TEXT,
    active         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by     UUID         REFERENCES users(id),
    updated_by     UUID         REFERENCES users(id),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_stock_location_type CHECK (
        location_type IN ('internal', 'supplier', 'customer', 'inventory', 'transit')
    )
);

CREATE INDEX IF NOT EXISTS idx_stock_location_parent ON stock_location (parent_id);
CREATE INDEX IF NOT EXISTS idx_stock_location_type   ON stock_location (location_type);

DROP TRIGGER IF EXISTS trg_stock_location_updated_at ON stock_location;
CREATE TRIGGER trg_stock_location_updated_at
    BEFORE UPDATE ON stock_location
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 3. stock_product
-- ============================================================================
CREATE TABLE IF NOT EXISTS stock_product (
    id           UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    code         VARCHAR(32)   NOT NULL,
    name         VARCHAR(200)  NOT NULL,
    barcode      VARCHAR(64),
    description  TEXT,
    category_id  UUID          REFERENCES stock_product_category(id) ON DELETE SET NULL,
    product_type VARCHAR(16)   NOT NULL DEFAULT 'stockable',
    uom_id       UUID          REFERENCES uoms(id),
    tracking     VARCHAR(8)    NOT NULL DEFAULT 'none',
    cost         NUMERIC(20,4) NOT NULL DEFAULT 0,
    reorder_min  NUMERIC(20,4) NOT NULL DEFAULT 0,
    reorder_max  NUMERIC(20,4) NOT NULL DEFAULT 0,
    company_id   UUID          REFERENCES companies(id),
    active       BOOLEAN       NOT NULL DEFAULT TRUE,
    created_by   UUID          REFERENCES users(id),
    updated_by   UUID          REFERENCES users(id),
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_stock_product_type CHECK (
        product_type IN ('stockable', 'consumable', 'service')
    ),
    CONSTRAINT chk_stock_product_tracking CHECK (
        tracking IN ('none', 'lot', 'serial')
    ),
    CONSTRAINT uq_stock_product_code UNIQUE (company_id, code)
);

CREATE INDEX IF NOT EXISTS idx_stock_product_category ON stock_product (category_id);
CREATE INDEX IF NOT EXISTS idx_stock_product_active   ON stock_product (active);

DROP TRIGGER IF EXISTS trg_stock_product_updated_at ON stock_product;
CREATE TRIGGER trg_stock_product_updated_at
    BEFORE UPDATE ON stock_product
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 4. stock_move — the movement ledger
-- ============================================================================
CREATE TABLE IF NOT EXISTS stock_move (
    id                  UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    reference           VARCHAR(32)   NOT NULL,
    product_id          UUID          NOT NULL REFERENCES stock_product(id),
    quantity            NUMERIC(20,4) NOT NULL,
    uom_id              UUID          REFERENCES uoms(id),
    source_location_id  UUID          NOT NULL REFERENCES stock_location(id),
    dest_location_id    UUID          NOT NULL REFERENCES stock_location(id),
    state               VARCHAR(12)   NOT NULL DEFAULT 'draft',
    scheduled_date      DATE,
    done_at             TIMESTAMPTZ,
    reference_doc       VARCHAR(120),
    note                TEXT,
    company_id          UUID          REFERENCES companies(id),
    created_by          UUID          REFERENCES users(id),
    updated_by          UUID          REFERENCES users(id),
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_stock_move_state CHECK (state IN ('draft', 'done', 'cancelled')),
    CONSTRAINT chk_stock_move_qty CHECK (quantity > 0),
    CONSTRAINT chk_stock_move_locations CHECK (source_location_id <> dest_location_id)
);

CREATE INDEX IF NOT EXISTS idx_stock_move_product ON stock_move (product_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_stock_move_state   ON stock_move (state);

DROP TRIGGER IF EXISTS trg_stock_move_updated_at ON stock_move;
CREATE TRIGGER trg_stock_move_updated_at
    BEFORE UPDATE ON stock_move
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 5. stock_quant — on-hand balance per (product, location)
-- ============================================================================
-- Maintained by the application when a move is validated (state -> done):
-- the source location is debited and the destination credited. Virtual
-- locations (supplier/customer/inventory) may go negative — that is the
-- expected double-entry counterpart of real on-hand stock.
CREATE TABLE IF NOT EXISTS stock_quant (
    id          UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id  UUID          NOT NULL REFERENCES stock_product(id) ON DELETE CASCADE,
    location_id UUID          NOT NULL REFERENCES stock_location(id) ON DELETE CASCADE,
    quantity    NUMERIC(20,4) NOT NULL DEFAULT 0,
    company_id  UUID          REFERENCES companies(id),
    updated_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_stock_quant UNIQUE (product_id, location_id)
);

CREATE INDEX IF NOT EXISTS idx_stock_quant_location ON stock_quant (location_id);

-- ============================================================================
-- 6. Seed virtual + default locations (stable UUIDs)
-- ============================================================================
INSERT INTO stock_location (id, code, name, location_type) VALUES
    ('51000000-0000-0000-0000-000000000001', 'STOCK', 'Main Stock',            'internal'),
    ('51000000-0000-0000-0000-000000000002', 'SUPP',  'Vendors',               'supplier'),
    ('51000000-0000-0000-0000-000000000003', 'CUST',  'Customers',             'customer'),
    ('51000000-0000-0000-0000-000000000004', 'ADJ',   'Inventory Adjustment',  'inventory')
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- 7. Runtime role grants
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            stock_product_category, stock_location, stock_product,
            stock_move, stock_quant TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE stock_product IS
    'Generic stockable item / spare-part catalogue. Reused by maintenance, procurement and any goods-handling vertical. uom_id references the core commerce uoms table.';
COMMENT ON TABLE stock_move IS
    'Double-entry stock movement ledger. A move is draft until validated; validation posts it (state=done) and updates stock_quant for source and destination locations.';
COMMENT ON TABLE stock_quant IS
    'Running on-hand balance per (product, location). Never edited directly by users — derived from validated stock_move rows.';
