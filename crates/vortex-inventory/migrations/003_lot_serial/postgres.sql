-- Migration: Lot / Serial tracking (vortex-inventory plugin)
--
-- Adds traceability to the generic stock primitive. A stock_product
-- already declares its `tracking` mode (none | lot | serial); this
-- migration adds the lot/serial records, links moves and quants to a
-- lot, and makes on-hand balances lot-aware.
--
--   stock_lot                 — a production lot (batch) or a serial number
--   stock_move.lot_id         — which lot/serial the movement applies to
--   stock_quant(lot_id)       — on-hand is now per (product, location, lot)
--
-- A "serial" is just a lot whose on-hand is tracked one unit at a time
-- (the application enforces quantity = 1 on serial moves).

-- ============================================================================
-- 1. stock_lot — production lots & serial numbers
-- ============================================================================
CREATE TABLE IF NOT EXISTS stock_lot (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(64)  NOT NULL,
    product_id  UUID         NOT NULL REFERENCES stock_product(id) ON DELETE CASCADE,
    lot_type    VARCHAR(8)   NOT NULL DEFAULT 'lot',
    note        TEXT,
    company_id  UUID         REFERENCES companies(id),
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by  UUID         REFERENCES users(id),
    updated_by  UUID         REFERENCES users(id),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_stock_lot_type CHECK (lot_type IN ('lot', 'serial')),
    -- A lot/serial name is unique per product.
    CONSTRAINT uq_stock_lot_name UNIQUE (product_id, name)
);

CREATE INDEX IF NOT EXISTS idx_stock_lot_product ON stock_lot (product_id);

DROP TRIGGER IF EXISTS trg_stock_lot_updated_at ON stock_lot;
CREATE TRIGGER trg_stock_lot_updated_at
    BEFORE UPDATE ON stock_lot
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 2. stock_move.lot_id
-- ============================================================================
ALTER TABLE stock_move
    ADD COLUMN IF NOT EXISTS lot_id UUID REFERENCES stock_lot(id);

CREATE INDEX IF NOT EXISTS idx_stock_move_lot ON stock_move (lot_id);

COMMENT ON COLUMN stock_move.lot_id IS
    'The lot/serial this movement applies to. Required (enforced by the application) when the moved product has tracking <> none.';

-- ============================================================================
-- 3. stock_quant.lot_id + lot-aware uniqueness
-- ============================================================================
ALTER TABLE stock_quant
    ADD COLUMN IF NOT EXISTS lot_id UUID REFERENCES stock_lot(id);

-- Replace the (product, location) uniqueness with one that also keys on
-- the lot. NULL lot_id (untracked products) collapses to a sentinel so
-- there is still exactly one untracked quant row per (product, location).
ALTER TABLE stock_quant DROP CONSTRAINT IF EXISTS uq_stock_quant;
CREATE UNIQUE INDEX IF NOT EXISTS uq_stock_quant_lot
    ON stock_quant (
        product_id,
        location_id,
        COALESCE(lot_id, '00000000-0000-0000-0000-000000000000'::uuid)
    );

-- ============================================================================
-- 4. Runtime role grant for the new table
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON stock_lot TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE stock_lot IS
    'Production lots (batches) and serial numbers for tracked products. A serial is a lot whose on-hand is moved one unit at a time. Names are unique per product.';
