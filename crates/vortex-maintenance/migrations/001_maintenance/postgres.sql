-- Migration: Maintenance / CMMS (vortex-maintenance plugin)
--
-- A GENERIC maintenance-management layer — assets, work orders,
-- preventive plans — that any asset-intensive vertical specializes.
-- The SESB electrical EAM will build its equipment hierarchy and
-- reliability analytics on top of these primitives rather than redefine
-- them. Composes two existing primitives:
--
--   - inventory : work-order parts are consumed via stock moves
--                 (vortex_inventory::post_move) out of a stock location
--   - scheduler : active plans generate work orders on a cadence
--
-- Reuses core contacts (vendor) and inventory stock_product/location;
-- depends on the inventory plugin's tables, so this plugin is registered
-- AFTER vortex-inventory.

-- ============================================================================
-- 1. maint_asset_category
-- ============================================================================
CREATE TABLE IF NOT EXISTS maint_asset_category (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(120) NOT NULL,
    parent_id   UUID         REFERENCES maint_asset_category(id) ON DELETE SET NULL,
    company_id  UUID         REFERENCES companies(id),
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_maint_asset_category_parent ON maint_asset_category (parent_id);

DROP TRIGGER IF EXISTS trg_maint_asset_category_updated_at ON maint_asset_category;
CREATE TRIGGER trg_maint_asset_category_updated_at
    BEFORE UPDATE ON maint_asset_category
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 2. maint_asset — the generic asset register
-- ============================================================================
CREATE TABLE IF NOT EXISTS maint_asset (
    id             UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    code           VARCHAR(32)   NOT NULL,
    name           VARCHAR(200)  NOT NULL,
    category_id    UUID          REFERENCES maint_asset_category(id) ON DELETE SET NULL,
    criticality    VARCHAR(12)   NOT NULL DEFAULT 'medium',
    state          VARCHAR(20)   NOT NULL DEFAULT 'operational',
    location       VARCHAR(200),
    model          VARCHAR(120),
    serial_number  VARCHAR(120),
    vendor_id      UUID          REFERENCES contacts(id),
    product_id     UUID          REFERENCES stock_product(id),
    parent_id      UUID          REFERENCES maint_asset(id) ON DELETE SET NULL,
    purchase_date  DATE,
    warranty_end   DATE,
    purchase_cost  NUMERIC(20,2) NOT NULL DEFAULT 0,
    note           TEXT,
    active         BOOLEAN       NOT NULL DEFAULT TRUE,
    company_id     UUID          REFERENCES companies(id),
    created_by     UUID          REFERENCES users(id),
    updated_by     UUID          REFERENCES users(id),
    created_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_maint_asset_crit CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT chk_maint_asset_state CHECK (
        state IN ('operational', 'under_maintenance', 'down', 'decommissioned')
    ),
    CONSTRAINT uq_maint_asset_code UNIQUE (company_id, code)
);
CREATE INDEX IF NOT EXISTS idx_maint_asset_category ON maint_asset (category_id);
CREATE INDEX IF NOT EXISTS idx_maint_asset_parent   ON maint_asset (parent_id);
CREATE INDEX IF NOT EXISTS idx_maint_asset_state    ON maint_asset (state);

DROP TRIGGER IF EXISTS trg_maint_asset_updated_at ON maint_asset;
CREATE TRIGGER trg_maint_asset_updated_at
    BEFORE UPDATE ON maint_asset
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 3. maint_plan — preventive maintenance plans
-- ============================================================================
CREATE TABLE IF NOT EXISTS maint_plan (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(200) NOT NULL,
    asset_id            UUID         REFERENCES maint_asset(id) ON DELETE CASCADE,
    wo_type             VARCHAR(16)  NOT NULL DEFAULT 'preventive',
    priority            VARCHAR(8)   NOT NULL DEFAULT 'normal',
    frequency_interval  INTEGER      NOT NULL DEFAULT 1,
    frequency_unit      VARCHAR(8)   NOT NULL DEFAULT 'month',
    next_date           DATE         NOT NULL DEFAULT CURRENT_DATE,
    lead_time_days      INTEGER      NOT NULL DEFAULT 0,
    assigned_to         UUID         REFERENCES users(id),
    consume_location_id UUID         REFERENCES stock_location(id),
    description         TEXT,
    state               VARCHAR(8)   NOT NULL DEFAULT 'active',
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id          UUID         REFERENCES companies(id),
    created_by          UUID         REFERENCES users(id),
    updated_by          UUID         REFERENCES users(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_maint_plan_type CHECK (wo_type IN ('corrective', 'preventive', 'inspection')),
    CONSTRAINT chk_maint_plan_freq_unit CHECK (frequency_unit IN ('day', 'week', 'month', 'year')),
    CONSTRAINT chk_maint_plan_interval CHECK (frequency_interval > 0),
    CONSTRAINT chk_maint_plan_state CHECK (state IN ('active', 'paused'))
);
CREATE INDEX IF NOT EXISTS idx_maint_plan_asset ON maint_plan (asset_id);
CREATE INDEX IF NOT EXISTS idx_maint_plan_due   ON maint_plan (state, next_date);

DROP TRIGGER IF EXISTS trg_maint_plan_updated_at ON maint_plan;
CREATE TRIGGER trg_maint_plan_updated_at
    BEFORE UPDATE ON maint_plan
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 4. maint_work_order
-- ============================================================================
CREATE TABLE IF NOT EXISTS maint_work_order (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    number              VARCHAR(32)  NOT NULL,
    asset_id            UUID         REFERENCES maint_asset(id) ON DELETE SET NULL,
    wo_type             VARCHAR(16)  NOT NULL DEFAULT 'corrective',
    priority            VARCHAR(8)   NOT NULL DEFAULT 'normal',
    state               VARCHAR(12)  NOT NULL DEFAULT 'draft',
    scheduled_date      DATE,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    assigned_to         UUID         REFERENCES users(id),
    plan_id             UUID         REFERENCES maint_plan(id) ON DELETE SET NULL,
    consume_location_id UUID         REFERENCES stock_location(id),
    description         TEXT,
    resolution          TEXT,
    downtime_hours      NUMERIC(10,2) NOT NULL DEFAULT 0,
    company_id          UUID         REFERENCES companies(id),
    created_by          UUID         REFERENCES users(id),
    updated_by          UUID         REFERENCES users(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_maint_wo_type CHECK (wo_type IN ('corrective', 'preventive', 'inspection')),
    CONSTRAINT chk_maint_wo_priority CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    CONSTRAINT chk_maint_wo_state CHECK (state IN ('draft', 'in_progress', 'done', 'cancelled')),
    CONSTRAINT uq_maint_wo_number UNIQUE (company_id, number)
);
CREATE INDEX IF NOT EXISTS idx_maint_wo_asset ON maint_work_order (asset_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_maint_wo_state ON maint_work_order (state);
CREATE INDEX IF NOT EXISTS idx_maint_wo_plan  ON maint_work_order (plan_id);

DROP TRIGGER IF EXISTS trg_maint_wo_updated_at ON maint_work_order;
CREATE TRIGGER trg_maint_wo_updated_at
    BEFORE UPDATE ON maint_work_order
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 5. maint_work_order_part — spare parts consumed on a work order
-- ============================================================================
CREATE TABLE IF NOT EXISTS maint_work_order_part (
    id             UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    work_order_id  UUID          NOT NULL REFERENCES maint_work_order(id) ON DELETE CASCADE,
    product_id     UUID          NOT NULL REFERENCES stock_product(id),
    description    VARCHAR(255),
    quantity       NUMERIC(20,4) NOT NULL DEFAULT 1,
    lot_name       VARCHAR(64),
    unit_cost      NUMERIC(20,4) NOT NULL DEFAULT 0,
    consumed       BOOLEAN       NOT NULL DEFAULT FALSE,
    move_id        UUID          REFERENCES stock_move(id),
    company_id     UUID          REFERENCES companies(id),
    created_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_maint_wo_part_qty CHECK (quantity > 0)
);
CREATE INDEX IF NOT EXISTS idx_maint_wo_part_order ON maint_work_order_part (work_order_id);

-- ============================================================================
-- 6. Runtime role grants
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            maint_asset_category, maint_asset, maint_plan,
            maint_work_order, maint_work_order_part TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE maint_asset IS
    'Generic asset register for maintenance. Verticals (e.g. the SESB electrical EAM) specialize it with equipment-type detail tables linked by asset_id, rather than redefining the base.';
COMMENT ON TABLE maint_work_order IS
    'Maintenance work order. Completing it consumes its parts as stock moves out of consume_location_id via the inventory primitive.';
COMMENT ON TABLE maint_plan IS
    'Preventive maintenance plan. A daily scheduled action generates a draft work order when next_date falls within lead_time, then advances next_date by frequency_interval/unit.';
