-- ============================================================================
-- EAM - Master Data Migration
-- Migration: 102_eam_master_data
-- Description: Add Manufacturer table, enhance VoltageLevel with voltage_type
-- ============================================================================

-- ============================================================================
-- NEW TABLES
-- ============================================================================

-- Manufacturers - Equipment manufacturer master data
CREATE TABLE IF NOT EXISTS eam_manufacturers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    code VARCHAR(50) NOT NULL,
    name VARCHAR(200) NOT NULL,
    short_name VARCHAR(50),
    description TEXT,
    -- Location
    country_code VARCHAR(2), -- ISO 3166-1 alpha-2
    country_name VARCHAR(100),
    address TEXT,
    -- Contact
    website VARCHAR(255),
    phone VARCHAR(50),
    email VARCHAR(255),
    support_phone VARCHAR(50),
    support_email VARCHAR(255),
    -- Vendor status
    is_warranty_provider BOOLEAN DEFAULT false,
    is_approved_vendor BOOLEAN DEFAULT false,
    approval_date DATE,
    approval_expiry DATE,
    -- Status
    display_order INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    is_deleted BOOLEAN DEFAULT false,
    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID REFERENCES users(id),
    UNIQUE(company_id, code)
);

CREATE INDEX idx_eam_manufacturers_company ON eam_manufacturers(company_id);
CREATE INDEX idx_eam_manufacturers_code ON eam_manufacturers(code);
CREATE INDEX idx_eam_manufacturers_name ON eam_manufacturers(name);
CREATE INDEX idx_eam_manufacturers_approved ON eam_manufacturers(is_approved_vendor) WHERE is_approved_vendor = true;

COMMENT ON TABLE eam_manufacturers IS 'Equipment manufacturers master data';
COMMENT ON COLUMN eam_manufacturers.country_code IS 'Country of origin (ISO 3166-1 alpha-2)';
COMMENT ON COLUMN eam_manufacturers.is_approved_vendor IS 'Whether manufacturer is an approved vendor';

-- ============================================================================
-- ALTER EXISTING TABLES
-- ============================================================================

-- Add voltage_type to voltage_levels (ac/dc)
ALTER TABLE eam_voltage_levels
ADD COLUMN IF NOT EXISTS voltage_type VARCHAR(10) DEFAULT 'ac';

-- Add is_deleted to voltage_levels if not exists
ALTER TABLE eam_voltage_levels
ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT false;

COMMENT ON COLUMN eam_voltage_levels.voltage_type IS 'Voltage type: ac or dc';

-- Add FK constraint for manufacturer_id on assets (column added in migration 101)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name = 'fk_eam_assets_manufacturer'
        AND table_name = 'eam_assets'
    ) THEN
        ALTER TABLE eam_assets
        ADD CONSTRAINT fk_eam_assets_manufacturer
        FOREIGN KEY (manufacturer_id) REFERENCES eam_manufacturers(id) ON DELETE SET NULL;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_eam_assets_manufacturer ON eam_assets(manufacturer_id);

-- ============================================================================
-- SEED DATA: Common Manufacturers
-- ============================================================================

-- Note: Actual seeding is done via seed.rs service
-- These are placeholder entries for reference

-- ============================================================================
-- AUDIT TRIGGERS
-- ============================================================================

CREATE TRIGGER trg_eam_manufacturers_updated_at
    BEFORE UPDATE ON eam_manufacturers
    FOR EACH ROW EXECUTE FUNCTION eam_update_timestamp();

-- ============================================================================
-- SEED DC VOLTAGE LEVELS
-- ============================================================================

-- DC voltage levels will be seeded via seed.rs with voltage_type = 'dc'
-- Common DC levels: 110V DC, 48V DC, 24V DC (for control systems, batteries)
