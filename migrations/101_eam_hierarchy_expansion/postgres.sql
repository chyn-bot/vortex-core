-- ============================================================================
-- EAM - Hierarchy Expansion Migration
-- Migration: 101_eam_hierarchy_expansion
-- Description: Expand from 4-level to 8-level asset hierarchy per SESB spec
-- Hierarchy: Region (L0) → Site (L1) → Substation (L2) → Bay (L3) →
--            Asset (L4) → Component (L5) → Part (L6-7)
-- ============================================================================

-- ============================================================================
-- NEW TABLES
-- ============================================================================

-- Regions (L0) - Parent of Sites
CREATE TABLE IF NOT EXISTS eam_regions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    code VARCHAR(50) NOT NULL,
    name VARCHAR(200) NOT NULL,
    short_name VARCHAR(50),
    description TEXT,
    -- Division type: transmission, distribution
    division VARCHAR(50),
    -- Region manager
    manager_id UUID REFERENCES users(id),
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

CREATE INDEX idx_eam_regions_company ON eam_regions(company_id);
CREATE INDEX idx_eam_regions_code ON eam_regions(code);
CREATE INDEX idx_eam_regions_division ON eam_regions(division);

COMMENT ON TABLE eam_regions IS 'Regions (L0) - Top level hierarchy, parent of Sites';
COMMENT ON COLUMN eam_regions.division IS 'Division type: transmission or distribution';

-- Substations (L2) - Between Site and Bay
CREATE TABLE IF NOT EXISTS eam_substations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    site_id UUID NOT NULL REFERENCES eam_sites(id) ON DELETE CASCADE,
    code VARCHAR(50) NOT NULL,
    name VARCHAR(200) NOT NULL,
    short_name VARCHAR(50),
    description TEXT,
    -- Classification
    substation_type VARCHAR(50), -- indoor_gis, outdoor_ais, hybrid, mobile
    busbar_configuration VARCHAR(50), -- single, double, ring, breaker_and_half, mesh
    ownership VARCHAR(50), -- sesb, tnb, ippp, customer
    design_life_years INTEGER,
    commissioning_date DATE,
    voltage_level_id UUID REFERENCES eam_voltage_levels(id),
    -- QR Code
    qr_code VARCHAR(100) UNIQUE,
    qr_code_generated_at TIMESTAMPTZ,
    -- Status
    display_order INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'active',
    is_active BOOLEAN DEFAULT true,
    is_deleted BOOLEAN DEFAULT false,
    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID REFERENCES users(id),
    UNIQUE(site_id, code)
);

CREATE INDEX idx_eam_substations_company ON eam_substations(company_id);
CREATE INDEX idx_eam_substations_site ON eam_substations(site_id);
CREATE INDEX idx_eam_substations_code ON eam_substations(code);
CREATE INDEX idx_eam_substations_type ON eam_substations(substation_type);

COMMENT ON TABLE eam_substations IS 'Substations (L2) - Electrical substations within Sites';
COMMENT ON COLUMN eam_substations.substation_type IS 'Type: indoor_gis, outdoor_ais, hybrid, mobile';
COMMENT ON COLUMN eam_substations.busbar_configuration IS 'Config: single, double, ring, breaker_and_half, mesh';

-- Bays (L3) - Replaces FunctionalLocation
CREATE TABLE IF NOT EXISTS eam_bays (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    substation_id UUID NOT NULL REFERENCES eam_substations(id) ON DELETE CASCADE,
    unit_type_id UUID NOT NULL REFERENCES eam_unit_types(id),
    parent_id UUID REFERENCES eam_bays(id),
    voltage_level_id UUID REFERENCES eam_voltage_levels(id),
    -- Identification
    code VARCHAR(50) NOT NULL,
    name VARCHAR(200) NOT NULL,
    short_name VARCHAR(50),
    description TEXT,
    -- Bay classification
    bay_type VARCHAR(50), -- feeder, transformer, bus_coupler, bus_section, capacitor, reactor
    feeder_name VARCHAR(100),
    rated_current_a DOUBLE PRECISION,
    -- References
    scada_point_group VARCHAR(100),
    sld_reference VARCHAR(100),
    -- QR Code
    qr_code VARCHAR(100) UNIQUE,
    qr_code_generated_at TIMESTAMPTZ,
    -- Status
    display_order INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'active',
    is_active BOOLEAN DEFAULT true,
    is_deleted BOOLEAN DEFAULT false,
    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID REFERENCES users(id),
    UNIQUE(substation_id, code)
);

CREATE INDEX idx_eam_bays_company ON eam_bays(company_id);
CREATE INDEX idx_eam_bays_substation ON eam_bays(substation_id);
CREATE INDEX idx_eam_bays_code ON eam_bays(code);
CREATE INDEX idx_eam_bays_type ON eam_bays(bay_type);

COMMENT ON TABLE eam_bays IS 'Bays (L3) - Functional units within Substations, replaces FunctionalLocation';
COMMENT ON COLUMN eam_bays.bay_type IS 'Type: feeder, transformer, bus_coupler, bus_section, capacitor, reactor';

-- Parts (L6-7) - Children of Components
CREATE TABLE IF NOT EXISTS eam_parts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    component_id UUID NOT NULL REFERENCES eam_components(id) ON DELETE CASCADE,
    -- Self-referencing for sub-parts (L7)
    parent_part_id UUID REFERENCES eam_parts(id),
    -- Identification
    code VARCHAR(50) NOT NULL,
    name VARCHAR(200) NOT NULL,
    part_type VARCHAR(50), -- consumable, spare, critical_spare, wear_part
    description TEXT,
    -- Manufacturer
    manufacturer VARCHAR(200),
    part_number VARCHAR(100),
    serial_number VARCHAR(100),
    -- Inventory
    quantity INTEGER DEFAULT 1,
    reorder_level INTEGER,
    uom VARCHAR(20), -- unit of measure
    unit_cost DOUBLE PRECISION,
    -- Lifecycle
    installation_date DATE,
    warranty_expiry DATE,
    expected_life_hours INTEGER,
    -- Status
    status VARCHAR(50) DEFAULT 'active',
    condition_score DOUBLE PRECISION,
    -- QR Code
    qr_code VARCHAR(100) UNIQUE,
    qr_code_generated_at TIMESTAMPTZ,
    -- Display
    display_order INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    is_deleted BOOLEAN DEFAULT false,
    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID REFERENCES users(id)
);

CREATE INDEX idx_eam_parts_component ON eam_parts(component_id);
CREATE INDEX idx_eam_parts_parent ON eam_parts(parent_part_id);
CREATE INDEX idx_eam_parts_code ON eam_parts(code);
CREATE INDEX idx_eam_parts_type ON eam_parts(part_type);

COMMENT ON TABLE eam_parts IS 'Parts (L6-7) - Replaceable parts within Components';
COMMENT ON COLUMN eam_parts.part_type IS 'Type: consumable, spare, critical_spare, wear_part';
COMMENT ON COLUMN eam_parts.parent_part_id IS 'Self-reference for sub-parts (L7 level)';

-- ============================================================================
-- ALTER EXISTING TABLES
-- ============================================================================

-- Add region_id to Sites
ALTER TABLE eam_sites
ADD COLUMN IF NOT EXISTS region_id UUID REFERENCES eam_regions(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_eam_sites_region ON eam_sites(region_id);

-- Add bay_id to Assets (for new SESB hierarchy)
ALTER TABLE eam_assets
ADD COLUMN IF NOT EXISTS bay_id UUID REFERENCES eam_bays(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_eam_assets_bay ON eam_assets(bay_id);

-- Make functional_location_id nullable for migration (was NOT NULL)
-- Note: New assets should use bay_id, functional_location_id kept for legacy
ALTER TABLE eam_assets
ALTER COLUMN functional_location_id DROP NOT NULL;

-- Add manufacturer_id to Assets (FK to manufacturers table, created in Phase 2)
-- Placeholder column, FK constraint added in migration 102
ALTER TABLE eam_assets
ADD COLUMN IF NOT EXISTS manufacturer_id UUID;

-- ============================================================================
-- DATA MIGRATION: Functional Locations to Substations/Bays
-- ============================================================================

-- Create substations from sites that don't have them yet
-- Each site gets a default substation
INSERT INTO eam_substations (
    id, company_id, site_id, code, name, short_name,
    substation_type, busbar_configuration, ownership,
    status, is_active, created_at, created_by
)
SELECT
    uuid_generate_v4(),
    s.company_id,
    s.id,
    s.code || '-SS01',
    s.name || ' - Main Substation',
    'SS01',
    s.site_type,
    s.busbar_configuration,
    s.ownership,
    s.status,
    s.is_active,
    NOW(),
    s.created_by
FROM eam_sites s
WHERE NOT EXISTS (
    SELECT 1 FROM eam_substations ss WHERE ss.site_id = s.id
)
ON CONFLICT DO NOTHING;

-- Migrate functional_locations to bays
-- Maps each functional_location to a bay in the appropriate substation
INSERT INTO eam_bays (
    id, company_id, substation_id, unit_type_id, parent_id, voltage_level_id,
    code, name, short_name, description,
    scada_point_group, sld_reference,
    qr_code, qr_code_generated_at,
    display_order, status, is_active, is_deleted,
    created_at, created_by, updated_at, updated_by
)
SELECT
    fl.id, -- Preserve the ID for FK references
    fl.company_id,
    ss.id, -- substation_id from the site's default substation
    fl.unit_type_id,
    fl.parent_id,
    fl.voltage_level_id,
    fl.code,
    fl.name,
    fl.short_name,
    fl.description,
    fl.scada_point_group,
    fl.sld_reference,
    fl.qr_code,
    fl.qr_code_generated_at,
    fl.display_order,
    fl.status,
    fl.is_active,
    fl.is_deleted,
    fl.created_at,
    fl.created_by,
    fl.updated_at,
    fl.updated_by
FROM eam_functional_locations fl
JOIN eam_substations ss ON ss.site_id = fl.site_id
WHERE NOT EXISTS (
    SELECT 1 FROM eam_bays b WHERE b.id = fl.id
)
ON CONFLICT DO NOTHING;

-- Update assets to reference bays (using same ID as functional_location)
UPDATE eam_assets a
SET bay_id = fl.id
FROM eam_functional_locations fl
WHERE a.functional_location_id = fl.id
AND a.bay_id IS NULL;

-- ============================================================================
-- AUDIT TRIGGERS
-- ============================================================================

-- Apply update timestamp triggers to new tables
CREATE TRIGGER trg_eam_regions_updated_at
    BEFORE UPDATE ON eam_regions
    FOR EACH ROW EXECUTE FUNCTION eam_update_timestamp();

CREATE TRIGGER trg_eam_substations_updated_at
    BEFORE UPDATE ON eam_substations
    FOR EACH ROW EXECUTE FUNCTION eam_update_timestamp();

CREATE TRIGGER trg_eam_bays_updated_at
    BEFORE UPDATE ON eam_bays
    FOR EACH ROW EXECUTE FUNCTION eam_update_timestamp();

CREATE TRIGGER trg_eam_parts_updated_at
    BEFORE UPDATE ON eam_parts
    FOR EACH ROW EXECUTE FUNCTION eam_update_timestamp();

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON COLUMN eam_sites.region_id IS 'Parent region (L0 hierarchy level)';
COMMENT ON COLUMN eam_assets.bay_id IS 'Bay reference (L3) - SESB hierarchy';
COMMENT ON COLUMN eam_assets.functional_location_id IS 'Legacy functional location (deprecated, use bay_id)';
COMMENT ON COLUMN eam_assets.manufacturer_id IS 'Manufacturer FK (constraint added in migration 102)';
