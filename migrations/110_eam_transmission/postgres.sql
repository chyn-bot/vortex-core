-- Migration 110: EAM Transmission Lines and Towers
-- Adds support for overhead transmission line assets alongside distribution substations

-- ============================================================================
-- TRANSMISSION LINES
-- ============================================================================

CREATE TABLE IF NOT EXISTS eam_transmission_lines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL,
    code VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,

    -- Hierarchy
    region_id UUID NOT NULL,
    voltage_level_id UUID,

    -- Route
    from_substation_id UUID,
    to_substation_id UUID,
    line_length_km DOUBLE PRECISION,

    -- Conductor specifications
    conductor_type VARCHAR(20),  -- acsr, acar, aaac, aac, accc, htls, opgw
    conductor_size_mm2 DOUBLE PRECISION,
    number_of_circuits INTEGER DEFAULT 1,
    earth_wire_type VARCHAR(100),
    rated_current_a DOUBLE PRECISION,
    max_sag_m DOUBLE PRECISION,

    -- Lifecycle
    state VARCHAR(20) DEFAULT 'planning',  -- planning, construction, operational, maintenance, decommissioned
    commissioning_date VARCHAR(20),
    design_life_years INTEGER DEFAULT 50,

    -- Ownership
    ownership VARCHAR(20) DEFAULT 'sesb',  -- sesb, ipp, shared

    notes TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID,

    -- Constraints
    CONSTRAINT chk_tl_conductor_type CHECK (
        conductor_type IS NULL OR conductor_type IN ('acsr', 'acar', 'aaac', 'aac', 'accc', 'htls', 'opgw')
    ),
    CONSTRAINT chk_tl_state CHECK (
        state IS NULL OR state IN ('planning', 'construction', 'operational', 'maintenance', 'decommissioned')
    ),
    CONSTRAINT chk_tl_ownership CHECK (
        ownership IS NULL OR ownership IN ('sesb', 'ipp', 'shared')
    )
);

-- Indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_eam_tl_code ON eam_transmission_lines(code);
CREATE INDEX IF NOT EXISTS idx_eam_tl_company ON eam_transmission_lines(company_id);
CREATE INDEX IF NOT EXISTS idx_eam_tl_region ON eam_transmission_lines(region_id);
CREATE INDEX IF NOT EXISTS idx_eam_tl_state ON eam_transmission_lines(state);
CREATE INDEX IF NOT EXISTS idx_eam_tl_voltage ON eam_transmission_lines(voltage_level_id);

-- Foreign keys
ALTER TABLE eam_transmission_lines
    ADD CONSTRAINT fk_tl_region FOREIGN KEY (region_id)
        REFERENCES eam_regions(id) ON DELETE RESTRICT;

ALTER TABLE eam_transmission_lines
    ADD CONSTRAINT fk_tl_voltage_level FOREIGN KEY (voltage_level_id)
        REFERENCES eam_voltage_levels(id) ON DELETE SET NULL;

ALTER TABLE eam_transmission_lines
    ADD CONSTRAINT fk_tl_from_substation FOREIGN KEY (from_substation_id)
        REFERENCES eam_substations(id) ON DELETE SET NULL;

ALTER TABLE eam_transmission_lines
    ADD CONSTRAINT fk_tl_to_substation FOREIGN KEY (to_substation_id)
        REFERENCES eam_substations(id) ON DELETE SET NULL;

COMMENT ON TABLE eam_transmission_lines IS 'Overhead power transmission lines connecting substations';

-- ============================================================================
-- TRANSMISSION TOWERS
-- ============================================================================

CREATE TABLE IF NOT EXISTS eam_transmission_towers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL,
    code VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,

    -- Hierarchy
    transmission_line_id UUID NOT NULL,
    tower_number INTEGER,

    -- Classification
    tower_type VARCHAR(30),  -- lattice_steel, tubular_steel, wood_pole, concrete_pole, monopole, h_frame, guyed_v, self_supporting
    tower_function VARCHAR(20),  -- suspension, tension, angle, dead_end, transposition, junction

    -- Physical dimensions
    height_m DOUBLE PRECISION,
    base_width_m DOUBLE PRECISION,
    weight_kg DOUBLE PRECISION,
    foundation_type VARCHAR(100),

    -- Span
    span_to_next_m DOUBLE PRECISION,
    span_to_previous_m DOUBLE PRECISION,

    -- GPS coordinates
    gps_latitude DOUBLE PRECISION,
    gps_longitude DOUBLE PRECISION,
    elevation_m DOUBLE PRECISION,
    ground_clearance_m DOUBLE PRECISION,
    right_of_way_m DOUBLE PRECISION,

    -- Electrical
    phase_configuration VARCHAR(50),
    insulator_type VARCHAR(20),  -- glass, porcelain, composite
    insulator_count INTEGER,
    earth_wire_attached BOOLEAN DEFAULT TRUE,
    aviation_marking BOOLEAN DEFAULT FALSE,

    -- Status and condition
    operational_status VARCHAR(20) DEFAULT 'operational',
    condition_status VARCHAR(20) DEFAULT 'good',
    health_index DOUBLE PRECISION,

    -- Inspection
    last_inspection_date VARCHAR(20),
    next_inspection_date VARCHAR(20),

    notes TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID,

    -- Constraints
    CONSTRAINT chk_tt_tower_type CHECK (
        tower_type IS NULL OR tower_type IN (
            'lattice_steel', 'tubular_steel', 'wood_pole', 'concrete_pole',
            'monopole', 'h_frame', 'guyed_v', 'self_supporting'
        )
    ),
    CONSTRAINT chk_tt_tower_function CHECK (
        tower_function IS NULL OR tower_function IN (
            'suspension', 'tension', 'angle', 'dead_end', 'transposition', 'junction'
        )
    ),
    CONSTRAINT chk_tt_operational_status CHECK (
        operational_status IS NULL OR operational_status IN (
            'operational', 'standby', 'out_of_service', 'under_repair', 'decommissioned'
        )
    ),
    CONSTRAINT chk_tt_condition_status CHECK (
        condition_status IS NULL OR condition_status IN (
            'excellent', 'good', 'fair', 'poor', 'critical'
        )
    ),
    CONSTRAINT chk_tt_insulator_type CHECK (
        insulator_type IS NULL OR insulator_type IN ('glass', 'porcelain', 'composite')
    )
);

-- Indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_eam_tt_code ON eam_transmission_towers(code);
CREATE INDEX IF NOT EXISTS idx_eam_tt_company ON eam_transmission_towers(company_id);
CREATE INDEX IF NOT EXISTS idx_eam_tt_line ON eam_transmission_towers(transmission_line_id);
CREATE INDEX IF NOT EXISTS idx_eam_tt_line_number ON eam_transmission_towers(transmission_line_id, tower_number);
CREATE INDEX IF NOT EXISTS idx_eam_tt_gps ON eam_transmission_towers(gps_latitude, gps_longitude);

-- Foreign keys
ALTER TABLE eam_transmission_towers
    ADD CONSTRAINT fk_tt_line FOREIGN KEY (transmission_line_id)
        REFERENCES eam_transmission_lines(id) ON DELETE RESTRICT;

-- Unique tower number per line
CREATE UNIQUE INDEX IF NOT EXISTS idx_eam_tt_line_tower_unique
    ON eam_transmission_towers(transmission_line_id, tower_number)
    WHERE tower_number IS NOT NULL;

COMMENT ON TABLE eam_transmission_towers IS 'Structures supporting conductors along a transmission line';

-- ============================================================================
-- ALTER ASSETS: Add tower_id for transmission equipment
-- ============================================================================

ALTER TABLE eam_assets ADD COLUMN IF NOT EXISTS tower_id UUID;

ALTER TABLE eam_assets
    ADD CONSTRAINT fk_asset_tower FOREIGN KEY (tower_id)
        REFERENCES eam_transmission_towers(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_eam_assets_tower ON eam_assets(tower_id) WHERE tower_id IS NOT NULL;

COMMENT ON COLUMN eam_assets.tower_id IS 'Tower reference for transmission equipment (alternative to bay_id)';

-- ============================================================================
-- Timestamps trigger for auto-updating updated_at
-- ============================================================================

CREATE OR REPLACE FUNCTION eam_transmission_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_eam_tl_updated_at
    BEFORE UPDATE ON eam_transmission_lines
    FOR EACH ROW EXECUTE FUNCTION eam_transmission_updated_at();

CREATE TRIGGER trg_eam_tt_updated_at
    BEFORE UPDATE ON eam_transmission_towers
    FOR EACH ROW EXECUTE FUNCTION eam_transmission_updated_at();
