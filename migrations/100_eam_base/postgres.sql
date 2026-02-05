-- ============================================================================
-- EAM - Enterprise Asset Management Module
-- Migration: 100_eam_base
-- Description: Base tables for Distribution Substation Asset Management
-- Based on Dx Substation Template hierarchy
-- ============================================================================

-- Note: Module registration is handled in 003_module_registry migration

-- ============================================================================
-- CONFIGURATION TABLES (User-configurable)
-- ============================================================================

-- Voltage Levels (e.g., 275kV, 132kV, 33kV, 11kV, 0.415kV)
CREATE TABLE IF NOT EXISTS eam_voltage_levels (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    voltage_value DOUBLE PRECISION NOT NULL,
    voltage_unit VARCHAR(10) DEFAULT 'kV',
    voltage_class VARCHAR(20), -- EHV, HV, MV, LV
    description TEXT,
    display_order INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    is_deleted BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID REFERENCES users(id),
    UNIQUE(company_id, code)
);

CREATE INDEX idx_eam_voltage_levels_company ON eam_voltage_levels(company_id);

-- Unit Types (e.g., PPU, SSU 33kV, SSU 11kV, PP, PE)
CREATE TABLE IF NOT EXISTS eam_unit_types (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    short_name VARCHAR(50),
    description TEXT,
    display_order INTEGER DEFAULT 0,
    equipment_template JSONB, -- Expected asset categories
    is_active BOOLEAN DEFAULT true,
    is_deleted BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID REFERENCES users(id),
    UNIQUE(company_id, code)
);

CREATE INDEX idx_eam_unit_types_company ON eam_unit_types(company_id);

-- Asset Categories (e.g., Transformer, Switch Gear, RMU, Battery)
CREATE TABLE IF NOT EXISTS eam_asset_categories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    short_name VARCHAR(50),
    description TEXT,
    icon VARCHAR(50),
    color VARCHAR(20),
    parent_id UUID REFERENCES eam_asset_categories(id),
    display_order INTEGER DEFAULT 0,
    default_pm_interval_days INTEGER,
    attribute_template JSONB,
    is_active BOOLEAN DEFAULT true,
    is_deleted BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID REFERENCES users(id),
    UNIQUE(company_id, code)
);

CREATE INDEX idx_eam_asset_categories_company ON eam_asset_categories(company_id);

-- Asset Statuses (e.g., In Service, Under Maintenance, Faulty)
CREATE TABLE IF NOT EXISTS eam_asset_statuses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    code VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    color VARCHAR(20),
    icon VARCHAR(50),
    is_operational BOOLEAN DEFAULT true,
    allows_maintenance BOOLEAN DEFAULT true,
    is_final BOOLEAN DEFAULT false,
    display_order INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID REFERENCES users(id),
    UNIQUE(company_id, code)
);

CREATE INDEX idx_eam_asset_statuses_company ON eam_asset_statuses(company_id);

-- ============================================================================
-- HIERARCHY TABLES
-- ============================================================================

-- Sites (Pencawang/Substation)
CREATE TABLE IF NOT EXISTS eam_sites (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    code VARCHAR(50) NOT NULL,
    name VARCHAR(200) NOT NULL,
    short_name VARCHAR(50),
    description TEXT,
    -- Location
    address TEXT,
    city VARCHAR(100),
    state VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(100) DEFAULT 'Malaysia',
    gps_latitude DOUBLE PRECISION,
    gps_longitude DOUBLE PRECISION,
    -- Classification
    site_type VARCHAR(50), -- Indoor GIS, Outdoor AIS, Hybrid
    voltage_levels JSONB,
    -- Operational
    commissioning_date DATE,
    ownership VARCHAR(100),
    operator VARCHAR(100),
    busbar_configuration VARCHAR(100),
    feeder_count INTEGER,
    -- Status
    status VARCHAR(50) DEFAULT 'active',
    is_active BOOLEAN DEFAULT true,
    is_deleted BOOLEAN DEFAULT false,
    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID REFERENCES users(id),
    UNIQUE(company_id, code)
);

CREATE INDEX idx_eam_sites_company ON eam_sites(company_id);
CREATE INDEX idx_eam_sites_code ON eam_sites(code);

-- Functional Locations (PPU, SSU 33kV, SSU 11kV, PP, PE)
CREATE TABLE IF NOT EXISTS eam_functional_locations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    site_id UUID NOT NULL REFERENCES eam_sites(id) ON DELETE CASCADE,
    unit_type_id UUID NOT NULL REFERENCES eam_unit_types(id),
    parent_id UUID REFERENCES eam_functional_locations(id),
    voltage_level_id UUID REFERENCES eam_voltage_levels(id),
    -- Identification
    code VARCHAR(50) NOT NULL,
    name VARCHAR(200) NOT NULL,
    short_name VARCHAR(50),
    description TEXT,
    -- References
    sld_reference VARCHAR(100),
    scada_point_group VARCHAR(100),
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

CREATE INDEX idx_eam_fl_company ON eam_functional_locations(company_id);
CREATE INDEX idx_eam_fl_site ON eam_functional_locations(site_id);
CREATE INDEX idx_eam_fl_code ON eam_functional_locations(code);

-- Assets (Transformer, Switch Gear, RMU, Battery, etc.)
CREATE TABLE IF NOT EXISTS eam_assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    functional_location_id UUID NOT NULL REFERENCES eam_functional_locations(id),
    category_id UUID NOT NULL REFERENCES eam_asset_categories(id),
    status_id UUID REFERENCES eam_asset_statuses(id),
    voltage_level_id UUID REFERENCES eam_voltage_levels(id),
    -- Identification
    asset_code VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(200) NOT NULL,
    tag_number VARCHAR(100),
    description TEXT,
    -- Manufacturer
    manufacturer VARCHAR(200),
    model VARCHAR(200),
    serial_number VARCHAR(100),
    -- Dates
    year_manufactured INTEGER,
    commissioning_date DATE,
    warranty_expiry DATE,
    expected_life_years INTEGER,
    -- Financial
    purchase_cost DOUBLE PRECISION,
    replacement_cost DOUBLE PRECISION,
    criticality_rating INTEGER CHECK (criticality_rating BETWEEN 1 AND 5),
    -- Status tracking
    operational_status VARCHAR(50) DEFAULT 'in_service',
    condition_score DOUBLE PRECISION,
    last_inspection_date DATE,
    last_maintenance_date DATE,
    next_maintenance_date DATE,
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

CREATE INDEX idx_eam_assets_company ON eam_assets(company_id);
CREATE INDEX idx_eam_assets_fl ON eam_assets(functional_location_id);
CREATE INDEX idx_eam_assets_category ON eam_assets(category_id);
CREATE INDEX idx_eam_assets_code ON eam_assets(asset_code);
CREATE INDEX idx_eam_assets_serial ON eam_assets(serial_number);

-- Asset Attributes (Dynamic type-specific fields)
CREATE TABLE IF NOT EXISTS eam_asset_attributes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES eam_assets(id) ON DELETE CASCADE,
    attribute_name VARCHAR(100) NOT NULL,
    attribute_label VARCHAR(200),
    attribute_group VARCHAR(100),
    value_text TEXT,
    value_numeric DOUBLE PRECISION,
    value_boolean BOOLEAN,
    value_date DATE,
    unit VARCHAR(20),
    data_type VARCHAR(20) DEFAULT 'text',
    display_order INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_eam_asset_attr_asset ON eam_asset_attributes(asset_id);
CREATE INDEX idx_eam_asset_attr_name ON eam_asset_attributes(attribute_name);

-- Components (Sub-components of assets)
CREATE TABLE IF NOT EXISTS eam_components (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES eam_assets(id) ON DELETE CASCADE,
    parent_id UUID REFERENCES eam_components(id),
    code VARCHAR(50) NOT NULL,
    name VARCHAR(200) NOT NULL,
    component_type VARCHAR(100),
    description TEXT,
    manufacturer VARCHAR(200),
    model VARCHAR(200),
    serial_number VARCHAR(100),
    year_manufactured INTEGER,
    installation_date DATE,
    warranty_expiry DATE,
    status VARCHAR(50) DEFAULT 'active',
    condition_score DOUBLE PRECISION,
    qr_code VARCHAR(100) UNIQUE,
    qr_code_generated_at TIMESTAMPTZ,
    display_order INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    is_deleted BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID REFERENCES users(id)
);

CREATE INDEX idx_eam_components_asset ON eam_components(asset_id);

-- ============================================================================
-- EQUIPMENT-SPECIFIC TABLES
-- ============================================================================

-- Transformers
CREATE TABLE IF NOT EXISTS eam_transformers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL UNIQUE REFERENCES eam_assets(id) ON DELETE CASCADE,
    transformer_type VARCHAR(50),
    mva_rating DOUBLE PRECISION,
    primary_voltage DOUBLE PRECISION,
    secondary_voltage DOUBLE PRECISION,
    tertiary_voltage DOUBLE PRECISION,
    vector_group VARCHAR(20),
    number_of_windings INTEGER,
    phases INTEGER DEFAULT 3,
    tap_changer_type VARCHAR(50),
    tap_range VARCHAR(50),
    tap_step_voltage DOUBLE PRECISION,
    cooling_type VARCHAR(20),
    oil_type VARCHAR(100),
    oil_volume_liters DOUBLE PRECISION,
    impedance_percent DOUBLE PRECISION,
    short_circuit_rating DOUBLE PRECISION,
    total_weight_kg DOUBLE PRECISION,
    number_of_radiators INTEGER,
    dga_baseline_date DATE,
    sfra_baseline_date DATE
);

-- Switch Gear
CREATE TABLE IF NOT EXISTS eam_switch_gears (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL UNIQUE REFERENCES eam_assets(id) ON DELETE CASCADE,
    switchgear_type VARCHAR(50),
    breaker_type VARCHAR(50),
    rated_voltage DOUBLE PRECISION,
    voltage_class VARCHAR(50),
    rated_current DOUBLE PRECISION,
    rated_short_circuit_current DOUBLE PRECISION,
    making_current DOUBLE PRECISION,
    closing_time_ms DOUBLE PRECISION,
    opening_time_ms DOUBLE PRECISION,
    break_time_ms DOUBLE PRECISION,
    sf6_pressure_rated DOUBLE PRECISION,
    sf6_pressure_alarm DOUBLE PRECISION,
    sf6_pressure_trip DOUBLE PRECISION,
    mechanism_type VARCHAR(50),
    number_of_operations INTEGER,
    max_operations INTEGER,
    number_of_poles INTEGER DEFAULT 3
);

-- Ring Main Units
CREATE TABLE IF NOT EXISTS eam_ring_main_units (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL UNIQUE REFERENCES eam_assets(id) ON DELETE CASCADE,
    rmu_configuration VARCHAR(20),
    number_of_ring_switches INTEGER,
    number_of_tee_off INTEGER,
    rmu_type VARCHAR(50),
    insulation_medium VARCHAR(50),
    rated_voltage DOUBLE PRECISION,
    rated_current DOUBLE PRECISION,
    short_circuit_rating DOUBLE PRECISION,
    has_fault_indicator BOOLEAN DEFAULT false,
    has_load_break_switch BOOLEAN DEFAULT true,
    has_fuse_switch BOOLEAN DEFAULT false,
    has_circuit_breaker BOOLEAN DEFAULT false,
    sf6_pressure_rated DOUBLE PRECISION
);

-- Feeder Pillars
CREATE TABLE IF NOT EXISTS eam_feeder_pillars (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL UNIQUE REFERENCES eam_assets(id) ON DELETE CASCADE,
    pillar_type VARCHAR(50),
    voltage_level DOUBLE PRECISION,
    number_of_ways INTEGER,
    incoming_cable_size VARCHAR(50),
    outgoing_cable_size VARCHAR(50),
    fuse_rating DOUBLE PRECISION,
    has_metering BOOLEAN DEFAULT false,
    enclosure_type VARCHAR(50),
    ip_rating VARCHAR(10)
);

-- Protection Systems
CREATE TABLE IF NOT EXISTS eam_protection_systems (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL UNIQUE REFERENCES eam_assets(id) ON DELETE CASCADE,
    functional_location_id UUID REFERENCES eam_functional_locations(id),
    protection_type VARCHAR(100),
    relay_type VARCHAR(50),
    relay_manufacturer VARCHAR(100),
    relay_model VARCHAR(100),
    relay_serial VARCHAR(100),
    protection_functions JSONB,
    firmware_version VARCHAR(50),
    last_firmware_update DATE,
    settings_reference VARCHAR(100),
    last_settings_update DATE,
    communication_protocol VARCHAR(50),
    ip_address VARCHAR(50),
    last_test_date DATE,
    test_interval_months INTEGER
);

-- SCADA Systems
CREATE TABLE IF NOT EXISTS eam_scada_systems (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL UNIQUE REFERENCES eam_assets(id) ON DELETE CASCADE,
    functional_location_id UUID REFERENCES eam_functional_locations(id),
    scada_type VARCHAR(100),
    rtu_type VARCHAR(50),
    rtu_manufacturer VARCHAR(100),
    rtu_model VARCHAR(100),
    rtu_serial VARCHAR(100),
    communication_protocol VARCHAR(50),
    primary_ip_address VARCHAR(50),
    secondary_ip_address VARCHAR(50),
    port_number INTEGER,
    number_of_di INTEGER,
    number_of_do INTEGER,
    number_of_ai INTEGER,
    number_of_ao INTEGER,
    scada_point_prefix VARCHAR(50),
    scada_station_address INTEGER,
    firmware_version VARCHAR(50)
);

-- Batteries
CREATE TABLE IF NOT EXISTS eam_batteries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL UNIQUE REFERENCES eam_assets(id) ON DELETE CASCADE,
    functional_location_id UUID REFERENCES eam_functional_locations(id),
    battery_type VARCHAR(50),
    battery_application VARCHAR(50),
    nominal_voltage DOUBLE PRECISION,
    capacity_ah DOUBLE PRECISION,
    number_of_cells INTEGER,
    cells_per_string INTEGER,
    number_of_strings INTEGER,
    charger_manufacturer VARCHAR(100),
    charger_model VARCHAR(100),
    charger_rating DOUBLE PRECISION,
    charger_redundancy VARCHAR(20),
    last_capacity_test DATE,
    last_impedance_test DATE,
    capacity_percent DOUBLE PRECISION,
    float_voltage DOUBLE PRECISION,
    boost_voltage DOUBLE PRECISION,
    low_voltage_alarm DOUBLE PRECISION,
    high_voltage_alarm DOUBLE PRECISION
);

-- ============================================================================
-- MAINTENANCE TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS eam_maintenance_schedules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES eam_assets(id),
    schedule_name VARCHAR(200) NOT NULL,
    frequency_days INTEGER NOT NULL,
    last_performed DATE,
    next_due DATE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS eam_work_orders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    wo_number VARCHAR(50) NOT NULL UNIQUE,
    asset_id UUID REFERENCES eam_assets(id),
    title VARCHAR(200) NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 5,
    status VARCHAR(50) DEFAULT 'draft',
    scheduled_start TIMESTAMPTZ,
    actual_start TIMESTAMPTZ,
    actual_end TIMESTAMPTZ,
    assigned_to UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS eam_inspection_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES eam_assets(id),
    inspection_date TIMESTAMPTZ NOT NULL,
    inspector_id UUID NOT NULL REFERENCES users(id),
    overall_condition VARCHAR(50),
    condition_score DOUBLE PRECISION,
    observations TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- CONDITION MONITORING TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS eam_condition_monitoring (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES eam_assets(id),
    parameter_name VARCHAR(100) NOT NULL,
    measurement_date TIMESTAMPTZ NOT NULL,
    value_numeric DOUBLE PRECISION,
    value_text TEXT,
    unit VARCHAR(20),
    status VARCHAR(20),
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_eam_cm_asset ON eam_condition_monitoring(asset_id);
CREATE INDEX idx_eam_cm_date ON eam_condition_monitoring(measurement_date);

CREATE TABLE IF NOT EXISTS eam_asset_health_indices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES eam_assets(id),
    calculated_at TIMESTAMPTZ NOT NULL,
    health_index DOUBLE PRECISION NOT NULL,
    health_category VARCHAR(20),
    probability_of_failure DOUBLE PRECISION,
    risk_score DOUBLE PRECISION,
    recommended_action VARCHAR(100),
    calculation_method VARCHAR(50)
);

CREATE INDEX idx_eam_health_asset ON eam_asset_health_indices(asset_id);
CREATE INDEX idx_eam_health_date ON eam_asset_health_indices(calculated_at);

-- ============================================================================
-- AUDIT TRIGGERS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION eam_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to all EAM tables
DO $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name LIKE 'eam_%'
        AND table_name NOT LIKE '%_view'
    LOOP
        EXECUTE format('
            DROP TRIGGER IF EXISTS %I ON %I;
            CREATE TRIGGER %I
            BEFORE UPDATE ON %I
            FOR EACH ROW EXECUTE FUNCTION eam_update_timestamp();
        ', 'trg_' || t || '_updated_at', t, 'trg_' || t || '_updated_at', t);
    END LOOP;
END;
$$;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE eam_sites IS 'Substations/Pencawang - top level of asset hierarchy';
COMMENT ON TABLE eam_functional_locations IS 'Functional units within sites - PPU, SSU, etc.';
COMMENT ON TABLE eam_assets IS 'Individual equipment - Transformers, Switchgear, RMU, etc.';
COMMENT ON TABLE eam_voltage_levels IS 'User-configurable voltage levels';
COMMENT ON TABLE eam_unit_types IS 'User-configurable unit types (PPU, SSU, etc.)';
COMMENT ON TABLE eam_asset_categories IS 'User-configurable asset categories';
