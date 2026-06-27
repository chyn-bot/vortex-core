-- ============================================================================
-- EAM - Equipment Types Expansion Migration
-- Migration: 103_eam_equipment_types
-- Description: Add new equipment types and enhance existing models per SESB spec
-- ============================================================================

-- ============================================================================
-- ENHANCE EXISTING TABLES
-- ============================================================================

-- Transformer enhancements
ALTER TABLE eam_transformers
ADD COLUMN IF NOT EXISTS winding_material VARCHAR(50),
ADD COLUMN IF NOT EXISTS phase_count INTEGER,
ADD COLUMN IF NOT EXISTS no_load_loss_kw DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS load_loss_kw DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS has_buchholz_relay BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS has_pressure_relief BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS has_wti BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS has_oti BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS has_mog BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS dga_status VARCHAR(20),
ADD COLUMN IF NOT EXISTS last_dga_date DATE;

COMMENT ON COLUMN eam_transformers.winding_material IS 'Winding material: copper, aluminum';
COMMENT ON COLUMN eam_transformers.has_wti IS 'Winding Temperature Indicator';
COMMENT ON COLUMN eam_transformers.has_oti IS 'Oil Temperature Indicator';
COMMENT ON COLUMN eam_transformers.has_mog IS 'Magnetic Oil Gauge';
COMMENT ON COLUMN eam_transformers.dga_status IS 'DGA status: normal, caution, warning, critical';

-- Switch Gear enhancements
ALTER TABLE eam_switch_gears
ADD COLUMN IF NOT EXISTS sf6_volume_kg DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS control_voltage_vdc DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS motor_voltage_vac DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS position VARCHAR(20),
ADD COLUMN IF NOT EXISTS contact_wear_percent DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS last_overhaul_date DATE;

COMMENT ON COLUMN eam_switch_gears.sf6_volume_kg IS 'SF6 gas volume in kg';
COMMENT ON COLUMN eam_switch_gears.position IS 'Current position: open, closed, intermediate';
COMMENT ON COLUMN eam_switch_gears.contact_wear_percent IS 'Contact wear percentage (0-100)';

-- Ring Main Unit enhancements
ALTER TABLE eam_ring_main_units
ADD COLUMN IF NOT EXISTS protection_type VARCHAR(50),
ADD COLUMN IF NOT EXISTS fuse_rating_a DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS ip_rating VARCHAR(10),
ADD COLUMN IF NOT EXISTS width_mm DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS height_mm DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS depth_mm DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS unit_1_type VARCHAR(20),
ADD COLUMN IF NOT EXISTS unit_1_position VARCHAR(20),
ADD COLUMN IF NOT EXISTS unit_2_type VARCHAR(20),
ADD COLUMN IF NOT EXISTS unit_2_position VARCHAR(20),
ADD COLUMN IF NOT EXISTS unit_3_type VARCHAR(20),
ADD COLUMN IF NOT EXISTS unit_3_position VARCHAR(20),
ADD COLUMN IF NOT EXISTS unit_4_type VARCHAR(20),
ADD COLUMN IF NOT EXISTS unit_4_position VARCHAR(20);

COMMENT ON COLUMN eam_ring_main_units.protection_type IS 'Protection type: fuse, relay, both';
COMMENT ON COLUMN eam_ring_main_units.unit_1_type IS 'Unit 1 type: ring, tee, cb, vt';

-- Battery enhancements
ALTER TABLE eam_batteries
ADD COLUMN IF NOT EXISTS state_of_health DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS state_of_charge DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS current_mode VARCHAR(20),
ADD COLUMN IF NOT EXISTS lowest_cell_voltage DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS highest_cell_voltage DOUBLE PRECISION;

COMMENT ON COLUMN eam_batteries.state_of_health IS 'State of health percentage (0-100)';
COMMENT ON COLUMN eam_batteries.state_of_charge IS 'State of charge percentage (0-100)';
COMMENT ON COLUMN eam_batteries.current_mode IS 'Current mode: float, boost, discharge, equalize';

-- ============================================================================
-- NEW EQUIPMENT TABLES
-- ============================================================================

-- Current/Voltage Transformers (CT/VT/CVT)
CREATE TABLE IF NOT EXISTS eam_current_voltage_transformers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL UNIQUE REFERENCES eam_assets(id) ON DELETE CASCADE,
    device_type VARCHAR(10), -- ct, vt, cvt
    ratio_primary DOUBLE PRECISION,
    ratio_secondary DOUBLE PRECISION,
    accuracy_class VARCHAR(20),
    burden_va DOUBLE PRECISION,
    rated_voltage_kv DOUBLE PRECISION,
    insulation_class VARCHAR(20),
    number_of_cores INTEGER,
    -- Multi-core details
    core_1_class VARCHAR(20),
    core_1_burden_va DOUBLE PRECISION,
    core_2_class VARCHAR(20),
    core_2_burden_va DOUBLE PRECISION,
    core_3_class VARCHAR(20),
    core_3_burden_va DOUBLE PRECISION,
    -- Ratings
    thermal_rating_factor DOUBLE PRECISION,
    short_time_current_ka DOUBLE PRECISION,
    -- Testing
    last_ratio_test DATE,
    last_polarity_test DATE
);

CREATE INDEX idx_eam_cvt_asset ON eam_current_voltage_transformers(asset_id);
CREATE INDEX idx_eam_cvt_type ON eam_current_voltage_transformers(device_type);

COMMENT ON TABLE eam_current_voltage_transformers IS 'Current and Voltage Transformers (CT/VT/CVT)';
COMMENT ON COLUMN eam_current_voltage_transformers.device_type IS 'Device type: ct, vt, cvt (combined)';
COMMENT ON COLUMN eam_current_voltage_transformers.accuracy_class IS 'Accuracy class: 0.2, 0.5, 1.0, 5P, etc.';

-- Surge Arresters
CREATE TABLE IF NOT EXISTS eam_surge_arresters (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL UNIQUE REFERENCES eam_assets(id) ON DELETE CASCADE,
    arrester_type VARCHAR(50), -- station, distribution, line
    mcov_kv DOUBLE PRECISION, -- Maximum Continuous Operating Voltage
    rated_voltage_kv DOUBLE PRECISION,
    discharge_class VARCHAR(10), -- 1, 2, 3, 4, 5
    nominal_discharge_current_ka DOUBLE PRECISION,
    leakage_current_ma DOUBLE PRECISION,
    reference_voltage_kv DOUBLE PRECISION,
    energy_capability_kj_kv DOUBLE PRECISION,
    housing_material VARCHAR(20), -- porcelain, polymer
    has_surge_counter BOOLEAN DEFAULT false,
    surge_counter_reading INTEGER,
    last_leakage_test DATE
);

CREATE INDEX idx_eam_sa_asset ON eam_surge_arresters(asset_id);
CREATE INDEX idx_eam_sa_type ON eam_surge_arresters(arrester_type);

COMMENT ON TABLE eam_surge_arresters IS 'Surge/Lightning Arresters';
COMMENT ON COLUMN eam_surge_arresters.mcov_kv IS 'Maximum Continuous Operating Voltage in kV';
COMMENT ON COLUMN eam_surge_arresters.discharge_class IS 'Discharge class per IEC: 1, 2, 3, 4, 5';

-- Cables
CREATE TABLE IF NOT EXISTS eam_cables (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL UNIQUE REFERENCES eam_assets(id) ON DELETE CASCADE,
    cable_type VARCHAR(20), -- xlpe, pilc, epr, pvc
    voltage_rating_kv DOUBLE PRECISION,
    conductor_material VARCHAR(20), -- copper, aluminum
    conductor_size_mm2 DOUBLE PRECISION,
    number_of_cores INTEGER,
    length_m DOUBLE PRECISION,
    from_equipment_id UUID REFERENCES eam_assets(id),
    to_equipment_id UUID REFERENCES eam_assets(id),
    from_location VARCHAR(200),
    to_location VARCHAR(200),
    installation_type VARCHAR(50), -- direct_buried, duct, tray, aerial
    rated_current_a DOUBLE PRECISION,
    insulation_resistance_mohm DOUBLE PRECISION,
    last_insulation_test DATE,
    last_vlf_test DATE
);

CREATE INDEX idx_eam_cables_asset ON eam_cables(asset_id);
CREATE INDEX idx_eam_cables_from ON eam_cables(from_equipment_id);
CREATE INDEX idx_eam_cables_to ON eam_cables(to_equipment_id);
CREATE INDEX idx_eam_cables_type ON eam_cables(cable_type);

COMMENT ON TABLE eam_cables IS 'Power and control cables';
COMMENT ON COLUMN eam_cables.cable_type IS 'Cable type: xlpe, pilc, epr, pvc';
COMMENT ON COLUMN eam_cables.installation_type IS 'Installation: direct_buried, duct, tray, aerial';

-- Busbars
CREATE TABLE IF NOT EXISTS eam_busbars (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL UNIQUE REFERENCES eam_assets(id) ON DELETE CASCADE,
    busbar_type VARCHAR(20), -- rigid, flexible, gis
    material VARCHAR(20), -- copper, aluminum
    rated_current_a DOUBLE PRECISION,
    rated_voltage_kv DOUBLE PRECISION,
    short_circuit_rating_ka DOUBLE PRECISION,
    cross_section VARCHAR(50), -- e.g., "100x10" mm
    length_m DOUBLE PRECISION,
    conductors_per_phase INTEGER,
    coating VARCHAR(20), -- bare, silver, tin
    configuration VARCHAR(20), -- single, double
    last_thermal_scan DATE
);

CREATE INDEX idx_eam_busbars_asset ON eam_busbars(asset_id);
CREATE INDEX idx_eam_busbars_type ON eam_busbars(busbar_type);

COMMENT ON TABLE eam_busbars IS 'Busbars';
COMMENT ON COLUMN eam_busbars.busbar_type IS 'Busbar type: rigid, flexible, gis';
COMMENT ON COLUMN eam_busbars.cross_section IS 'Cross section dimensions (e.g., "100x10" mm)';

-- Isolators / Disconnectors
CREATE TABLE IF NOT EXISTS eam_isolators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL UNIQUE REFERENCES eam_assets(id) ON DELETE CASCADE,
    isolator_type VARCHAR(20), -- line, bus, transfer, earthing
    rated_voltage_kv DOUBLE PRECISION,
    rated_current_a DOUBLE PRECISION,
    short_circuit_rating_ka DOUBLE PRECISION,
    mechanism_type VARCHAR(20), -- manual, motor, pneumatic
    position VARCHAR(20), -- open, closed
    has_earth_switch BOOLEAN DEFAULT false,
    earth_switch_position VARCHAR(20),
    number_of_poles INTEGER DEFAULT 3,
    interlock_type VARCHAR(50),
    operation_count INTEGER DEFAULT 0,
    last_maintenance DATE
);

CREATE INDEX idx_eam_isolators_asset ON eam_isolators(asset_id);
CREATE INDEX idx_eam_isolators_type ON eam_isolators(isolator_type);

COMMENT ON TABLE eam_isolators IS 'Isolators / Disconnectors';
COMMENT ON COLUMN eam_isolators.isolator_type IS 'Type: line, bus, transfer, earthing';
COMMENT ON COLUMN eam_isolators.mechanism_type IS 'Mechanism: manual, motor, pneumatic';

-- Earthing Systems
CREATE TABLE IF NOT EXISTS eam_earthing_systems (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL UNIQUE REFERENCES eam_assets(id) ON DELETE CASCADE,
    earth_type VARCHAR(20), -- grid, rod, plate, ring
    earth_resistance_ohm DOUBLE PRECISION,
    target_resistance_ohm DOUBLE PRECISION,
    material VARCHAR(20), -- copper, steel, galvanized
    conductor_size_mm2 DOUBLE PRECISION,
    number_of_rods INTEGER,
    rod_length_m DOUBLE PRECISION,
    grid_depth_m DOUBLE PRECISION,
    grid_area_m2 DOUBLE PRECISION,
    soil_resistivity_ohm_m DOUBLE PRECISION,
    step_potential_v DOUBLE PRECISION,
    touch_potential_v DOUBLE PRECISION,
    last_resistance_test DATE,
    last_potential_test DATE
);

CREATE INDEX idx_eam_earthing_asset ON eam_earthing_systems(asset_id);
CREATE INDEX idx_eam_earthing_type ON eam_earthing_systems(earth_type);

COMMENT ON TABLE eam_earthing_systems IS 'Earthing/Grounding Systems';
COMMENT ON COLUMN eam_earthing_systems.earth_type IS 'Earth type: grid, rod, plate, ring';
COMMENT ON COLUMN eam_earthing_systems.soil_resistivity_ohm_m IS 'Soil resistivity in Ohm-meters';

-- ============================================================================
-- AUDIT TRIGGERS
-- ============================================================================

-- Note: These tables don't have updated_at columns, so no triggers needed
-- If we add updated_at later, add triggers here
