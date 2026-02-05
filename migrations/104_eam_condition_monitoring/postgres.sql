-- ============================================================================
-- EAM - Condition Monitoring Expansion Migration
-- Migration: 104_eam_condition_monitoring
-- Description: Add specialized condition monitoring tables per SESB spec
-- ============================================================================

-- ============================================================================
-- SPECIALIZED CONDITION MONITORING TABLES
-- ============================================================================

-- Dissolved Gas Analysis (DGA) for transformer oil
CREATE TABLE IF NOT EXISTS eam_dga_analyses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES eam_assets(id) ON DELETE CASCADE,
    sample_date TIMESTAMPTZ NOT NULL,
    lab_reference VARCHAR(100),
    -- Key fault gases (all in ppm)
    hydrogen_h2_ppm DOUBLE PRECISION,
    methane_ch4_ppm DOUBLE PRECISION,
    ethane_c2h6_ppm DOUBLE PRECISION,
    ethylene_c2h4_ppm DOUBLE PRECISION,
    acetylene_c2h2_ppm DOUBLE PRECISION,
    carbon_monoxide_co_ppm DOUBLE PRECISION,
    carbon_dioxide_co2_ppm DOUBLE PRECISION,
    oxygen_o2_ppm DOUBLE PRECISION,
    nitrogen_n2_ppm DOUBLE PRECISION,
    -- Calculated values
    total_combustible_gas_ppm DOUBLE PRECISION,
    fault_type VARCHAR(50),
    status VARCHAR(20), -- normal, caution, warning, critical
    assessment_method VARCHAR(50), -- duval_triangle, rogers_ratio, ieee_c57_104
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_eam_dga_asset ON eam_dga_analyses(asset_id);
CREATE INDEX idx_eam_dga_date ON eam_dga_analyses(sample_date);
CREATE INDEX idx_eam_dga_status ON eam_dga_analyses(status);

COMMENT ON TABLE eam_dga_analyses IS 'Dissolved Gas Analysis results for transformer oil';
COMMENT ON COLUMN eam_dga_analyses.hydrogen_h2_ppm IS 'Hydrogen - key indicator for PD and arcing';
COMMENT ON COLUMN eam_dga_analyses.acetylene_c2h2_ppm IS 'Acetylene - arcing fault indicator';
COMMENT ON COLUMN eam_dga_analyses.total_combustible_gas_ppm IS 'TCG = H2 + CH4 + C2H6 + C2H4 + C2H2 + CO';
COMMENT ON COLUMN eam_dga_analyses.fault_type IS 'Fault type from Duval Triangle or other method';

-- Oil Quality Test
CREATE TABLE IF NOT EXISTS eam_oil_quality_tests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES eam_assets(id) ON DELETE CASCADE,
    test_date TIMESTAMPTZ NOT NULL,
    lab_reference VARCHAR(100),
    -- Dielectric properties
    bdv_kv DOUBLE PRECISION, -- Breakdown Voltage
    moisture_ppm DOUBLE PRECISION,
    acidity_mg_koh DOUBLE PRECISION, -- Neutralization number
    ift_mn_m DOUBLE PRECISION, -- Interfacial Tension
    tan_delta DOUBLE PRECISION, -- Dissipation Factor at 90C
    -- Physical properties
    color DOUBLE PRECISION, -- ASTM scale 0-8
    specific_gravity DOUBLE PRECISION,
    flash_point_c DOUBLE PRECISION,
    pour_point_c DOUBLE PRECISION,
    viscosity_40c_cst DOUBLE PRECISION,
    -- Contaminants
    pcb_ppm DOUBLE PRECISION,
    furan_2fal_ppb DOUBLE PRECISION, -- Paper degradation indicator
    -- Assessment
    status VARCHAR(20), -- good, acceptable, marginal, poor
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_eam_oil_asset ON eam_oil_quality_tests(asset_id);
CREATE INDEX idx_eam_oil_date ON eam_oil_quality_tests(test_date);

COMMENT ON TABLE eam_oil_quality_tests IS 'Oil quality test results for transformer insulating oil';
COMMENT ON COLUMN eam_oil_quality_tests.bdv_kv IS 'Breakdown Voltage - dielectric strength';
COMMENT ON COLUMN eam_oil_quality_tests.furan_2fal_ppb IS 'Furan content - paper degradation indicator';

-- Thermal Imaging / Infrared Scan Results
CREATE TABLE IF NOT EXISTS eam_thermal_imaging (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES eam_assets(id) ON DELETE CASCADE,
    scan_date TIMESTAMPTZ NOT NULL,
    component_location VARCHAR(200),
    -- Environmental conditions
    ambient_temp_c DOUBLE PRECISION,
    load_percent DOUBLE PRECISION,
    -- Measurements
    max_temp_c DOUBLE PRECISION,
    reference_temp_c DOUBLE PRECISION,
    hot_spot_location VARCHAR(200),
    delta_t_c DOUBLE PRECISION, -- Temperature rise above reference
    -- Assessment
    severity VARCHAR(20), -- normal, attention, intermediate, serious, critical
    emissivity DOUBLE PRECISION,
    distance_m DOUBLE PRECISION,
    -- Image references
    thermal_image_id UUID,
    visual_image_id UUID,
    recommended_action VARCHAR(500),
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_eam_thermal_asset ON eam_thermal_imaging(asset_id);
CREATE INDEX idx_eam_thermal_date ON eam_thermal_imaging(scan_date);
CREATE INDEX idx_eam_thermal_severity ON eam_thermal_imaging(severity);

COMMENT ON TABLE eam_thermal_imaging IS 'Thermal imaging / infrared scan results';
COMMENT ON COLUMN eam_thermal_imaging.delta_t_c IS 'Temperature rise above reference in Celsius';
COMMENT ON COLUMN eam_thermal_imaging.severity IS 'Severity: normal, attention, intermediate, serious, critical';

-- Partial Discharge (PD) Test Results
CREATE TABLE IF NOT EXISTS eam_partial_discharge_tests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES eam_assets(id) ON DELETE CASCADE,
    test_date TIMESTAMPTZ NOT NULL,
    -- Test parameters
    test_method VARCHAR(50), -- online, offline, acoustic, uhf, hfct
    test_voltage_kv DOUBLE PRECISION,
    -- Measurements
    magnitude_pc DOUBLE PRECISION, -- PD magnitude in picocoulombs
    inception_voltage_kv DOUBLE PRECISION,
    extinction_voltage_kv DOUBLE PRECISION,
    repetition_rate_pps DOUBLE PRECISION, -- pulses per second
    pattern VARCHAR(50), -- surface, void, corona, floating
    phase_angle_deg DOUBLE PRECISION,
    pd_location VARCHAR(200),
    background_noise_pc DOUBLE PRECISION,
    -- Assessment
    status VARCHAR(20), -- pass, fail, marginal
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_eam_pd_asset ON eam_partial_discharge_tests(asset_id);
CREATE INDEX idx_eam_pd_date ON eam_partial_discharge_tests(test_date);
CREATE INDEX idx_eam_pd_status ON eam_partial_discharge_tests(status);

COMMENT ON TABLE eam_partial_discharge_tests IS 'Partial discharge test results';
COMMENT ON COLUMN eam_partial_discharge_tests.magnitude_pc IS 'Maximum PD magnitude in picocoulombs';
COMMENT ON COLUMN eam_partial_discharge_tests.pattern IS 'PD pattern type: surface, void, corona, floating';

-- Insulation Resistance (IR) / Megger Test Results
CREATE TABLE IF NOT EXISTS eam_insulation_resistance_tests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES eam_assets(id) ON DELETE CASCADE,
    test_date TIMESTAMPTZ NOT NULL,
    -- Test parameters
    test_configuration VARCHAR(50), -- e.g., HV-LV, HV-E, LV-E
    test_voltage_v DOUBLE PRECISION,
    temperature_c DOUBLE PRECISION,
    humidity_percent DOUBLE PRECISION,
    -- Measurements
    ir_1min_mohm DOUBLE PRECISION, -- 1-minute reading
    ir_10min_mohm DOUBLE PRECISION, -- 10-minute reading
    polarization_index DOUBLE PRECISION, -- PI = IR_10min / IR_1min
    dielectric_absorption_ratio DOUBLE PRECISION, -- DAR = IR_1min / IR_30sec
    ir_corrected_20c_mohm DOUBLE PRECISION, -- Temperature corrected
    -- Acceptance criteria
    minimum_ir_mohm DOUBLE PRECISION,
    status VARCHAR(20), -- pass, fail, marginal
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_eam_ir_asset ON eam_insulation_resistance_tests(asset_id);
CREATE INDEX idx_eam_ir_date ON eam_insulation_resistance_tests(test_date);
CREATE INDEX idx_eam_ir_status ON eam_insulation_resistance_tests(status);

COMMENT ON TABLE eam_insulation_resistance_tests IS 'Insulation resistance / Megger test results';
COMMENT ON COLUMN eam_insulation_resistance_tests.polarization_index IS 'PI = IR_10min / IR_1min, indicates insulation condition';
COMMENT ON COLUMN eam_insulation_resistance_tests.ir_corrected_20c_mohm IS 'IR value corrected to 20 deg C reference';

-- ============================================================================
-- USEFUL VIEWS
-- ============================================================================

-- Latest DGA results per asset
CREATE OR REPLACE VIEW eam_latest_dga AS
SELECT DISTINCT ON (asset_id)
    d.*,
    a.asset_code,
    a.name as asset_name
FROM eam_dga_analyses d
JOIN eam_assets a ON d.asset_id = a.id
ORDER BY asset_id, sample_date DESC;

COMMENT ON VIEW eam_latest_dga IS 'Latest DGA results for each asset';

-- Assets with critical DGA status
CREATE OR REPLACE VIEW eam_dga_alerts AS
SELECT
    d.id,
    d.asset_id,
    a.asset_code,
    a.name as asset_name,
    d.sample_date,
    d.status,
    d.fault_type,
    d.total_combustible_gas_ppm,
    d.acetylene_c2h2_ppm
FROM eam_dga_analyses d
JOIN eam_assets a ON d.asset_id = a.id
WHERE d.status IN ('warning', 'critical')
AND d.sample_date > NOW() - INTERVAL '1 year'
ORDER BY
    CASE d.status WHEN 'critical' THEN 1 WHEN 'warning' THEN 2 END,
    d.sample_date DESC;

COMMENT ON VIEW eam_dga_alerts IS 'DGA results requiring attention (warning or critical)';

-- Thermal hotspots requiring action
CREATE OR REPLACE VIEW eam_thermal_hotspots AS
SELECT
    t.id,
    t.asset_id,
    a.asset_code,
    a.name as asset_name,
    t.scan_date,
    t.component_location,
    t.max_temp_c,
    t.delta_t_c,
    t.severity,
    t.recommended_action
FROM eam_thermal_imaging t
JOIN eam_assets a ON t.asset_id = a.id
WHERE t.severity IN ('intermediate', 'serious', 'critical')
AND t.scan_date > NOW() - INTERVAL '6 months'
ORDER BY
    CASE t.severity WHEN 'critical' THEN 1 WHEN 'serious' THEN 2 WHEN 'intermediate' THEN 3 END,
    t.scan_date DESC;

COMMENT ON VIEW eam_thermal_hotspots IS 'Thermal hotspots requiring attention';
