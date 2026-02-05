-- Migration: 106_eam_checklist_plans
-- Module: asset_management
-- Description: Checklist system, maintenance plans, part lines, extended condition monitoring
-- Date: 2026-02-05

-- ============================================================================
-- CHECKLIST SYSTEM
-- ============================================================================

-- Checklist Templates (reusable per equipment category + maintenance type)
CREATE TABLE IF NOT EXISTS eam_checklist_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    equipment_category VARCHAR(50) NOT NULL,
    maintenance_type VARCHAR(50) NOT NULL,
    version INTEGER DEFAULT 1,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT now(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT now(),
    updated_by UUID REFERENCES users(id)
);

CREATE INDEX idx_checklist_templates_company ON eam_checklist_templates(company_id);
CREATE INDEX idx_checklist_templates_category ON eam_checklist_templates(equipment_category);
CREATE INDEX idx_checklist_templates_type ON eam_checklist_templates(maintenance_type);

COMMENT ON TABLE eam_checklist_templates IS 'Reusable checklist templates per equipment category and maintenance type';

-- Checklist Template Items (individual check items within a template)
CREATE TABLE IF NOT EXISTS eam_checklist_template_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id UUID NOT NULL REFERENCES eam_checklist_templates(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    sequence INTEGER DEFAULT 10,
    section VARCHAR(100),
    input_type VARCHAR(20) NOT NULL CHECK (input_type IN ('pass_fail', 'yes_no', 'measurement', 'text', 'selection', 'rating')),
    -- Measurement configuration
    measurement_unit VARCHAR(50),
    measurement_min DOUBLE PRECISION,
    measurement_max DOUBLE PRECISION,
    -- Selection configuration (JSON array of {value, label, score_value, is_fail})
    selection_options JSONB,
    -- Rating configuration
    rating_scale_max INTEGER,
    -- Flags
    is_required BOOLEAN DEFAULT FALSE,
    is_critical BOOLEAN DEFAULT FALSE,
    is_scored BOOLEAN DEFAULT TRUE,
    weight DOUBLE PRECISION DEFAULT 1.0,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_checklist_items_template ON eam_checklist_template_items(template_id);
CREATE INDEX idx_checklist_items_sequence ON eam_checklist_template_items(template_id, sequence);

COMMENT ON TABLE eam_checklist_template_items IS 'Individual check items within a checklist template, supporting 6 input types';

-- Checklist Lines (instantiated items on a work order)
CREATE TABLE IF NOT EXISTS eam_checklist_lines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    work_order_id UUID NOT NULL REFERENCES eam_work_orders(id) ON DELETE CASCADE,
    template_item_id UUID REFERENCES eam_checklist_template_items(id) ON DELETE SET NULL,
    -- Copied from template item
    name VARCHAR(255) NOT NULL,
    description TEXT,
    sequence INTEGER DEFAULT 10,
    section VARCHAR(100),
    input_type VARCHAR(20) NOT NULL CHECK (input_type IN ('pass_fail', 'yes_no', 'measurement', 'text', 'selection', 'rating')),
    -- Measurement config (copied)
    measurement_unit VARCHAR(50),
    measurement_min DOUBLE PRECISION,
    measurement_max DOUBLE PRECISION,
    -- Selection config (copied)
    selection_options JSONB,
    -- Rating config (copied)
    rating_scale_max INTEGER,
    -- Flags (copied)
    is_required BOOLEAN DEFAULT FALSE,
    is_critical BOOLEAN DEFAULT FALSE,
    is_scored BOOLEAN DEFAULT TRUE,
    weight DOUBLE PRECISION DEFAULT 1.0,
    -- User-input value fields (one per input type)
    value_pass_fail VARCHAR(10),  -- pass, fail, na
    value_yes_no VARCHAR(5),      -- yes, no
    value_measurement DOUBLE PRECISION,
    value_text TEXT,
    value_selection VARCHAR(100),
    value_rating INTEGER,
    -- Computed status fields
    is_completed BOOLEAN DEFAULT FALSE,
    line_score DOUBLE PRECISION,
    is_out_of_range BOOLEAN DEFAULT FALSE,
    is_failed BOOLEAN DEFAULT FALSE,
    measurement_filled BOOLEAN DEFAULT FALSE,
    note TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_checklist_lines_wo ON eam_checklist_lines(work_order_id);
CREATE INDEX idx_checklist_lines_sequence ON eam_checklist_lines(work_order_id, sequence);

COMMENT ON TABLE eam_checklist_lines IS 'Instantiated checklist items on work orders with scoring and completion tracking';

-- ============================================================================
-- MAINTENANCE PLANS
-- ============================================================================

CREATE TABLE IF NOT EXISTS eam_maintenance_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    plan_code VARCHAR(50),
    description TEXT,
    asset_id UUID NOT NULL REFERENCES eam_assets(id) ON DELETE CASCADE,
    maintenance_type VARCHAR(50) NOT NULL,
    priority INTEGER DEFAULT 2,
    planned_duration_hours DOUBLE PRECISION,
    assigned_to UUID REFERENCES users(id),
    checklist_template_id UUID REFERENCES eam_checklist_templates(id) ON DELETE SET NULL,
    -- Schedule configuration
    start_date VARCHAR(20),
    next_maintenance_date VARCHAR(20),
    frequency_interval INTEGER,
    frequency_unit VARCHAR(10) CHECK (frequency_unit IN ('day', 'week', 'month', 'year')),
    planning_horizon_interval INTEGER,
    planning_horizon_unit VARCHAR(10) CHECK (planning_horizon_unit IN ('day', 'week', 'month', 'year')),
    -- State
    state VARCHAR(20) DEFAULT 'draft' CHECK (state IN ('draft', 'active', 'done', 'cancelled')),
    notes TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT now(),
    created_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ DEFAULT now(),
    updated_by UUID REFERENCES users(id)
);

CREATE INDEX idx_maintenance_plans_company ON eam_maintenance_plans(company_id);
CREATE INDEX idx_maintenance_plans_asset ON eam_maintenance_plans(asset_id);
CREATE INDEX idx_maintenance_plans_state ON eam_maintenance_plans(state);
CREATE UNIQUE INDEX idx_maintenance_plans_code ON eam_maintenance_plans(plan_code) WHERE plan_code IS NOT NULL;

COMMENT ON TABLE eam_maintenance_plans IS 'Recurring maintenance schedules with automatic work order generation';

-- ============================================================================
-- MAINTENANCE PART LINES
-- ============================================================================

CREATE TABLE IF NOT EXISTS eam_maintenance_part_lines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    work_order_id UUID NOT NULL REFERENCES eam_work_orders(id) ON DELETE CASCADE,
    part_id UUID,
    sequence INTEGER DEFAULT 10,
    name VARCHAR(255) NOT NULL,
    part_number VARCHAR(100),
    quantity DOUBLE PRECISION DEFAULT 1.0,
    unit VARCHAR(20),
    unit_cost DOUBLE PRECISION DEFAULT 0.0,
    total_cost DOUBLE PRECISION DEFAULT 0.0,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_part_lines_wo ON eam_maintenance_part_lines(work_order_id);

COMMENT ON TABLE eam_maintenance_part_lines IS 'Parts used during work order execution with cost tracking';

-- ============================================================================
-- EXTENDED CONDITION MONITORING
-- ============================================================================

-- SF6 Gas Analysis
CREATE TABLE IF NOT EXISTS eam_sf6_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES eam_assets(id) ON DELETE CASCADE,
    test_date TIMESTAMPTZ NOT NULL,
    lab_reference VARCHAR(100),
    sf6_purity_percent DOUBLE PRECISION,
    sf6_moisture_ppm DOUBLE PRECISION,
    sf6_so2_ppm DOUBLE PRECISION,
    sf6_pressure_bar DOUBLE PRECISION,
    sf6_dew_point_c DOUBLE PRECISION,
    status VARCHAR(20),
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_sf6_asset ON eam_sf6_analyses(asset_id);
CREATE INDEX idx_sf6_date ON eam_sf6_analyses(test_date);

COMMENT ON TABLE eam_sf6_analyses IS 'SF6 gas quality analysis for gas-insulated switchgear and circuit breakers';

-- Contact Resistance / Timing Tests
CREATE TABLE IF NOT EXISTS eam_contact_timing_tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES eam_assets(id) ON DELETE CASCADE,
    test_date TIMESTAMPTZ NOT NULL,
    lab_reference VARCHAR(100),
    contact_resistance_micro_ohm DOUBLE PRECISION,
    closing_time_ms DOUBLE PRECISION,
    opening_time_ms DOUBLE PRECISION,
    close_open_time_ms DOUBLE PRECISION,
    reclose_time_ms DOUBLE PRECISION,
    simultaneity_ms DOUBLE PRECISION,
    status VARCHAR(20),
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_contact_timing_asset ON eam_contact_timing_tests(asset_id);
CREATE INDEX idx_contact_timing_date ON eam_contact_timing_tests(test_date);

COMMENT ON TABLE eam_contact_timing_tests IS 'Contact resistance and timing measurements for circuit breakers';

-- Battery Discharge Tests
CREATE TABLE IF NOT EXISTS eam_battery_discharge_tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES eam_assets(id) ON DELETE CASCADE,
    test_date TIMESTAMPTZ NOT NULL,
    lab_reference VARCHAR(100),
    capacity_percent DOUBLE PRECISION,
    discharge_time_hours DOUBLE PRECISION,
    internal_resistance_mohm DOUBLE PRECISION,
    float_voltage_v DOUBLE PRECISION,
    equalize_voltage_v DOUBLE PRECISION,
    specific_gravity DOUBLE PRECISION,
    electrolyte_temp_c DOUBLE PRECISION,
    status VARCHAR(20),
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_battery_discharge_asset ON eam_battery_discharge_tests(asset_id);
CREATE INDEX idx_battery_discharge_date ON eam_battery_discharge_tests(test_date);

COMMENT ON TABLE eam_battery_discharge_tests IS 'Battery bank discharge and condition test results';

-- ============================================================================
-- ALTER EXISTING TABLES
-- ============================================================================

-- Add IR 30-second reading to insulation resistance tests (for DAR calculation)
ALTER TABLE eam_insulation_resistance_tests
    ADD COLUMN IF NOT EXISTS ir_30s_mohm DOUBLE PRECISION;

COMMENT ON COLUMN eam_insulation_resistance_tests.ir_30s_mohm IS '30-second IR reading in MOhm for DAR calculation';

-- Add checklist template reference to work orders
ALTER TABLE eam_work_orders
    ADD COLUMN IF NOT EXISTS checklist_template_id UUID REFERENCES eam_checklist_templates(id) ON DELETE SET NULL;

-- Add maintenance plan reference to work orders
ALTER TABLE eam_work_orders
    ADD COLUMN IF NOT EXISTS plan_id UUID REFERENCES eam_maintenance_plans(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_work_orders_plan ON eam_work_orders(plan_id) WHERE plan_id IS NOT NULL;

-- ============================================================================
-- USEFUL VIEWS
-- ============================================================================

-- Checklist progress per work order
CREATE OR REPLACE VIEW eam_checklist_progress AS
SELECT
    cl.work_order_id,
    COUNT(*) AS total_items,
    COUNT(*) FILTER (WHERE cl.is_completed = TRUE) AS completed_items,
    ROUND(
        (COUNT(*) FILTER (WHERE cl.is_completed = TRUE)::numeric / NULLIF(COUNT(*), 0)::numeric) * 100, 1
    ) AS progress_percent,
    AVG(cl.line_score) FILTER (WHERE cl.is_scored = TRUE AND cl.line_score IS NOT NULL) AS avg_score,
    BOOL_OR(cl.is_failed = TRUE AND cl.is_critical = TRUE) AS has_critical_failure
FROM eam_checklist_lines cl
GROUP BY cl.work_order_id;

COMMENT ON VIEW eam_checklist_progress IS 'Checklist completion progress and scoring summary per work order';

-- Active maintenance plans with next due info
CREATE OR REPLACE VIEW eam_active_plans AS
SELECT
    mp.*,
    a.name AS asset_name,
    a.asset_code AS asset_code,
    ct.name AS checklist_name
FROM eam_maintenance_plans mp
JOIN eam_assets a ON a.id = mp.asset_id
LEFT JOIN eam_checklist_templates ct ON ct.id = mp.checklist_template_id
WHERE mp.state = 'active' AND mp.is_active = TRUE;

COMMENT ON VIEW eam_active_plans IS 'Active maintenance plans with asset and checklist details';
