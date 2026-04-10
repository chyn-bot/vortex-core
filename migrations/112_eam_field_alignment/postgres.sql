-- Migration 112: EAM Field Alignment
-- Adds missing fields to eam_assets, eam_work_orders, eam_inspection_results
-- for SESB specification parity with Odoo module.

-- ============================================================================
-- 1. eam_assets - Missing equipment fields
-- ============================================================================

ALTER TABLE eam_assets
ADD COLUMN IF NOT EXISTS manufacture_date DATE,
ADD COLUMN IF NOT EXISTS installation_date DATE,
ADD COLUMN IF NOT EXISTS rated_voltage_kv DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS rated_current_a DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS rated_power_kva DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS condition_status VARCHAR(20) DEFAULT 'good',
ADD COLUMN IF NOT EXISTS health_index DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS notes TEXT;

-- Constraint for condition_status values
ALTER TABLE eam_assets
DROP CONSTRAINT IF EXISTS chk_asset_condition_status;

ALTER TABLE eam_assets
ADD CONSTRAINT chk_asset_condition_status CHECK (
    condition_status IS NULL OR condition_status IN ('good', 'fair', 'poor', 'critical', 'unknown')
);

CREATE INDEX IF NOT EXISTS idx_eam_assets_condition_status ON eam_assets(condition_status);
CREATE INDEX IF NOT EXISTS idx_eam_assets_health_index ON eam_assets(health_index);

COMMENT ON COLUMN eam_assets.manufacture_date IS 'Full manufacture date (supplements year_manufactured)';
COMMENT ON COLUMN eam_assets.installation_date IS 'Date equipment was installed at site';
COMMENT ON COLUMN eam_assets.rated_voltage_kv IS 'Rated voltage in kV (base equipment level)';
COMMENT ON COLUMN eam_assets.rated_current_a IS 'Rated current in Amperes (base equipment level)';
COMMENT ON COLUMN eam_assets.rated_power_kva IS 'Rated power in kVA (base equipment level)';
COMMENT ON COLUMN eam_assets.condition_status IS 'Condition assessment: good, fair, poor, critical, unknown';
COMMENT ON COLUMN eam_assets.health_index IS 'Computed health index (0-100 scale, higher is better)';
COMMENT ON COLUMN eam_assets.notes IS 'Additional notes separate from description';

-- ============================================================================
-- 2. eam_work_orders - Missing maintenance fields
-- ============================================================================

ALTER TABLE eam_work_orders
ADD COLUMN IF NOT EXISTS request_date DATE DEFAULT CURRENT_DATE,
ADD COLUMN IF NOT EXISTS scheduled_time DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS actual_duration_hours DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS work_description TEXT,
ADD COLUMN IF NOT EXISTS checklist_total INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS checklist_completed INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS checklist_progress DOUBLE PRECISION DEFAULT 0,
ADD COLUMN IF NOT EXISTS checklist_score DOUBLE PRECISION DEFAULT 0,
ADD COLUMN IF NOT EXISTS checklist_result VARCHAR(20) DEFAULT 'not_started',
ADD COLUMN IF NOT EXISTS has_critical_failure BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;

-- Constraint for checklist_result values
ALTER TABLE eam_work_orders
DROP CONSTRAINT IF EXISTS chk_wo_checklist_result;

ALTER TABLE eam_work_orders
ADD CONSTRAINT chk_wo_checklist_result CHECK (
    checklist_result IS NULL OR checklist_result IN (
        'not_started', 'in_progress', 'pass', 'fail', 'pass_with_remarks'
    )
);

CREATE INDEX IF NOT EXISTS idx_eam_wo_request_date ON eam_work_orders(request_date);
CREATE INDEX IF NOT EXISTS idx_eam_wo_checklist_result ON eam_work_orders(checklist_result);
CREATE INDEX IF NOT EXISTS idx_eam_wo_is_active ON eam_work_orders(is_active) WHERE is_active = TRUE;

COMMENT ON COLUMN eam_work_orders.request_date IS 'Date the maintenance was requested';
COMMENT ON COLUMN eam_work_orders.scheduled_time IS 'Scheduled time of day (float hours, e.g. 14.5 = 2:30 PM)';
COMMENT ON COLUMN eam_work_orders.actual_duration_hours IS 'Computed actual duration from start/end timestamps';
COMMENT ON COLUMN eam_work_orders.work_description IS 'Detailed work description (separate from title/description)';
COMMENT ON COLUMN eam_work_orders.checklist_total IS 'Total checklist items count';
COMMENT ON COLUMN eam_work_orders.checklist_completed IS 'Completed checklist items count';
COMMENT ON COLUMN eam_work_orders.checklist_progress IS 'Checklist completion percentage (0-100)';
COMMENT ON COLUMN eam_work_orders.checklist_score IS 'Checklist weighted score (0-100)';
COMMENT ON COLUMN eam_work_orders.checklist_result IS 'Result: not_started, in_progress, pass, fail, pass_with_remarks';
COMMENT ON COLUMN eam_work_orders.has_critical_failure IS 'Whether any checklist item flagged critical failure';
COMMENT ON COLUMN eam_work_orders.is_active IS 'Soft active flag for archival';

-- ============================================================================
-- 3. eam_inspection_results - Missing fields and type fixes
-- ============================================================================

-- Add missing fields
ALTER TABLE eam_inspection_results
ADD COLUMN IF NOT EXISTS noise_level_db DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS findings TEXT,
ADD COLUMN IF NOT EXISTS recommendations TEXT,
ADD COLUMN IF NOT EXISTS notes TEXT,
ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;

-- Change check columns from BOOLEAN to VARCHAR(20) for multi-value semantics
-- Must drop the columns and re-add since PostgreSQL cannot ALTER BOOLEAN -> VARCHAR
-- We use a safe approach: add new columns, migrate data, drop old columns, rename

-- Step 1: Add new VARCHAR columns with _v2 suffix
ALTER TABLE eam_inspection_results
ADD COLUMN IF NOT EXISTS visual_check_v2 VARCHAR(20),
ADD COLUMN IF NOT EXISTS cleanliness_check_v2 VARCHAR(20),
ADD COLUMN IF NOT EXISTS corrosion_check_v2 VARCHAR(20),
ADD COLUMN IF NOT EXISTS oil_leak_check_v2 VARCHAR(20),
ADD COLUMN IF NOT EXISTS connection_check_v2 VARCHAR(20),
ADD COLUMN IF NOT EXISTS labeling_check_v2 VARCHAR(20);

-- Step 2: Migrate existing boolean data to string values
UPDATE eam_inspection_results SET visual_check_v2 = CASE
    WHEN visual_check = TRUE THEN 'ok'
    WHEN visual_check = FALSE THEN 'attention'
    ELSE NULL END
WHERE visual_check IS NOT NULL AND visual_check_v2 IS NULL;

UPDATE eam_inspection_results SET cleanliness_check_v2 = CASE
    WHEN cleanliness_check = TRUE THEN 'ok'
    WHEN cleanliness_check = FALSE THEN 'attention'
    ELSE NULL END
WHERE cleanliness_check IS NOT NULL AND cleanliness_check_v2 IS NULL;

UPDATE eam_inspection_results SET corrosion_check_v2 = CASE
    WHEN corrosion_check = TRUE THEN 'none'
    WHEN corrosion_check = FALSE THEN 'moderate'
    ELSE NULL END
WHERE corrosion_check IS NOT NULL AND corrosion_check_v2 IS NULL;

UPDATE eam_inspection_results SET oil_leak_check_v2 = CASE
    WHEN oil_leak_check = TRUE THEN 'none'
    WHEN oil_leak_check = FALSE THEN 'minor'
    ELSE NULL END
WHERE oil_leak_check IS NOT NULL AND oil_leak_check_v2 IS NULL;

UPDATE eam_inspection_results SET connection_check_v2 = CASE
    WHEN connection_check = TRUE THEN 'ok'
    WHEN connection_check = FALSE THEN 'loose'
    ELSE NULL END
WHERE connection_check IS NOT NULL AND connection_check_v2 IS NULL;

UPDATE eam_inspection_results SET labeling_check_v2 = CASE
    WHEN labeling_check = TRUE THEN 'ok'
    WHEN labeling_check = FALSE THEN 'faded'
    ELSE NULL END
WHERE labeling_check IS NOT NULL AND labeling_check_v2 IS NULL;

-- Step 3: Drop old boolean columns
ALTER TABLE eam_inspection_results
DROP COLUMN IF EXISTS visual_check,
DROP COLUMN IF EXISTS cleanliness_check,
DROP COLUMN IF EXISTS corrosion_check,
DROP COLUMN IF EXISTS oil_leak_check,
DROP COLUMN IF EXISTS connection_check,
DROP COLUMN IF EXISTS labeling_check;

-- Step 4: Rename new columns
ALTER TABLE eam_inspection_results RENAME COLUMN visual_check_v2 TO visual_check;
ALTER TABLE eam_inspection_results RENAME COLUMN cleanliness_check_v2 TO cleanliness_check;
ALTER TABLE eam_inspection_results RENAME COLUMN corrosion_check_v2 TO corrosion_check;
ALTER TABLE eam_inspection_results RENAME COLUMN oil_leak_check_v2 TO oil_leak_check;
ALTER TABLE eam_inspection_results RENAME COLUMN connection_check_v2 TO connection_check;
ALTER TABLE eam_inspection_results RENAME COLUMN labeling_check_v2 TO labeling_check;

-- Add CHECK constraints for multi-value check fields
ALTER TABLE eam_inspection_results
DROP CONSTRAINT IF EXISTS chk_visual_check;
ALTER TABLE eam_inspection_results
ADD CONSTRAINT chk_visual_check CHECK (
    visual_check IS NULL OR visual_check IN ('ok', 'attention', 'critical', 'na')
);

ALTER TABLE eam_inspection_results
DROP CONSTRAINT IF EXISTS chk_cleanliness_check;
ALTER TABLE eam_inspection_results
ADD CONSTRAINT chk_cleanliness_check CHECK (
    cleanliness_check IS NULL OR cleanliness_check IN ('ok', 'attention', 'critical', 'na')
);

ALTER TABLE eam_inspection_results
DROP CONSTRAINT IF EXISTS chk_corrosion_check;
ALTER TABLE eam_inspection_results
ADD CONSTRAINT chk_corrosion_check CHECK (
    corrosion_check IS NULL OR corrosion_check IN ('none', 'light', 'moderate', 'severe', 'na')
);

ALTER TABLE eam_inspection_results
DROP CONSTRAINT IF EXISTS chk_oil_leak_check;
ALTER TABLE eam_inspection_results
ADD CONSTRAINT chk_oil_leak_check CHECK (
    oil_leak_check IS NULL OR oil_leak_check IN ('none', 'minor', 'major', 'na')
);

ALTER TABLE eam_inspection_results
DROP CONSTRAINT IF EXISTS chk_connection_check;
ALTER TABLE eam_inspection_results
ADD CONSTRAINT chk_connection_check CHECK (
    connection_check IS NULL OR connection_check IN ('ok', 'loose', 'damaged', 'na')
);

ALTER TABLE eam_inspection_results
DROP CONSTRAINT IF EXISTS chk_labeling_check;
ALTER TABLE eam_inspection_results
ADD CONSTRAINT chk_labeling_check CHECK (
    labeling_check IS NULL OR labeling_check IN ('ok', 'faded', 'missing', 'na')
);

-- Expand inspection_type enum values
ALTER TABLE eam_inspection_results
DROP CONSTRAINT IF EXISTS chk_inspection_type;

ALTER TABLE eam_inspection_results
ADD CONSTRAINT chk_inspection_type CHECK (
    inspection_type IS NULL OR inspection_type IN (
        'routine', 'detailed', 'commissioning', 'post_fault',
        'visual', 'thermal', 'ultrasonic', 'special'
    )
);

-- Expand inspection state to include in_progress and completed
ALTER TABLE eam_inspection_results
DROP CONSTRAINT IF EXISTS chk_inspection_state;

ALTER TABLE eam_inspection_results
ADD CONSTRAINT chk_inspection_state CHECK (
    state IS NULL OR state IN (
        'draft', 'in_progress', 'completed', 'submitted', 'approved', 'rejected'
    )
);

COMMENT ON COLUMN eam_inspection_results.noise_level_db IS 'Ambient noise level in decibels';
COMMENT ON COLUMN eam_inspection_results.findings IS 'Detailed inspection findings';
COMMENT ON COLUMN eam_inspection_results.recommendations IS 'Recommended actions based on inspection';
COMMENT ON COLUMN eam_inspection_results.notes IS 'Additional inspector notes';
COMMENT ON COLUMN eam_inspection_results.visual_check IS 'Visual: ok, attention, critical, na';
COMMENT ON COLUMN eam_inspection_results.cleanliness_check IS 'Cleanliness: ok, attention, critical, na';
COMMENT ON COLUMN eam_inspection_results.corrosion_check IS 'Corrosion: none, light, moderate, severe, na';
COMMENT ON COLUMN eam_inspection_results.oil_leak_check IS 'Oil leak: none, minor, major, na';
COMMENT ON COLUMN eam_inspection_results.connection_check IS 'Connections: ok, loose, damaged, na';
COMMENT ON COLUMN eam_inspection_results.labeling_check IS 'Labeling: ok, faded, missing, na';
COMMENT ON COLUMN eam_inspection_results.inspection_type IS 'Type: routine, detailed, commissioning, post_fault, visual, thermal, ultrasonic, special';
COMMENT ON COLUMN eam_inspection_results.state IS 'State: draft, in_progress, completed, submitted, approved, rejected';

-- ============================================================================
-- 4. Update views that reference inspection checks
-- ============================================================================

-- Recreate the inspections pending view with updated semantics
CREATE OR REPLACE VIEW eam_inspections_pending AS
SELECT
    ir.id,
    ir.inspection_code,
    ir.asset_id,
    a.name as asset_name,
    a.asset_code,
    ir.inspection_date,
    ir.inspection_type,
    ir.state,
    ir.overall_condition,
    ir.condition_score,
    a.criticality_rating,
    u.username as inspector_name
FROM eam_inspection_results ir
JOIN eam_assets a ON ir.asset_id = a.id
LEFT JOIN users u ON ir.inspector_id = u.id
WHERE ir.state IN ('draft', 'in_progress', 'submitted')
ORDER BY
    a.criticality_rating ASC NULLS LAST,
    ir.inspection_date DESC;

COMMENT ON VIEW eam_inspections_pending IS 'Inspections awaiting completion or approval';
