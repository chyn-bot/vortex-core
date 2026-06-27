-- Migration 113: Condition Monitoring Metadata
-- Adds common metadata fields to all 8 specialized condition monitoring tables
-- for SESB specification parity.

-- ============================================================================
-- Common fields to add to ALL condition monitoring tables:
--   test_report_number  VARCHAR(100)  - External lab report reference
--   result_summary      TEXT          - Overall result narrative
--   tested_by           UUID          - FK to users (who performed the test)
--   workflow_state       VARCHAR(20)  - draft/submitted/reviewed
--   recommendations     TEXT          - Recommended follow-up actions
-- ============================================================================

-- 1. eam_dga_analyses
ALTER TABLE eam_dga_analyses
ADD COLUMN IF NOT EXISTS test_report_number VARCHAR(100),
ADD COLUMN IF NOT EXISTS result_summary TEXT,
ADD COLUMN IF NOT EXISTS tested_by UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS workflow_state VARCHAR(20) DEFAULT 'draft',
ADD COLUMN IF NOT EXISTS recommendations TEXT;

-- 2. eam_oil_quality_tests
ALTER TABLE eam_oil_quality_tests
ADD COLUMN IF NOT EXISTS test_report_number VARCHAR(100),
ADD COLUMN IF NOT EXISTS result_summary TEXT,
ADD COLUMN IF NOT EXISTS tested_by UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS workflow_state VARCHAR(20) DEFAULT 'draft',
ADD COLUMN IF NOT EXISTS recommendations TEXT;

-- 3. eam_thermal_imaging (already has recommended_action, skip recommendations)
ALTER TABLE eam_thermal_imaging
ADD COLUMN IF NOT EXISTS test_report_number VARCHAR(100),
ADD COLUMN IF NOT EXISTS result_summary TEXT,
ADD COLUMN IF NOT EXISTS tested_by UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS workflow_state VARCHAR(20) DEFAULT 'draft';

-- 4. eam_partial_discharge_tests
ALTER TABLE eam_partial_discharge_tests
ADD COLUMN IF NOT EXISTS test_report_number VARCHAR(100),
ADD COLUMN IF NOT EXISTS result_summary TEXT,
ADD COLUMN IF NOT EXISTS tested_by UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS workflow_state VARCHAR(20) DEFAULT 'draft',
ADD COLUMN IF NOT EXISTS recommendations TEXT;

-- 5. eam_insulation_resistance_tests
ALTER TABLE eam_insulation_resistance_tests
ADD COLUMN IF NOT EXISTS test_report_number VARCHAR(100),
ADD COLUMN IF NOT EXISTS result_summary TEXT,
ADD COLUMN IF NOT EXISTS tested_by UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS workflow_state VARCHAR(20) DEFAULT 'draft',
ADD COLUMN IF NOT EXISTS recommendations TEXT;

-- 6. eam_sf6_analyses
ALTER TABLE eam_sf6_analyses
ADD COLUMN IF NOT EXISTS test_report_number VARCHAR(100),
ADD COLUMN IF NOT EXISTS result_summary TEXT,
ADD COLUMN IF NOT EXISTS tested_by UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS workflow_state VARCHAR(20) DEFAULT 'draft',
ADD COLUMN IF NOT EXISTS recommendations TEXT;

-- 7. eam_contact_timing_tests
ALTER TABLE eam_contact_timing_tests
ADD COLUMN IF NOT EXISTS test_report_number VARCHAR(100),
ADD COLUMN IF NOT EXISTS result_summary TEXT,
ADD COLUMN IF NOT EXISTS tested_by UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS workflow_state VARCHAR(20) DEFAULT 'draft',
ADD COLUMN IF NOT EXISTS recommendations TEXT;

-- 8. eam_battery_discharge_tests
ALTER TABLE eam_battery_discharge_tests
ADD COLUMN IF NOT EXISTS test_report_number VARCHAR(100),
ADD COLUMN IF NOT EXISTS result_summary TEXT,
ADD COLUMN IF NOT EXISTS tested_by UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS workflow_state VARCHAR(20) DEFAULT 'draft',
ADD COLUMN IF NOT EXISTS recommendations TEXT;

-- ============================================================================
-- CHECK constraints for workflow_state on all 8 tables
-- ============================================================================

ALTER TABLE eam_dga_analyses
DROP CONSTRAINT IF EXISTS chk_dga_workflow_state;
ALTER TABLE eam_dga_analyses
ADD CONSTRAINT chk_dga_workflow_state CHECK (
    workflow_state IS NULL OR workflow_state IN ('draft', 'submitted', 'reviewed')
);

ALTER TABLE eam_oil_quality_tests
DROP CONSTRAINT IF EXISTS chk_oil_workflow_state;
ALTER TABLE eam_oil_quality_tests
ADD CONSTRAINT chk_oil_workflow_state CHECK (
    workflow_state IS NULL OR workflow_state IN ('draft', 'submitted', 'reviewed')
);

ALTER TABLE eam_thermal_imaging
DROP CONSTRAINT IF EXISTS chk_thermal_workflow_state;
ALTER TABLE eam_thermal_imaging
ADD CONSTRAINT chk_thermal_workflow_state CHECK (
    workflow_state IS NULL OR workflow_state IN ('draft', 'submitted', 'reviewed')
);

ALTER TABLE eam_partial_discharge_tests
DROP CONSTRAINT IF EXISTS chk_pd_workflow_state;
ALTER TABLE eam_partial_discharge_tests
ADD CONSTRAINT chk_pd_workflow_state CHECK (
    workflow_state IS NULL OR workflow_state IN ('draft', 'submitted', 'reviewed')
);

ALTER TABLE eam_insulation_resistance_tests
DROP CONSTRAINT IF EXISTS chk_ir_workflow_state;
ALTER TABLE eam_insulation_resistance_tests
ADD CONSTRAINT chk_ir_workflow_state CHECK (
    workflow_state IS NULL OR workflow_state IN ('draft', 'submitted', 'reviewed')
);

ALTER TABLE eam_sf6_analyses
DROP CONSTRAINT IF EXISTS chk_sf6_workflow_state;
ALTER TABLE eam_sf6_analyses
ADD CONSTRAINT chk_sf6_workflow_state CHECK (
    workflow_state IS NULL OR workflow_state IN ('draft', 'submitted', 'reviewed')
);

ALTER TABLE eam_contact_timing_tests
DROP CONSTRAINT IF EXISTS chk_contact_workflow_state;
ALTER TABLE eam_contact_timing_tests
ADD CONSTRAINT chk_contact_workflow_state CHECK (
    workflow_state IS NULL OR workflow_state IN ('draft', 'submitted', 'reviewed')
);

ALTER TABLE eam_battery_discharge_tests
DROP CONSTRAINT IF EXISTS chk_battery_workflow_state;
ALTER TABLE eam_battery_discharge_tests
ADD CONSTRAINT chk_battery_workflow_state CHECK (
    workflow_state IS NULL OR workflow_state IN ('draft', 'submitted', 'reviewed')
);

-- ============================================================================
-- Indexes for workflow_state and tested_by on all tables
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_dga_workflow_state ON eam_dga_analyses(workflow_state);
CREATE INDEX IF NOT EXISTS idx_dga_tested_by ON eam_dga_analyses(tested_by);

CREATE INDEX IF NOT EXISTS idx_oil_workflow_state ON eam_oil_quality_tests(workflow_state);
CREATE INDEX IF NOT EXISTS idx_oil_tested_by ON eam_oil_quality_tests(tested_by);

CREATE INDEX IF NOT EXISTS idx_thermal_workflow_state ON eam_thermal_imaging(workflow_state);
CREATE INDEX IF NOT EXISTS idx_thermal_tested_by ON eam_thermal_imaging(tested_by);

CREATE INDEX IF NOT EXISTS idx_pd_workflow_state ON eam_partial_discharge_tests(workflow_state);
CREATE INDEX IF NOT EXISTS idx_pd_tested_by ON eam_partial_discharge_tests(tested_by);

CREATE INDEX IF NOT EXISTS idx_ir_workflow_state ON eam_insulation_resistance_tests(workflow_state);
CREATE INDEX IF NOT EXISTS idx_ir_tested_by ON eam_insulation_resistance_tests(tested_by);

CREATE INDEX IF NOT EXISTS idx_sf6_workflow_state ON eam_sf6_analyses(workflow_state);
CREATE INDEX IF NOT EXISTS idx_sf6_tested_by ON eam_sf6_analyses(tested_by);

CREATE INDEX IF NOT EXISTS idx_contact_workflow_state ON eam_contact_timing_tests(workflow_state);
CREATE INDEX IF NOT EXISTS idx_contact_tested_by ON eam_contact_timing_tests(tested_by);

CREATE INDEX IF NOT EXISTS idx_battery_workflow_state ON eam_battery_discharge_tests(workflow_state);
CREATE INDEX IF NOT EXISTS idx_battery_tested_by ON eam_battery_discharge_tests(tested_by);

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON COLUMN eam_dga_analyses.test_report_number IS 'External lab report reference number';
COMMENT ON COLUMN eam_dga_analyses.result_summary IS 'Overall test result narrative';
COMMENT ON COLUMN eam_dga_analyses.tested_by IS 'User who performed or supervised the test';
COMMENT ON COLUMN eam_dga_analyses.workflow_state IS 'Workflow state: draft, submitted, reviewed';
COMMENT ON COLUMN eam_dga_analyses.recommendations IS 'Recommended follow-up actions';
