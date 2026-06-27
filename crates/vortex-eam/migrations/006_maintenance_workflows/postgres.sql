-- ============================================================================
-- EAM - Maintenance Workflows Migration
-- Migration: 105_eam_maintenance_workflows
-- Description: Add state machine support to WorkOrder, enhance InspectionResult
-- ============================================================================

-- ============================================================================
-- ENHANCE WORK ORDERS
-- ============================================================================

-- Add state machine and workflow fields
ALTER TABLE eam_work_orders
ADD COLUMN IF NOT EXISTS maintenance_type VARCHAR(50),
ADD COLUMN IF NOT EXISTS team_ids JSONB,
ADD COLUMN IF NOT EXISTS planned_duration_hours DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS state VARCHAR(20) DEFAULT 'draft',
ADD COLUMN IF NOT EXISTS hold_reason TEXT,
ADD COLUMN IF NOT EXISTS cancel_reason TEXT,
ADD COLUMN IF NOT EXISTS scheduled_end TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS assigned_team_id UUID,
ADD COLUMN IF NOT EXISTS findings TEXT,
ADD COLUMN IF NOT EXISTS actions_taken TEXT,
ADD COLUMN IF NOT EXISTS recommendations TEXT,
ADD COLUMN IF NOT EXISTS parts_used JSONB,
ADD COLUMN IF NOT EXISTS materials_cost DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS labor_cost DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS total_cost DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS requires_approval BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS approved_by UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS approval_signature TEXT,
ADD COLUMN IF NOT EXISTS parent_wo_id UUID REFERENCES eam_work_orders(id),
ADD COLUMN IF NOT EXISTS schedule_id UUID REFERENCES eam_maintenance_schedules(id),
ADD COLUMN IF NOT EXISTS updated_by UUID REFERENCES users(id);

-- Add constraint for valid states
ALTER TABLE eam_work_orders
DROP CONSTRAINT IF EXISTS chk_wo_state;

ALTER TABLE eam_work_orders
ADD CONSTRAINT chk_wo_state CHECK (
    state IS NULL OR state IN ('draft', 'scheduled', 'in_progress', 'on_hold', 'completed', 'cancelled')
);

-- Add constraint for valid maintenance types
ALTER TABLE eam_work_orders
DROP CONSTRAINT IF EXISTS chk_wo_maintenance_type;

ALTER TABLE eam_work_orders
ADD CONSTRAINT chk_wo_maintenance_type CHECK (
    maintenance_type IS NULL OR maintenance_type IN ('pm', 'cm', 'emergency', 'inspection', 'testing', 'overhaul')
);

-- Add constraint for priority (0-3)
ALTER TABLE eam_work_orders
DROP CONSTRAINT IF EXISTS chk_wo_priority;

ALTER TABLE eam_work_orders
ADD CONSTRAINT chk_wo_priority CHECK (
    priority IS NULL OR (priority >= 0 AND priority <= 3)
);

CREATE INDEX IF NOT EXISTS idx_eam_wo_state ON eam_work_orders(state);
CREATE INDEX IF NOT EXISTS idx_eam_wo_maintenance_type ON eam_work_orders(maintenance_type);
CREATE INDEX IF NOT EXISTS idx_eam_wo_assigned_team ON eam_work_orders(assigned_team_id);

COMMENT ON COLUMN eam_work_orders.maintenance_type IS 'Type: pm, cm, emergency, inspection, testing, overhaul';
COMMENT ON COLUMN eam_work_orders.state IS 'State machine: draft, scheduled, in_progress, on_hold, completed, cancelled';
COMMENT ON COLUMN eam_work_orders.priority IS 'Priority: 0=Critical, 1=High, 2=Medium, 3=Low';
COMMENT ON COLUMN eam_work_orders.approval_signature IS 'Base64 encoded signature or cryptographic hash';

-- Migrate existing status to state
UPDATE eam_work_orders
SET state = CASE
    WHEN status = 'draft' THEN 'draft'
    WHEN status = 'pending' THEN 'scheduled'
    WHEN status = 'in_progress' THEN 'in_progress'
    WHEN status = 'completed' THEN 'completed'
    WHEN status = 'cancelled' THEN 'cancelled'
    ELSE 'draft'
END
WHERE state IS NULL AND status IS NOT NULL;

-- ============================================================================
-- ENHANCE INSPECTION RESULTS
-- ============================================================================

ALTER TABLE eam_inspection_results
ADD COLUMN IF NOT EXISTS inspection_code VARCHAR(50) UNIQUE,
ADD COLUMN IF NOT EXISTS work_order_id UUID REFERENCES eam_work_orders(id),
ADD COLUMN IF NOT EXISTS secondary_inspector_id UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS inspection_type VARCHAR(50),
-- Checklist fields
ADD COLUMN IF NOT EXISTS visual_check BOOLEAN,
ADD COLUMN IF NOT EXISTS cleanliness_check BOOLEAN,
ADD COLUMN IF NOT EXISTS corrosion_check BOOLEAN,
ADD COLUMN IF NOT EXISTS oil_leak_check BOOLEAN,
ADD COLUMN IF NOT EXISTS connection_check BOOLEAN,
ADD COLUMN IF NOT EXISTS labeling_check BOOLEAN,
ADD COLUMN IF NOT EXISTS ventilation_check BOOLEAN,
ADD COLUMN IF NOT EXISTS security_check BOOLEAN,
-- Environmental
ADD COLUMN IF NOT EXISTS temperature_c DOUBLE PRECISION,
ADD COLUMN IF NOT EXISTS humidity_percent DOUBLE PRECISION,
-- Assessment
ADD COLUMN IF NOT EXISTS defects_found TEXT,
ADD COLUMN IF NOT EXISTS immediate_action_required BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS immediate_action_taken TEXT,
-- Photos (up to 4)
ADD COLUMN IF NOT EXISTS photo_1_id UUID,
ADD COLUMN IF NOT EXISTS photo_1_caption VARCHAR(200),
ADD COLUMN IF NOT EXISTS photo_2_id UUID,
ADD COLUMN IF NOT EXISTS photo_2_caption VARCHAR(200),
ADD COLUMN IF NOT EXISTS photo_3_id UUID,
ADD COLUMN IF NOT EXISTS photo_3_caption VARCHAR(200),
ADD COLUMN IF NOT EXISTS photo_4_id UUID,
ADD COLUMN IF NOT EXISTS photo_4_caption VARCHAR(200),
-- Approval workflow
ADD COLUMN IF NOT EXISTS state VARCHAR(20) DEFAULT 'draft',
ADD COLUMN IF NOT EXISTS approved_by UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS approved_date TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS approval_signature TEXT,
ADD COLUMN IF NOT EXISTS rejection_reason TEXT,
-- Audit
ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id),
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS updated_by UUID REFERENCES users(id);

-- Add constraint for valid inspection states
ALTER TABLE eam_inspection_results
DROP CONSTRAINT IF EXISTS chk_inspection_state;

ALTER TABLE eam_inspection_results
ADD CONSTRAINT chk_inspection_state CHECK (
    state IS NULL OR state IN ('draft', 'submitted', 'approved', 'rejected')
);

-- Add constraint for valid inspection types
ALTER TABLE eam_inspection_results
DROP CONSTRAINT IF EXISTS chk_inspection_type;

ALTER TABLE eam_inspection_results
ADD CONSTRAINT chk_inspection_type CHECK (
    inspection_type IS NULL OR inspection_type IN ('routine', 'detailed', 'commissioning', 'post_fault')
);

CREATE INDEX IF NOT EXISTS idx_eam_inspection_state ON eam_inspection_results(state);
CREATE INDEX IF NOT EXISTS idx_eam_inspection_wo ON eam_inspection_results(work_order_id);

COMMENT ON COLUMN eam_inspection_results.inspection_type IS 'Type: routine, detailed, commissioning, post_fault';
COMMENT ON COLUMN eam_inspection_results.state IS 'Approval state: draft, submitted, approved, rejected';

-- ============================================================================
-- WORK ORDER STATE HISTORY (Audit Trail)
-- ============================================================================

CREATE TABLE IF NOT EXISTS eam_work_order_state_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    work_order_id UUID NOT NULL REFERENCES eam_work_orders(id) ON DELETE CASCADE,
    from_state VARCHAR(20) NOT NULL,
    to_state VARCHAR(20) NOT NULL,
    action VARCHAR(20) NOT NULL,
    reason TEXT,
    changed_by UUID NOT NULL REFERENCES users(id),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    signature TEXT
);

CREATE INDEX idx_eam_wo_history_wo ON eam_work_order_state_history(work_order_id);
CREATE INDEX idx_eam_wo_history_date ON eam_work_order_state_history(changed_at);

-- Make state history immutable (per CLAUDE.md WORM requirements)
-- No UPDATE or DELETE triggers - records are append-only

COMMENT ON TABLE eam_work_order_state_history IS 'Immutable audit trail of work order state changes';
COMMENT ON COLUMN eam_work_order_state_history.signature IS 'Digital signature for critical transitions (eSig)';

-- Sequence generator is provided by the core platform sequence service
-- (see core migration 117_sequence_service and `vortex_orm::sequence`).
-- EAM used to ship its own `eam_sequences` table here; that DDL was
-- removed when the sequence primitive was promoted to core. Fresh
-- installs never create the legacy table; the core 117 migration
-- handles cleanup on upgrading dev databases that still have it.

-- ============================================================================
-- USEFUL VIEWS
-- ============================================================================

-- Work orders requiring attention (overdue or critical)
CREATE OR REPLACE VIEW eam_work_orders_attention AS
SELECT
    wo.id,
    wo.wo_number,
    wo.title,
    wo.state,
    wo.maintenance_type,
    wo.priority,
    wo.scheduled_start,
    wo.scheduled_end,
    wo.assigned_to,
    a.asset_code,
    a.name as asset_name,
    a.criticality_rating,
    CASE
        WHEN wo.priority = 0 THEN 'Critical'
        WHEN wo.scheduled_start < NOW() AND wo.state IN ('draft', 'scheduled') THEN 'Overdue'
        WHEN a.criticality_rating >= 4 THEN 'Critical Asset'
        ELSE 'Normal'
    END as attention_reason
FROM eam_work_orders wo
LEFT JOIN eam_assets a ON wo.asset_id = a.id
WHERE wo.state NOT IN ('completed', 'cancelled')
AND (
    wo.priority = 0
    OR (wo.scheduled_start < NOW() AND wo.state IN ('draft', 'scheduled'))
    OR a.criticality_rating >= 4
)
ORDER BY
    CASE wo.priority WHEN 0 THEN 1 WHEN 1 THEN 2 WHEN 2 THEN 3 ELSE 4 END,
    wo.scheduled_start;

COMMENT ON VIEW eam_work_orders_attention IS 'Work orders requiring immediate attention';

-- Inspections pending approval
CREATE OR REPLACE VIEW eam_inspections_pending_approval AS
SELECT
    ir.id,
    ir.inspection_code,
    ir.inspection_date,
    ir.state,
    ir.overall_condition,
    ir.condition_score,
    ir.immediate_action_required,
    a.asset_code,
    a.name as asset_name,
    a.criticality_rating,
    u.username as inspector_name
FROM eam_inspection_results ir
JOIN eam_assets a ON ir.asset_id = a.id
LEFT JOIN users u ON ir.inspector_id = u.id
WHERE ir.state = 'submitted'
ORDER BY
    ir.immediate_action_required DESC,
    a.criticality_rating DESC,
    ir.inspection_date;

COMMENT ON VIEW eam_inspections_pending_approval IS 'Inspections awaiting supervisor approval';

-- Work order lifecycle metrics
CREATE OR REPLACE VIEW eam_work_order_metrics AS
SELECT
    wo.company_id,
    wo.maintenance_type,
    COUNT(*) as total_count,
    COUNT(*) FILTER (WHERE wo.state = 'completed') as completed_count,
    COUNT(*) FILTER (WHERE wo.state = 'cancelled') as cancelled_count,
    COUNT(*) FILTER (WHERE wo.state NOT IN ('completed', 'cancelled')) as open_count,
    AVG(EXTRACT(EPOCH FROM (wo.actual_end - wo.actual_start))/3600)
        FILTER (WHERE wo.actual_end IS NOT NULL AND wo.actual_start IS NOT NULL) as avg_duration_hours,
    AVG(wo.total_cost) FILTER (WHERE wo.total_cost IS NOT NULL) as avg_cost
FROM eam_work_orders wo
WHERE wo.created_at > NOW() - INTERVAL '1 year'
GROUP BY wo.company_id, wo.maintenance_type;

COMMENT ON VIEW eam_work_order_metrics IS 'Work order statistics by maintenance type';
