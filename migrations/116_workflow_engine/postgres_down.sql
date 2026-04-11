-- Rollback migration 116. Drops triggers first, then tables in
-- FK-safe order (transitions references instances).
DROP TRIGGER IF EXISTS trg_workflow_transitions_no_update ON workflow_transitions;
DROP TRIGGER IF EXISTS trg_workflow_transitions_no_delete ON workflow_transitions;
DROP TRIGGER IF EXISTS trg_workflow_transitions_no_truncate ON workflow_transitions;
DROP FUNCTION IF EXISTS workflow_transitions_block_mutation();
DROP TABLE IF EXISTS workflow_transitions;
DROP TRIGGER IF EXISTS trg_workflow_instances_updated_at ON workflow_instances;
DROP INDEX IF EXISTS idx_workflow_instances_type_state;
DROP INDEX IF EXISTS idx_workflow_instances_company;
DROP INDEX IF EXISTS idx_workflow_instances_created_by;
DROP TABLE IF EXISTS workflow_instances;
