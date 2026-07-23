-- Rollback migration 008 (SESB EAM): remove the work-order transition policy.
-- Removing the permit reverts WorkOrder transitions to Cedar default-deny
-- (relevant only when EAM_TRANSITION_POLICY=enforce).
DELETE FROM policy_rules WHERE name = 'eam_work_order_transitions';
