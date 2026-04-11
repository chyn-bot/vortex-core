-- Rollback plugin migration `change_request:001_change_requests`
--
-- Removes the seed Cedar policies and the change_requests table.
-- Does NOT touch workflow_instances or workflow_transitions — those
-- are owned by migration 116 and surviving a CR plugin uninstall is
-- a feature, not a bug (instances become orphans but the history is
-- preserved for audit).

DELETE FROM policy_rules WHERE name IN (
    'change_request_admins_full_access',
    'change_request_admin_role_full_access',
    'change_request_approvers_can_review_and_decide',
    'change_request_any_user_can_submit_or_withdraw_or_close'
);

DROP TABLE IF EXISTS change_requests;
