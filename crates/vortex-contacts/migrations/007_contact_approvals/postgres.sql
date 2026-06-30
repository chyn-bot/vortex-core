-- Turn the confirmed -> done "Approve" button into an approval workflow:
-- anyone may submit it, but it now needs a 2-step sign-off
-- (Administrator, then System Administrator). Admins reconfigure in
-- Settings > Approval Rules.
UPDATE record_stage_actions SET required_role = NULL, label = 'Submit for Approval'
 WHERE model = 'contacts' AND label = 'Approve';

INSERT INTO approval_rules (action_id, step, label, approver_role, min_approvals)
SELECT a.id, 1, 'Manager review', 'Administrator', 1
  FROM record_stage_actions a WHERE a.model = 'contacts' AND a.label = 'Submit for Approval'
ON CONFLICT (action_id, step) DO NOTHING;

INSERT INTO approval_rules (action_id, step, label, approver_role, min_approvals)
SELECT a.id, 2, 'Final approval', 'System Administrator', 1
  FROM record_stage_actions a WHERE a.model = 'contacts' AND a.label = 'Submit for Approval'
ON CONFLICT (action_id, step) DO NOTHING;
