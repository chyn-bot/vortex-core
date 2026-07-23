-- Reconciliation — role-gated stage-transition BUTTONS (not clickable chips).
--
-- The status bar is display-only; movement happens via these buttons, each
-- shown only to users holding the required role. Admins configure all of this
-- from Settings ▸ Stage Buttons. Roles are recon-owned (only active where the
-- module is installed).

-- Workflow roles.
INSERT INTO roles (id, name, description, permissions, is_system, owning_module)
SELECT gen_random_uuid(), v.name, v.descr, '[]'::jsonb, false, 'recon'
FROM (VALUES
    ('Recon Operator',  'Reconciliation: extract & match invoices'),
    ('Recon Validator', 'Reconciliation: validate invoices against M3'),
    ('Recon Approver',  'Reconciliation: approve invoices for payment')
) AS v(name, descr)
WHERE NOT EXISTS (SELECT 1 FROM roles r WHERE r.name = v.name);

-- Transition buttons for recon_batch. from_stage NULL = shown from any stage.
INSERT INTO record_stage_actions (model, label, target_stage, from_stage, required_role, color, sequence) VALUES
    ('recon_batch', 'Mark Matched', 'matched',   'extracted', 'Recon Operator',  'info',    10),
    ('recon_batch', 'Validate',     'validated', NULL,        'Recon Validator', 'success', 20),
    ('recon_batch', 'Approve',      'approved',  'validated', 'Recon Approver',  'primary', 30),
    ('recon_batch', 'Reject',       'rejected',  NULL,        'Recon Validator', 'error',   40),
    ('recon_batch', 'Reopen',       'extracted', 'rejected',  'Recon Operator',  'neutral', 50)
ON CONFLICT (model, label) DO NOTHING;

-- Grant the default admin all recon roles so the workflow is operable out of the
-- box (clients reassign as they see fit).
INSERT INTO user_roles (id, user_id, role_id)
SELECT gen_random_uuid(), u.id, r.id
  FROM users u, roles r
 WHERE u.username = 'admin' AND r.name IN ('Recon Operator', 'Recon Validator', 'Recon Approver')
ON CONFLICT (user_id, role_id) DO NOTHING;
