-- Lock the terminal stages and seed example transition buttons. Admins can
-- change all of this from Settings > Stages / Stage Buttons.
UPDATE record_stages SET locked = true WHERE model = 'contacts' AND code IN ('done', 'cancelled');

INSERT INTO record_stage_actions (model, label, target_stage, from_stage, required_role, color, sequence) VALUES
    ('contacts', 'Confirm',        'confirmed', 'draft',     NULL,                  'primary', 10),
    ('contacts', 'Approve',        'done',      'confirmed', 'System Administrator','success', 20),
    ('contacts', 'Cancel',         'cancelled', NULL,        NULL,                  'error',   30),
    ('contacts', 'Reset to Draft', 'draft',     NULL,        'System Administrator','neutral', 40)
ON CONFLICT (model, label) DO NOTHING;
