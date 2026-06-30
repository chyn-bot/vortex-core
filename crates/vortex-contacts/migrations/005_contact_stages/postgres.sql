-- Seed the contacts lifecycle stages for the dynamic status bar. Users can
-- add/edit/reorder more from Settings > Stages; these are just the defaults.
INSERT INTO record_stages (model, code, label, color, sequence, always_visible) VALUES
    ('contacts', 'draft',     'Draft',     'neutral', 10, true),
    ('contacts', 'confirmed', 'Confirmed', 'info',    20, true),
    ('contacts', 'done',      'Done',      'success', 30, true),
    ('contacts', 'cancelled', 'Cancelled', 'error',   40, false)
ON CONFLICT (model, code) DO NOTHING;
