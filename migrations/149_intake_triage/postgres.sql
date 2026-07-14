-- Vortex Intake — governance depth (Phase 2).
--
-- Quarantine turns a form into a hold-for-review queue: a submission is captured
-- but the target record is NOT written until an admin approves it. To commit it
-- later we must persist the (already allow-listed) values at capture time, and
-- record who triaged it and when.

ALTER TABLE web_form_submission
    ADD COLUMN IF NOT EXISTS payload     JSONB,                          -- allow-listed values captured at submit (quarantine replays these)
    ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES users(id),      -- admin who approved/rejected a quarantined submission
    ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
