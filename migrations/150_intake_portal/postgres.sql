-- Vortex Intake — interactive customer portal (Phase 3).
--
-- A signed-in portal user can submit a portal-enabled web_form and track it.
-- The submission ledger gains the actor so portal submissions are attributable
-- and listable ("my requests"), and so a quarantined portal submission replays
-- with the same owner when an admin approves it later.

ALTER TABLE web_form_submission
    ADD COLUMN IF NOT EXISTS partner_id   UUID,                     -- portal partner (contacts) the record belongs to; NULL for anonymous
    ADD COLUMN IF NOT EXISTS submitted_by UUID REFERENCES users(id); -- portal user who submitted; NULL for anonymous

CREATE INDEX IF NOT EXISTS idx_web_form_submission_partner
    ON web_form_submission (partner_id, created_at DESC);
