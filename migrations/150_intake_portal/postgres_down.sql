DROP INDEX IF EXISTS idx_web_form_submission_partner;
ALTER TABLE web_form_submission
    DROP COLUMN IF EXISTS partner_id,
    DROP COLUMN IF EXISTS submitted_by;
