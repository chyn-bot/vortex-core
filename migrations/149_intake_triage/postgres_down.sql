ALTER TABLE web_form_submission
    DROP COLUMN IF EXISTS payload,
    DROP COLUMN IF EXISTS reviewed_by,
    DROP COLUMN IF EXISTS reviewed_at;
