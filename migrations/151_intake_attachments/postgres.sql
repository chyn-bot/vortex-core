-- Vortex Intake — attachments (Phase 4).
--
-- A submission may carry uploaded files (FileStore blobs). For an immediate
-- accept they are linked as ir_attachment on the new record right away; for a
-- quarantined submission the blobs are already stored but the ir_attachment
-- links are created only on approval — so we remember the stored-blob metadata
-- (key, name, size, mime, checksum) on the submission until then.

ALTER TABLE web_form_submission
    ADD COLUMN IF NOT EXISTS attachments JSONB NOT NULL DEFAULT '[]'::jsonb;
