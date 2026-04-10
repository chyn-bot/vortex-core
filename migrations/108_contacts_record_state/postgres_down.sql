-- Remove record_state column from contacts table
DROP INDEX IF EXISTS idx_contacts_record_state;
ALTER TABLE contacts DROP COLUMN IF EXISTS record_state;
