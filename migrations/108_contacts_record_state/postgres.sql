-- Add record_state column to contacts table
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS record_state VARCHAR(20) NOT NULL DEFAULT 'draft';
CREATE INDEX IF NOT EXISTS idx_contacts_record_state ON contacts(record_state);
