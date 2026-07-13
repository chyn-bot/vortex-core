-- Down: portal users
DELETE FROM roles WHERE id = '00000000-0000-0000-0000-000000000005';
DROP INDEX IF EXISTS idx_users_portal;
DROP INDEX IF EXISTS idx_users_contact;
ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_users_portal_contact;
ALTER TABLE users DROP COLUMN IF EXISTS contact_id;
ALTER TABLE users DROP COLUMN IF EXISTS is_portal;
