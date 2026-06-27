-- Migration 120 down: Platform i18n
ALTER TABLE users DROP COLUMN IF EXISTS locale;
ALTER TABLE companies DROP COLUMN IF EXISTS locale;
DROP TABLE IF EXISTS translations;
