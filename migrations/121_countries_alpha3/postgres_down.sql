DROP INDEX IF EXISTS idx_countries_alpha3;
ALTER TABLE countries DROP COLUMN IF EXISTS alpha3;
