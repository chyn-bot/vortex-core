-- Trigram (pg_trgm) indexes for index-served contacts search.
--
-- The list search is a leading-wildcard `ILIKE '%term%'`, which a btree index
-- cannot serve. With the search prefilter enabled on the contacts list, search
-- becomes `c.id IN (SELECT id FROM contacts WHERE COALESCE(name::text,'') ILIKE $1
-- OR COALESCE(email::text,'') ILIKE $1 OR COALESCE(city::text,'') ILIKE $1)`.
--
-- These GIN indexes are on the EXACT expression the prefilter emits
-- (`COALESCE(col::text,'')`), so the planner uses them for the ILIKE — turning a
-- ~375 ms full seq scan of the whole table into a ~7 ms bitmap index scan.
--
-- On a very large existing table, build these out-of-band with CREATE INDEX
-- CONCURRENTLY (which cannot run inside a migration transaction), then mark the
-- migration applied.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_contacts_name_trgm
    ON contacts USING gin ((COALESCE(name::text, '')) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_contacts_email_trgm
    ON contacts USING gin ((COALESCE(email::text, '')) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_contacts_city_trgm
    ON contacts USING gin ((COALESCE(city::text, '')) gin_trgm_ops);
