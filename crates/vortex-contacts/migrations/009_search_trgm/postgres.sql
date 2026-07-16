-- Trigram (pg_trgm) GIN indexes backing free-text search on the Contacts
-- list. A leading-wildcard `ILIKE '%term%'` cannot use a btree index and
-- otherwise seq-scans the whole table (~20s per search at 12M rows). A GIN
-- trigram index turns it into a bitmap index scan (tens of ms).
--
-- The index expressions MUST match the predicate the list framework emits
-- verbatim — `COALESCE(<col>::text, '')` — or the planner won't use them.
-- Paired with ListConfig::search_prefilter("contacts c") on the list,
-- which wraps the search in `c.id IN (SELECT id FROM contacts c WHERE …)`
-- so the trigram bitmap drives the query instead of the name sort index.
--
-- Searchable columns are name, email, city (all on `contacts`); country
-- was intentionally dropped from search because an OR against the joined
-- countries table defeats these base-table indexes.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_contacts_name_coalesce_trgm
    ON contacts USING gin ((COALESCE(name::text, '')) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_contacts_email_coalesce_trgm
    ON contacts USING gin ((COALESCE(email::text, '')) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_contacts_city_coalesce_trgm
    ON contacts USING gin ((COALESCE(city::text, '')) gin_trgm_ops);
