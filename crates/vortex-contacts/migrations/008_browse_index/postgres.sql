-- Composite index backing the default Contacts list browse.
--
-- The list sorts by `name` with `id` as the stable tiebreaker
-- (ORDER BY c.name ASC, c.id). On a large tenant (millions of rows) this
-- ordering is otherwise a full external-merge sort of the whole table on
-- every page load — the dominant cost of paging deep into the list. A
-- (name, id) index lets Postgres satisfy the order by an index scan and
-- drive the two LEFT JOINs by nested-loop PK lookups, so page N is read
-- directly instead of sorted from scratch.
--
-- Paired with ListConfig::count_estimate_from("contacts") on the list,
-- which replaces the full-scan COUNT(*) with the planner's reltuples
-- estimate for unfiltered browses.
--
-- CREATE INDEX (not CONCURRENTLY) so it runs inside the migration
-- transaction like every other plugin migration; on a fresh/empty tenant
-- this is instant, and on a large pre-existing table it is a one-time
-- build during the upgrade window.
CREATE INDEX IF NOT EXISTS idx_contacts_name_browse
    ON contacts (name, id);
