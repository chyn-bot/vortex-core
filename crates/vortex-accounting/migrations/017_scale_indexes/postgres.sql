-- Scale-ready indexes for the acc_move lists (journal entries, invoices/bills).
--
-- Browse ordering — serve `ORDER BY <date>, id` from an index instead of sorting
-- the whole table per page:
--   Journal Entries sorts by move_date.
--   Invoices/bills filter by move_type and sort by invoice_date, so a composite
--   leading with move_type lets the filter + ordering come from one index.
CREATE INDEX IF NOT EXISTS idx_acc_move_movedate_id ON acc_move (move_date, id);
CREATE INDEX IF NOT EXISTS idx_acc_move_type_invdate_id ON acc_move (move_type, invoice_date, id);

-- Index-served search — the list's `search_prefilter()` runs
-- `m.id IN (SELECT id FROM acc_move WHERE COALESCE(number::text,'') ILIKE $1
-- OR COALESCE(ref::text,'') ILIKE $1)`. These pg_trgm GIN indexes on the exact
-- expression let a leading-wildcard ILIKE use an index instead of a seq scan.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_acc_move_number_trgm
    ON acc_move USING gin ((COALESCE(number::text, '')) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_acc_move_ref_trgm
    ON acc_move USING gin ((COALESCE(ref::text, '')) gin_trgm_ops);
