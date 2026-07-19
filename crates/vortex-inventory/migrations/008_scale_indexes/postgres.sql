-- Scale-ready indexes for the Stock Moves list.
--
-- Browse ordering — serve `ORDER BY reference, id` from an index instead of
-- sorting the whole (high-volume) stock_move table per page.
CREATE INDEX IF NOT EXISTS idx_stock_move_reference_id ON stock_move (reference, id);

-- Index-served search — the list's `search_prefilter()` runs
-- `m.id IN (SELECT id FROM stock_move WHERE COALESCE(reference::text,'') ILIKE $1)`.
-- This pg_trgm GIN index on the exact expression serves the leading-wildcard ILIKE.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_stock_move_reference_trgm
    ON stock_move USING gin ((COALESCE(reference::text, '')) gin_trgm_ops);
