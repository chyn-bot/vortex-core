-- ============================================================================
-- Migration 119 down: Commerce Primitives
-- ============================================================================
--
-- Drops the commerce primitive tables in reverse dependency order.
-- Any domain tables with FKs to `currencies`, `uoms`, or `taxes`
-- (added by plugins after this migration ran) will fail the
-- rollback — which is correct, since rolling back commerce would
-- orphan their references. Unplug dependent plugins first.

-- Remove the FK from companies before dropping currencies.
ALTER TABLE companies DROP COLUMN IF EXISTS currency_id;

DROP TABLE IF EXISTS taxes;
DROP TABLE IF EXISTS uoms;
DROP TABLE IF EXISTS uom_categories;
DROP TABLE IF EXISTS currency_rates;
DROP TABLE IF EXISTS currencies;
