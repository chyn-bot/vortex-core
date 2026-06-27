-- ============================================================================
-- Migration 117 down: Platform Sequence Service
-- ============================================================================
--
-- Drops the platform `sequences` table.
--
-- WARNING: this is destructive — every plugin's generated-code counters
-- live in this table. Run `SELECT code, scope, current_value FROM
-- sequences;` and preserve the output before rolling back if you need
-- to restore counters later.

DROP TABLE IF EXISTS sequences;
