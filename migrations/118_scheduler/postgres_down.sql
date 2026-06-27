-- ============================================================================
-- Migration 118 down: Platform Scheduler
-- ============================================================================
--
-- Drops the scheduler table. Any plugin counters, error history, and
-- admin-toggled active flags are lost — back up `scheduled_actions`
-- before rolling back if that state matters.

DROP TABLE IF EXISTS scheduled_actions;
