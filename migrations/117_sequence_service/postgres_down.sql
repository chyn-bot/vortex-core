-- ============================================================================
-- Migration 117 down: Platform Sequence Service
-- ============================================================================
--
-- Rolls back to the EAM-owned `eam_sequences` table from migration
-- 105. EAM-namespaced rows in the new `sequences` table are migrated
-- back to the old synthetic-key format; rows from other plugins are
-- dropped (they have no home in the old schema and were never valid
-- under migration 105's contract).
--
-- WARNING: if any non-EAM plugin has been using the new sequence
-- service (CRM, finance, …) rolling this migration back will lose
-- their counters. Run `SELECT code, scope, current_value FROM
-- sequences WHERE code NOT LIKE 'eam.%';` before rolling back and
-- preserve the output if you need to restore it later.

CREATE TABLE IF NOT EXISTS eam_sequences (
    sequence_key VARCHAR(100) PRIMARY KEY,
    current_value BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_eam_sequences_key ON eam_sequences(sequence_key);

COMMENT ON TABLE eam_sequences IS 'Auto-increment sequences for EAM codes (EQP, CMP, PRT, MNT, INS)';

-- Reverse the data split: recombine (code='eam.foo', scope='2026')
-- into sequence_key='foo_2026', and (code='eam.foo', scope='')
-- into sequence_key='foo'.
INSERT INTO eam_sequences (sequence_key, current_value, updated_at)
SELECT
    CASE
        WHEN scope = '' THEN regexp_replace(code, '^eam\.', '')
        ELSE regexp_replace(code, '^eam\.', '') || '_' || scope
    END AS sequence_key,
    current_value,
    updated_at
FROM sequences
WHERE code LIKE 'eam.%'
ON CONFLICT (sequence_key) DO NOTHING;

DROP TABLE sequences;
