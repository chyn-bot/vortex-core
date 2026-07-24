-- ============================================================================
-- Migration 010: MNEC asset-ID expansion (spec §4.9)
--
-- Adds the columns the composed IDs need and the uniqueness constraints that
-- make a composed ID unique by construction:
--   * eam_substation.acronym       — the location code used in SE-{TS|DS}-{kv}-{acronym}
--   * eam_distribution_line.asset_id + route_number — feeders are an L1 root
--                                     (SE-DF-{kv}-{loc}-F{route}); route_number is unique
--   * unique(company_id, asset_id) on distribution_line / ugc_line / transmission_tower
--     (substation / bay / equipment already carry theirs)
-- ============================================================================

ALTER TABLE eam_substation        ADD COLUMN IF NOT EXISTS acronym VARCHAR(16);
ALTER TABLE eam_distribution_line ADD COLUMN IF NOT EXISTS asset_id VARCHAR(64);
ALTER TABLE eam_distribution_line ADD COLUMN IF NOT EXISTS route_number INTEGER;

-- Uniqueness on the composed ID. NULLs are allowed to repeat (an as-yet
-- uncomposed asset), matching how substation/bay/equipment already behave.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_eam_distribution_line_asset_id') THEN
    ALTER TABLE eam_distribution_line ADD CONSTRAINT uq_eam_distribution_line_asset_id UNIQUE (company_id, asset_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_eam_ugc_line_asset_id') THEN
    ALTER TABLE eam_ugc_line ADD CONSTRAINT uq_eam_ugc_line_asset_id UNIQUE (company_id, asset_id);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_eam_transmission_tower_asset_id') THEN
    ALTER TABLE eam_transmission_tower ADD CONSTRAINT uq_eam_transmission_tower_asset_id UNIQUE (company_id, asset_id);
  END IF;
END$$;

-- Index the feeder route number (used to compose and to enforce uniqueness of
-- the source-location + route pair conceptually).
CREATE INDEX IF NOT EXISTS idx_eam_distribution_line_route ON eam_distribution_line(route_number);
