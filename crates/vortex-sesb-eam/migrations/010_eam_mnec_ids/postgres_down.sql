-- Down migration for 010_eam_mnec_ids.
ALTER TABLE eam_distribution_line DROP CONSTRAINT IF EXISTS uq_eam_distribution_line_asset_id;
ALTER TABLE eam_ugc_line          DROP CONSTRAINT IF EXISTS uq_eam_ugc_line_asset_id;
ALTER TABLE eam_transmission_tower DROP CONSTRAINT IF EXISTS uq_eam_transmission_tower_asset_id;
DROP INDEX IF EXISTS idx_eam_distribution_line_route;
ALTER TABLE eam_distribution_line DROP COLUMN IF EXISTS route_number;
ALTER TABLE eam_distribution_line DROP COLUMN IF EXISTS asset_id;
ALTER TABLE eam_substation        DROP COLUMN IF EXISTS acronym;
