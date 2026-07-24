-- ============================================================================
-- Migration 012: field-level parity (spec §3) — remaining columns
--
-- Adds the concrete columns still missing after Phases 1–4. The bulk of the
-- headline "1170 missing fields" was an Odoo `_inherits` flattening artifact
-- (base-equipment fields correctly live on eam_equipment, not the detail rows)
-- or was already delivered (division §6.3, acronym §4.9, the asset register
-- §3.9). What remains:
--
--  1. Denormalized geo roll-ups (region/zon/kawasan/site/hierarchy_level) on
--     substation/bay/equipment — parity, and they also back the region filters
--     the analytics/dashboards already reference (previously a latent gap).
--  2. A short tail of scattered single fields on approval / inspection / defect
--     / field-agent-group / equipment.
-- ============================================================================

-- ── 1. Geo roll-up columns ──────────────────────────────────────────────────
ALTER TABLE eam_substation ADD COLUMN IF NOT EXISTS region_id  UUID REFERENCES eam_region(id) ON DELETE SET NULL;
ALTER TABLE eam_substation ADD COLUMN IF NOT EXISTS kawasan_id UUID REFERENCES eam_kawasan(id) ON DELETE SET NULL;
ALTER TABLE eam_substation ADD COLUMN IF NOT EXISTS zon_id     UUID REFERENCES eam_zon(id) ON DELETE SET NULL;
ALTER TABLE eam_substation ADD COLUMN IF NOT EXISTS hierarchy_level INTEGER;

ALTER TABLE eam_bay ADD COLUMN IF NOT EXISTS site_id    UUID REFERENCES eam_site(id) ON DELETE SET NULL;
ALTER TABLE eam_bay ADD COLUMN IF NOT EXISTS region_id  UUID REFERENCES eam_region(id) ON DELETE SET NULL;
ALTER TABLE eam_bay ADD COLUMN IF NOT EXISTS kawasan_id UUID REFERENCES eam_kawasan(id) ON DELETE SET NULL;
ALTER TABLE eam_bay ADD COLUMN IF NOT EXISTS zon_id     UUID REFERENCES eam_zon(id) ON DELETE SET NULL;
ALTER TABLE eam_bay ADD COLUMN IF NOT EXISTS hierarchy_level INTEGER;

ALTER TABLE eam_equipment ADD COLUMN IF NOT EXISTS site_id    UUID REFERENCES eam_site(id) ON DELETE SET NULL;
ALTER TABLE eam_equipment ADD COLUMN IF NOT EXISTS region_id  UUID REFERENCES eam_region(id) ON DELETE SET NULL;
ALTER TABLE eam_equipment ADD COLUMN IF NOT EXISTS kawasan_id UUID REFERENCES eam_kawasan(id) ON DELETE SET NULL;
ALTER TABLE eam_equipment ADD COLUMN IF NOT EXISTS zon_id     UUID REFERENCES eam_zon(id) ON DELETE SET NULL;
ALTER TABLE eam_equipment ADD COLUMN IF NOT EXISTS site_type       VARCHAR(24);
ALTER TABLE eam_equipment ADD COLUMN IF NOT EXISTS substation_type VARCHAR(24);
ALTER TABLE eam_equipment ADD COLUMN IF NOT EXISTS panel_number    VARCHAR(32);

CREATE INDEX IF NOT EXISTS idx_eam_substation_region ON eam_substation(region_id);
CREATE INDEX IF NOT EXISTS idx_eam_bay_region        ON eam_bay(region_id);
CREATE INDEX IF NOT EXISTS idx_eam_equipment_region  ON eam_equipment(region_id);

-- Backfill top-down so each level can read the one above.
UPDATE eam_substation ss SET region_id = si.region_id, kawasan_id = si.kawasan_id, zon_id = si.zon_id
  FROM eam_site si WHERE si.id = ss.site_id;
UPDATE eam_bay b SET site_id = ss.site_id, region_id = si.region_id, kawasan_id = si.kawasan_id, zon_id = si.zon_id
  FROM eam_substation ss JOIN eam_site si ON si.id = ss.site_id WHERE ss.id = b.substation_id;
UPDATE eam_equipment e SET site_id = si.id, region_id = si.region_id, kawasan_id = si.kawasan_id, zon_id = si.zon_id
  FROM eam_substation ss JOIN eam_site si ON si.id = ss.site_id
  WHERE ss.id = COALESCE(e.substation_id, (SELECT substation_id FROM eam_bay WHERE id = e.bay_id));

-- ── 2. Short tail ───────────────────────────────────────────────────────────
-- Approval matrix: currency + the three approval-level groups (roles).
ALTER TABLE eam_approval_matrix ADD COLUMN IF NOT EXISTS currency_id      UUID;
ALTER TABLE eam_approval_matrix ADD COLUMN IF NOT EXISTS level_1_group_id UUID REFERENCES roles(id) ON DELETE SET NULL;
ALTER TABLE eam_approval_matrix ADD COLUMN IF NOT EXISTS level_2_group_id UUID REFERENCES roles(id) ON DELETE SET NULL;
ALTER TABLE eam_approval_matrix ADD COLUMN IF NOT EXISTS level_3_group_id UUID REFERENCES roles(id) ON DELETE SET NULL;

-- Approval request can target a register asset (§3.9 now exists).
ALTER TABLE eam_approval_request ADD COLUMN IF NOT EXISTS asset_id UUID REFERENCES eam_asset(id) ON DELETE SET NULL;

-- Inspection photos (binary).
ALTER TABLE eam_inspection ADD COLUMN IF NOT EXISTS photo_1 BYTEA;
ALTER TABLE eam_inspection ADD COLUMN IF NOT EXISTS photo_2 BYTEA;
ALTER TABLE eam_inspection ADD COLUMN IF NOT EXISTS photo_3 BYTEA;
ALTER TABLE eam_inspection ADD COLUMN IF NOT EXISTS photo_4 BYTEA;

-- Defect: asset class + the "Perlu Pembaikan" repair sub-state (§5.4).
ALTER TABLE eam_defect ADD COLUMN IF NOT EXISTS asset_class_id UUID REFERENCES eam_asset_class(id) ON DELETE SET NULL;
ALTER TABLE eam_defect ADD COLUMN IF NOT EXISTS repair_maintenance_state VARCHAR(24);

-- Field-agent group supervisor.
ALTER TABLE eam_field_agent_group ADD COLUMN IF NOT EXISTS supervisor_agent_id UUID REFERENCES eam_field_agent(id) ON DELETE SET NULL;
